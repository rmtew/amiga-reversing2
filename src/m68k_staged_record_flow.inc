/* Candidate pointer flow through a unique concrete staging slot and an anchored
 * strided field family. This is bounded static may-flow, not writer ordering,
 * receiver ABI, all aliases or runtime target closure. */
typedef struct StagedOwner {
  uint32_t root, alignment;
  int32_t delta;
  uint8_t valid;
} StagedOwner;
typedef struct StagedFlowState {
  StagedOwner a[8];
  uint32_t multiple[8];
} StagedFlowState;
typedef struct StagedFieldKey {
  uint32_t root, modulus, field;
} StagedFieldKey;

static int staged_static_slot(const M68kDecodeSectionIR *s, const M68kRuntimeAddressSpace *runtime,
    const M68kDecodeCandidate *c, size_t op, uint32_t *at) {
  uint32_t raw;
  M68kInstructionIR instruction;
  const M68kSimFormMetadata *m;
  if (op >= c->operand_count) return 0;
  if (m68k_decode_candidate_to_instruction(c, &instruction) != 0 ||
      !(m = m68k_sim_metadata_for_instruction(&instruction)) ||
      (m->operand_access_kinds[op] != M68K_SIM_ACCESS_MEMORY_READ &&
       m->operand_access_kinds[op] != M68K_SIM_ACCESS_MEMORY_WRITE &&
       m->operand_access_kinds[op] != M68K_SIM_ACCESS_COMPUTE_ADDRESS)) return 0;
  if (m68k_asm_operand_absolute_value(c->operand_kinds[op], &c->operands[op], &raw))
    return record_absolute_pointer_source(runtime, s->section_index, s->size, raw, at);
  return candidate_operand_data_target_offset(c, op, s->section_index, at);
}

static int staged_lea_root(const M68kDecodeSectionIR *s, const M68kRuntimeAddressSpace *runtime,
    const M68kDecodeCandidate *c, uint8_t *reg, uint32_t *at) {
  if (c->mnemonic_id != M68K_ASM_MNEMONIC_LEA || c->operand_count != 2U ||
      !operand_is_address_register_direct(&c->operands[1], reg)) return 0;
  return staged_static_slot(s, runtime, c, 0U, at);
}

static uint32_t staged_constant_multiple(uint32_t value) {
  return !value ? 65536U : (value & (0U - value)) > 65536U ? 65536U : value & (0U - value);
}

static void staged_flow_step(const M68kDecodeSectionIR *s, const M68kRuntimeAddressSpace *runtime,
    const M68kDecodeCandidate *c, StagedFlowState *state) {
  StagedFlowState before = *state;
  uint8_t dest, from;
  uint32_t root, value;
  int32_t displacement;
  for (uint8_t r = 0U; r < 8U; ++r) {
    if (record_writes_reg(c, 1U, r)) memset(&state->a[r], 0, sizeof(state->a[r]));
    if (record_writes_reg(c, 0U, r)) state->multiple[r] = 1U;
  }
  if (staged_lea_root(s, runtime, c, &dest, &root)) {
    memset(&state->a[dest], 0, sizeof(state->a[dest]));
    state->a[dest].root = root; state->a[dest].valid = 1U;
  } else if (c->mnemonic_id == M68K_ASM_MNEMONIC_LEA && c->operand_count == 2U &&
      operand_is_address_register_direct(&c->operands[1], &dest) &&
      candidate_operand_base_field_slot(c, 0U, &from, &displacement) && before.a[from].valid) {
    int64_t delta = (int64_t)before.a[from].delta + displacement;
    if (delta >= INT32_MIN && delta <= INT32_MAX) {
      state->a[dest] = before.a[from]; state->a[dest].delta = (int32_t)delta;
    }
  } else if (c->mnemonic_id == M68K_ASM_MNEMONIC_MOVEA && c->size_suffix == 'l' &&
      c->operand_count == 2U && operand_is_address_register_direct(&c->operands[0], &from) &&
      operand_is_address_register_direct(&c->operands[1], &dest)) state->a[dest] = before.a[from];
  else if (c->mnemonic_id == M68K_ASM_MNEMONIC_ADDA && c->operand_count == 2U &&
      operand_is_address_register_direct(&c->operands[1], &dest) && before.a[dest].valid) {
    if (operand_is_data_register_direct(&c->operands[0], &from)) {
      state->a[dest] = before.a[dest];
      state->a[dest].alignment = before.a[dest].alignment && before.a[dest].alignment < before.multiple[from]
        ? before.a[dest].alignment : before.multiple[from];
    } else if (operand_immediate_value(c->operand_kinds[0], &c->operands[0], &value) && value <= INT16_MAX &&
        (int64_t)before.a[dest].delta + value <= INT32_MAX) {
      state->a[dest] = before.a[dest]; state->a[dest].delta += (int32_t)value;
    }
  }
  if (c->operand_count == 2U && operand_is_data_register_direct(&c->operands[1], &dest)) {
    if ((c->mnemonic_id == M68K_ASM_MNEMONIC_ASL || c->mnemonic_id == M68K_ASM_MNEMONIC_LSL) &&
        (c->size_suffix == 'w' || c->size_suffix == 'l') &&
        operand_immediate_value(c->operand_kinds[0], &c->operands[0], &value) && value <= 15U)
      state->multiple[dest] = before.multiple[dest] >= (65536U >> value) ? 65536U : before.multiple[dest] << value;
    else if (c->mnemonic_id == M68K_ASM_MNEMONIC_ADD &&
        operand_is_data_register_direct(&c->operands[0], &from) && from == dest &&
        (c->size_suffix == 'w' || c->size_suffix == 'l'))
      state->multiple[dest] = before.multiple[dest] >= 32768U ? 65536U : before.multiple[dest] * 2U;
    else if ((c->mnemonic_id == M68K_ASM_MNEMONIC_MOVE || c->mnemonic_id == M68K_ASM_MNEMONIC_MOVEQ) &&
        (c->size_suffix == 'w' || c->size_suffix == 'l')) {
      if (operand_is_data_register_direct(&c->operands[0], &from)) state->multiple[dest] = before.multiple[from];
      else if (operand_immediate_value(c->operand_kinds[0], &c->operands[0], &value))
        state->multiple[dest] = staged_constant_multiple(value);
    }
  }
}

static int staged_field_key(const M68kDecodeCandidate *c, size_t op, const StagedFlowState *state,
    uint32_t required_modulus, StagedFieldKey *key) {
  M68kInstructionIR instruction;
  uint8_t base;
  uint32_t modulus = required_modulus;
  int32_t displacement;
  if (!candidate_operand_base_field_slot(c, op, &base, &displacement)) {
    if (m68k_decode_candidate_to_instruction(c, &instruction) != 0 || op >= instruction.operand_count ||
        !m68k_ir_operand_brief_index_displacement(&instruction.operands[op], &displacement) ||
        instruction.operands[op].value.index_is_address ||
        instruction.operands[op].value.scale > 1U || instruction.operands[op].value.index_reg >= 8U) return 0;
    base = instruction.operands[op].value.ea_reg;
    uint32_t index_multiple = state->multiple[instruction.operands[op].value.index_reg];
    if (!modulus) modulus = index_multiple;
    if (index_multiple < modulus) return 0;
  } else if (!modulus) {
    /* Folding the scaled index into An is the same field family. */
    if (base >= 8U || !state->a[base].valid || !state->a[base].alignment) return 0;
    modulus = state->a[base].alignment;
  }
  if (base >= 8U || !state->a[base].valid || modulus < 4U || modulus > 256U ||
      (state->a[base].alignment && state->a[base].alignment < modulus)) return 0;
  int64_t field = (int64_t)state->a[base].delta + displacement;
  field %= modulus; if (field < 0) field += modulus;
  if ((field & 1U) || (uint32_t)field + 4U > modulus) return 0;
  *key = (StagedFieldKey){state->a[base].root, modulus, (uint32_t)field};
  return 1;
}

static int staged_no_local_overwrite(const M68kDecodeSectionIR *, const uint8_t *,
  const M68kRuntimeAddressSpace *, const M68kDecodeCandidate *, uint32_t);

static int staged_writes_slot(const M68kDecodeSectionIR *s, const M68kRuntimeAddressSpace *runtime,
    const M68kDecodeCandidate *c, uint32_t slot) {
  M68kInstructionIR i; const M68kSimFormMetadata *m;
  if (m68k_decode_candidate_to_instruction(c, &i) != 0 ||
      !(m = m68k_sim_metadata_for_instruction(&i))) return 1;
  for (size_t op = 0U; op < c->operand_count; ++op) {
    uint32_t at; uint8_t width = m68k_sim_operand_width_bytes(&i, (uint8_t)op);
    if (m->operand_access_kinds[op] == M68K_SIM_ACCESS_MEMORY_WRITE && width &&
        staged_static_slot(s, runtime, c, op, &at) &&
        (uint64_t)at + width > slot && (uint64_t)slot + 4U > at) return 1;
  }
  return 0;
}

/* Forward-only accepted CFG witnesses. Calls/unknown transfers stop a path;
 * unsupported register writes invalidate that register. No callee preservation
 * or backward-loop invariant is invented to reach the requested operand. */
static int staged_key_at(const M68kDecodeSectionIR *s, const uint8_t *accepted,
    const M68kRuntimeAddressSpace *runtime, const M68kDecodeCandidate *target, size_t op,
    uint32_t modulus, uint32_t preserved_slot, StagedFieldKey *out) {
  enum { WINDOW = 512, PATH_LIMIT = 128, TOTAL_LIMIT = 4096 };
  typedef struct Node { uint32_t offset; StagedFlowState state; } Node;
  Node nodes[PATH_LIMIT];
  uint32_t total = 0U;
  int found = 0;
  for (size_t origin = 0U; origin < s->candidate_count; ++origin) {
    const M68kDecodeCandidate *anchor = &s->candidates[origin];
    uint8_t reg; uint32_t root;
    if (anchor->offset >= target->offset || target->offset - anchor->offset > WINDOW ||
        !accepted[anchor->offset] || !staged_lea_root(s, runtime, anchor, &reg, &root) ||
        (preserved_slot != UINT32_MAX &&
         !staged_no_local_overwrite(s, accepted, runtime, anchor, preserved_slot))) continue;
    memset(nodes, 0, sizeof(nodes));
    for (reg = 0U; reg < 8U; ++reg) nodes[0].state.multiple[reg] = 1U;
    /* A shift before the anchor may already establish an indexed row stride.
     * Only a bounded sequential slice is used; no branch/call is crossed. */
    for (reg = 0U; reg < 8U; ++reg) {
      uint32_t cursor = anchor->offset;
      for (unsigned back = 0U; back < 16U; ++back) {
        const M68kDecodeCandidate *p = find_accepted_candidate_ending_at(s, accepted, cursor);
        uint8_t dest; uint32_t shift;
        if (!record_sequential_read_only(p)) break;
        if (record_writes_reg(p, 0U, reg)) {
          if ((p->mnemonic_id == M68K_ASM_MNEMONIC_ASL || p->mnemonic_id == M68K_ASM_MNEMONIC_LSL) &&
              (p->size_suffix == 'w' || p->size_suffix == 'l') && p->operand_count == 2U &&
              operand_is_data_register_direct(&p->operands[1], &dest) && dest == reg &&
              operand_immediate_value(p->operand_kinds[0], &p->operands[0], &shift) && shift <= 8U)
            nodes[0].state.multiple[reg] = 1U << shift;
          break;
        }
        cursor = p->offset;
      }
    }
    nodes[0].offset = anchor->offset;
    uint32_t count = 1U;
    for (uint32_t index = 0U; index < count; ++index) {
      Node current = nodes[index];
      if (++total > TOTAL_LIMIT) return 0;
      if (current.offset == target->offset) {
        StagedFieldKey key;
        if (staged_field_key(target, op, &current.state, modulus, &key)) {
          if (found && memcmp(out, &key, sizeof(key))) return 0;
          *out = key; found = 1;
        }
        continue;
      }
      const M68kDecodeCandidate *c = m68k_decode_ir_find_candidate_at_offset(s, current.offset);
      M68kInstructionIR instruction; const M68kSimFormMetadata *m;
      if (!c || !accepted[c->offset] || m68k_decode_candidate_to_instruction(c, &instruction) != 0 ||
          !(m = m68k_sim_metadata_for_instruction(&instruction)) || m->flow_kind == M68K_SIM_FLOW_CALL ||
          m->flow_kind == M68K_SIM_FLOW_RETURN || m->flow_kind == M68K_SIM_FLOW_TRAP ||
          (preserved_slot != UINT32_MAX && staged_writes_slot(s, runtime, c, preserved_slot))) continue;
      staged_flow_step(s, runtime, c, &current.state);
      uint32_t next[2], n = 0U, branch;
      if (candidate_has_normal_fallthrough(c)) next[n++] = c->offset + c->byte_count;
      if (record_branch_to(s, c, &branch) && n < 2U) next[n++] = branch;
      for (uint32_t j = 0U; j < n; ++j) {
        if (next[j] <= c->offset || next[j] > target->offset || !accepted[next[j]]) continue;
        uint32_t k;
        for (k = 0U; k < count; ++k)
          if (nodes[k].offset == next[j] && !memcmp(&nodes[k].state, &current.state, sizeof(current.state))) break;
        if (k != count) continue;
        if (count == PATH_LIMIT) return 0;
        nodes[count++] = (Node){next[j], current.state};
      }
    }
  }
  return found;
}

static int staged_export_table(const M68kDecodeSectionIR *s, const uint8_t *accepted,
    const uint8_t *accepted_bytes, const M68kRuntimeAddressSpace *runtime,
    const M68kDecodeCandidate *export, M68kStagedRecordProbe *out) {
  uint8_t base, dest;
  int32_t field, stride, test_field;
  uint32_t slot, loop, exit, table = 0U;
  const M68kDecodeCandidate *back, *zero, *test, *step, *origin;
  if (export->mnemonic_id != M68K_ASM_MNEMONIC_MOVE || export->size_suffix != 'l' || export->operand_count != 2U ||
      !candidate_operand_base_field_slot(export, 0U, &base, &field) || field < 0 ||
      !staged_static_slot(s, runtime, export, 1U, &slot) || slot > s->size || s->size - slot < 4U) return 0;
  back = find_accepted_candidate_ending_at(s, accepted, export->offset);
  zero = back ? find_accepted_candidate_ending_at(s, accepted, back->offset) : NULL;
  test = zero ? find_accepted_candidate_ending_at(s, accepted, zero->offset) : NULL;
  step = test ? find_accepted_candidate_ending_at(s, accepted, test->offset) : NULL;
  if (!back || back->mnemonic_id != M68K_ASM_MNEMONIC_BRA || !record_branch_to(s, back, &loop) ||
      !zero || zero->mnemonic_id != M68K_ASM_MNEMONIC_BEQ || !record_branch_to(s, zero, &exit) ||
      (exit >= loop && exit <= export->offset) || !test || test->mnemonic_id != M68K_ASM_MNEMONIC_TST ||
      test->size_suffix != 'w' || test->operand_count != 1U ||
      !candidate_operand_base_field_slot(test, 0U, &dest, &test_field) || dest != base || test_field != 0 ||
      !step || step->mnemonic_id != M68K_ASM_MNEMONIC_LEA || step->operand_count != 2U ||
      !operand_is_address_register_direct(&step->operands[1], &dest) || dest != base ||
      !candidate_operand_base_field_slot(step, 0U, &dest, &stride) || dest != base ||
      stride < 4 || stride > 256 || (stride & 1) || field + 4 > stride || (field & 1) || loop >= step->offset) return 0;
  origin = m68k_decode_ir_find_candidate_at_offset(s, loop);
  uint32_t cursor = loop;
  for (unsigned n = 0U; n < 16U; ++n) {
    origin = find_accepted_candidate_ending_at(s, accepted, cursor);
    if (!origin || !record_sequential_read_only(origin)) return 0;
    if (record_writes_reg(origin, 1U, base)) {
      if (!staged_lea_root(s, runtime, origin, &dest, &table) || dest != base) return 0;
      break;
    }
    cursor = origin->offset;
  }
  if (!origin || !staged_lea_root(s, runtime, origin, &dest, &table) || dest != base || (table & 1U)) return 0;
  int match = 0;
  cursor = loop;
  for (unsigned n = 0U; cursor < step->offset && n < 64U; ++n) {
    const M68kDecodeCandidate *c = m68k_decode_ir_find_candidate_at_offset(s, cursor);
    M68kInstructionIR i; const M68kSimFormMetadata *m; uint32_t branch;
    if (!c || !accepted[cursor] || m68k_decode_candidate_to_instruction(c, &i) != 0 ||
        !(m = m68k_sim_metadata_for_instruction(&i)) || record_writes_reg(c, 1U, base) ||
        m->flow_kind == M68K_SIM_FLOW_CALL || m->flow_kind == M68K_SIM_FLOW_RETURN ||
        m->flow_kind == M68K_SIM_FLOW_TRAP ||
        (m->flow_kind == M68K_SIM_FLOW_SEQUENTIAL && !record_sequential_read_only(c))) return 0;
    if (record_branch_to(s, c, &branch)) {
      if (branch == export->offset && candidate_has_normal_fallthrough(c)) match = 1;
      else if (branch < loop || branch > step->offset) return 0;
    }
    cursor += c->byte_count;
  }
  if (!match || cursor != step->offset) return 0;
  /* Known incompatible writes to the same concrete staging cell invalidate
   * this chain. Unknown aliases remain explicitly outside target-set closure. */
  for (size_t n = 0U; n < s->candidate_count; ++n) {
    const M68kDecodeCandidate *c = &s->candidates[n];
    M68kInstructionIR i; const M68kSimFormMetadata *m;
    if (!accepted[c->offset] || c->offset == export->offset ||
        m68k_decode_candidate_to_instruction(c, &i) != 0 || !(m = m68k_sim_metadata_for_instruction(&i))) continue;
    for (size_t j = 0U; j < c->operand_count; ++j) {
      uint32_t write; uint8_t width = m68k_sim_operand_width_bytes(&i, (uint8_t)j);
      if (m->operand_access_kinds[j] != M68K_SIM_ACCESS_MEMORY_WRITE ||
          !staged_static_slot(s, runtime, c, j, &write) || !width ||
          (uint64_t)write + width <= slot || (uint64_t)slot + 4U <= write) continue;
      uint32_t value;
      if (write == slot && width == 4U &&
          (c->mnemonic_id == M68K_ASM_MNEMONIC_CLR ||
           (c->mnemonic_id == M68K_ASM_MNEMONIC_MOVE && j == 1U &&
            operand_immediate_value(c->operand_kinds[0], &c->operands[0], &value) && value == 0U))) continue;
      return 0;
    }
  }
  out->initial.table_offset = table;
  out->initial.entry_size = (uint32_t)stride;
  cursor = table;
  for (uint32_t n = 0U; n <= M68K_RECORD_DISPATCH_LIMIT; ++n) {
    uint32_t raw;
    if (cursor > s->size || s->size - cursor < 2U) return 0;
    if (!m68k_read_u16be(s->data + cursor)) {
      if (!n) return 0;
      out->initial.entry_count = n; out->initial.table_size = cursor - table;
      out->producer = export->offset; out->staging_slot = slot;
      return 1;
    }
    if (n == M68K_RECORD_DISPATCH_LIMIT || (uint32_t)stride > s->size - cursor ||
        accepted_range_has_code_byte_local(accepted_bytes, s->size, cursor, (uint32_t)stride)) return 0;
    raw = m68k_read_u32be(s->data + cursor + field);
    if (!raw || (raw & 1U) || !record_absolute_pointer_source(runtime, s->section_index, s->size,
        raw, &out->initial.targets[n])) return 0;
    out->initial.runtime_targets[n] = raw;
    cursor += (uint32_t)stride;
  }
  return 0;
}

static int staged_no_local_overwrite(const M68kDecodeSectionIR *s, const uint8_t *accepted,
    const M68kRuntimeAddressSpace *runtime, const M68kDecodeCandidate *writer, uint32_t slot) {
  uint32_t cursor = writer->offset;
  for (unsigned n = 0U; n < 64U; ++n) {
    const M68kDecodeCandidate *c = find_accepted_candidate_ending_at(s, accepted, cursor);
    M68kInstructionIR i; const M68kSimFormMetadata *m;
    if (!c || m68k_decode_candidate_to_instruction(c, &i) != 0 ||
        !(m = m68k_sim_metadata_for_instruction(&i))) return 0;
    if (m->flow_kind != M68K_SIM_FLOW_SEQUENTIAL) return 1;
    for (size_t op = 0U; op < c->operand_count; ++op) {
      uint32_t at; uint8_t width = m68k_sim_operand_width_bytes(&i, (uint8_t)op);
      if (m->operand_access_kinds[op] == M68K_SIM_ACCESS_MEMORY_WRITE && width &&
          staged_static_slot(s, runtime, c, op, &at) &&
          (uint64_t)at + width > slot && (uint64_t)slot + 4U > at) return 0;
    }
    cursor = c->offset;
    if (!cursor) return 1;
  }
  return 0;
}

static int probe_staged_record_dispatch(M68kDecodeIR *decode, const M68kAnalysisPolicy *policy,
    const M68kRuntimeAddressSpace *runtime, uint8_t **accepted_start, uint8_t **accepted_bytes,
    size_t section_index, const M68kDecodeCandidate *site, uint8_t cpu, M68kStagedRecordProbe *out) {
  const M68kDecodeSectionIR *s = &decode->sections[section_index];
  const M68kDecodeCandidate *load;
  uint8_t control, dest;
  M68kDecodeCandidate consumer;
  int found = 0;
  memset(out, 0, sizeof(*out));
  if (!candidate_indirect_control_address_register(site, &control)) return 0;
  load = find_accepted_candidate_ending_at(s, accepted_start[section_index], site->offset);
  if (!load || load->mnemonic_id != M68K_ASM_MNEMONIC_MOVEA || load->size_suffix != 'l' ||
      load->operand_count != 2U || !operand_is_address_register_direct(&load->operands[1], &dest) || dest != control)
    return 0;
  consumer = *load;
  for (size_t p = 0U; p < s->candidate_count; ++p) {
    M68kStagedRecordProbe probe;
    M68kDecodeCandidate export = s->candidates[p];
    if (!accepted_start[section_index][export.offset]) continue;
    memset(&probe, 0, sizeof(probe));
    if (!staged_export_table(s, accepted_start[section_index], accepted_bytes[section_index], runtime,
        &export, &probe)) continue;
    for (size_t w = 0U; w < s->candidate_count; ++w) {
      const M68kDecodeCandidate *writer = &s->candidates[w];
      uint32_t slot;
      StagedFieldKey write, read;
      if (!accepted_start[section_index][writer->offset] || writer->mnemonic_id != M68K_ASM_MNEMONIC_MOVE ||
          writer->size_suffix != 'l' || writer->operand_count != 2U ||
          !staged_static_slot(s, runtime, writer, 0U, &slot) || slot != probe.staging_slot ||
          !staged_key_at(s, accepted_start[section_index], runtime, writer, 1U, 0U, slot, &write) ||
          !staged_key_at(s, accepted_start[section_index], runtime, &consumer, 0U, write.modulus, UINT32_MAX, &read) ||
          memcmp(&write, &read, sizeof(write)) || write.root > s->size ||
          write.field > s->size - write.root || s->size - write.root - write.field < 4U) continue;
      probe.writer = writer->offset; probe.record_root = write.root;
      probe.record_modulus = write.modulus; probe.record_field = write.field;
      if (found && (out->producer != probe.producer || out->staging_slot != probe.staging_slot ||
          out->record_root != probe.record_root || out->record_modulus != probe.record_modulus ||
          out->record_field != probe.record_field)) return 0;
      if (!found || probe.writer < out->writer) *out = probe;
      found = 1;
    }
  }
  if (!found) return 0;
  for (uint32_t n = 0U; n < out->initial.entry_count; ++n) {
    uint32_t at = out->initial.targets[n], conflict;
    const M68kDecodeCandidate *target = NULL;
    if ((at >= out->initial.table_offset && at < out->initial.table_offset + out->initial.table_size + 2U) ||
        control_target_starts_in_zero_padding(s, at) ||
        record_target_enters_direct_instruction(s, accepted_start[section_index], at) ||
        accepted_offset_is_interior(s, accepted_start[section_index], accepted_bytes[section_index], at) ||
        m68k_decode_ir_ensure_candidate_at(decode, section_index, at, cpu, &target, m68k_diag_sink(NULL)) != 0 ||
        !target || !candidate_reencodes_exactly(s, target) ||
        policy_structured_data_overlaps_range(policy, section_index, at, target->byte_count, &conflict)) return 0;
  }
  return 1;
}

static int seed_staged_record_dispatches(M68kDecodeIR *decode, const M68kAnalysisPolicy *policy,
    const M68kRuntimeAddressSpace *runtime, M68kFactIR *facts, M68kFactsV2WorkQueue *queue,
    uint8_t **accepted_start, uint8_t **accepted_bytes, M68kFactsV2Profile *profile, uint8_t cpu) {
  for (size_t section = 0U; section < decode->section_count; ++section) {
    const M68kDecodeSectionIR *s = &decode->sections[section];
    for (size_t n = 0U; n < s->candidate_count; ++n) {
      M68kStagedRecordProbe probe;
      M68kDecodeCandidate site = s->candidates[n];
      if (!accepted_start[section][site.offset] || !probe_staged_record_dispatch(decode, policy,
          runtime, accepted_start, accepted_bytes, section, &site, cpu, &probe)) continue;
      M68kFactsV2TraceState unknown; trace_state_init_unknown(&unknown);
      for (uint32_t j = 0U; j < probe.initial.entry_count; ++j)
        if (enqueue_same_section_control_resolved_target_from_offset(decode, facts, queue, accepted_start,
            accepted_bytes, profile, cpu, section, site.offset, probe.initial.targets[j], 1U,
            probe.initial.runtime_targets[j], M68K_FACT_CONFIDENCE_TOOL_INFERRED,
            M68K_FACT_CODE_START_REASON_CONTROL_TARGET, M68K_CODE_ORIGIN_EVIDENCE_STAGED_RECORD_CONTROL_TARGET,
            &unknown) != 0) return -1;
    }
  }
  return 0;
}

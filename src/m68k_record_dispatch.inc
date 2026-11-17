/* Initial-image record walkers. All instruction/EA interpretation comes from
 * decoded IR and generated metadata. This is candidate discovery, never a
 * claim that writable records or all incoming register states are closed. */
static const M68kDecodeCandidate *record_next(const M68kDecodeSectionIR *s,
    const uint8_t *accepted, const M68kDecodeCandidate *c) {
  uint32_t at;
  if (!s || !accepted || !c || c->byte_count > UINT32_MAX - c->offset) return NULL;
  at = c->offset + c->byte_count;
  return at < s->size && accepted[at] ? m68k_decode_ir_find_candidate_at_offset(s, at) : NULL;
}

static int record_word_read(const M68kDecodeCandidate *c, uint8_t base,
    uint8_t *dest, int32_t *displacement) {
  M68kInstructionIR i;
  const M68kSimFormMetadata *m;
  uint8_t reg;
  if (!c || c->mnemonic_id != M68K_ASM_MNEMONIC_MOVE || c->size_suffix != 'w' ||
      c->operand_count != 2U || !operand_is_data_register_direct(&c->operands[1], dest) ||
      !candidate_operand_base_field_slot(c, 0U, &reg, displacement) || reg != base ||
      m68k_decode_candidate_to_instruction(c, &i) != 0) return 0;
  m = m68k_sim_metadata_for_instruction(&i);
  return m && m->operand_access_kinds[0] == M68K_SIM_ACCESS_MEMORY_READ;
}

static int record_writes_reg(const M68kDecodeCandidate *c, uint8_t address, uint8_t reg) {
  M68kInstructionIR i;
  const M68kSimFormMetadata *m;
  size_t n;
  if (!c || m68k_decode_candidate_to_instruction(c, &i) != 0 ||
      !(m = m68k_sim_metadata_for_instruction(&i))) return 1;
  for (n = 0U; n < c->operand_count; ++n) {
    uint8_t r;
    if (m->operand_access_kinds[n] == M68K_SIM_ACCESS_REGISTER_LIST_WRITE) return 1;
    /* Generic EA destinations carry MEMORY_WRITE in the KB even when the
     * decoded EA is a direct register. Normalize that case before checking
     * clobbers, just as for an explicit register destination. */
    if ((m->operand_access_kinds[n] == M68K_SIM_ACCESS_REGISTER_WRITE ||
         m->operand_access_kinds[n] == M68K_SIM_ACCESS_MEMORY_WRITE) &&
        (address ? operand_is_address_register_direct(&c->operands[n], &r) :
                   operand_is_data_register_direct(&c->operands[n], &r)) && r == reg) return 1;
    if (address && m68k_sim_operand_ea_update(&i, (uint8_t)n) != M68K_SIM_EA_UPDATE_NONE &&
        c->operands[n].ea_reg == reg) return 1;
  }
  return 0;
}

static int record_branch_to(const M68kDecodeSectionIR *s, const M68kDecodeCandidate *c,
    uint32_t *target) {
  size_t n;
  if (!s || !c || !target) return 0;
  for (n = 0U; n < c->target_count; ++n) {
    const M68kDecodeTarget *t = &c->targets[n];
    if (t->kind == M68K_DECODE_TARGET_BRANCH && t->has_section && t->section_index == s->section_index) {
      *target = t->offset;
      return 1;
    }
  }
  return 0;
}

/* Encoded handlers are absolute pointers. A present load/copy address space
 * forbids treating an unmapped integer as a file offset; competing temporal
 * views must also agree before a source identity is admitted. */
static int record_absolute_pointer_source(const M68kRuntimeAddressSpace *space,
    size_t section, uint32_t size, uint32_t address, uint32_t *out) {
  size_t n; int mapped = 0, has_view = 0; uint32_t selected = 0U;
  for (n = 0U; n < space->count; ++n) {
    const M68kRuntimeAddressRange *view = &space->ranges[n];
    uint32_t delta, source;
    if (view->section_index != section || !view->size ||
        view->kind == M68K_FACT_RUNTIME_RANGE_KIND_CONFLICTING_DISCOVERED_COPY) continue;
    has_view = 1;
    if (address < view->runtime_address || (delta = address - view->runtime_address) >= view->size ||
        view->source_offset > UINT32_MAX - delta || (source = view->source_offset + delta) >= size) continue;
    if (mapped && selected != source) return 0;
    mapped = 1; selected = source;
  }
  if (mapped) { *out = selected; return 1; }
  if (!has_view && address < size) { *out = address; return 1; }
  return 0;
}

/* A direct entry can still be awaiting admission (for example because a data
 * reference splits its operand). Do not let a new pointer into that operand
 * win merely because the containing instruction is not accepted yet. */
static int record_target_enters_direct_instruction(const M68kDecodeSectionIR *s,
    const uint8_t *accepted, uint32_t at) {
  size_t i, j;
  for (i = 0U; i < s->candidate_count; ++i) {
    const M68kDecodeCandidate *source = &s->candidates[i];
    if (!accepted[source->offset]) continue;
    for (j = 0U; j < source->target_count; ++j) {
      const M68kDecodeTarget *t = &source->targets[j];
      const M68kDecodeCandidate *entry;
      if (t->kind == M68K_DECODE_TARGET_DATA || !t->has_section ||
          t->section_index != s->section_index || t->offset >= at) continue;
      entry = m68k_decode_ir_find_candidate_at_offset(s, t->offset);
      if (entry && at - entry->offset < entry->byte_count && candidate_reencodes_exactly(s, entry)) return 1;
    }
  }
  return 0;
}

/* A counted search may leave its mismatch loop before the pointer load. Prove
 * the counter initializer, cursor origin, per-iteration update and match edge
 * independently of table contents; never infer a sentinel or scan past count. */
static int record_sequential_read_only(const M68kDecodeCandidate *c) {
  M68kInstructionIR instruction;
  const M68kSimFormMetadata *m;
  size_t n;
  if (!c || m68k_decode_candidate_to_instruction(c, &instruction) != 0 ||
      !(m = m68k_sim_metadata_for_instruction(&instruction)) ||
      m->flow_kind != M68K_SIM_FLOW_SEQUENTIAL) return 0;
  for (n = 0U; n < c->operand_count; ++n)
    if ((m->operand_access_kinds[n] == M68K_SIM_ACCESS_MEMORY_WRITE &&
         !operand_is_data_register_direct(&c->operands[n], NULL) &&
         !operand_is_address_register_direct(&c->operands[n], NULL)) ||
        m->operand_access_kinds[n] == M68K_SIM_ACCESS_REGISTER_LIST_WRITE) return 0;
  return 1;
}

static int probe_counted_record_dispatch(M68kDecodeIR *decode, const M68kAnalysisPolicy *policy,
    const M68kRuntimeAddressSpace *runtime, uint8_t **accepted_start, uint8_t **accepted_bytes,
    size_t section_index, const M68kDecodeCandidate *site, uint8_t cpu, M68kRecordDispatchProbe *out) {
  enum { LOOP_LIMIT = 32, PREFIX_LIMIT = 16, MATCH_WINDOW = 128 };
  const M68kDecodeSectionIR *s = &decode->sections[section_index];
  const M68kDecodeCandidate *load, *guard = NULL, *step = NULL, *tail = NULL, *header, *c;
  uint8_t control, dest, base, counter = 0U, r;
  uint32_t loop = 0U, table = 0U, initial = 0U, advance, stride, prefix_advance, cursor, n, target_offset;
  int32_t field;
  int got_table = 0, got_count = 0;
  size_t i;
  M68kInstructionIR instruction;
  const M68kSimFormMetadata *m;
  if (!candidate_indirect_control_address_register(site, &control)) return 0;
  load = find_accepted_candidate_ending_at(s, accepted_start[section_index], site->offset);
  if (!load || load->mnemonic_id != M68K_ASM_MNEMONIC_MOVEA || load->size_suffix != 'l' ||
      load->operand_count != 2U || !operand_is_address_register_direct(&load->operands[1], &dest) ||
      dest != control || !candidate_operand_base_field_slot(load, 0U, &base, &field) || field < 0) return 0;
  /* Search only accepted conditional predecessors in a bounded nearby window.
   * The failure path may contain a call, but is never followed to reach load. */
  for (i = 0U; i < s->candidate_count; ++i) {
    const M68kDecodeCandidate *g = &s->candidates[i], *a, *b;
    uint32_t branch;
    if (g->offset >= load->offset || load->offset - g->offset > MATCH_WINDOW ||
        !accepted_start[section_index][g->offset] || !candidate_has_normal_fallthrough(g) ||
        !record_branch_to(s, g, &branch) || branch != load->offset) continue;
    a = record_next(s, accepted_start[section_index], g);
    b = record_next(s, accepted_start[section_index], a);
    if (!a || !b || b->mnemonic_id != M68K_ASM_MNEMONIC_DBF || b->operand_count != 2U ||
        !operand_is_data_register_direct(&b->operands[0], &r) ||
        !record_branch_to(s, b, &branch) || branch >= g->offset) continue;
    if (guard) return 0;
    guard = g; step = a; tail = b; counter = r; loop = branch;
  }
  if (!guard || !step || !tail || loop >= s->size || !accepted_start[section_index][loop]) return 0;
  header = m68k_decode_ir_find_candidate_at_offset(s, loop);
  if (!header || !record_sequential_read_only(header) ||
      m68k_decode_candidate_to_instruction(header, &instruction) != 0 ||
      !(m = m68k_sim_metadata_for_instruction(&instruction)) || header->operand_count != 2U ||
      !operand_is_data_register_direct(&header->operands[1], &r) ||
      m->operand_access_kinds[0] != M68K_SIM_ACCESS_MEMORY_READ ||
      m68k_sim_operand_ea_update(&instruction, 0U) != M68K_SIM_EA_UPDATE_POSTINCREMENT ||
      header->operands[0].ea_reg != base || record_writes_reg(header, 0U, counter)) return 0;
  prefix_advance = m68k_sim_operand_width_bytes(&instruction, 0U);
  if (!prefix_advance || prefix_advance & 1U) return 0;
  c = record_next(s, accepted_start[section_index], header);
  for (n = 0U; c && c->offset < guard->offset && n < LOOP_LIMIT; ++n) {
    if (!record_sequential_read_only(c) || record_writes_reg(c, 1U, base) ||
        record_writes_reg(c, 0U, counter)) return 0;
    c = record_next(s, accepted_start[section_index], c);
  }
  if (c != guard || record_writes_reg(guard, 1U, base) || record_writes_reg(guard, 0U, counter) ||
      step->operand_count != 2U ||
      (step->mnemonic_id != M68K_ASM_MNEMONIC_ADDQ && step->mnemonic_id != M68K_ASM_MNEMONIC_ADDA) ||
      !operand_is_address_register_direct(&step->operands[1], &r) || r != base ||
      !operand_immediate_value(step->operand_kinds[0], &step->operands[0], &advance) ||
      !advance || advance > INT16_MAX || (advance & 1U)) return 0;
  stride = prefix_advance + advance;
  if ((uint32_t)field > stride || prefix_advance > stride - (uint32_t)field ||
      stride - (uint32_t)field - prefix_advance < 4U) return 0;
  cursor = loop;
  for (n = 0U; n < PREFIX_LIMIT && (!got_table || !got_count); ++n) {
    c = find_accepted_candidate_ending_at(s, accepted_start[section_index], cursor);
    if (!record_sequential_read_only(c)) return 0;
    if (!got_table && record_writes_reg(c, 1U, base)) {
      if (!candidate_lea_pc_relative_data_target(c, section_index, s->size, &r, &table) || r != base)
        return 0;
      got_table = 1;
    }
    if (!got_count && record_writes_reg(c, 0U, counter)) {
      if ((c->mnemonic_id != M68K_ASM_MNEMONIC_MOVEQ &&
          !(c->mnemonic_id == M68K_ASM_MNEMONIC_MOVE && c->size_suffix == 'w')) ||
          c->operand_count != 2U || !operand_is_data_register_direct(&c->operands[1], &r) || r != counter ||
          !operand_immediate_value(c->operand_kinds[0], &c->operands[0], &initial)) return 0;
      got_count = 1;
    }
    cursor = c->offset;
  }
  if (!got_table || !got_count) return 0;
  out->table_offset = table;
  out->refusal_reason = M68K_RECOVERED_INDIRECT_TABLE_BOUNDS_REJECTED_SCAN_LIMIT;
  if (initial >= M68K_RECORD_DISPATCH_LIMIT) return 0;
  out->entry_count = initial + 1U;
  out->refusal_reason = M68K_RECOVERED_INDIRECT_TABLE_BOUNDS_REJECTED_RECORD_LAYOUT;
  if ((table & 1U) || table >= s->size || out->entry_count > (s->size - table) / stride ||
      accepted_range_has_code_byte_local(accepted_bytes[section_index], s->size, table,
        out->entry_count * stride)) return 0;
  out->table_size = out->entry_count * stride;
  out->entry_size = stride;
  out->refusal_reason = M68K_RECOVERED_INDIRECT_TABLE_BOUNDS_REJECTED_RECORD_TARGET;
  for (n = 0U; n < out->entry_count; ++n) {
    uint32_t raw = m68k_read_u32be(s->data + table + n * stride + prefix_advance + (uint32_t)field);
    if (!raw || (raw & 1U) || !record_absolute_pointer_source(runtime, section_index, s->size, raw,
        &target_offset)) return 0;
    out->runtime_targets[n] = raw; out->targets[n] = target_offset;
  }
  /* No partial collection: validate every pointer before publishing any. */
  for (n = 0U; n < out->entry_count; ++n) {
    uint32_t at = out->targets[n], conflict;
    const M68kDecodeCandidate *target = NULL;
    if ((at >= table && at < table + out->table_size) || control_target_starts_in_zero_padding(s, at) ||
        record_target_enters_direct_instruction(s, accepted_start[section_index], at) ||
        accepted_offset_is_interior(s, accepted_start[section_index], accepted_bytes[section_index], at) ||
        m68k_decode_ir_ensure_candidate_at(decode, section_index, at, cpu, &target, m68k_diag_sink(NULL)) != 0 ||
        !target || !candidate_reencodes_exactly(s, target) ||
        policy_structured_data_overlaps_range(policy, section_index, at, target->byte_count, &conflict)) return 0;
  }
  out->refusal_reason = M68K_RECOVERED_INDIRECT_TABLE_BOUNDS_NONE;
  out->counted = 1U;
  return 1;
}

static int probe_initial_record_dispatch(M68kDecodeIR *decode, const M68kAnalysisPolicy *policy,
    const M68kRuntimeAddressSpace *runtime, uint8_t **accepted_start, uint8_t **accepted_bytes,
    size_t section_index, const M68kDecodeCandidate *site, uint8_t cpu, M68kRecordDispatchProbe *out) {
  enum { PREFIX_LIMIT = 64 };
  const M68kDecodeSectionIR *s;
  const M68kDecodeCandidate *load, *tail, *step, *prefix[PREFIX_LIMIT], *origin = NULL;
  uint32_t count = 0U, n, table = 0U, loop = 0U, fixed_stride = 0U, cursor;
  uint32_t first_adjustment = UINT32_MAX;
  uint8_t control, dest, base, stride_reg = 0U, index_reg = 0U;
  int indexed = 0, found_index = 0, found_stride = 0, found_guard = 0;
  int32_t field = 0, index_field = 0, stride_field = 0, terminator_field = 0, base_addend = 0;
  M68kInstructionIR instruction;
  if (out) memset(out, 0, sizeof(*out));
  if (!decode || !runtime || !accepted_start || !accepted_bytes || !site || !out ||
      section_index >= decode->section_count || !candidate_indirect_control_address_register(site, &control)) return 0;
  if (probe_counted_record_dispatch(decode, policy, runtime, accepted_start, accepted_bytes,
      section_index, site, cpu, out) || out->refusal_reason) return out->refusal_reason == 0U;
  s = &decode->sections[section_index];
  load = find_accepted_candidate_ending_at(s, accepted_start[section_index], site->offset);
  if (!load || load->mnemonic_id != M68K_ASM_MNEMONIC_MOVEA || load->size_suffix != 'l' ||
      load->operand_count != 2U || !operand_is_address_register_direct(&load->operands[1], &dest) ||
      dest != control) return 0;
  if (!candidate_operand_base_field_slot(load, 0U, &base, &field)) {
    if (m68k_decode_candidate_to_instruction(load, &instruction) != 0 ||
        !m68k_ir_operand_brief_index_displacement(&instruction.operands[0], &field) ||
        instruction.operands[0].value.index_is_address || instruction.operands[0].value.index_long ||
        instruction.operands[0].value.scale > 1U ||
        instruction.operands[0].value.index_reg >= 8U)
      return 0;
    base = instruction.operands[0].value.ea_reg;
    index_reg = instruction.operands[0].value.index_reg;
    indexed = 1;
  }
  /* The mismatch edge advances the record cursor and branches back to the
   * tested record header. No calls, intervening writes or unbounded scan of
   * arbitrary surrounding data are used to invent that edge. */
  step = record_next(s, accepted_start[section_index], site);
  if (!step || step->operand_count != 2U ||
      (step->mnemonic_id != M68K_ASM_MNEMONIC_ADDA && step->mnemonic_id != M68K_ASM_MNEMONIC_ADDQ) ||
      !operand_is_address_register_direct(&step->operands[1], &dest) || dest != base) return 0;
  if (!operand_immediate_value(step->operand_kinds[0], &step->operands[0], &fixed_stride)) {
    if (step->mnemonic_id != M68K_ASM_MNEMONIC_ADDA || step->size_suffix != 'w' ||
        !operand_is_data_register_direct(&step->operands[0], &stride_reg)) return 0;
  }
  tail = record_next(s, accepted_start[section_index], step);
  if (fixed_stride) {
    uint8_t ignored;
    if (fixed_stride < 4U || (fixed_stride & 1U) ||
        !record_word_read(tail, base, &ignored, &terminator_field)) return 0;
    tail = record_next(s, accepted_start[section_index], tail);
    if (!tail || tail->mnemonic_id != M68K_ASM_MNEMONIC_BNE || !record_branch_to(s, tail, &loop)) return 0;
  } else if (!tail || tail->mnemonic_id != M68K_ASM_MNEMONIC_BRA || !record_branch_to(s, tail, &loop)) return 0;
  if (loop >= load->offset) return 0;
  cursor = load->offset;
  while (count < PREFIX_LIMIT) {
    const M68kDecodeCandidate *c = find_accepted_candidate_ending_at(s, accepted_start[section_index], cursor);
    const M68kSimFormMetadata *m;
    uint8_t r;
    uint32_t value;
    int32_t displacement;
    if (!c || m68k_decode_candidate_to_instruction(c, &instruction) != 0 ||
        !(m = m68k_sim_metadata_for_instruction(&instruction))) return 0;
    if (m->flow_kind == M68K_SIM_FLOW_CALL || m->flow_kind == M68K_SIM_FLOW_JUMP ||
        m->flow_kind == M68K_SIM_FLOW_RETURN || m->flow_kind == M68K_SIM_FLOW_TRAP) return 0;
    prefix[count++] = c;
    if (candidate_lea_pc_relative_data_target(c, section_index, s->size, &r, &value) && r == base) {
      table = value; origin = c; break;
    }
    if (record_writes_reg(c, 1U, base)) {
      if (c->mnemonic_id != M68K_ASM_MNEMONIC_LEA || c->operand_count != 2U ||
          !operand_is_address_register_direct(&c->operands[1], &r) || r != base ||
          !candidate_operand_base_field_slot(c, 0U, &r, &displacement) || r != base ||
          displacement < 0 || base_addend > INT32_MAX - displacement) return 0;
      base_addend += displacement;
      first_adjustment = c->offset;
    }
    if (indexed && !found_index && record_writes_reg(c, 0U, index_reg)) {
      if (!record_word_read(c, base, &r, &index_field) || r != index_reg || base_addend) return 0;
      found_index = 1;
    }
    if (!fixed_stride && !found_stride && record_writes_reg(c, 0U, stride_reg)) {
      const M68kDecodeCandidate *guard;
      uint32_t exit;
      if (!record_word_read(c, base, &r, &stride_field) || r != stride_reg || base_addend || c->offset != loop)
        return 0;
      guard = record_next(s, accepted_start[section_index], c);
      if (!guard || guard->mnemonic_id != M68K_ASM_MNEMONIC_BEQ || !record_branch_to(s, guard, &exit) ||
          (exit >= loop && exit < tail->offset + tail->byte_count)) return 0;
      terminator_field = stride_field; found_stride = found_guard = 1;
    }
    cursor = c->offset;
    if (!cursor) return 0;
  }
  if (!origin || (table & 1U) || loop < origin->offset + origin->byte_count ||
      (indexed && !found_index) || (!fixed_stride && (!found_stride || !found_guard)) ||
      field < 0 || index_field < 0 || stride_field < 0 || terminator_field < 0 ||
      (index_field & 1) || (stride_field & 1) || (terminator_field & 1) ||
      (indexed && base_addend)) return 0;
  /* A conditional mismatch edge must actually reach the advancing tail. */
  for (n = 0U; n < count; ++n) {
    uint32_t target;
    if (prefix[n]->offset >= loop && prefix[n]->offset < first_adjustment &&
        record_branch_to(s, prefix[n], &target) && target == step->offset &&
        candidate_has_normal_fallthrough(prefix[n])) break;
  }
  if (n == count) return 0;
  out->table_offset = table;
  out->refusal_reason = M68K_RECOVERED_INDIRECT_TABLE_BOUNDS_REJECTED_RECORD_LAYOUT;
  cursor = table;
  for (n = 0U; n <= M68K_RECORD_DISPATCH_LIMIT; ++n) {
    uint32_t stride, pointer_offset, raw;
    if (cursor > s->size || (uint32_t)terminator_field > s->size - cursor ||
        s->size - cursor - (uint32_t)terminator_field < 2U) return 0;
    if (m68k_read_u16be(s->data + cursor + terminator_field) == 0U) break;
    if (n == M68K_RECORD_DISPATCH_LIMIT) {
      out->refusal_reason = M68K_RECOVERED_INDIRECT_TABLE_BOUNDS_REJECTED_SCAN_LIMIT;
      return 0;
    }
    stride = fixed_stride ? fixed_stride : m68k_read_u16be(s->data + cursor + stride_field);
    if (stride < 4U || stride > INT16_MAX || (stride & 1U) || stride > s->size - cursor ||
        (uint32_t)terminator_field + 2U > stride) return 0;
    if (indexed) {
      if ((uint32_t)index_field + 2U > stride) return 0;
      pointer_offset = m68k_read_u16be(s->data + cursor + index_field);
      if (pointer_offset > INT16_MAX || pointer_offset > UINT32_MAX - (uint32_t)field) return 0;
      pointer_offset += (uint32_t)field;
      if (pointer_offset < (uint32_t)stride_field + 2U || pointer_offset < (uint32_t)index_field + 2U) return 0;
    } else pointer_offset = (uint32_t)base_addend + (uint32_t)field;
    if ((pointer_offset & 1U) || pointer_offset > stride || stride - pointer_offset < 4U ||
        accepted_range_has_code_byte_local(accepted_bytes[section_index], s->size, cursor, stride)) return 0;
    raw = m68k_read_u32be(s->data + cursor + pointer_offset);
    out->refusal_reason = M68K_RECOVERED_INDIRECT_TABLE_BOUNDS_REJECTED_RECORD_TARGET;
    if (!raw || (raw & 1U) || !record_absolute_pointer_source(runtime, section_index, s->size, raw,
        &out->targets[n])) return 0;
    out->runtime_targets[n] = raw;
    cursor += stride;
    out->refusal_reason = M68K_RECOVERED_INDIRECT_TABLE_BOUNDS_REJECTED_RECORD_LAYOUT;
  }
  if (!n) return 0;
  out->table_offset = table; out->table_size = cursor - table;
  out->entry_count = n; out->entry_size = fixed_stride;
  out->refusal_reason = M68K_RECOVERED_INDIRECT_TABLE_BOUNDS_REJECTED_RECORD_TARGET;
  for (n = 0U; n < out->entry_count; ++n) {
    const M68kDecodeCandidate *target = NULL;
    uint32_t at = out->targets[n];
    if ((at >= table && at < cursor + 2U) || control_target_starts_in_zero_padding(s, at) ||
        accepted_offset_is_interior(s, accepted_start[section_index], accepted_bytes[section_index], at) ||
        m68k_decode_ir_ensure_candidate_at(decode, section_index, at, cpu, &target, m68k_diag_sink(NULL)) != 0 ||
        !target) return 0;
  }
  out->refusal_reason = M68K_RECOVERED_INDIRECT_TABLE_BOUNDS_NONE;
  return 1;
}

static int seed_initial_record_dispatches(M68kDecodeIR *decode, M68kFactIR *facts,
    M68kFactsV2WorkQueue *queue, const M68kRuntimeAddressSpace *runtime, const M68kAnalysisPolicy *policy,
    uint8_t **accepted_start, uint8_t **accepted_bytes, M68kFactsV2Profile *profile, uint8_t cpu) {
  size_t section_index;
  for (section_index = 0U; section_index < decode->section_count; ++section_index) {
    const M68kDecodeSectionIR *s = &decode->sections[section_index];
    size_t index;
    for (index = 0U; index < s->candidate_count; ++index) {
      const M68kDecodeCandidate *site = &s->candidates[index];
      M68kRecordDispatchProbe probe;
      uint32_t site_offset = site->offset;
      uint32_t n;
      M68kFactsV2TraceState unknown;
      if (!accepted_start[section_index][site->offset] ||
          !probe_initial_record_dispatch(decode, policy, runtime, accepted_start, accepted_bytes,
            section_index, site, cpu, &probe)) continue;
      trace_state_init_unknown(&unknown);
      for (n = 0U; n < probe.entry_count; ++n) {
        uint32_t mapped_offset;
        uint8_t mapped = runtime_address_space_translate(runtime, section_index,
          probe.runtime_targets[n], s->size, &mapped_offset) != 0;
        if (enqueue_same_section_control_resolved_target_from_offset(decode, facts, queue,
            accepted_start, accepted_bytes, profile, cpu, section_index, site_offset,
            probe.targets[n], mapped, probe.runtime_targets[n], M68K_FACT_CONFIDENCE_TOOL_INFERRED,
            M68K_FACT_CODE_START_REASON_CONTROL_TARGET,
            M68K_CODE_ORIGIN_EVIDENCE_INITIAL_RECORD_CONTROL_TARGET, &unknown) != 0) return -1;
      }
    }
  }
  return 0;
}

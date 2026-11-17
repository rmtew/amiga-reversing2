/* A folded indexed pointer read still has an executable consumer. Retain a
 * validated initial prefix ending exactly at its nearest forward handler;
 * neither that physical boundary nor selector arithmetic closes runtime use. */
static int pointer_double_word(const M68kDecodeCandidate *c, uint8_t reg) {
  uint8_t a, b;
  return c && c->mnemonic_id == M68K_ASM_MNEMONIC_ADD && c->size_suffix == 'w' &&
    c->operand_count == 2U && operand_is_data_register_direct(&c->operands[0], &a) &&
    operand_is_data_register_direct(&c->operands[1], &b) && a == reg && b == reg;
}

static int probe_initial_pointer_prefix(M68kDecodeIR *decode, const M68kAnalysisPolicy *policy,
    const M68kRuntimeAddressSpace *runtime, uint8_t **accepted_start, uint8_t **accepted_bytes,
    size_t section_index, const M68kDecodeCandidate *site, uint8_t cpu, M68kRecordDispatchProbe *out) {
  const M68kDecodeSectionIR *s;
  const M68kDecodeCandidate *load, *add, *double1, *double2, *origin;
  uint8_t control, base, dest, index;
  int32_t field;
  uint32_t table, end, cursor, n, first;
  memset(out, 0, sizeof(*out));
  if (!decode || !site || section_index >= decode->section_count ||
      !candidate_indirect_control_address_register(site, &control)) return 0;
  s = &decode->sections[section_index];
  load = find_accepted_candidate_ending_at(s, accepted_start[section_index], site->offset);
  if (!load || load->mnemonic_id != M68K_ASM_MNEMONIC_MOVEA || load->size_suffix != 'l' ||
      load->operand_count != 2U || !operand_is_address_register_direct(&load->operands[1], &dest) ||
      dest != control || !candidate_operand_base_field_slot(load, 0U, &base, &field) || field != 0) return 0;
  add = find_accepted_candidate_ending_at(s, accepted_start[section_index], load->offset);
  if (!add || add->mnemonic_id != M68K_ASM_MNEMONIC_ADDA || add->size_suffix != 'w' ||
      add->operand_count != 2U || !operand_is_data_register_direct(&add->operands[0], &index) ||
      !operand_is_address_register_direct(&add->operands[1], &dest) || dest != base) return 0;
  double1 = find_accepted_candidate_ending_at(s, accepted_start[section_index], add->offset);
  if (!pointer_double_word(double1, index)) return 0;
  double2 = find_accepted_candidate_ending_at(s, accepted_start[section_index], double1->offset);
  if (!pointer_double_word(double2, index)) return 0;
  origin = find_accepted_candidate_ending_at(s, accepted_start[section_index], double2->offset);
  if (!origin || !candidate_lea_pc_relative_data_target(origin, section_index, s->size, &dest, &table) || dest != base)
    return 0;
  out->table_offset = table;
  out->refusal_reason = M68K_RECOVERED_INDIRECT_TABLE_BOUNDS_REJECTED_POINTER_PREFIX;
  if ((table & 1U) || table >= s->size || s->size - table < 4U ||
      !record_absolute_pointer_source(runtime, section_index, s->size,
        m68k_read_u32be(s->data + table), &first) || first <= table ||
      first - table > M68K_RECORD_DISPATCH_LIMIT * 4U || ((first - table) & 3U)) return 0;
  end = first;
  cursor = table;
  for (n = 0U; cursor < end; ++n, cursor += 4U) {
    uint32_t raw, target;
    if (n == M68K_RECORD_DISPATCH_LIMIT || end - cursor < 4U ||
        accepted_range_has_code_byte_local(accepted_bytes[section_index], s->size, cursor, 4U)) return 0;
    raw = m68k_read_u32be(s->data + cursor);
    if (!raw || (raw & 1U) || !record_absolute_pointer_source(runtime, section_index, s->size, raw, &target)) return 0;
    if (target >= table && target < end) {
      if (target <= cursor || ((target - table) & 3U)) return 0;
      end = target;
    }
    out->runtime_targets[n] = raw;
    out->targets[n] = target;
  }
  if (!n || cursor != end) return 0;
  /* Validate the entire collection before publishing any handler evidence. */
  for (uint32_t i = 0U; i < n; ++i) {
    uint32_t at = out->targets[i], conflict;
    const M68kDecodeCandidate *target = NULL;
    if ((at >= table && at < end) || control_target_starts_in_zero_padding(s, at) ||
        accepted_offset_is_interior(s, accepted_start[section_index], accepted_bytes[section_index], at) ||
        m68k_decode_ir_ensure_candidate_at(decode, section_index, at, cpu, &target, m68k_diag_sink(NULL)) != 0 ||
        !target || !candidate_reencodes_exactly(s, target) ||
        policy_structured_data_overlaps_range(policy, section_index, at, target->byte_count, &conflict)) return 0;
  }
  out->entry_count = n;
  out->entry_size = 4U;
  out->table_size = end - table;
  out->refusal_reason = M68K_RECOVERED_INDIRECT_TABLE_BOUNDS_NONE;
  return 1;
}

static int seed_initial_pointer_prefixes(M68kDecodeIR *decode, const M68kAnalysisPolicy *policy,
    M68kFactIR *facts, M68kFactsV2WorkQueue *queue, const M68kRuntimeAddressSpace *runtime,
    uint8_t **accepted_start, uint8_t **accepted_bytes, M68kFactsV2Profile *profile, uint8_t cpu) {
  for (size_t section_index = 0U; section_index < decode->section_count; ++section_index) {
    const M68kDecodeSectionIR *s = &decode->sections[section_index];
    for (size_t index = 0U; index < s->candidate_count; ++index) {
      const M68kDecodeCandidate *site = &s->candidates[index];
      M68kRecordDispatchProbe probe;
      M68kFactsV2TraceState unknown;
      uint32_t site_offset = site->offset;
      if (!accepted_start[section_index][site_offset] ||
          !probe_initial_pointer_prefix(decode, policy, runtime, accepted_start, accepted_bytes,
            section_index, site, cpu, &probe)) continue;
      trace_state_init_unknown(&unknown);
      for (uint32_t n = 0U; n < probe.entry_count; ++n)
        if (enqueue_same_section_control_resolved_target_from_offset(decode, facts, queue,
            accepted_start, accepted_bytes, profile, cpu, section_index, site_offset, probe.targets[n],
            1U, probe.runtime_targets[n], M68K_FACT_CONFIDENCE_TOOL_INFERRED,
            M68K_FACT_CODE_START_REASON_CONTROL_TARGET,
            M68K_CODE_ORIGIN_EVIDENCE_INITIAL_POINTER_CONTROL_TARGET, &unknown) != 0) return -1;
    }
  }
  return 0;
}

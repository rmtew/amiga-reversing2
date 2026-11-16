/* Conditional code-operand installation evidence. Uses the generated operand
 * codec and existing value trace; no opcode bytes, addresses or target names
 * are special-cased. Only already accepted code is eligible in this pass. */
static int conditional_control_value_address(const M68kFactsV2TraceValue *value,
    const M68kRuntimeAddressSpace *space, size_t section_index, uint32_t writer,
    uint32_t *address) {
  if (value->kind == M68K_FACTS_V2_TRACE_RUNTIME_ADDRESS || value->kind == M68K_FACTS_V2_TRACE_CONSTANT) {
    *address = value->value; return 1;
  }
  if (value->kind != M68K_FACTS_V2_TRACE_SOURCE_OFFSET || value->section_index != section_index) return 0;
  int found = 0;
  for (size_t i = 0; i < space->count; ++i) {
    const M68kRuntimeAddressRange *r = &space->ranges[i];
    if (r->section_index != section_index || r->kind != M68K_FACT_RUNTIME_RANGE_KIND_POLICY ||
        value->value < r->source_offset || value->value - r->source_offset >= r->size ||
        writer < r->source_offset || writer - r->source_offset >= r->size) continue;
    uint64_t candidate = (uint64_t)r->runtime_address + value->value - r->source_offset;
    if (candidate > UINT32_MAX || (found && *address != (uint32_t)candidate)) return 0;
    *address = (uint32_t)candidate; found = 1;
  }
  return found;
}

static int conditional_control_store_address(const M68kDecodeCandidate *candidate,
    const M68kFactsV2TraceState *state, const M68kRuntimeAddressSpace *space,
    size_t section_index, uint32_t *address) {
  if (trace_state_operand_runtime_address(state, candidate, 1U, address)) return 1;
  const M68kAsmOperandValue *operand = &candidate->operands[1];
  if (candidate->operand_kinds[1] != M68K_ASM_OPERAND_EA || operand->ea_reg >= 8U ||
      (operand->ea_mode != 2U && operand->ea_mode != 5U)) return 0;
  M68kFactsV2TraceValue value = state->a[operand->ea_reg];
  int64_t displacement = operand->ea_mode == 5U ? (int16_t)operand->value : 0;
  int64_t sum = (int64_t)value.value + displacement;
  if (value.kind != M68K_FACTS_V2_TRACE_SOURCE_OFFSET || sum < 0 || sum > UINT32_MAX) return 0;
  value.value = (uint32_t)sum;
  return conditional_control_value_address(&value, space, section_index, candidate->offset, address);
}

static const M68kDecodeCandidate *conditional_control_instruction_owner(const M68kDecodeSectionIR *section,
    const uint8_t *accepted_start, const uint8_t *accepted_bytes, uint32_t at) {
  if (at >= section->size || !accepted_bytes[at]) return NULL;
  uint32_t start = at;
  while (!accepted_start[start]) { if (start == 0U) return NULL; --start; }
  const M68kDecodeCandidate *owner = m68k_decode_ir_find_candidate_at_offset(section, start);
  return owner != NULL && at - start < owner->byte_count ? owner : NULL;
}

/* The older trace source helper also has an address-operand fallback used by
 * other recognizers. A memory operand's address is not its loaded value. This
 * rule accepts only literal/direct-register values and kills unproved memory
 * loads below; memory-version provenance is intentionally outside this slice. */
static int conditional_control_store_value(size_t section_index, const M68kDecodeSectionIR *section,
    const M68kDecodeCandidate *writer, const M68kFactsV2TraceState *state, M68kFactsV2TraceValue *value) {
  uint8_t reg=0U; uint32_t immediate=0U;
  if (!operand_immediate_value(writer->operand_kinds[0], &writer->operands[0], &immediate) &&
      !operand_is_data_register_direct(&writer->operands[0], &reg) &&
      !operand_is_address_register_direct(&writer->operands[0], &reg)) return 0;
  return trace_value_from_candidate_source(section_index,section,writer,0U,state,value);
}

static int record_conditional_control_store(M68kDecodeIR *decode, const M68kAnalysisPolicy *policy,
    const M68kRuntimeAddressSpace *space, uint8_t **accepted_start, uint8_t **accepted_bytes,
    size_t section_index, const M68kDecodeCandidate *writer, const M68kFactsV2TraceState *state,
    M68kSectionAnalysisIR *analysis) {
  if (writer->mnemonic_id != M68K_ASM_MNEMONIC_MOVE || writer->operand_count != 2U) return 0;
  M68kInstructionIR instruction;
  if (m68k_decode_candidate_to_instruction(writer, &instruction) != 0) return 0;
  uint32_t width = facts_v2_instruction_access_width(&instruction, M68K_SIM_ACCESS_MEMORY_WRITE);
  uint32_t address = 0U, offset = 0U;
  if (!width || !conditional_control_store_address(writer, state, space, section_index, &address)) return 0;
  const M68kDecodeSectionIR *section = &decode->sections[section_index];
  const char *binding = source_control_binding(space, section_index, writer->offset, address, &offset);
  const M68kDecodeCandidate *jump = NULL;
  if (!binding) jump = conditional_control_instruction_owner(section, accepted_start[section_index], accepted_bytes[section_index], offset);
  else {
    /* A competing policy must not be resolved by smallest range or a numeric
     * fallback. Find only whether this is a relevant *refused* code write. */
    for (size_t i = 0; i < space->count && jump == NULL; ++i) {
      const M68kRuntimeAddressRange *r = &space->ranges[i];
      if (r->section_index != section_index || address < r->runtime_address || address-r->runtime_address >= r->size) continue;
      uint32_t candidate = r->source_offset + address-r->runtime_address;
      const M68kDecodeCandidate *possible = conditional_control_instruction_owner(section, accepted_start[section_index], accepted_bytes[section_index], candidate);
      if (possible && possible->mnemonic_id == M68K_ASM_MNEMONIC_JMP) jump = possible;
    }
  }
  if (jump == NULL || jump->mnemonic_id != M68K_ASM_MNEMONIC_JMP) {
    /* Preserve a diagnostic numeric code-address store without guessing that
     * unclassified/owned storage is an instruction or decoding its bytes. */
    M68kFactsV2TraceValue value;
    uint32_t value_address=0U, target_offset=0U;
    if (binding || width!=4U || !conditional_control_store_value(section_index, section, writer, state, &value) ||
        !conditional_control_value_address(&value, space, section_index, writer->offset, &value_address) ||
        source_control_binding(space, section_index, writer->offset, value_address, &target_offset) != NULL ||
        target_offset>=section->size || !accepted_start[section_index][target_offset]) return 0;
    M68kConditionalControlIR candidate;
    memset(&candidate,0,sizeof(candidate));
    candidate.writer_offset=writer->offset; candidate.write_address=address; candidate.write_offset=offset;
    candidate.jump_offset=candidate.operand_offset=UINT32_MAX;
    candidate.write_size=(uint8_t)width; candidate.value_known=1U;
    candidate.value_address=value_address; candidate.target_offset=target_offset;
    snprintf(candidate.reason,sizeof(candidate.reason),"%s",
      policy_structured_data_overlaps_range(policy,section_index,offset,width,NULL)
        ? "destination has structured data ownership; no control installation inferred"
        : "destination is not an established JMP operand; no control installation inferred");
    return m68k_ir_section_analysis_append_conditional_control(analysis,&candidate);
  }
  M68kConditionalControlIR result;
  memset(&result, 0, sizeof(result));
  result.writer_offset = writer->offset;
  result.jump_offset = result.operand_offset = result.write_offset = result.target_offset = UINT32_MAX;
  result.write_address = address; result.write_size = (uint8_t)width;
  const char *reason = binding;
  size_t extension = 0U, extent = 0U;
  M68kAsmOperandValue operands[M68K_DECODE_IR_MAX_OPERANDS];
  for (size_t i=0; i<jump->operand_count; ++i) { operands[i]=jump->operands[i]; operands[i].kind=jump->operand_kinds[i]; }
  if (!reason) {
    result.jump_offset = jump->offset; result.write_offset = offset;
    M68kInstructionIR transfer;
    result.stored_target_known = (uint8_t)candidate_absolute_control_address(jump, &result.stored_target_address);
    if (m68k_decode_candidate_to_instruction(jump, &transfer) != 0 || jump->operand_count != 1U ||
        m68k_instruction_operand_decoded_ea_shape(&transfer.operands[0]) != M68K_SIM_EA_SHAPE_ABSOLUTE_LONG ||
        !result.stored_target_known ||
        m68k_asm_operand_extension_span(jump->asm_form_index, operands, jump->operand_count,
          jump->size_suffix, 0U, &extension, &extent) != 0 || extent != 4U ||
        extension + extent != jump->byte_count) reason = "not an absolute LONG control operand";
    else {
      result.operand_offset = jump->offset + (uint32_t)extension; result.operand_size = (uint8_t)extent;
      uint32_t end_offset = 0U;
      if (width != extent || offset != result.operand_offset) reason = "write does not exactly cover control operand";
      else if (address > UINT32_MAX - width + 1U ||
          source_control_binding(space, section_index, writer->offset, address + width - 1U, &end_offset) != NULL ||
          end_offset != offset + width - 1U) reason = "write crosses address binding";
      else if (policy_structured_data_overlaps_range(policy, section_index, jump->offset, jump->byte_count, NULL))
        reason = "patch instruction has structured data ownership";
    }
  }
  M68kFactsV2TraceValue value;
  if (conditional_control_store_value(section_index, section, writer, state, &value) &&
      conditional_control_value_address(&value, space, section_index, writer->offset, &result.value_address))
    result.value_known = 1U;
  if (!reason && !result.value_known) reason = "stored value is unknown";
  if (!reason) {
    reason = source_control_binding(space, section_index, writer->offset, result.value_address, &result.target_offset);
    if (!reason && (result.target_offset >= section->size || (result.target_offset & 1U))) reason = "target is unaligned or outside source";
    if (!reason && policy_structured_data_overlaps_range(policy, section_index, result.target_offset, 1U, NULL)) reason = "target has structured data ownership";
    if (!reason && accepted_offset_is_interior(section, accepted_start[section_index], accepted_bytes[section_index], result.target_offset)) reason = "target is an instruction interior";
    if (!reason && !accepted_start[section_index][result.target_offset]) reason = "target is not an established instruction start";
    const M68kDecodeCandidate *target = !reason ? m68k_decode_ir_find_candidate_at_offset(section, result.target_offset) : NULL;
    if (!reason && (!target || !candidate_reencodes_exactly(section, target))) reason = "target encoding is not established";
    if (!reason) {
      uint32_t end_offset = 0U;
      if (result.value_address > UINT32_MAX - target->byte_count + 1U ||
          source_control_binding(space, section_index, writer->offset, result.value_address + target->byte_count - 1U, &end_offset) != NULL ||
          end_offset != result.target_offset + target->byte_count - 1U) reason = "target instruction crosses address binding";
    }
    if (!reason && policy_structured_data_overlaps_range(policy, section_index, target->offset, target->byte_count, NULL))
      reason = "target has structured data ownership";
  }
  result.admitted = reason == NULL;
  snprintf(result.reason, sizeof(result.reason), "%s", reason ? reason : "conditional installation; execution and writer order unknown");
  return m68k_ir_section_analysis_append_conditional_control(analysis, &result);
}

static int append_conditional_controls_for_accepted(M68kDecodeIR *decode, const M68kFactIR *facts,
    const M68kAnalysisPolicy *policy, const M68kRuntimeAddressSpace *space,
    const M68kFactsV2RelocationLookup *relocations, uint8_t **accepted_start, uint8_t **accepted_bytes,
    Arena *scratch, M68kFactsV2Profile *profile, M68kSourceAnalysisIR *analysis) {
  for (size_t si = 0; si < decode->section_count; ++si) {
    const M68kDecodeSectionIR *section = &decode->sections[si];
    uint8_t *barriers = (uint8_t *)arena_calloc(scratch, section->size ? section->size : 1U, 1U);
    if (!barriers) return -1;
    for (size_t i = 0; i < facts->fact_count; ++i) {
      const M68kFact *f = &facts->facts[i];
      if (f->kind == M68K_FACT_CODE_START && f->section_index == si && f->offset < section->size &&
          f->reason != M68K_FACT_CODE_START_REASON_FALLTHROUGH) barriers[f->offset] = 1U;
    }
    M68kFactsV2TraceState state;
    trace_state_init_unknown(&state);
    for (uint32_t offset = 0; offset < section->size;) {
      const M68kDecodeCandidate *candidate = accepted_start[si][offset] ? m68k_decode_ir_find_candidate_at_offset(section, offset) : NULL;
      if (!candidate || !candidate->byte_count) { trace_state_init_unknown(&state); ++offset; continue; }
      if (barriers[offset]) trace_state_init_unknown(&state);
      if (record_conditional_control_store(decode, policy, space, accepted_start, accepted_bytes, si, candidate, &state,
          &analysis->sections[si]) != 0) return -1;
      M68kFactsV2TraceState after;
      if (trace_state_after_candidate(si, section, candidate, &state, relocations, facts, space,
          accepted_start[si], accepted_bytes[si], &after, scratch, profile) != 0) return -1;
      M68kInstructionIR instruction;
      const M68kSimFormMetadata *metadata = NULL;
      if (m68k_decode_candidate_to_instruction(candidate, &instruction) == 0) metadata = m68k_sim_metadata_for_instruction(&instruction);
      if (metadata) {
        if (metadata->sp_effect_count != 0U) trace_value_set_unknown(&after.a[7]);
        int memory_read=0;
        for (size_t i=0;i<instruction.operand_count && i<4U;++i)
          if (metadata->operand_access_kinds[i]==M68K_SIM_ACCESS_MEMORY_READ) memory_read=1;
        for (size_t i=0;i<instruction.operand_count && i<4U;++i) {
          uint8_t reg=0U;
          if (memory_read && metadata->operand_access_kinds[i]==M68K_SIM_ACCESS_REGISTER_WRITE) {
            if (ir_operand_direct_data_register(&instruction.operands[i],&reg)) trace_value_set_unknown(&after.d[reg]);
            else if (ir_operand_direct_address_register(&instruction.operands[i],&reg)) trace_value_set_unknown(&after.a[reg]);
          }
          if (memory_read && metadata->operand_access_kinds[i]==M68K_SIM_ACCESS_REGISTER_LIST_WRITE) {
            for (size_t r=0;r<8;++r) { trace_value_set_unknown(&after.d[r]);trace_value_set_unknown(&after.a[r]); }
          }
          if (metadata->operand_ea_register_updates[i]!=M68K_SIM_EA_UPDATE_NONE &&
              candidate->operand_kinds[i]==M68K_ASM_OPERAND_EA && candidate->operands[i].ea_reg<8U)
            trace_value_set_unknown(&after.a[candidate->operands[i].ea_reg]);
        }
      }
      if (!metadata || metadata->flow_kind != M68K_SIM_FLOW_SEQUENTIAL) trace_state_init_unknown(&state);
      else state = after;
      offset += candidate->byte_count;
    }
  }
  return 0;
}

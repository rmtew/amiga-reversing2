/* Copy-linked callback candidates, not a must-memory or closed-target proof.
 * A known four-byte callback may straddle adjacent LONG copies.  Only a
 * straight-line, byte-complete pair with one stable signed WORD selector is
 * transported.  In particular, halves from different rows cannot be joined.
 * Unknown selector values remain unknown; this only adds the same kind of
 * store-linked may-candidates as the ordinary receiver collector. */
static int callback_fragment_index(const M68kDecodeCandidate *c, size_t op,
    uint8_t *base, uint8_t *index, int32_t *disp) {
  M68kInstructionIR i;
  if (m68k_decode_candidate_to_instruction(c,&i)!=0 || op>=i.operand_count ||
      !m68k_ir_operand_brief_index_displacement(&i.operands[op],disp) ||
      i.operands[op].value.index_is_address || i.operands[op].value.index_long ||
      i.operands[op].value.scale>1U || i.operands[op].value.index_reg>=8U ||
      i.operands[op].value.ea_reg>=7U) return 0;
  *base=i.operands[op].value.ea_reg;*index=i.operands[op].value.index_reg;
  return 1;
}

static int callback_fragment_address(M68kReceiverContext *ctx, const M68kDecodeCandidate *c,
    size_t op, uint8_t base, uint8_t index, uint32_t root, int32_t selector, uint32_t *out) {
  uint8_t b,x;int32_t d;M68kReceiverValues slots;
  if(callback_fragment_index(c,op,&b,&x,&d)) {
    int64_t address=(int64_t)root+selector+d;
    if(b!=base || x!=index || address<0 || address>UINT32_MAX) return 0;
    *out=(uint32_t)address;return 1;
  }
  if(!receiver_field_slots(ctx,c,op,&slots) || slots.count!=1U) return 0;
  *out=slots.offsets[0];return 1;
}

static int callback_fragment_overlaps(uint32_t at,uint32_t size,uint32_t start,uint32_t length) {
  return (uint64_t)at+size>start && (uint64_t)start+length>at;
}

static int collect_callback_fragment_targets(Arena *arena,M68kFactsV2CallbackFieldTargets *targets,
    size_t section_index,const M68kDecodeCandidate *first,int selector_known,int32_t selector_value) {
  M68kReceiverContext *ctx=targets->receivers[section_index];
  const M68kDecodeSectionIR *s=ctx->section;
  uint8_t base,index;int32_t displacement;M68kReceiverValues roots,destinations;
  if(first->mnemonic_id!=M68K_ASM_MNEMONIC_MOVE || first->size_suffix!='l' || first->operand_count!=2U ||
      !callback_fragment_index(first,0U,&base,&index,&displacement) ||
      !receiver_register_values(ctx,first->offset,base,0,0,&roots,0U) || roots.count!=1U ||
      !receiver_field_slots(ctx,first,1U,&destinations) || destinations.count!=1U) return 0;
  M68kInstructionIR first_ir;
  if(m68k_decode_candidate_to_instruction(first,&first_ir)!=0 ||
      m68k_sim_operand_ea_update(&first_ir,0U) || m68k_sim_operand_ea_update(&first_ir,1U)) return 0;
  uint32_t root=roots.offsets[0],destination=destinations.offsets[0];
  if(destination>s->size || s->size-destination<8U) return 0;
  size_t initial_count=targets->count;
  for(size_t n=0U;n<initial_count;++n) {
    /* Appending can move the arena-backed array. Keep this item by value. */
    M68kFactsV2CallbackFieldTarget known=targets->items[n];
    if(known.section_index!=section_index || known.storage_offset<2U ||
        known.storage_offset>s->size || s->size-known.storage_offset<6U ||
        callback_fragment_overlaps(destination,4U,known.storage_offset+2U,2U)) continue;
    int64_t selected=(int64_t)known.storage_offset-2-(int64_t)root-displacement;
    if(selected<INT16_MIN || selected>INT16_MAX || (selected&1) ||
        (selector_known && selected!=selector_value)) continue;
    uint32_t cursor=first->offset+first->byte_count,previous=first->offset;
    for(unsigned step=0U;step<16U;++step) {
      if(cursor>=s->size || !ctx->accepted[cursor] || targets->entry_boundaries[section_index][cursor]) break;
      /* No alternate predecessor may enter between the two fragment reads. */
      uint32_t edge=ctx->heads[cursor];
      if(!edge || ctx->preds[edge].next || ctx->preds[edge].source!=previous || ctx->preds[edge].kind) break;
      const M68kDecodeCandidate *c=m68k_decode_ir_find_candidate_at_offset(s,cursor);
      M68kInstructionIR i;const M68kSimFormMetadata *m;
      if(!c || m68k_decode_candidate_to_instruction(c,&i)!=0 ||
          !(m=m68k_sim_metadata_for_instruction(&i)) || m->flow_kind!=M68K_SIM_FLOW_SEQUENTIAL ||
          (c->mnemonic_id!=M68K_ASM_MNEMONIC_MOVE && c->mnemonic_id!=M68K_ASM_MNEMONIC_MOVEA) ||
          c->size_suffix!='l' ||
          record_writes_reg(c,1U,base) || record_writes_reg(c,0U,index)) break;
      int updated=0;
      for(size_t op=0U;op<i.operand_count;++op)
        if(m68k_sim_operand_ea_update(&i,(uint8_t)op)) updated=1;
      if(updated) break;
      uint8_t b,x;int32_t d;M68kReceiverValues to;
      if(c->mnemonic_id==M68K_ASM_MNEMONIC_MOVE && c->size_suffix=='l' && c->operand_count==2U &&
          callback_fragment_index(c,0U,&b,&x,&d) && b==base && x==index && d==displacement+4 &&
          receiver_field_slots(ctx,c,1U,&to) && to.count==1U && to.offsets[0]==destination+4U) {
        known.storage_offset=destination+2U;
        /* Completion anchor of a composite copy, never an asserted full-pointer store. */
        known.store_offset=c->offset;
        if(callback_field_targets_append(arena,targets,&known)!=0) return -1;
        break;
      }
      int barrier=0;
      for(size_t op=0U;op<i.operand_count;++op) {
        uint8_t access=m->operand_access_kinds[op];
        if(access==M68K_SIM_ACCESS_REGISTER_LIST_WRITE || m68k_sim_operand_ea_update(&i,(uint8_t)op)) {barrier=1;break;}
        uint8_t direct;
        if(access!=M68K_SIM_ACCESS_MEMORY_WRITE ||
            operand_is_data_register_direct(&c->operands[op],&direct) ||
            operand_is_address_register_direct(&c->operands[op],&direct)) continue;
        uint32_t at;uint8_t width=m68k_sim_operand_width_bytes(&i,(uint8_t)op);
        /* Previously read source bytes may be overwritten by an exchange.
         * Unread source bytes and already written destination bytes must survive. */
        if(!width || !callback_fragment_address(ctx,c,op,base,index,root,(int32_t)selected,&at) ||
            at>s->size || s->size-at<width ||
            callback_fragment_overlaps(at,width,known.storage_offset+2U,2U) ||
            callback_fragment_overlaps(at,width,destination+2U,2U)) {barrier=1;break;}
      }
      if(barrier) break;
      previous=cursor;cursor+=c->byte_count;
    }
  }
  return 0;
}

/* Byte-origin transport for existing callback may-values. Only accepted,
 * uniquely entered straight-line LONG moves participate. Four lanes must
 * retain one original pointer's ordering and version; no numeric lane mixing,
 * new roots, receiver ABI, index bounds or target closure are inferred. */
typedef struct CallbackByteExpr {
  uint32_t root;int32_t displacement;
  uint8_t base,index;
} CallbackByteExpr;
typedef struct CallbackByteMove {
  M68kDecodeCandidate c;
  CallbackByteExpr source,destination;
  uint8_t source_reg,destination_reg,source_memory,destination_memory;
} CallbackByteMove;
typedef struct CallbackByteSelectors {uint8_t known;int16_t value[8];} CallbackByteSelectors;

static int callback_byte_expr(M68kReceiverContext *ctx,uint32_t anchor,const M68kDecodeCandidate *c,
    size_t op,CallbackByteExpr *out) {
  uint32_t slot;uint8_t base;int32_t displacement;M68kInstructionIR i;M68kReceiverValues roots;
  memset(out,0,sizeof(*out));out->base=out->index=UINT8_MAX;
  if(staged_static_slot(ctx->section,ctx->runtime,c,op,&slot)) {out->root=slot;return 1;}
  if(m68k_decode_candidate_to_instruction(c,&i)!=0 || op>=i.operand_count) return 0;
  if(m68k_ir_operand_brief_index_displacement(&i.operands[op],&displacement)) {
    if(i.operands[op].value.index_is_address || i.operands[op].value.index_long ||
        i.operands[op].value.scale>1U || i.operands[op].value.index_reg>=8U) return 0;
    out->index=i.operands[op].value.index_reg;base=i.operands[op].value.ea_reg;
  } else if(!candidate_operand_base_field_slot(c,op,&base,&displacement)) return 0;
  if(!receiver_register_values(ctx,anchor,base,0,0,&roots,0U) || roots.count!=1U) return 0;
  out->root=roots.offsets[0];out->base=base;out->displacement=displacement;return 1;
}

static int callback_byte_reg(const M68kDecodeCandidate *c,size_t op,uint8_t *out) {
  uint8_t reg;
  if(operand_is_data_register_direct(&c->operands[op],&reg)) {*out=reg;return 1;}
  if(operand_is_address_register_direct(&c->operands[op],&reg)) {*out=8U+reg;return 1;}
  return 0;
}

static int callback_byte_bind(CallbackByteSelectors *selectors,const CallbackByteExpr *e,uint32_t address) {
  int64_t delta=(int64_t)address-e->root-e->displacement;
  if(e->index==UINT8_MAX) return delta==0;
  if(delta<INT16_MIN || delta>INT16_MAX || (delta&1)) return 0;
  uint8_t bit=(uint8_t)(1U<<e->index);
  if(selectors->known&bit) return selectors->value[e->index]==delta;
  selectors->known|=bit;selectors->value[e->index]=(int16_t)delta;return 1;
}

static int callback_byte_address(const CallbackByteExpr *e,const CallbackByteSelectors *selectors,
    uint8_t written_data,uint8_t written_address,uint32_t size,uint32_t *out) {
  if((e->base<8U && (written_address&(1U<<e->base))) ||
      (e->index<8U && (!(selectors->known&(1U<<e->index)) || (written_data&(1U<<e->index))))) return 0;
  int64_t value=(int64_t)e->root+e->displacement+(e->index<8U ? selectors->value[e->index] : 0);
  if(value<0 || (value&1) || (uint64_t)value+4U>size) return 0;
  *out=(uint32_t)value;return 1;
}

static int callback_byte_window(M68kReceiverContext *ctx,const uint8_t *entries,
    const M68kDecodeCandidate *first,CallbackByteMove *moves) {
  uint32_t cursor=first->offset,previous=0U;int count=0;
  while(count<16 && cursor<ctx->section->size && ctx->accepted[cursor]) {
    if(count) {
      uint32_t edge=ctx->heads[cursor];
      if(entries[cursor] || !edge || ctx->preds[edge].next || ctx->preds[edge].source!=previous || ctx->preds[edge].kind) break;
    }
    const M68kDecodeCandidate *c=m68k_decode_ir_find_candidate_at_offset(ctx->section,cursor);
    M68kInstructionIR i;const M68kSimFormMetadata *m;
    if(!c || c->operand_count!=2U || c->size_suffix!='l' ||
        (c->mnemonic_id!=M68K_ASM_MNEMONIC_MOVE && c->mnemonic_id!=M68K_ASM_MNEMONIC_MOVEA) ||
        m68k_decode_candidate_to_instruction(c,&i)!=0 || !(m=m68k_sim_metadata_for_instruction(&i)) ||
        m->flow_kind!=M68K_SIM_FLOW_SEQUENTIAL || m68k_sim_operand_ea_update(&i,0U) ||
        m68k_sim_operand_ea_update(&i,1U) || m68k_sim_operand_width_bytes(&i,0U)!=4U ||
        m68k_sim_operand_width_bytes(&i,1U)!=4U) break;
    CallbackByteMove *move=&moves[count];memset(move,0,sizeof(*move));move->c=*c;
    move->source_reg=move->destination_reg=UINT8_MAX;
    uint32_t literal;
    if(!callback_byte_reg(c,0U,&move->source_reg) &&
        !operand_immediate_value(c->operand_kinds[0],&c->operands[0],&literal)) {
      if(m->operand_access_kinds[0]!=M68K_SIM_ACCESS_MEMORY_READ ||
          !callback_byte_expr(ctx,first->offset,c,0U,&move->source)) break;
      move->source_memory=1U;
    }
    if(!callback_byte_reg(c,1U,&move->destination_reg)) {
      if(m->operand_access_kinds[1]!=M68K_SIM_ACCESS_MEMORY_WRITE ||
          !callback_byte_expr(ctx,first->offset,c,1U,&move->destination)) break;
      move->destination_memory=1U;
    }
    ++count;previous=cursor;cursor+=c->byte_count;
  }
  return count;
}

/* Eight tracked byte addresses suffice for a single source pointer and demanded
 * destination. Overlap is real memory: later writes update the same tag. */
static int callback_byte_transfer(const M68kReceiverContext *ctx,const CallbackByteMove *moves,int count,uint32_t size,
    uint32_t source,uint32_t destination,const CallbackByteSelectors *selectors,uint32_t *completion) {
  uint32_t address[8];uint8_t tags[8]={0},used=0U,registers[16][4]={{0}};
  for(uint8_t n=0U;n<4U;++n) address[used++]=destination+n;
  for(uint8_t n=0U;n<4U;++n) {
    uint8_t k;for(k=0U;k<used && address[k]!=source+n;++k) {}
    if(k==used) address[used++]=source+n;
    tags[k]=n+1U;
  }
  uint8_t written_data=0U,written_address=0U,written_destination=0U;
  for(int n=0;n<count;++n) {
    const CallbackByteMove *move=&moves[n];uint8_t value[4]={0};uint32_t at;
    if(move->source_memory) {
      if(move->source.index<8U && !receiver_selector_allows(ctx,move->c.offset,0U,move->source.index,selectors->value[move->source.index])) return 0;
      if(!callback_byte_address(&move->source,selectors,written_data,written_address,size,&at)) return 0;
      for(uint8_t b=0U;b<4U;++b) for(uint8_t k=0U;k<used;++k)
        if(address[k]==at+b) value[b]=tags[k];
    } else if(move->source_reg<16U) memcpy(value,registers[move->source_reg],sizeof(value));
    if(move->destination_memory) {
      if(move->destination.index<8U && !receiver_selector_allows(ctx,move->c.offset,1U,move->destination.index,selectors->value[move->destination.index])) return 0;
      if(!callback_byte_address(&move->destination,selectors,written_data,written_address,size,&at)) return 0;
      for(uint8_t b=0U;b<4U;++b) {
        for(uint8_t k=0U;k<used;++k) if(address[k]==at+b) tags[k]=value[b];
        if(at+b>=destination && at+b-destination<4U) written_destination|=(uint8_t)(1U<<(at+b-destination));
      }
      if(written_destination==15U) {
        int complete=1;
        for(uint8_t b=0U;b<4U;++b) {
          uint8_t k;for(k=0U;k<used && address[k]!=destination+b;++k) {}
          if(k==used || tags[k]!=b+1U) complete=0;
        }
        if(complete) {*completion=move->c.offset;return 1;}
      }
    } else if(move->destination_reg<16U) {
      memcpy(registers[move->destination_reg],value,sizeof(value));
      if(move->destination_reg<8U) written_data|=(uint8_t)(1U<<move->destination_reg);
      else written_address|=(uint8_t)(1U<<(move->destination_reg-8U));
    }
  }
  return 0;
}

static int collect_callback_fragment_targets(Arena *arena,M68kFactsV2CallbackFieldTargets *targets,
    size_t section_index,const M68kDecodeCandidate *first,const M68kFactsV2RelocationLookup *relocations,
    uint8_t **accepted_start,uint8_t **accepted_bytes) {
  if(!targets->count || !targets->consumed_count || first->operand_count!=2U || first->size_suffix!='l' ||
      (first->mnemonic_id!=M68K_ASM_MNEMONIC_MOVE && first->mnemonic_id!=M68K_ASM_MNEMONIC_MOVEA)) return 0;
  M68kReceiverContext *ctx=targets->receivers[section_index];CallbackByteMove moves[16];
  int count=callback_byte_window(ctx,targets->entry_boundaries[section_index],first,moves);
  if(count<1 || !moves[0].source_memory) return 0;
  M68kFactsV2TraceState trace;CallbackByteSelectors initial={0};
  if(trace_callback_site_linear_state(relocations,ctx->runtime,accepted_start,accepted_bytes,section_index,
      ctx->section,first,targets->entry_boundaries[section_index],arena,&trace)) {
    initial.known=(uint8_t)trace.d_low16_known;
    for(uint8_t n=0U;n<8U;++n) initial.value[n]=(int16_t)trace.d_low16[n];
  }
  size_t known_count=targets->count;
  for(size_t n=0U;n<known_count;++n) {
    M68kFactsV2CallbackFieldTarget known=targets->items[n];
    if(known.section_index!=section_index ||
        (uint64_t)known.storage_offset+4U>ctx->section->size) continue;
    size_t prior;
    for(prior=0U;prior<n;++prior)
      if(targets->items[prior].section_index==section_index && targets->items[prior].storage_offset==known.storage_offset) break;
    if(prior<n) continue;
    for(size_t d=0U;d<targets->consumed_count;++d) {
      const M68kCallbackConsumedCell *demand=&targets->consumed[d];
      if(demand->section_index!=section_index || (uint64_t)demand->offset+4U>ctx->section->size) continue;
      uint32_t completion=0U;int copied=0;
      /* LONG-aligned pointers and the even-addressed straddling case share
       * one byte proof, not separate numeric pointer heuristics. */
      for(uint32_t source_part=0U;source_part<=2U && !copied;source_part+=2U) {
        if(known.storage_offset<source_part) continue;
        CallbackByteSelectors source_selectors=initial;
        if(!callback_byte_bind(&source_selectors,&moves[0].source,known.storage_offset-source_part)) continue;
        for(int k=0;k<count && !copied;++k) {
          if(!moves[k].destination_memory) continue;
          for(uint32_t destination_part=0U;destination_part<=2U && !copied;destination_part+=2U) {
            if(demand->offset<destination_part) continue;
            CallbackByteSelectors selectors=source_selectors;
            if(!callback_byte_bind(&selectors,&moves[k].destination,demand->offset-destination_part)) continue;
            copied=callback_byte_transfer(ctx,moves,count,ctx->section->size,known.storage_offset,demand->offset,&selectors,&completion);
          }
        }
      }
      if(!copied) continue;
      /* Preserve whole values, not independently discovered pointer halves. */
      for(size_t v=0U;v<known_count;++v) {
        M68kFactsV2CallbackFieldTarget value=targets->items[v];
        if(value.section_index!=section_index || value.storage_offset!=known.storage_offset) continue;
        value.storage_offset=demand->offset;value.store_offset=completion;
        if(callback_field_targets_append(arena,targets,&value)!=0) return -1;
      }
    }
  }
  return 0;
}

/* Exact receiver-slot may-flow across accepted CFG and direct call entries.
 * Continuations cross helpers only after a bounded no-write / ordinary-return
 * proof for the tracked register. Stack receivers and unknown ABIs stay out. */
typedef struct ReceiverPred { uint32_t source, next; uint8_t kind; } ReceiverPred;
struct M68kReceiverContext {
  const M68kDecodeSectionIR *section;
  const M68kRuntimeAddressSpace *runtime;
  const M68kAnalysisPolicy *policy;
  const uint8_t *accepted;
  uint32_t *heads;
  ReceiverPred *preds;
  uint32_t count, capacity;
  struct { uint32_t entry; uint8_t reg, value; } cache[256];
  uint32_t cache_count;
};

static int receiver_direct_target(const M68kReceiverContext *ctx, const M68kDecodeCandidate *c,
    uint32_t *target) {
  uint32_t address;
  const M68kDecodeSectionIR *s = ctx->section;
  if (!candidate_has_decoded_direct_control_target(c)) return 0;
  if (candidate_absolute_control_address(c, &address)) {
    if (source_control_binding(ctx->runtime, s->section_index, c->offset, address, target) &&
        (runtime_address_space_section_has_range(ctx->runtime, s->section_index) ||
         !record_absolute_pointer_source(ctx->runtime, s->section_index, s->size, address, target))) return 0;
  } else {
    size_t n;
    for (n=0U;n<c->target_count;++n)
      if (c->targets[n].kind != M68K_DECODE_TARGET_DATA && c->targets[n].has_section &&
          c->targets[n].section_index == s->section_index) { *target=c->targets[n].offset;break; }
    if (n==c->target_count) return 0;
  }
  return *target < s->size && ctx->accepted[*target];
}

static int receiver_add_pred(M68kReceiverContext *ctx, uint32_t target, uint32_t source, uint8_t kind) {
  if (target>=ctx->section->size || !ctx->accepted[target]) return 0;
  if (ctx->count==ctx->capacity) return -1;
  uint32_t index=ctx->count++;
  ctx->preds[index]=(ReceiverPred){source,ctx->heads[target],kind};ctx->heads[target]=index;
  return 0;
}

static M68kReceiverContext *receiver_context_create(const M68kDecodeSectionIR *s,
    const M68kFactIR *facts, const M68kRuntimeAddressSpace *runtime, const M68kAnalysisPolicy *policy,
    const uint8_t *accepted, Arena *arena) {
  if (facts->fact_count>=UINT32_MAX || s->candidate_count>(UINT32_MAX-facts->fact_count-1U)/3U) return NULL;
  M68kReceiverContext *ctx=arena_calloc(arena,1U,sizeof(*ctx));
  if (!ctx) return NULL;
  ctx->section=s;ctx->runtime=runtime;ctx->policy=policy;ctx->accepted=accepted;
  ctx->capacity=(uint32_t)(s->candidate_count*3U+facts->fact_count+1U);ctx->count=1U;
  ctx->heads=arena_calloc(arena,s->size ? s->size : 1U,sizeof(*ctx->heads));
  ctx->preds=arena_calloc(arena,ctx->capacity,sizeof(*ctx->preds));
  if (!ctx->heads || !ctx->preds) return NULL;
  for (size_t n=0U;n<s->candidate_count;++n) {
    const M68kDecodeCandidate *c=&s->candidates[n];M68kInstructionIR i;const M68kSimFormMetadata *m;
    uint32_t target;
    if (!accepted[c->offset] || m68k_decode_candidate_to_instruction(c,&i)!=0 ||
        !(m=m68k_sim_metadata_for_instruction(&i))) continue;
    if (candidate_has_normal_fallthrough(c) && receiver_add_pred(ctx,c->offset+c->byte_count,c->offset,
        m->flow_kind==M68K_SIM_FLOW_CALL ? 2U : 0U)!=0) return NULL;
    if (receiver_direct_target(ctx,c,&target) && receiver_add_pred(ctx,target,c->offset,
        m->flow_kind==M68K_SIM_FLOW_CALL ? 1U : 0U)!=0) return NULL;
  }
  for (size_t n=0U;n<facts->fact_count;++n) {
    const M68kFact *f=&facts->facts[n];M68kInstructionIR i;const M68kSimFormMetadata *m;
    if (f->kind!=M68K_FACT_CODE_START || f->reason!=M68K_FACT_CODE_START_REASON_CONTROL_TARGET ||
        f->code_start_evidence_kind!=M68K_CODE_ORIGIN_EVIDENCE_CALLBACK_FIELD_CONTROL_TARGET ||
        f->section_index!=s->section_index || f->source_section_index!=s->section_index ||
        f->source_offset>=s->size || !accepted[f->source_offset]) continue;
    const M68kDecodeCandidate *c=m68k_decode_ir_find_candidate_at_offset(s,f->source_offset);
    if (!c || candidate_has_decoded_direct_control_target(c) || m68k_decode_candidate_to_instruction(c,&i)!=0 ||
        !(m=m68k_sim_metadata_for_instruction(&i)) || m->flow_kind!=M68K_SIM_FLOW_CALL) continue;
    if (receiver_add_pred(ctx,f->offset,c->offset,1U)!=0) return NULL;
  }
  return ctx;
}

static int receiver_callee_preserves(M68kReceiverContext *ctx,uint32_t entry,uint8_t reg,unsigned depth) {
  enum { LIMIT=128 };
  uint32_t pending[LIMIT],seen[LIMIT],count=1U,used=0U;int returned=0;
  if (reg>=7U || depth>2U) return 0;
  if (!depth) for (uint32_t n=0U;n<ctx->cache_count;++n)
    if (ctx->cache[n].entry==entry && ctx->cache[n].reg==reg) return ctx->cache[n].value;
  pending[0]=entry;
  while(count) {
    uint32_t at=pending[--count],n;M68kInstructionIR i;const M68kSimFormMetadata *m;
    for(n=0U;n<used && seen[n]!=at;++n) {}
    if(n<used) continue;
    if(used==LIMIT || at>=ctx->section->size || !ctx->accepted[at]) goto refused;
    seen[used++]=at;
    const M68kDecodeCandidate *c=m68k_decode_ir_find_candidate_at_offset(ctx->section,at);
    if(!c || m68k_decode_candidate_to_instruction(c,&i)!=0 || !(m=m68k_sim_metadata_for_instruction(&i)) ||
       record_writes_reg(c,1U,reg) || record_writes_reg(c,1U,7U) ||
       (m->sp_effect_count && m->flow_kind!=M68K_SIM_FLOW_CALL && m->flow_kind!=M68K_SIM_FLOW_RETURN)) goto refused;
    /* Explicit stack access or deriving a stack alias is outside this proof. */
    for(size_t op=0U;op<c->operand_count;++op) {
      uint8_t base;int32_t displacement;
      if(operand_is_address_register_direct(&c->operands[op],&base) && base==7U) goto refused;
      if(candidate_operand_base_field_slot(c,op,&base,&displacement) && base==7U) goto refused;
      if(m68k_ir_operand_brief_index_displacement(&i.operands[op],&displacement) &&
          i.operands[op].value.ea_reg==7U) goto refused;
    }
    if(m->flow_kind==M68K_SIM_FLOW_RETURN) {
      if(c->mnemonic_id!=M68K_ASM_MNEMONIC_RTS) goto refused;
      returned=1;continue;
    }
    if(m->flow_kind==M68K_SIM_FLOW_TRAP) goto refused;
    uint32_t target;
    if(m->flow_kind==M68K_SIM_FLOW_CALL) {
      if(!receiver_direct_target(ctx,c,&target) || !receiver_callee_preserves(ctx,target,reg,depth+1U)) goto refused;
    } else if(m->flow_kind==M68K_SIM_FLOW_BRANCH || m->flow_kind==M68K_SIM_FLOW_JUMP) {
      if(!receiver_direct_target(ctx,c,&target) || count==LIMIT) goto refused;
      pending[count++]=target;
    }
    if(candidate_has_normal_fallthrough(c)) {
      if(count==LIMIT) goto refused;
      pending[count++]=c->offset+c->byte_count;
    }
  }
  if(!returned) goto refused;
  if(!depth && ctx->cache_count<256U) {
    uint32_t n=ctx->cache_count++;ctx->cache[n].entry=entry;ctx->cache[n].reg=reg;ctx->cache[n].value=1U;
  }
  return 1;
refused:
  if(!depth && ctx->cache_count<256U) {
    uint32_t n=ctx->cache_count++;ctx->cache[n].entry=entry;ctx->cache[n].reg=reg;ctx->cache[n].value=0U;
  }
  return 0;
}

static int receiver_values_add_origin(M68kReceiverValues *out,uint32_t value,uint32_t definition) {
  for(uint32_t n=0U;n<out->count;++n) if(out->offsets[n]==value && out->definitions[n]==definition) return 1;
  if(out->count==M68K_RECEIVER_VALUE_LIMIT) return 0;
  out->definitions[out->count]=definition;out->offsets[out->count++]=value;return 1;
}
static int receiver_values_add(M68kReceiverValues *out,uint32_t value) {
  return receiver_values_add_origin(out,value,UINT32_MAX);
}

static int receiver_register_values(M68kReceiverContext *ctx,uint32_t at,uint8_t reg,int32_t delta,
    int field_mode,M68kReceiverValues *out,unsigned recursion) {
  enum { LIMIT=4096 };
  typedef struct Query { uint32_t at;int32_t delta;uint8_t reg,depth; } Query;
  Query nodes[LIMIT];uint32_t count=1U;
  memset(out,0,sizeof(*out));
  if(reg>=7U || at>=ctx->section->size || recursion>1U) return 0;
  memset(nodes,0,sizeof(nodes));nodes[0]=(Query){at,delta,reg,0U};
  for(uint32_t q=0U;q<count;++q) {
    Query current=nodes[q];
    for(uint32_t e=ctx->heads[current.at];e;e=ctx->preds[e].next) {
      const ReceiverPred *edge=&ctx->preds[e];
      const M68kDecodeCandidate *c=m68k_decode_ir_find_candidate_at_offset(ctx->section,edge->source);
      if(!c) continue;
      Query next={c->offset,current.delta,current.reg,current.depth};
      if(edge->kind==1U) { if(current.depth==3U) continue;next.depth++; }
      else if(edge->kind==2U) {
        uint32_t target;
        if(!receiver_direct_target(ctx,c,&target) || !receiver_callee_preserves(ctx,target,current.reg,0U)) continue;
      } else if(record_writes_reg(c,1U,current.reg)) {
        uint8_t base,dest;int32_t displacement;uint32_t root,value;
        if(field_mode==1 && !current.delta && candidate_loads_callback_field_to_control_register(c,current.reg,&base,&displacement)) {
          M68kReceiverValues slots;
          if(receiver_register_values(ctx,c->offset,base,displacement,0,&slots,recursion+1U))
            for(uint32_t n=0U;n<slots.count;++n) if(!receiver_values_add(out,slots.offsets[n])) goto overflow;
          continue;
        }
        if(staged_lea_root(ctx->section,ctx->runtime,c,&dest,&root) && dest==current.reg) {
          if(field_mode!=1) {
            int64_t value=(int64_t)root+current.delta;
            if(value>=0 && value<ctx->section->size && !receiver_values_add_origin(out,(uint32_t)value,field_mode==2 ? c->offset : UINT32_MAX)) goto overflow;
          }
          continue;
        }
        if(c->mnemonic_id==M68K_ASM_MNEMONIC_MOVEA && c->size_suffix=='l' && c->operand_count==2U &&
            operand_is_address_register_direct(&c->operands[1],&dest) && dest==current.reg &&
            operand_is_address_register_direct(&c->operands[0],&base)) next.reg=base;
        else if(c->mnemonic_id==M68K_ASM_MNEMONIC_LEA && c->operand_count==2U &&
            operand_is_address_register_direct(&c->operands[1],&dest) && dest==current.reg &&
            candidate_operand_base_field_slot(c,0U,&base,&displacement) && field_mode!=1) {
          int64_t delta=(int64_t)current.delta+displacement;
          if(delta<INT32_MIN || delta>INT32_MAX) continue;
          next.reg=base;next.delta=(int32_t)delta;
        } else if(c->mnemonic_id==M68K_ASM_MNEMONIC_MOVEA && c->size_suffix=='l' && c->operand_count==2U &&
            operand_is_address_register_direct(&c->operands[1],&dest) && dest==current.reg &&
            operand_immediate_value(c->operand_kinds[0],&c->operands[0],&value) && field_mode!=1) {
          if(record_absolute_pointer_source(ctx->runtime,ctx->section->section_index,ctx->section->size,value,&root)) {
            int64_t address=(int64_t)root+current.delta;
            if(address>=0 && address<ctx->section->size && !receiver_values_add_origin(out,(uint32_t)address,field_mode==2 ? c->offset : UINT32_MAX)) goto overflow;
          }
          continue;
        } else if(field_mode!=1 && c->operand_count==2U &&
            (c->mnemonic_id==M68K_ASM_MNEMONIC_ADDA || c->mnemonic_id==M68K_ASM_MNEMONIC_ADDQ || c->mnemonic_id==M68K_ASM_MNEMONIC_SUBQ) &&
            operand_is_address_register_direct(&c->operands[1],&dest) && dest==current.reg &&
            operand_immediate_value(c->operand_kinds[0],&c->operands[0],&value) && value<=INT16_MAX) {
          int64_t delta=(int64_t)current.delta+(c->mnemonic_id==M68K_ASM_MNEMONIC_SUBQ ? -(int64_t)value : value);
          if(delta<INT32_MIN || delta>INT32_MAX) continue;
          next.delta=(int32_t)delta;
        } else if(field_mode!=1) {
          M68kInstructionIR instruction;const M68kSimFormMetadata *metadata;int64_t delta=current.delta;int updated=0,unsupported=0;
          if(m68k_decode_candidate_to_instruction(c,&instruction)!=0 || !(metadata=m68k_sim_metadata_for_instruction(&instruction))) continue;
          if(metadata->multi_transfer_direction) unsupported=1;
          for(size_t op=0U;op<c->operand_count;++op) {
            uint8_t r;
            if(metadata->operand_access_kinds[op]==M68K_SIM_ACCESS_REGISTER_LIST_WRITE) unsupported=1;
            if((metadata->operand_access_kinds[op]==M68K_SIM_ACCESS_REGISTER_WRITE || metadata->operand_access_kinds[op]==M68K_SIM_ACCESS_MEMORY_WRITE) &&
                operand_is_address_register_direct(&c->operands[op],&r) && r==current.reg) unsupported=1;
            uint8_t update=m68k_sim_operand_ea_update(&instruction,(uint8_t)op);
            if(c->operands[op].ea_reg==current.reg && update!=M68K_SIM_EA_UPDATE_NONE) {
              uint8_t width=m68k_sim_operand_width_bytes(&instruction,(uint8_t)op);
              if(!width || (update!=M68K_SIM_EA_UPDATE_POSTINCREMENT && update!=M68K_SIM_EA_UPDATE_PREDECREMENT)) unsupported=1;
              else {delta+=update==M68K_SIM_EA_UPDATE_POSTINCREMENT ? width : -(int32_t)width;updated=1;}
            }
          }
          if(unsupported || !updated || delta<INT32_MIN || delta>INT32_MAX) continue;
          next.delta=(int32_t)delta;
        } else continue;
      }
      if(next.reg>=7U) continue;
      uint32_t n;
      for(n=0U;n<count;++n)
        if(nodes[n].at==next.at && nodes[n].delta==next.delta && nodes[n].reg==next.reg && nodes[n].depth==next.depth) break;
      if(n<count) continue;
      if(count==LIMIT) goto overflow;
      nodes[count++]=next;
    }
  }
  return out->count!=0U;
overflow:
  out->count=0U;return 0;
}

static int receiver_base_field(const M68kDecodeCandidate *c,size_t op,uint8_t *base,int32_t *displacement) {
  if(candidate_operand_base_field_slot(c,op,base,displacement)) return 1;
  M68kInstructionIR i;
  if(m68k_decode_candidate_to_instruction(c,&i)!=0 || op>=i.operand_count) return 0;
  uint8_t update=m68k_sim_operand_ea_update(&i,(uint8_t)op);
  uint8_t width=m68k_sim_operand_width_bytes(&i,(uint8_t)op);
  if(!width || (update!=M68K_SIM_EA_UPDATE_POSTINCREMENT && update!=M68K_SIM_EA_UPDATE_PREDECREMENT)) return 0;
  *base=c->operands[op].ea_reg;
  *displacement=update==M68K_SIM_EA_UPDATE_PREDECREMENT ? -(int32_t)width : 0;
  return 1;
}

static int receiver_field_slots(M68kReceiverContext *ctx,const M68kDecodeCandidate *c,size_t op,
    M68kReceiverValues *out) {
  uint8_t base;int32_t displacement;uint32_t slot;
  memset(out,0,sizeof(*out));
  if(staged_static_slot(ctx->section,ctx->runtime,c,op,&slot)) return receiver_values_add(out,slot);
  if(!receiver_base_field(c,op,&base,&displacement)) return 0;
  if(!receiver_register_values(ctx,c->offset,base,displacement,0,out,0U)) return 0;
  for(uint32_t n=0U;n<out->count;++n)
    if(out->offsets[n]&1U || ctx->section->size-out->offsets[n]<4U) {out->count=0U;return 0;}
  return 1;
}

static int receiver_control_slots(M68kReceiverContext *ctx,const M68kDecodeCandidate *c,M68kReceiverValues *out) {
  uint8_t reg;
  if(!candidate_indirect_control_address_register(c,&reg)) return 0;
  return receiver_register_values(ctx,c->offset,reg,0,1,out,0U);
}

static int receiver_table_values(M68kReceiverContext *ctx,const M68kDecodeCandidate *c,size_t op,M68kReceiverValues *out) {
  M68kInstructionIR i;int32_t displacement;
  if(m68k_decode_candidate_to_instruction(c,&i)!=0 || op>=i.operand_count ||
      !m68k_ir_operand_brief_index_displacement(&i.operands[op],&displacement) ||
      i.operands[op].value.index_is_address || i.operands[op].value.scale>1U) return 0;
  uint8_t index=i.operands[op].value.index_reg;
  uint32_t multiple=1U,cursor=c->offset,selector=0U;int known_selector=0;
  for(unsigned n=0U;n<48U;++n) {
    uint32_t edge=ctx->heads[cursor];
    if(!edge || ctx->preds[edge].next || ctx->preds[edge].kind) break;
    const M68kDecodeCandidate *p=find_accepted_candidate_ending_at(ctx->section,ctx->accepted,cursor);
    M68kInstructionIR pi;const M68kSimFormMetadata *pm;
    if(!p || m68k_decode_candidate_to_instruction(p,&pi)!=0 || !(pm=m68k_sim_metadata_for_instruction(&pi)) ||
        pm->flow_kind!=M68K_SIM_FLOW_SEQUENTIAL) break;
    if(record_writes_reg(p,0U,index)) {
      uint8_t a,b;uint32_t shift;
      if(p->operand_count==2U && p->mnemonic_id==M68K_ASM_MNEMONIC_ADD &&
          (p->size_suffix=='w'||p->size_suffix=='l') && operand_is_data_register_direct(&p->operands[0],&a) &&
          operand_is_data_register_direct(&p->operands[1],&b) && a==index && b==index) multiple*=2U;
      else if(p->operand_count==2U && (p->mnemonic_id==M68K_ASM_MNEMONIC_ASL || p->mnemonic_id==M68K_ASM_MNEMONIC_LSL) &&
          (p->size_suffix=='w'||p->size_suffix=='l') && operand_immediate_value(p->operand_kinds[0],&p->operands[0],&shift) && shift<=8U)
        multiple<<=shift;
      else {
        uint8_t dest;uint32_t value;
        if((p->mnemonic_id==M68K_ASM_MNEMONIC_MOVEQ || p->mnemonic_id==M68K_ASM_MNEMONIC_MOVE) &&
            p->operand_count==2U && (p->size_suffix=='w' || p->size_suffix=='l') &&
            operand_is_data_register_direct(&p->operands[1],&dest) && dest==index &&
            operand_immediate_value(p->operand_kinds[0],&p->operands[0],&value)) {
          selector=value*multiple;
          if(!i.operands[op].value.index_long) selector=(uint32_t)(int32_t)(int16_t)selector;
          known_selector=1;
        }
        break;
      }
      if(multiple>65536U) return 0;
    }
    cursor=p->offset;
  }
  if(multiple<4U) return 0;
  M68kReceiverValues bases;
  if(!receiver_register_values(ctx,c->offset,i.operands[op].value.ea_reg,displacement,0,&bases,0U)) return 0;
  memset(out,0,sizeof(*out));
  for(uint32_t n=0U;n<bases.count;++n) {
    const M68kAnalysisStructuredDataItem *table=NULL;
    for(size_t k=0U;k<ctx->policy->structured_data_item_count;++k) {
      const M68kAnalysisStructuredDataItem *item=&ctx->policy->structured_data_items[k];
      if((item->has_section_index ? item->section_index : 0U)!=ctx->section->section_index ||
          item->kind!=M68K_ANALYSIS_STRUCTURED_DATA_LONGS ||
          !(item->semantic_role_flags&M68K_ANALYSIS_STRUCTURED_DATA_ROLE_POINTER_TABLE) ||
          item->offset!=bases.offsets[n] || !item->size || (item->size&3U) || item->size/4U>M68K_RECEIVER_VALUE_LIMIT) continue;
      if(table && table->size!=item->size) return 0;
      table=item;
    }
    if(!table || table->offset>ctx->section->size || table->size>ctx->section->size-table->offset) return 0;
    if(known_selector && ((selector&3U) || selector>=table->size)) return 0;
    for(uint32_t k=known_selector ? selector : 0U;k<table->size;k+=4U) {
      uint32_t raw=m68k_read_u32be(ctx->section->data+table->offset+k),at;
      if(!raw || (raw&1U) || !record_absolute_pointer_source(ctx->runtime,ctx->section->section_index,
          ctx->section->size,raw,&at) || !receiver_values_add(out,at)) {out->count=0U;return 0;}
      if(known_selector) break;
    }
  }
  return out->count!=0U;
}

static int receiver_store_values(M68kReceiverContext *ctx,const M68kDecodeCandidate *c,M68kReceiverValues *out) {
  uint8_t reg;uint32_t raw,at;
  memset(out,0,sizeof(*out));
  if(operand_is_address_register_direct(&c->operands[0],&reg))
    return receiver_register_values(ctx,c->offset,reg,0,2,out,0U);
  if(operand_immediate_value(c->operand_kinds[0],&c->operands[0],&raw)) {
    if(raw && !(raw&1U) && record_absolute_pointer_source(ctx->runtime,ctx->section->section_index,
        ctx->section->size,raw,&at)) return receiver_values_add_origin(out,at,c->offset);
    return 0;
  }
  if(!receiver_table_values(ctx,c,0U,out)) return 0;
  for(uint32_t n=0U;n<out->count;++n) out->definitions[n]=c->offset;
  return 1;
}

/* Correlate the receiver with the defining pointer assignment. Resolving the
 * two registers independently at a merge would create false Cartesian pairs. */
static int receiver_value_owner_slots(M68kReceiverContext *ctx,const M68kDecodeCandidate *store,
    uint32_t definition,M68kReceiverValues *out) {
  uint8_t base;int32_t displacement;
  if(definition==store->offset) return receiver_field_slots(ctx,store,1U,out);
  if(definition>store->offset || store->offset-definition>1024U ||
      !receiver_base_field(store,1U,&base,&displacement)) return 0;
  uint32_t pending[128],seen[128],count=0U,used=0U;int reached=0;
  const M68kDecodeCandidate *origin=m68k_decode_ir_find_candidate_at_offset(ctx->section,definition);
  if(!origin) return 0;
  pending[count++]=origin->offset+origin->byte_count;
  while(count) {
    uint32_t at=pending[--count],n;
    if(at==store->offset) {reached=1;continue;}
    if(at>store->offset || at<=definition) continue;
    for(n=0U;n<used && seen[n]!=at;++n) {}
    if(n<used) continue;
    if(used==128U || !ctx->accepted[at]) return 0;
    seen[used++]=at;
    const M68kDecodeCandidate *c=m68k_decode_ir_find_candidate_at_offset(ctx->section,at);
    M68kInstructionIR i;const M68kSimFormMetadata *m;uint32_t target;
    if(!c || m68k_decode_candidate_to_instruction(c,&i)!=0 || !(m=m68k_sim_metadata_for_instruction(&i)) ||
        record_writes_reg(c,1U,base)) return 0;
    if(m->flow_kind==M68K_SIM_FLOW_RETURN || m->flow_kind==M68K_SIM_FLOW_TRAP) continue;
    if(m->flow_kind==M68K_SIM_FLOW_CALL) {
      if(!receiver_direct_target(ctx,c,&target) || !receiver_callee_preserves(ctx,target,base,0U)) return 0;
    } else if(m->flow_kind==M68K_SIM_FLOW_BRANCH || m->flow_kind==M68K_SIM_FLOW_JUMP) {
      if(!receiver_direct_target(ctx,c,&target) || target<=definition || count==128U) return 0;
      pending[count++]=target;
    }
    if(candidate_has_normal_fallthrough(c)) {
      if(count==128U) return 0;
      pending[count++]=at+c->byte_count;
    }
  }
  return reached && receiver_register_values(ctx,definition,base,displacement,0,out,0U);
}

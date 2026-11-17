#include "m68k_platform_projection.h"
#include "m68k_source_package.h"
#include "m68k_instruction_spec.h"
#include "m68k_ir_codec.h"
#include "m68k_render_ir.h"
#include "m68k_simulator.h"
#include "m68k_fact_ir.h"
#include "platform_common.h"
#include "json_builder.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
/* Narrow constant transport over the accepted CFG. It never seeds/decodes code,
 * reads memory contents, assumes caller state, or joins unrelated register types. */
typedef struct ConstantState { uint8_t seen; uint16_t known; uint32_t value[16],origin[16]; } ConstantState;
static int direct(const M68kOperandIR *operand,uint8_t *slot) {
  uint8_t address,reg;
  if(!m68k_instruction_operand_direct_register(operand,&address,&reg) || reg>=8)return 0;
  *slot=(uint8_t)(reg+(address ? 8 : 0));return 1;
}
static int numeric_address(const M68kOperandIR *op,const ConstantState *state,
    uint32_t *address,uint32_t *base,uint32_t *origin,uint8_t *relative) {
  uint8_t shape=m68k_instruction_operand_decoded_ea_shape(op),reg=op->value.ea_reg;
  *relative=0;*base=0;*origin=UINT32_MAX;
  if(m68k_asm_operand_absolute_value(op->kind,&op->value,address))return 1;
  /* The first projection supports only nonnegative aperture-sized displacement
   * cursors. Negative/full/indexed rebases stay unknown, not misinterpreted. */
  if(shape!=M68K_SIM_EA_SHAPE_DISPLACEMENT || reg>=8 || op->value.value>0x1ffU ||
      !(state->known&(1U<<(reg+8))))return 0;
  *base=state->value[reg+8];*address=*base+op->value.value;
  *origin=state->origin[reg+8];*relative=1;return 1;
}
static void step(ConstantState *state,const M68kRenderPlannedInstruction *planned) {
  const M68kInstructionIR *ins=&planned->instruction;
  const M68kSimFormMetadata *m=m68k_sim_metadata_for_instruction(ins);
  ConstantState before=*state;uint16_t writes=0;uint8_t destination=0,source=0;uint32_t value=0,origin=planned->source_offset;
  int known=0;
  if(!m) {state->known=0;return;}
  for(size_t i=0;i<ins->operand_count;++i)writes|=platform_operand_register_write_mask(ins,i);
  writes|=m68k_sim_sp_effect_bound_register_write_mask(ins);state->known&=(uint16_t)~writes;
  if(m->flow_kind==M68K_SIM_FLOW_CALL || m->flow_kind==M68K_SIM_FLOW_TRAP ||
      m->flow_kind==M68K_SIM_FLOW_RETURN || m->flow_kind==M68K_SIM_FLOW_NONE) {state->known=0;return;}
  if(m->dest_operand_index>=ins->operand_count || m->source_operand_index>=ins->operand_count ||
      !direct(&ins->operands[m->dest_operand_index],&destination))return;
  const M68kOperandIR *src=&ins->operands[m->source_operand_index];
  if(m->operation_class==M68K_SIM_CLASS_LOAD_EFFECTIVE_ADDRESS) {
    uint32_t base;uint8_t relative;
    known=numeric_address(src,&before,&value,&base,&origin,&relative);
    if(!relative)origin=planned->source_offset;
  } else if(m->operation_type==M68K_SIM_OP_MOVE && ins->size_suffix=='l' &&
      (ins->mnemonic_id==M68K_ASM_MNEMONIC_MOVE || ins->mnemonic_id==M68K_ASM_MNEMONIC_MOVEA)) {
    known=m68k_ir_operand_immediate_value(src,&value);
    if(!known && direct(src,&source) && (before.known&(1U<<source))) {
      known=1;value=before.value[source];origin=before.origin[source];
    }
  }
  if(known) {state->known|=(uint16_t)(1U<<destination);state->value[destination]=value;state->origin[destination]=origin;}
}
static int merge(ConstantState *into,const ConstantState *from) {
  if(!from->seen)return 0;
  if(!into->seen) {*into=*from;return 1;}
  int changed=0;
  for(uint8_t i=0;i<16;++i)if(into->known&(1U<<i)) {
    if(!(from->known&(1U<<i)) || into->value[i]!=from->value[i]) {into->known&=(uint16_t)~(1U<<i);changed=1;}
    else if(into->origin[i]!=from->origin[i] && into->origin[i]!=UINT32_MAX) {into->origin[i]=UINT32_MAX;changed=1;}
  }
  return changed;
}
static size_t block_at(const M68kSectionAnalysisIR *s,uint32_t offset) {
  size_t lo=0,hi=s->block_count;
  while(lo<hi) {size_t mid=lo+(hi-lo)/2;if(s->blocks[mid].start_offset<=offset)lo=mid+1;else hi=mid;}
  return lo && offset<s->blocks[lo-1].end_offset ? lo-1 : SIZE_MAX;
}
static int synchronous(uint32_t kind) {
  return kind==M68K_CODE_ORIGIN_EVIDENCE_DIRECT_CONTROL_TARGET || kind==M68K_CODE_ORIGIN_EVIDENCE_RUNTIME_CONTROL_TARGET ||
    kind==M68K_CODE_ORIGIN_EVIDENCE_DISPATCH_TABLE_CONTROL_TARGET;
}
static int states(const M68kRenderPlan *plan,const M68kSectionAnalysisIR *s,uint32_t section_index,ConstantState **out) {
  ConstantState *input=calloc(s->block_count ? s->block_count : 1,sizeof(*input));
  uint8_t *inbound=calloc(s->block_count ? s->block_count : 1,1);
  if(!input || !inbound) {free(input);free(inbound);return -1;}
  for(size_t i=0;i<s->edge_count;++i)if(s->edges[i].target_block_index<s->block_count)inbound[s->edges[i].target_block_index]=1;
  for(size_t i=0;i<s->code_start_ref_count;++i) {
    const M68kCodeStartRefIR *r=&s->code_start_refs[i];size_t at=block_at(s,r->offset);
    if(at==SIZE_MAX)continue;
    if(synchronous(r->evidence_kind) && r->source_section_index==section_index)inbound[at]=1;
    else input[at].seen=1; /* Every external/manual/asynchronous root is unknown. */
  }
  for(size_t i=0;i<s->conditional_control_count;++i)if(s->conditional_controls[i].admitted) {
    size_t at=block_at(s,s->conditional_controls[i].target_offset);if(at!=SIZE_MAX)input[at].seen=1;
  }
  for(size_t i=0;i<s->block_count;++i)if(!inbound[i])input[i].seen=1;
  free(inbound);
  for(size_t round=0;;++round) {
    int changed=0;
    if(round>s->block_count*17U+1U) {free(input);return -1;}
    for(size_t b=0;b<s->block_count;++b)if(input[b].seen) {
      ConstantState output=input[b];
      for(uint32_t at=s->blocks[b].start_offset;at<s->blocks[b].end_offset;) {
        const M68kRenderPlannedInstruction *ins=m68k_render_plan_find_instruction(plan,section_index,at);
        if(!ins || !ins->instruction.byte_count) {output.known=0;break;}
        step(&output,ins);at+=(uint32_t)ins->instruction.byte_count;
      }
      for(size_t i=0;i<s->edge_count;++i)if(s->edges[i].source_block_index==b && s->edges[i].target_block_index<s->block_count) {
        ConstantState target=output;if(s->edges[i].kind==M68K_CFG_EDGE_CALL)target.known=0;
        changed|=merge(&input[s->edges[i].target_block_index],&target);
      }
      for(size_t i=0;i<s->code_start_ref_count;++i) {
        const M68kCodeStartRefIR *r=&s->code_start_refs[i];
        if(!synchronous(r->evidence_kind) || r->source_section_index!=section_index || block_at(s,r->source_offset)!=b)continue;
        size_t target=block_at(s,r->offset);if(target!=SIZE_MAX)changed|=merge(&input[target],&output);
      }
    }
    if(!changed)break;
  }
  *out=input;return 0;
}
static int append_use(M68kPlatformProjection *p,const M68kPlatformProjectedUse *use) {
  if(p->use_count==p->use_capacity) {
    size_t count=p->use_capacity ? p->use_capacity*2 : 256;
    if(count>SIZE_MAX/sizeof(*p->uses))return -1;
    void *next=realloc(p->uses,count*sizeof(*p->uses));if(!next)return -1;p->uses=next;p->use_capacity=count;
  }
  p->uses[p->use_count++]=*use;return 0;
}
static int conflicts(const M68kSectionAnalysisIR *s,uint32_t offset,uint32_t operand,
    uint32_t address,uint8_t width,uint8_t *source_overlap_disambiguated) {
  uint8_t full_policy=0;uint32_t policy_base=0;
  for(size_t i=0;i<s->runtime_view_count;++i) {
    const M68kRuntimeViewIR *v=&s->runtime_views[i];
    if((uint64_t)address+(width ? width : 1U)>v->runtime_address &&
        (uint64_t)v->runtime_address+v->size>address)return 1;
    if(v->kind==M68K_FACT_RUNTIME_RANGE_KIND_POLICY && v->storage_offset==0 && v->size>=s->section_size) {
      if(full_policy && policy_base!=v->runtime_address)return 1;
      full_policy=1;policy_base=v->runtime_address;
    }
  }
  for(size_t i=0;i<s->address_observation_count;++i) {
    const M68kAddressObservationIR *o=&s->address_observations[i];
    if(o->offset!=offset || o->operand_index!=operand)continue;
    if(o->has_address && o->address!=address)return 1;
    if(o->conflicted) {
      /* A source-file offset coincidence is not physical code ownership under
       * one complete nonidentity load view. Keep the original observation;
       * only this spelling projection records the additional identity proof. */
      if(o->conflict_state!=M68K_ANALYSIS_CONFLICT_STATE_CODE_OVERLAP || !full_policy || !policy_base)return 1;
      *source_overlap_disambiguated=1;
    }
  }
  return 0;
}
static int project_instruction(M68kPlatformProjection *p,const M68kRenderPlan *base,const M68kSectionAnalysisIR *s,
    M68kRenderPlannedInstruction *ins,const ConstantState *state,int *changed) {
  const M68kInstructionIR *raw=&ins->instruction;
  for(size_t i=0;i<raw->operand_count;++i) {
    uint8_t access=platform_operand_access_kind(raw,i),width=0,count,span,relative;uint32_t address,base_address,origin;
    if(access!=M68K_SIM_ACCESS_MEMORY_READ && access!=M68K_SIM_ACCESS_MEMORY_WRITE && access!=M68K_SIM_ACCESS_COMPUTE_ADDRESS)continue;
    if(!numeric_address(&raw->operands[i],state,&address,&base_address,&origin,&relative))continue;
    if(access!=M68K_SIM_ACCESS_COMPUTE_ADDRESS && (!platform_operand_memory_span(raw,i,&width,&count,&span) || count!=1))continue;
    uint8_t vector=0;
    for(size_t r=0;r<s->code_start_ref_count;++r)if(s->code_start_refs[r].source_section_index==ins->source_section_index &&
        s->code_start_refs[r].source_offset==ins->source_offset &&
        s->code_start_refs[r].evidence_kind==M68K_CODE_ORIGIN_EVIDENCE_VECTOR_STORE_CONTROL_TARGET)vector=1;
    M68kPlatformProjectedUse use={0};use.section_index=ins->source_section_index;use.offset=ins->source_offset;
    use.operand_index=(uint32_t)i;use.base_origin=origin;use.base=base_address;
    use.admitted=(uint8_t)m68k_platform_symbol_resolve(p->profiles,address,width,access,relative,base_address,vector,&use.binding);
    if(use.admitted && (raw->operands[i].manual_representation_style_id || ins->render_instruction.operands[i].manual_representation_style_id)) {
      use.admitted=0;use.binding.reason="manual_operand_representation";
    }
    if(use.admitted && conflicts(s,ins->source_offset,(uint32_t)i,address,width,&use.source_overlap_disambiguated)) {use.admitted=0;use.binding.reason="ambiguous_address_binding";}
    if(use.admitted && m68k_platform_symbol_name_collides(base,use.binding.name)) {use.admitted=0;use.binding.reason="platform_namespace_collision";}
    if(!use.admitted && (!strcmp(use.binding.reason,"platform_namespace_collision") ||
        !strcmp(use.binding.reason,"ambiguous_address_binding"))) {
      ins->render_instruction.operands[i]=raw->operands[i];
      memset(&ins->render_instruction.operands[i].symbol_ref,0,sizeof(M68kSymbolRefIR));*changed=1;
    }
    if(use.admitted && use.source_overlap_disambiguated)use.binding.reason="bound_with_separate_source_and_runtime_identity";
    if(use.admitted) {
      M68kSymbolRefIR *symbol=&ins->render_instruction.operands[i].symbol_ref;
      uint8_t force=symbol->force_word_displacement;
      memset(symbol,0,sizeof(*symbol));symbol->force_word_displacement=force;symbol->has_name=1;symbol->kind=M68K_IR_SYMBOL_REF_ABS;
      snprintf(symbol->name,sizeof(symbol->name),"%s",use.binding.name);*changed=1;
    }
    if(use.admitted || strcmp(use.binding.reason,"no_supported_platform_address_contract"))if(append_use(p,&use))return -1;
  }
  return 0;
}
/* Text is used only to preserve the native row's comments and labels. */
static const char *comment_at(const char *a,const char *end) {
  char quote=0;
  for(const char *q=a;q<end;++q) {
    if(quote) {if(*q==quote) {if(q+1<end && q[1]==quote)++q;else quote=0;}}
    else if(*q=='\'' || *q=='"')quote=*q;
    else if(*q==';')return q;
  }
  return end;
}
/* Only native label-line metadata changes lexical scope. A qualified local
 * definition does not open a global scope in either assembler. */
static void line_scope(const M68kRenderPlanRow *row,unsigned line,const char *start,const char *end,char scope[64]) {
  if(!((line<32 && (row->label_line_mask&(1U<<line))) || row->kind==M68K_RENDER_PLAN_ROW_LABEL))return;
  const char *colon=memchr(start,':',(size_t)(end-start));
  if(!colon || start==colon || *start=='.' || memchr(start,'\\',(size_t)(colon-start)))return;
  size_t size=(size_t)(colon-start);scope[0]=0;
  if(size<64) {memcpy(scope,start,size);scope[size]=0;}
}
static void row_scope(const M68kRenderPlanRow *row,char scope[64]) {
  if(row->kind==M68K_RENDER_PLAN_ROW_SECTION)scope[0]=0;
  const char *cursor=row->text;unsigned line=0;
  while(*cursor) {
    const char *end=strchr(cursor,'\n');if(!end)end=cursor+strlen(cursor);
    line_scope(row,line++,cursor,end,scope);cursor=*end ? end+1 : end;
  }
}
static char *instruction_text(const M68kRenderPlanRow *row,const M68kRenderPlannedInstruction *ins,char scope[64]) {
  M68kRenderPolicy policy;JsonBuilder text={0};const char *cursor=row->text;unsigned line=0,rewritten=0;
  m68k_render_policy_init_default(&policy);policy.syntax.syntax_mode=M68K_IR_SYNTAX_VASM;
  M68kIrRenderResult rendered=m68k_ir_render_one_at_with_policy(&ins->render_instruction,ins->source_offset,&policy,m68k_diag_sink(NULL));
  if(!rendered.text[0] || json_builder_create(&text))return NULL;
  while(*cursor) {
    const char *end=strchr(cursor,'\n');if(!end)end=cursor+strlen(cursor);
    line_scope(row,line,cursor,end,scope);
    if((line<32 && (row->source_line_mask&(1U<<line)) && row->source_line_offsets[line]==row->source_offset) ||
        (!row->source_line_mask && row->line_count==1U && row->has_source_range &&
         row->source_size==ins->instruction.byte_count)) {
      const char *comment=comment_at(cursor,end);char scoped[sizeof(rendered.text)];
      m68k_render_ir_scoped_spelling(scope,rendered.text,scoped);
      if(json_builder_append(&text,"\t") || json_builder_append(&text,scoped) ||
          (comment<end && json_builder_append(&text,"\t")))goto fail;
      for(const char *q=comment;q<end;++q)if(json_builder_appendf(&text,"%c",*q))goto fail;
      ++rewritten;
    } else for(const char *q=cursor;q<end;++q)if(json_builder_appendf(&text,"%c",*q))goto fail;
    if(*end && json_builder_append(&text,"\n"))goto fail;
    cursor=*end ? end+1 : end;++line;
  }
  if(rewritten!=1)goto fail;
  char *result=json_builder_build(&text);json_builder_destroy(&text);return result;
fail:json_builder_destroy(&text);return NULL;
}
void m68k_platform_projection_destroy(M68kPlatformProjection *p) {
  if(!p)return;
  if(p->texts)for(size_t i=0;i<p->plan.row_count;++i)free(p->texts[i]);
  free(p->texts);free(p->rows);free(p->instructions);free(p->declarations);free(p->uses);
  for(size_t i=0;i<3;++i)free(p->headers[i]);
  memset(p,0,sizeof(*p));
}
int m68k_platform_projection_build(M68kPlatformProjection *p,const M68kRenderPlan *base,
    const M68kSourceAnalysisIR *analysis,uint32_t profiles,uint8_t inline_definitions) {
  if(!p)return -1;
  memset(p,0,sizeof(*p));p->profiles=profiles;p->inline_definitions=inline_definitions;
  p->reason="invalid_projection_request";
  if(!base || !analysis || !base->finalized || !profiles || (profiles&~7U))return -1;
  p->plan=*base;p->plan.row_count=base->row_count+1;
  p->rows=calloc(p->plan.row_count,sizeof(*p->rows));p->texts=calloc(p->plan.row_count,sizeof(*p->texts));
  p->instructions=malloc((base->instruction_count ? base->instruction_count : 1)*sizeof(*p->instructions));
  if(!p->rows || !p->texts || !p->instructions)return -1;
  if(base->row_count)memcpy(p->rows+1,base->rows,base->row_count*sizeof(*p->rows));
  if(base->instruction_count)memcpy(p->instructions,base->instructions,base->instruction_count*sizeof(*p->instructions));
  p->plan.rows=p->rows;p->plan.instructions=p->instructions;
  uint8_t *changed=calloc(base->instruction_count ? base->instruction_count : 1,1);if(!changed)return -1;
  for(size_t si=0;si<analysis->section_count;++si) {
    const M68kSectionAnalysisIR *s=&analysis->sections[si];ConstantState *input=NULL;
    if(states(base,s,(uint32_t)si,&input)) {free(changed);p->reason="constant_address_proof_did_not_converge";return -1;}
    for(size_t b=0;b<s->block_count;++b)if(input[b].seen) {
      ConstantState state=input[b];
      for(uint32_t at=s->blocks[b].start_offset;at<s->blocks[b].end_offset;) {
        const M68kRenderPlannedInstruction *original=m68k_render_plan_find_instruction(base,(uint32_t)si,at);
        if(!original || !original->instruction.byte_count)break;
        size_t index=(size_t)(original-base->instructions);int modified=0;
        if(project_instruction(p,base,s,&p->instructions[index],&state,&modified)) {free(input);free(changed);return -1;}
        changed[index]=(uint8_t)modified;step(&state,original);at+=(uint32_t)original->instruction.byte_count;
      }
    }
    free(input);
  }
  char scope[64]={0};
  for(size_t r=1;r<p->plan.row_count;++r) {
    if(p->rows[r].kind!=M68K_RENDER_PLAN_ROW_INSTRUCTION) {row_scope(&p->rows[r],scope);continue;}
    const M68kRenderPlannedInstruction *ins=m68k_render_plan_find_instruction(&p->plan,p->rows[r].source_section_index,p->rows[r].source_offset);
    if(!ins || !changed[ins-p->instructions]) {row_scope(&p->rows[r],scope);continue;}
    p->texts[r]=instruction_text(&p->rows[r],ins,scope);
    if(!p->texts[r]) {free(changed);p->reason="instruction_row_projection_refused";return -1;}
    p->rows[r].text=p->texts[r];p->rows[r].byte_count=strlen(p->texts[r]);p->rows[r].statement_instruction=ins->render_instruction;
  }
  free(changed);
  M68kPlatformSymbolBinding *definitions=malloc((p->use_count ? p->use_count : 1)*sizeof(*definitions));size_t count=0;
  if(!definitions)return -1;
  for(size_t i=0;i<p->use_count;++i)if(p->uses[i].admitted)definitions[count++]=p->uses[i].binding;
  JsonBuilder header={0};if(json_builder_create(&header)) {free(definitions);return -1;}
  static const char *paths[]={"platform/cpu-symbols.i","platform/amiga-custom-symbols.i","platform/st-mfp-symbols.i"};
  for(size_t i=0;i<3;++i) {
    if(m68k_platform_symbol_definitions_alloc(definitions,count,(uint8_t)(1U<<i),&p->headers[i])) {p->reason="conflicting_or_invalid_platform_definitions";free(definitions);json_builder_destroy(&header);return -1;}
    if(p->headers[i][0] && (inline_definitions ? json_builder_append(&header,p->headers[i]) :
        json_builder_appendf(&header,"    INCLUDE \"%s\"\n",paths[i]))) {free(definitions);json_builder_destroy(&header);return -1;}
  }
  if(base->declaration_count>SIZE_MAX/sizeof(*p->declarations)-count) {free(definitions);json_builder_destroy(&header);return -1;}
  p->declarations=calloc(base->declaration_count+count+1,sizeof(*p->declarations));
  if(!p->declarations) {free(definitions);json_builder_destroy(&header);return -1;}
  if(base->declaration_count)memcpy(p->declarations,base->declarations,base->declaration_count*sizeof(*p->declarations));
  p->plan.declarations=p->declarations;
  for(size_t i=0;i<count;++i) {
    int present=0;
    for(size_t j=base->declaration_count;j<p->plan.declaration_count;++j)
      if(!strcmp(p->declarations[j].name,definitions[i].name))present=1;
    if(present)continue;
    M68kRenderPlannedDeclaration *d=&p->declarations[p->plan.declaration_count++];
    d->kind=M68K_RENDER_PLANNED_DECLARATION_EQUATE;
    snprintf(d->name,sizeof(d->name),"%s",definitions[i].name);
    snprintf(d->expression,sizeof(d->expression),"$%08X",definitions[i].value);
    d->logical_address=definitions[i].value;
  }
  free(definitions);p->texts[0]=json_builder_build(&header);json_builder_destroy(&header);
  if(!p->texts[0])return -1;
  p->rows[0].kind=inline_definitions ? M68K_RENDER_PLAN_ROW_EQUATE : M68K_RENDER_PLAN_ROW_INCLUDE;
  p->rows[0].text=p->texts[0];p->rows[0].source_section_index=M68K_RENDER_PLAN_NO_SECTION;
  p->rows[0].byte_count=strlen(p->texts[0]);p->rows[0].id=base->next_row_id;
  p->plan.next_row_id=base->next_row_id+1;p->plan.row_capacity=p->plan.row_count;
  p->plan.total_bytes=0;p->plan.total_lines=0;
  for(size_t i=0;i<p->plan.row_count;++i) {
    M68kRenderPlanRow *row=&p->rows[i];row->start_byte=p->plan.total_bytes;row->start_line=p->plan.total_lines;
    row->byte_count=strlen(row->text ? row->text : "");row->line_count=0;
    for(size_t j=0;j<row->byte_count;++j)if(row->text[j]=='\n')++row->line_count;
    if(row->byte_count && row->text[row->byte_count-1]!='\n')++row->line_count;
    p->plan.total_bytes+=row->byte_count;p->plan.total_lines+=row->line_count;
  }
  p->reason="ok";return 0;
}
int m68k_platform_projection_json_alloc(const M68kPlatformProjection *p,const M68kObject *object,
    uint32_t minimum,char **out_text) {
  JsonBuilder json={0};char *package=NULL;int status=-1;
  static const char *paths[]={"platform/cpu-symbols.i","platform/amiga-custom-symbols.i","platform/st-mfp-symbols.i"};
  if(!p || !object || !out_text)return -1;
  *out_text=NULL;
  if(m68k_source_package_json_alloc(object,&p->plan,minimum,&package) || json_builder_create(&json))goto done;
  if(json_builder_append(&json,"{\"status\":\"ok\",\"package\":") || json_builder_append(&json,package) || json_builder_append(&json,",\"includes\":["))goto done;
  int emitted=0;
  for(size_t i=0;i<3;++i)if(!p->inline_definitions && p->headers[i] && p->headers[i][0]) {
    if((emitted++ && json_builder_append(&json,",")) || json_builder_append(&json,"{\"path\":") ||
        json_builder_append_json_string(&json,paths[i]) || json_builder_append(&json,",\"source_text\":") ||
        json_builder_append_json_string(&json,p->headers[i]) || json_builder_append(&json,"}"))goto done;
  }
  if(json_builder_append(&json,"],\"discovery_analysis_runs\":0,\"address_binding_projection_runs\":1,\"bindings\":["))goto done;
  for(size_t i=0;i<p->use_count;++i) {
    const M68kPlatformProjectedUse *u=&p->uses[i];const M68kPlatformSymbolBinding *b=&u->binding;
    if((i && json_builder_append(&json,",")) || json_builder_appendf(&json,"{\"section_index\":%u,\"source_offset\":%u,\"operand_index\":%u,\"address\":%u,\"encoded_value\":%u,\"base\":%u,\"admitted\":%s,\"relative\":%s,\"conditional\":%s,\"profile\":%u,\"name\":",
        u->section_index,u->offset,u->operand_index,b->address,b->value,u->base,u->admitted ? "true" : "false",b->relative ? "true" : "false",b->conditional ? "true" : "false",b->profile) ||
        json_builder_append_json_string(&json,b->name) || json_builder_append(&json,",\"reason\":") ||
        json_builder_append_json_string(&json,b->reason) || json_builder_appendf(&json,",\"source_overlap_disambiguated\":%s",u->source_overlap_disambiguated ? "true" : "false") || json_builder_append(&json,",\"provenance\":") ||
        (b->provenance ? json_builder_append_json_string(&json,b->provenance) : json_builder_append(&json,"null")) || json_builder_append(&json,"}"))goto done;
  }
  if(json_builder_append(&json,"]}"))goto done;
  *out_text=json_builder_build(&json);status=*out_text ? 0 : -1;
done:free(package);json_builder_destroy(&json);return status;
}

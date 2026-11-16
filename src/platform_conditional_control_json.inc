static int append_conditional_controls_json(JsonBuilder *builder, const M68kSectionAnalysisIR *section) {
  if (json_builder_appendf(builder, "],\"conditional_control_count\":%u,\"conditional_controls\":[",
        (unsigned)section->conditional_control_count) != 0) return -1;
  for (size_t ci=0; ci<section->conditional_control_count; ++ci) {
    const M68kConditionalControlIR *c=&section->conditional_controls[ci];
    size_t writers=0;
    for (size_t wi=0; wi<section->conditional_control_count; ++wi)
      if (c->operand_offset!=UINT32_MAX && section->conditional_controls[wi].operand_offset==c->operand_offset) ++writers;
    if (ci && json_builder_append(builder,",") != 0) return -1;
    if (json_builder_appendf(builder,
        "{\"writer_offset\":%u,\"write_address\":%u,\"write_size\":%u,\"admitted\":%s,",
        c->writer_offset,c->write_address,c->write_size,
        c->admitted?"true":"false") != 0) return -1;
    if (json_builder_append(builder,"\"operand_size\":") != 0) return -1;
    if (c->operand_offset==UINT32_MAX) {
      if (json_builder_append(builder,"null,\"observed_writers_to_operand\":null,") != 0) return -1;
    } else if (json_builder_appendf(builder,"%u,\"observed_writers_to_operand\":%u,",c->operand_size,(unsigned)writers) != 0) return -1;
    const char *names[]={"jump_offset","operand_offset","write_offset","target_offset","value_address","stored_target_address"};
    uint32_t values[]={c->jump_offset,c->operand_offset,c->write_offset,c->target_offset,c->value_address,c->stored_target_address};
    for (size_t k=0;k<6;k++) {
      if (json_builder_appendf(builder,"\"%s\":",names[k]) != 0) return -1;
      if ((k<4 && values[k]==UINT32_MAX) || (k==4 && !c->value_known) || (k==5 && !c->stored_target_known)) {
        if (json_builder_append(builder,"null,") != 0) return -1;
      } else if (json_builder_appendf(builder,"%u,",values[k]) != 0) return -1;
    }
    if (json_builder_appendf(builder,"\"kind\":\"%s\",", c->jump_offset==UINT32_MAX ? "numeric_code_address_store_candidate" : "absolute_jump_operand_installation") != 0) return -1;
    if (json_builder_appendf(builder,"\"conditional\":%s,",c->jump_offset==UINT32_MAX ? "null" : "true") != 0) return -1;
    if (json_builder_append(builder,"\"execution_proven\":false,\"installer_state_propagated\":false,\"writer_order_known\":false,\"writers_complete\":false,\"reason\":") != 0 ||
        json_builder_append_json_string(builder,c->reason) != 0) return -1;
    if (json_builder_append(builder,",\"condition\":") != 0) return -1;
    if (c->jump_offset==UINT32_MAX) {
      if (json_builder_append(builder,"null}") != 0) return -1;
    } else if (json_builder_append(builder,"\"writer path executed; stored opcode and installed value survive until transfer\"}") != 0) return -1;
  }
  return 0;
}

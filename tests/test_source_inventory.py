from amiga_reversing.disasm.source_inventory import source_inventory


def test_native_inventory_separates_raw_candidates_from_disconnected_accepted_code():
    section=dict(section_index=0,accepted_code_runs=[dict(start_offset=0,end_offset=4),dict(start_offset=8,end_offset=10)],
        range_ownerships=[],rendered_symbol_accesses=[
            dict(symbol_name='abs_0_00001008',target_offset=8,target_section_index=0,access_kind='label_statement'),
            dict(symbol_name='known',target_offset=0,target_section_index=0,access_kind='label_statement')],
        blocks=[dict(start_offset=0,end_offset=2),dict(start_offset=2,end_offset=4),dict(start_offset=8,end_offset=10)],
        edges=[dict(source_block_index=0,target_block_index=1)],code_start_refs=[],
        orphan_code_signals=[dict(offset=12,size=2)])
    a=source_inventory(dict(sections=[section]))
    assert a['counts']['generic_labels']==1
    assert a['counts']['disconnected_accepted_blocks']==1
    assert a['counts']['entry_connected_blocks']==2
    assert a['disconnected_components']==[[8]]
    assert a['counts']['raw_terminal_candidates']==1
    assert a['generic_labels'][0]['source_offset']==8 # native binding, not parsed label text
    assert a['blocks_without_inbound']==[8]
    section['code_start_refs']=[dict(evidence_kind='dispatch_table_control_target',source_section_index=0,source_offset=2,offset=8)]
    b=source_inventory(dict(sections=[section]))
    assert b['counts']['disconnected_accepted_blocks']==0
    assert b['counts']['raw_terminal_candidates']==1

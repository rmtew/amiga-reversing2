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
    for evidence in ('dispatch_table_control_target', 'initial_record_control_target'):
        section['code_start_refs']=[dict(evidence_kind=evidence,source_section_index=0,source_offset=2,offset=8)]
        b=source_inventory(dict(sections=[section]))
        assert b['counts']['disconnected_accepted_blocks']==0
        assert b['counts']['raw_terminal_candidates']==1


def test_vector_and_conditional_roots_do_not_change_ordinary_reachability():
    section=dict(section_index=0,accepted_code_runs=[dict(start_offset=0,end_offset=2),dict(start_offset=8,end_offset=12)],
        range_ownerships=[],rendered_symbol_accesses=[],symbol_origins=[],
        blocks=[dict(start_offset=0,end_offset=2),dict(start_offset=8,end_offset=10),dict(start_offset=10,end_offset=12)],
        edges=[dict(source_block_index=1,target_block_index=2)],
        code_start_refs=[dict(evidence_kind='vector_store_control_target',source_section_index=0,source_offset=0,offset=8)],
        conditional_controls=[dict(admitted=True,target_offset=10)],orphan_code_signals=[dict(offset=16,size=2)])
    result=source_inventory(dict(sections=[section]))
    assert result['schema']=='native-source-inventory/v2'
    assert result['counts']['entry_connected_blocks']==1
    assert result['counts']['disconnected_accepted_blocks']==2
    assert result['counts']['disconnected_asynchronous_blocks']==2
    assert result['counts']['disconnected_conditional_blocks']==1
    assert result['counts']['disconnected_unexplained_blocks']==0
    assert result['disconnected_component_records'][0]['causes']==['asynchronous_vector_entry','conditional_installation']
    assert result['counts']['raw_terminal_candidates']==1
    assert result['counting_policy']['ordinary_roots']==[dict(section_index=0,source_offset=0)]


def test_semantic_local_count_and_bindings_ignore_rendered_spelling():
    from copy import deepcopy
    section=dict(section_index=0,accepted_code_runs=[],range_ownerships=[],blocks=[],edges=[],code_start_refs=[],orphan_code_signals=[],
        rendered_symbol_accesses=[dict(symbol_name='owner\\.loop',target_offset=8,target_section_index=0,access_kind='label_statement')],
        symbol_origins=[dict(symbol_name='owner\\.loop',offset=8),dict(symbol_name='other\\.loop',offset=16),dict(symbol_name='owner\\.loop',offset=8)])
    qualified=source_inventory(dict(sections=[section]))
    bare=deepcopy(section);bare['rendered_symbol_accesses'][0]['symbol_name']='.loop'
    plain=source_inventory(dict(sections=[bare]))
    assert qualified['counts']['scoped_labels']==plain['counts']['scoped_labels']==2
    assert qualified['semantic_local_bindings']==plain['semantic_local_bindings']
    del bare['symbol_origins']
    assert source_inventory(dict(sections=[bare]))['counts']['scoped_labels']is None


def test_inventory_cli_reuses_native_snapshot_without_building_listing(tmp_path,monkeypatch):
    import hashlib,json,sys
    from amiga_reversing.tools import source_inventory as cli
    section=dict(section_index=0,accepted_code_runs=[],range_ownerships=[],blocks=[],edges=[],
        code_start_refs=[],orphan_code_signals=[],rendered_symbol_accesses=[],symbol_origins=[])
    path=tmp_path/'analysis.json';path.write_text(json.dumps(dict(sections=[section])))
    output=tmp_path/'inventory.json'
    def refuse(*args,**kwargs):raise AssertionError('offline inventory must not resolve/build a listing')
    monkeypatch.setattr(cli,'resolve_target_binary_source',refuse)
    monkeypatch.setattr(cli,'build_listing_artifact_profile_from_binary_source',refuse)
    monkeypatch.setattr(sys,'argv',['source_inventory','--target','starglider2_retail','--analysis-json',str(path),'--output',str(output)])
    cli.main()
    result=json.loads(output.read_text())
    assert result['snapshot_provenance']['sha256']==hashlib.sha256(path.read_bytes()).hexdigest()
    assert result['snapshot_provenance']['analyzer_identity']is None
    assert result['counts']['scoped_labels']==0

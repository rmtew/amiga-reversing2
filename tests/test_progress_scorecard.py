import copy
import hashlib
import json
import sys
import pytest
from amiga_reversing.disasm.progress_scorecard import build_scorecard, compare_scorecards, commit_delta


def inputs():
    section=dict(section_index=0,section_kind=1,section_size=24,
        accepted_code_runs=[dict(start_offset=0,end_offset=4),dict(start_offset=8,end_offset=10)],
        range_ownerships=[dict(start_offset=a,end_offset=b,status_name='accepted',kind_name=k,role=role)
            for a,b,k,role in [(0,4,'code',None),(8,10,'code',None),(12,14,'text','string'),
                              (14,22,'structured_data','bitmap'),(16,20,'structured_data',None)]],
        blocks=[dict(start_offset=0,end_offset=4),dict(start_offset=8,end_offset=10)],edges=[],
        rendered_symbol_accesses=[dict(symbol_name='abs_0_00001008',target_offset=8,target_section_index=0,access_kind='label_statement')],
        symbol_origins=[dict(symbol_name='owner\\.loop',offset=8)],
        code_start_refs=[dict(evidence_kind='vector_store_control_target',source_section_index=0,source_offset=0,offset=8)],
        conditional_controls=[],orphan_code_signals=[dict(offset=22,size=2)],
        recovered_platform_typed_accesses=[dict(offset=0,operand_index=0,root_struct_name='Child',owner_struct_name='Workspace',field_name='count',field_offset=0,field_size=2),
            dict(offset=0,operand_index=1,root_struct_name='Unrelated',owner_struct_name='Unrelated',field_name='count',field_offset=0,field_size=2)],
        recovered_platform_unresolved_typed_accesses=[dict(offset=2,operand_index=0,root_struct_name='Child',classification='field_gap'),
            dict(offset=8,operand_index=0,root_struct_name='Child',classification='type_conflict')])
    identity=dict(target='fixture',payload_sha256='a'*64,source_version='reviewed-source',analysis_sha256='b'*64,analyzer=dict(source_revision='reviewed-analyzer'))
    metadata=dict(custom_structs=[dict(name='Workspace'),dict(name='Child',base_struct='Workspace'),dict(name='Unrelated')])
    package=dict(manifest=dict(target_identity_sha256='a'*64,files=[dict(kind='asset',source_section_index=0,source_offset=14,size=4),dict(kind='asset',source_section_index=0,source_offset=18,size=4)]))
    return dict(sections=[section]),dict(identity=identity,metadata=metadata,package=package,workspace_roots=['Workspace'])


def card(**overrides):
    analysis,options=inputs();options.update(overrides)
    return build_scorecard(analysis,**options)


def metric(result,name):
    return result['metrics'][name]['value']


def test_duplicate_facts_and_overlapping_owners_do_not_inflate_progress():
    analysis,options=inputs();baseline=build_scorecard(analysis,**options)
    s=analysis['sections'][0]
    for key in ['range_ownerships','recovered_platform_typed_accesses','recovered_platform_unresolved_typed_accesses','symbol_origins']:
        s[key]*=2
    options['package']['manifest']['files']*=2
    repeated=build_scorecard(analysis,**options)
    assert repeated==baseline
    assert metric(repeated,'payload.unclassified_bytes')==8
    assert metric(repeated,'payload.unclassified_intervals')==3
    assert metric(repeated,'assets.incbin_bytes')==8
    assert metric(repeated,'assets.packaged_ranges')==2 # adjacent assets remain separate records
    assert metric(repeated,'typed.unresolved')==2
    assert repeated['metrics']['typed.unresolved']['denominator']==4
    assert metric(repeated,'workspace.resolved')==1 # same-offset unrelated owner excluded
    assert metric(repeated,'workspace.reported_conflicts')==1
    assert repeated['metrics']['workspace.unresolved']['denominator']==3
    assert metric(repeated,'control.disconnected_only_asynchronous_blocks')==1
    assert metric(repeated,'control.raw_terminal_candidates')==1


def test_unknown_eligibility_emission_and_missing_subset_are_not_zero():
    result=card(metadata=None,package=None)
    for key in ['workspace.unresolved','assets.incbin_bytes','assets.confirmed_inline_assets',
                'assets.candidate_ranges','text.confirmed_raw_bytes','text.suspected_plain_ranges','text.suspected_control_coded_ranges']:
        m=result['metrics'][key]
        assert m['status']=='unavailable' and m['value']is None and m['unavailable_reason']
    assert metric(result,'text.confirmed_bytes')==2 # text ownership does not prove raw emission
    assert card()['metrics']['assets.confirmed_bytes_not_packaged']['value']==0
    assert card()['metrics']['assets.confirmed_inline_eligible_bytes']['status']=='unavailable'


def test_missing_old_control_capability_remains_unavailable():
    analysis,options=inputs();del analysis['sections'][0]['conditional_controls']
    old=build_scorecard(analysis,**options);new=card()
    assert metric(old,'control.disconnected_conditional_blocks')is None
    comparison=compare_scorecards(old,new)
    assert comparison['comparable']
    assert any(r['measure']=='control.disconnected_conditional_blocks'for r in comparison['availability_changes'])
    assert 'availability' in commit_delta(comparison)


def test_comparison_rejects_different_payload_or_roots_and_keeps_workspace_domains_separate():
    before=card();after=copy.deepcopy(before)
    after['identity']['payload_sha256']='c'*64
    assert not compare_scorecards(before,after)['comparable']
    assert 'unavailable' in commit_delta(compare_scorecards(before,after))
    after=copy.deepcopy(before);after['counting_policy']['ordinary_roots'][0]['source_offset']=8
    assert not compare_scorecards(before,after)['comparable']
    after=card(workspace_roots=['Unrelated'])
    comparison=compare_scorecards(before,after)
    assert comparison['comparable'] and 'workspace.unresolved'in comparison['excluded_measures']


def test_changed_count_delta_and_deterministic_detail_preserve_unexplained_and_refusals():
    analysis,options=inputs();before=build_scorecard(analysis,**options)
    analysis['sections'][0]['range_ownerships'].append(dict(start_offset=22,end_offset=24,status_name='accepted',kind_name='structured_data',role=None))
    options['detail']=['all']
    first=build_scorecard(analysis,**options);second=build_scorecard(copy.deepcopy(analysis),**options)
    assert json.dumps(first,sort_keys=True)==json.dumps(second,sort_keys=True)
    assert 'payload.unclassified_bytes: 8 -> 6' in commit_delta(compare_scorecards(before,first))
    assert first['detail']['payload']['unclassified_intervals']==[[4,8],[10,12]]
    assert 'conditional_refusals' in first['detail']['control']
    assert 'detail'not in before


def test_bss_is_not_unclassified_file_payload():
    analysis,options=inputs();analysis['sections'][0]['section_kind']=3
    result=build_scorecard(analysis,**options)
    assert result['metrics']['payload.unclassified_bytes']['status']=='unavailable'


def test_scope_identity_does_not_follow_rendered_spelling():
    analysis,options=inputs();before=build_scorecard(analysis,**options)
    analysis['sections'][0]['rendered_symbol_accesses'][0]['symbol_name']='.loop'
    assert metric(build_scorecard(analysis,**options),'labels.semantic_locals')==metric(before,'labels.semantic_locals')==1


def test_mismatching_package_identity_is_not_zero_packaged_bytes():
    analysis,options=inputs();options['package']['manifest']['target_identity_sha256']='c'*64
    result=build_scorecard(analysis,**options)
    assert result['metrics']['assets.incbin_bytes']['status']=='unavailable'


def test_cli_uses_only_bound_snapshot_and_refuses_stale_provenance(tmp_path,monkeypatch,capsys):
    from amiga_reversing.tools import progress_scorecard as cli
    analysis,options=inputs();source=tmp_path/'analysis.json';source.write_text(json.dumps(analysis))
    identity=options['identity'];identity['analysis_sha256']=hashlib.sha256(source.read_bytes()).hexdigest()
    provenance=tmp_path/'identity.json';provenance.write_text(json.dumps(identity));output=tmp_path/'scorecard.json'
    args=['progress_scorecard','--analysis-json',str(source),'--provenance',str(provenance),'--output',str(output)]
    monkeypatch.setattr(sys,'argv',args);cli.main();first=output.read_bytes();cli.main();assert output.read_bytes()==first
    identity['analysis_sha256']='0'*64;provenance.write_text(json.dumps(identity))
    with pytest.raises(SystemExit):cli.main()
    assert 'analysis_sha256'in capsys.readouterr().err


def test_unidentified_snapshot_cannot_claim_comparable_progress():
    before=card();after=copy.deepcopy(before);after['identity']['analyzer']={}
    comparison=compare_scorecards(before,after)
    assert not comparison['comparable'] and 'analyzer identity'in comparison['reasons'][0]

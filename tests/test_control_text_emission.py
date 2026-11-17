"""Accepted control owners and native mappings constrain numeric-emission counts."""
from copy import deepcopy
import pytest
from amiga_reversing.disasm.control_text_emission import control_text_emission


def fixture():
    section=dict(section_index=0,section_size=16,range_ownerships=[dict(start_offset=4,end_offset=12,status_name='accepted',kind_name='text',role='string_control_stream')])
    def row(at,text,size,**extra):return dict(kind=10,source_section_index=0,source_offset=at,source_size=size,has_source_range=1,source_line_mask=0,line_ranges=[],text=text,**extra)
    plan=dict(sections=[dict(section_index=0,stored_size=16)],rows=[row(4,'\tdc.b $01,$20,$02,0 ; control\n',4),row(8,' dcb.b 4,$00\n',4)])
    return section,plan,row


def test_complete_numeric_owners_duplicate_and_overlap_are_counted_once():
    section,plan,row=fixture();expected=control_text_emission(section,plan)
    assert expected['known_numeric_bytes']==8 and expected['wholly_numeric_ranges']==1
    section['range_ownerships']*=2;plan['rows']*=2
    assert control_text_emission(section,plan)==expected
    section['range_ownerships'].append(dict(section['range_ownerships'][0],start_offset=6,end_offset=10))
    result=control_text_emission(section,plan)
    assert result['confirmed_bytes']==8 and result['known_numeric_bytes']==8 and result['confirmed_ranges']==2


@pytest.mark.parametrize('text,kind',[(" dc.b ' ',0,0,0\n",10),(' dc.b symbol,0,0,0\n',10),(' dc.b $01,$20\n',10),(' dc.b $01,$20,$02,0\n',9)])
def test_quoted_expression_wrong_extent_and_instruction_are_not_numeric_proof(text,kind):
    section,plan,row=fixture();plan['rows'][0]=row(4,text,4);plan['rows'][0]['kind']=kind
    result=control_text_emission(section,plan)
    assert result['known_numeric_bytes']==4 and result['unresolved_numeric_emission_bytes']==4
    assert not result['complete_numeric_emission_inventory']


def test_conflicting_rows_and_missing_mapping_stay_unknown():
    section,plan,row=fixture();plan['rows'].append(row(4,' dc.b $FF,$20,$02,0\n',4))
    result=control_text_emission(section,plan);assert result['known_numeric_bytes']==7 and result['unresolved_numeric_emission_bytes']==1
    plan['rows'][0]['has_source_range']=0;plan['rows'].pop()
    assert control_text_emission(section,plan)['known_numeric_bytes']==4


def test_explicit_line_maps_and_owner_interior_are_respected():
    section,plan,row=fixture();plan['rows']=[row(0,'label:\n dc.b 1,2,3,4\n dcb.b 4,0\n',0)]
    plan['rows'][0].update(source_line_mask=6,line_ranges=[[0,0,0],[4,4,0],[8,4,0]])
    assert control_text_emission(section,plan)['known_numeric_bytes']==8
    section['range_ownerships'][0].update(start_offset=5,end_offset=11)
    assert control_text_emission(section,plan)['known_numeric_bytes']==6


def test_missing_plan_is_unavailable_and_wrong_section_extent_is_refused():
    section,plan,row=fixture();assert control_text_emission(section,None)is None
    plan['sections'][0]['stored_size']=17
    with pytest.raises(ValueError,match='stored section'):control_text_emission(section,plan)


def test_scorecard_optional_plan_is_explicitly_unknown_and_never_global_raw_coverage():
    from tests.test_progress_scorecard import inputs
    from amiga_reversing.disasm.progress_scorecard import build_scorecard
    analysis,options=inputs();section=analysis['sections'][0]
    section['range_ownerships'].append(dict(start_offset=10,end_offset=14,status_name='accepted',kind_name='text',role='string_control_stream'))
    plan=dict(sections=[dict(section_index=0,stored_size=24)],rows=[dict(kind=10,source_section_index=0,source_offset=10,source_size=4,has_source_range=1,text=' dc.b 1,32,2,0\n')])
    missing=build_scorecard(analysis,**options);present=build_scorecard(analysis,source_plan=plan,detail=['text'],**options)
    assert missing['metrics']['text.control_stream_numeric_bytes']['status']=='unavailable'
    assert present['metrics']['text.control_stream_numeric_bytes']['value']==4
    assert present['metrics']['text.control_stream_unresolved_numeric_emission_bytes']['value']==0
    assert present['metrics']['text.confirmed_raw_bytes']['status']=='unavailable'
    assert present['detail']['text']['control_emission']['wholly_numeric_ranges']==1


def test_cli_binds_the_optional_plan_and_rejects_changed_plan(tmp_path):
    import hashlib,json,subprocess,sys
    from tests.test_progress_scorecard import inputs
    analysis,options=inputs();section=analysis['sections'][0]
    section['range_ownerships'].append(dict(start_offset=10,end_offset=14,status_name='accepted',kind_name='text',role='string_control_stream'))
    plan=dict(sections=[dict(section_index=0,stored_size=24)],rows=[dict(kind=10,source_section_index=0,source_offset=10,source_size=4,has_source_range=1,text=' dc.b 1,32,2,0\n')])
    def save(name,value):
        p=tmp_path/name;p.write_text(json.dumps(value));return p
    ap=save('analysis.json',analysis);pp=save('plan.json',plan);identity=options['identity']
    identity.update(analysis_sha256=hashlib.sha256(ap.read_bytes()).hexdigest(),source_plan_sha256=hashlib.sha256(pp.read_bytes()).hexdigest())
    ip=save('identity.json',identity)
    command=[sys.executable,'-m','amiga_reversing.tools.progress_scorecard','--analysis-json',str(ap),'--provenance',str(ip),'--source-plan-json',str(pp)]
    good=subprocess.run(command,check=True,capture_output=True,text=True)
    card=json.loads(good.stdout);assert card['metrics']['text.control_stream_numeric_bytes']['value']==4
    assert card['identity']['control_text_emission_implementation_sha256']
    pp.write_text('{}')
    bad=subprocess.run(command,capture_output=True,text=True)
    assert bad.returncode and 'Input identity mismatch: source_plan_sha256'in bad.stderr


def test_older_scorecard_missing_additive_measures_compares_as_unavailable():
    from tests.test_progress_scorecard import inputs
    from amiga_reversing.disasm.progress_scorecard import build_scorecard,compare_scorecards
    analysis,options=inputs();analysis['sections'][0]['range_ownerships'].append(dict(start_offset=10,end_offset=14,status_name='accepted',kind_name='text',role='string_control_stream'))
    old=build_scorecard(analysis,**options)
    for key in list(old['metrics']):
        if key.startswith('text.control_stream_'):old['metrics'].pop(key)
    plan=dict(sections=[dict(section_index=0,stored_size=24)],rows=[dict(kind=10,source_section_index=0,source_offset=10,source_size=4,has_source_range=1,text=' dc.b 1,32,2,0\n')])
    new=build_scorecard(analysis,source_plan=plan,**options);comparison=compare_scorecards(old,new)
    assert comparison['comparable']and not comparison['changed']and len(comparison['availability_changes'])==3
    assert all(r['before']=='unavailable'and not r['before_recorded']for r in comparison['availability_changes'])

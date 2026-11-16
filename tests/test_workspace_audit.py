"""Factoring an established owner family preserves phase and coordinate guards."""
from copy import deepcopy
import pytest
from amiga_reversing.disasm.workspace_audit import audit_owner_family,plan_owner_family_factoring


def layout():
    field=dict(name='shared',offset=4,size=4,type='LONG',value_kind='scalar')
    return [dict(name='Root',size=2,fields=[]),dict(name='A',base_struct='Root',base_offset=0,size=12,fields=[deepcopy(field)]),dict(name='B',base_struct='Root',base_offset=0,size=12,fields=[deepcopy(field)]),dict(name='Other',size=12,fields=[dict(field,name='unrelated')])]


def plan(structs):return plan_owner_family_factoring(structs,root='Root',owner_evidence=['s0:00000000:instruction'])


def test_same_owner_uses_lowest_common_ancestor_with_bounded_growth():
    structs=layout();before=deepcopy(structs);audit,commands=plan(structs)
    assert structs==before and len(commands)==3
    root=commands[0]['parameters'];assert root['name']=='Root'and root['size']==8
    assert root['fields'][0]['name']=='shared'
    assert all(c['parameters']['fields']==[]for c in commands[1:])
    assert audit['members']==['A','B','Root']
    assert 'Other'not in [c['parameters']['name']for c in commands]


@pytest.mark.parametrize('change',['phase','width','pointer','small'])
def test_overlap_pointer_and_descendant_extent_conflicts_remain_explicit(change):
    structs=layout();other=dict(name='C',base_struct='Root',base_offset=0,size=12,fields=[])
    if change=='small':other['size']=6
    else:
        f=deepcopy(structs[1]['fields'][0])
        if change=='phase':f['name']='different_phase'
        if change=='width':f['size']=2
        if change=='pointer':f.update(type='APTR',value_kind='struct_pointer',pointer_struct='Other')
        other['fields']=[f]
    structs.append(other);audit,commands=plan(structs)
    assert not commands and audit['duplicate_groups'][0]['status']=='conflicting_view'
    if change!='small':assert audit['overlapping_contracts']


def test_rebase_missing_owner_and_invalid_hierarchy_refuse():
    structs=layout();structs[1]['base_offset']=2
    assert audit_owner_family(structs,root='Root')['rebased_views']==['A']
    with pytest.raises(ValueError,match='rebased'):plan(structs)
    with pytest.raises(ValueError,match='owner evidence'):plan_owner_family_factoring(layout(),root='Root',owner_evidence=[])
    structs=layout();structs[0]['base_struct']='A'
    with pytest.raises(ValueError,match='cyclic'):plan(structs)


def test_lca_keeps_sibling_phase_private_and_catalogue_accepts_batch():
    from amiga_reversing.disasm.manual_action_catalog import target_catalog_manual_payload
    structs=layout();structs[0]['size']=12
    structs.append(dict(name='Parent',base_struct='Root',base_offset=0,size=12,fields=[]))
    for st in structs:
        if st['name']in ('A','B'):st['base_struct']='Parent'
    structs.append(dict(name='Phase',base_struct='Root',size=12,fields=[dict(name='other',offset=4,size=4,type='LONG')]))
    audit,commands=plan(structs)
    assert audit['duplicate_groups'][0]['host']=='Parent'
    assert len(commands)==3
    for c in commands:assert target_catalog_manual_payload(c['command_id'],parameters=c['parameters'])[0]=='create_manual_custom_struct'


def test_large_family_native_alias_cursor_and_exact_both_assemblers(tmp_path):
    from tests.test_app_cursor_propagation import cursor_artifact
    from amiga_reversing.disasm import c_backend
    from pathlib import Path
    import subprocess
    fields=[dict(name=f'word_{i}',offset=2*i,size=2,type='WORD',value_kind='scalar')for i in range(64)]
    structs=[dict(name='Root',size=2,fields=[])]+[dict(name=n,base_struct='Root',base_offset=0,size=128,fields=deepcopy(fields))for n in ['A','B']]
    _,commands=plan(structs);factored={s['name']:s for s in structs}
    for command in commands:factored[command['parameters']['name']]=command['parameters']
    observed=[]
    for index,view in enumerate([structs,list(factored.values())]):
        directory=tmp_path/str(index);directory.mkdir()
        artifact,raw=cursor_artifact(directory,'movea.l a0,a5\n lea.l 2(a5),a4\n move.w 124(a4),d0\n rts\n move.w 126(a0),d1\n rts',regions=False,
            metadata_extra=dict(custom_structs=view,seeded_code_entrypoints=[dict(hunk=0,addr=12,name='second')],
                entry_register_seeds=[dict(hunk=0,entry_offset=at,register='A0',kind='struct_ptr',struct_name=n,note='Fixture reviewed owner contract')for at,n in [(0,'A'),(12,'B')]]))
        try:
            section=artifact.analysis_payload()[0]['sections'][0]
            uses=[r for r in section['recovered_platform_typed_accesses']if r['field_name']=='word_63']
            assert len(uses)==2
            assert {r['owner_struct_name']for r in uses}==({'A','B'}if index==0 else{'Root'})
            observed.append({k:section[k]for k in ('blocks','edges','range_ownerships')})
            text=artifact.inline_source_text_with_profile()[0]
            assert c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',text)[0]==raw
            source=directory/'output.s';source.write_text(text);out=directory/'rebuilt.bin'
            vasm=Path(__file__).resolve().parents[1]/'tools/vasmm68k_mot.exe'
            subprocess.run([str(vasm),'-quiet','-Fbin','-m68000','-no-opt','-o',str(out),str(source)],check=True,capture_output=True)
            assert out.read_bytes()==raw
        finally:artifact.close()
    assert observed[0]==observed[1]


def test_native_field_capacity_is_reported_and_overflow_refuses_catalogue():
    from amiga_reversing.disasm.c_backend import custom_struct_field_capacity_with_c_backend
    from amiga_reversing.disasm.manual_action_catalog import target_catalog_manual_payload
    capacity=custom_struct_field_capacity_with_c_backend();assert capacity>=64
    fields=[dict(name=f'w{i}',offset=i*2,size=2,type='WORD')for i in range(capacity+1)]
    with pytest.raises(ValueError,match=f'at most {capacity} fields'):
        target_catalog_manual_payload('target.custom_struct.add',parameters=dict(name='TooMany',size=len(fields)*2,fields=fields))

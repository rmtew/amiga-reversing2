"""Explicit owner factoring preserves sparse and conflicting record views."""
from copy import deepcopy
import pytest
from amiga_reversing.disasm.shared_record_fields import plan_shared_prefix
from amiga_reversing.disasm.manual_action_catalog import target_catalog_manual_payload


def fixtures():
    field=dict(name='cursor',offset=4,size=4,type='LONG',value_kind='scalar')
    return [dict(name=n,size=12,fields=[deepcopy(field)])for n in ['A','B']]


def plan(structs, **kw):
    return plan_shared_prefix(structs,roots=['A','B'],offsets=[4],name='Shared',
        owner_evidence={'A':['s0:00000000:instruction'],'B':['s0:00000010:instruction']},**kw)


def test_same_owner_scalar_slots_become_one_declared_prefix_without_mutating_inputs():
    structs=fixtures();structs[1]['fields'][0]['type']='APTR';before=deepcopy(structs)
    commands=plan(structs)
    assert structs==before
    assert len(commands)==3
    assert commands[0]['parameters']['fields'][0]['type']=='LONG'
    for c in commands:
        kind,payload=target_catalog_manual_payload(c['command_id'],parameters=c['parameters'])
        assert kind=='create_manual_custom_struct'
        if c!=commands[0]:
            assert payload['custom_struct']['fields']==[]
            assert payload['custom_struct']['base_struct']=='Shared'
            assert payload['custom_struct']['size']==12


@pytest.mark.parametrize('change',['name','width','pointer','overlap','small_descendant','unknown_parent','cycle'])
def test_conflicting_phase_and_pointer_views_are_refused(change):
    structs=fixtures()
    if change=='name':structs[1]['fields'][0]['name']='different_phase'
    if change=='width':structs[1]['fields'][0]['size']=2
    if change=='pointer':structs[1]['fields'][0].update(type='APTR',value_kind='struct_pointer',pointer_struct='Object')
    if change=='overlap':structs.append(dict(name='C',size=12,base_struct='A',fields=[dict(name='overlay',offset=6,size=4,type='LONG')]))
    if change=='small_descendant':structs.append(dict(name='C',size=6,base_struct='A',fields=[]))
    if change=='unknown_parent':structs.append(dict(name='C',size=12,base_struct='Missing',fields=[]))
    if change=='cycle':structs.extend([dict(name='C',size=12,base_struct='D',fields=[]),dict(name='D',size=12,base_struct='C',fields=[])])
    with pytest.raises(ValueError):plan(structs)


def test_missing_owner_proof_and_equal_register_names_are_insufficient():
    with pytest.raises(ValueError,match='owner evidence'):
        plan_shared_prefix(fixtures(),roots=['A','B'],offsets=[4],name='Shared',owner_evidence={})


def test_factored_views_keep_address_binding_native_ownership_and_exact_bytes(tmp_path):
    from tests.test_app_cursor_propagation import cursor_artifact
    from amiga_reversing.disasm import c_backend
    import subprocess
    from pathlib import Path
    structs=fixtures()
    for st in structs:
        st['fields'][0].update(type='LONG',size=4)
    commands=plan(structs)
    factored={s['name']:s for s in structs}
    for command in commands:
        st=command['parameters'];factored[st['name']]=st
    observations=[]
    for index,view in enumerate((structs,list(factored.values()))):
        directory=tmp_path/str(index);directory.mkdir()
        artifact,raw=cursor_artifact(directory,'movea.l a0,a5\n lea.l 2(a5),a4\n move.l 2(a4),d0\n rts\n move.l 4(a0),d1',regions=False,
            metadata_extra=dict(custom_structs=view,
                seeded_code_entrypoints=[dict(hunk=0,addr=12,name='second')],
                entry_register_seeds=[dict(hunk=0,entry_offset=o,register='A0',kind='struct_ptr',struct_name=n,note='Fixture original owner contract')
                                      for o,n in [(0,'A'),(12,'B')]]))
        try:
            section=artifact.analysis_payload()[0]['sections'][0]
            uses=[r for r in section['recovered_platform_typed_accesses']if r['field_name']=='cursor']
            assert len(uses)==2
            assert {r['root_struct_name']for r in uses}=={'A','B'}
            assert {r['owner_struct_name']for r in uses}==({'A','B'}if index==0 else{'Shared'})
            observations.append({k:section[k]for k in ('blocks','edges','range_ownerships')})
            text=artifact.inline_source_text_with_profile()[0]
            rebuilt,_=c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',text)
            assert rebuilt==raw
            asm=directory/'output.s';asm.write_text(text);out=directory/'rebuilt.bin'
            vasm=Path(__file__).resolve().parents[1]/'tools/vasmm68k_mot.exe'
            subprocess.run([str(vasm),'-quiet','-Fbin','-m68000','-no-opt','-o',str(out),str(asm)],check=True,capture_output=True)
            assert out.read_bytes()==raw
        finally:artifact.close()
    assert observations[0]==observations[1]

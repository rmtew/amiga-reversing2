"""Scoped locals retain owner/address identity through actions, C and vasm."""
from pathlib import Path
import json
import subprocess
import pytest
from amiga_reversing.disasm import c_backend
from amiga_reversing.disasm.binary_source import BinarySourceKind,RawAddressModel,RawBinarySource
from amiga_reversing.disasm.target_metadata import TargetMetadata,write_target_metadata
from amiga_reversing.disasm.effective_metadata import effective_metadata_file,effective_target_metadata
from amiga_reversing.disasm.manual_actions import ManualActionKind,append_manual_actions
from amiga_reversing.disasm.manual_action_catalog import target_catalog_manual_payload

ROOT=Path(__file__).resolve().parents[1]
HEADER=' SECTION code,code\n ORG $1000\n'


def assemble_both(tmp_path,text,expected):
    assert c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',text)[0]==expected
    source=tmp_path/'input.s';source.write_text(text);out=tmp_path/'vasm.bin'
    subprocess.run([str(ROOT/'tools/vasmm68k_mot.exe'),'-quiet','-Fbin','-m68000','-no-opt',
                    '-o',str(out),str(source)],check=True,capture_output=True)
    assert out.read_bytes()==expected


def test_reused_forward_locals_and_qualified_cross_routine_reference(tmp_path):
    text=HEADER+'first:\n bra.b .done\n nop\n.done:\n rts\nsecond:\n bra.b .done\n nop\n.done:\n rts\nthird:\n bra.w first\\.done\n'
    assemble_both(tmp_path,text,bytes.fromhex('60024e714e7560024e714e756000fff6'))


def test_local_data_differences_quoted_text_and_register_aliases(tmp_path):
    text=HEADER+'first:\n dc.w .done-first\n dc.b ".x"\n.done:\n move.l sp,a0\n rts\n'
    assemble_both(tmp_path,text,bytes.fromhex('00042e78204f4e75'))


@pytest.mark.parametrize('body',[
    '.done:\n rts',
    'first:\n.done:\n rts\n.done:\n rts',
    'first:\n.done:\n rts\nsecond:\n bra.w .done',
])
def test_missing_owner_duplicate_or_crossed_scope_never_binds_another_local(body):
    with pytest.raises(RuntimeError):c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',HEADER+body+'\n')


def test_actions_project_locals_and_generated_qualified_definitions_roundtrip(tmp_path):
    raw=bytes.fromhex('60024e714e7560024e714e756000fff6')
    binary=tmp_path/'input.bin';binary.write_bytes(raw)
    source=RawBinarySource(kind=BinarySourceKind.RAW_BINARY,path=binary,address_model=RawAddressModel.RUNTIME_ABSOLUTE,
        load_address=0x1000,entrypoint=0x1000,code_start_offset=0,display_path=str(binary),analysis_cache_path=tmp_path/'analysis')
    (tmp_path/'source_binary.json').write_text(json.dumps(dict(kind='raw_binary',path=str(binary),address_model='runtime_absolute',load_address=0x1000,entrypoint=0x1000,code_start_offset=0)))
    write_target_metadata(tmp_path,TargetMetadata(target_type='program',entry_register_seeds=()))
    commands=[dict(hunk=0,addr=at,name=name)for at,name in [(0,'first'),(6,'second'),(12,'third')]]
    commands += [dict(hunk=0,addr=4,name='.done',scope='local',owner_offset=0),dict(hunk=0,addr=10,name='.done',scope='local',owner_offset=6)]
    actions=[]
    for params in commands:
        kind,payload=target_catalog_manual_payload('target.code_label.add',params)
        actions.append((ManualActionKind(kind),payload))
    append_manual_actions(tmp_path,binary_source=source,actions=actions)
    metadata=effective_target_metadata(tmp_path,binary_source=source)
    names={r.addr:r for r in metadata.seeded_code_labels}
    assert names[4].name=='first\\.done' and names[10].name=='second\\.done'
    assert 'scope_owner=s0:00000000:label' in names[4].source_locator
    with effective_metadata_file(tmp_path) as path:
        artifact=c_backend.build_listing_artifact_profile_from_binary_source(source,metadata_path=path)[2]
    try:
        text=artifact.inline_source_text_with_profile()[0]
        assert 'first\\.done:' in text and 'second\\.done:' in text
        assemble_both(tmp_path,text,raw)
    finally:artifact.close()
    # Save the projected snapshot, retain history, then rename both a local
    # and its global owner. Source coordinates, not old spellings, own scope.
    write_target_metadata(tmp_path, metadata)
    append_manual_actions(tmp_path,binary_source=source,actions=[
        (ManualActionKind.RENAME_MANUAL_LABEL,dict(label_id='catalog-code-label-h0-00000004',name='.finish')),
        (ManualActionKind.RENAME_MANUAL_LABEL,dict(label_id='catalog-code-label-h0-00000000',name='renamed_first'))])
    renamed=effective_target_metadata(tmp_path,binary_source=source)
    assert [r.name for r in renamed.seeded_code_labels if r.addr==4]==['renamed_first\\.finish']
    assert [r.name for r in renamed.seeded_code_labels if r.addr==0]==['renamed_first']
    with effective_metadata_file(tmp_path) as path:
        artifact=c_backend.build_listing_artifact_profile_from_binary_source(source,metadata_path=path)[2]
    try:
        text=artifact.inline_source_text_with_profile()[0]
        assert 'renamed_first\\.finish:' in text and 'second\\.done:' in text
        assemble_both(tmp_path,text,raw)
    finally:artifact.close()
    write_target_metadata(tmp_path, renamed)
    append_manual_actions(tmp_path,binary_source=source,actions=[
        (ManualActionKind.RENAME_MANUAL_LABEL,dict(label_id='catalog-code-label-h0-00000004',name='public_finish')),
        (ManualActionKind.CHANGE_LABEL_SCOPE,dict(label_id='catalog-code-label-h0-00000004',scope='global'))])
    promoted=effective_target_metadata(tmp_path,binary_source=source)
    assert [r.name for r in promoted.seeded_code_labels if r.addr==4]==['public_finish']
    with effective_metadata_file(tmp_path) as path:
        artifact=c_backend.build_listing_artifact_profile_from_binary_source(source,metadata_path=path)[2]
    try:assemble_both(tmp_path,artifact.inline_source_text_with_profile()[0],raw)
    finally:artifact.close()


@pytest.mark.parametrize('params',[
    dict(hunk=0,addr=4,name='.done'),
    dict(hunk=0,addr=4,name='.done',scope='local'),
    dict(hunk=0,addr=4,name='done',scope='local',owner_offset=0),
    dict(hunk=0,addr=4,name='.done',scope='local',owner_offset=6),
])
def test_catalog_requires_explicit_local_scope_and_earlier_owner(params):
    with pytest.raises(ValueError):target_catalog_manual_payload('target.code_label.add',params)


def test_qualified_absolute_control_and_register_named_local_are_symbols(tmp_path):
    text=HEADER+'first:\n jmp first\\.sp.l\n.sp:\n rts\n'
    assemble_both(tmp_path,text,bytes.fromhex('4ef9000010064e75'))


def test_invalid_owner_or_duplicate_pending_scope_is_atomic(tmp_path):
    binary=tmp_path/'input.bin';binary.write_bytes(bytes.fromhex('60024e714e7560024e714e75'))
    source=RawBinarySource(kind=BinarySourceKind.RAW_BINARY,path=binary,address_model=RawAddressModel.LOCAL_OFFSET,
        load_address=0,entrypoint=0,code_start_offset=0,display_path=str(binary),analysis_cache_path=tmp_path/'analysis')
    (tmp_path/'source_binary.json').write_text(json.dumps(dict(kind='raw_binary',path=str(binary),address_model='local_offset',load_address=0,entrypoint=0,code_start_offset=0)))
    write_target_metadata(tmp_path,TargetMetadata(target_type='program',entry_register_seeds=()))
    def action(**params):
        kind,payload=target_catalog_manual_payload('target.code_label.add',dict(hunk=0,**params))
        return ManualActionKind(kind),payload
    append_manual_actions(tmp_path,binary_source=source,actions=[action(addr=0,name='first'),action(addr=6,name='second')])
    before=(tmp_path/'manual_actions.jsonl').read_bytes()
    for bad in [[action(addr=4,name='.missing',scope='local',owner_offset=2)],
                [action(addr=4,name='.done',scope='local',owner_offset=0),action(addr=10,name='.done',scope='local',owner_offset=0)]]:
        with pytest.raises(ValueError):append_manual_actions(tmp_path,binary_source=source,actions=bad)
        assert (tmp_path/'manual_actions.jsonl').read_bytes()==before


def test_runtime_owner_id_cannot_be_reinterpreted_as_a_source_coordinate():
    from amiga_reversing.disasm.effective_metadata import _manual_label_to_code_label
    from amiga_reversing.disasm.manual_actions import ManualLabelScope
    owner=dict(label_id='runtime-owner',addr=0x1000,hunk=0,name='runtime_root',scope=ManualLabelScope.GLOBAL,address_domain='runtime')
    local=dict(label_id='local',addr=0x2000,hunk=0,name='.done',scope=ManualLabelScope.LOCAL,owner_id='runtime-owner')
    with pytest.raises(ValueError,match='source owner'):
        _manual_label_to_code_label(local,TargetMetadata(target_type='program',entry_register_seeds=()),[owner,local])


def test_runtime_local_annotation_requires_source_binding():
    from amiga_reversing.disasm.effective_metadata import _manual_label_to_absolute_code_label
    from amiga_reversing.disasm.manual_actions import ManualLabelScope
    with pytest.raises(ValueError,match='source-domain binding'):
        _manual_label_to_absolute_code_label(dict(addr=0x1004,name='.done',scope=ManualLabelScope.LOCAL,address_domain='runtime'))


def test_row_rename_uses_source_binding_and_preserves_explicit_local_scope():
    from amiga_reversing.disasm.manual_action_catalog import _row_label_payload,_label_validation_metadata
    row=dict(section_index=0,start_offset=4,end_offset=4,stable_key='s0:00000004:label')
    label=_row_label_payload(row,{'symbol':'abs_0_00001004'},dict(name='.done',scope='local',owner_offset=0))
    assert label['addr']==4 and label['address_domain']=='source'
    assert label['owner_offset']==0 and label['scope']=='local'
    assert label['label_id']=='catalog-code-label-h0-00000004'
    renamed=_row_label_payload(row,{'symbol':'first\\.done'},dict(name='.finish',owner_offset=0))
    assert renamed['scope']=='local' and renamed['name']=='.finish'
    with pytest.raises(ValueError):_row_label_payload(row,{'symbol':'first\\.done'},dict(name='unqualified_global'))
    ui=_label_validation_metadata({'symbol':'first\\.done'})
    assert ui['current_scope']=='local' and ui['current_name']=='.done'

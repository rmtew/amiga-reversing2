"""Installation evidence retains stored CFG, writer alternatives and unknowns."""
import subprocess
from pathlib import Path
import pytest
from amiga_reversing.disasm import c_backend
from tests.test_app_cursor_propagation import cursor_artifact


def fixture(tmp_path,installer,extra=None):
    prefix=installer+'\n rts\n'
    data,_=c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',' SECTION code,code\n ORG $1000\n'+prefix)
    assert len(data)<=128
    body=prefix+f' dcb.b {128-len(data)},0\nbank:\n jmp $10A0.l\n dcb.b 26,0\noriginal:\n moveq #1,d0\n rts\n dcb.b 28,0\nreplacement:\n move.l #$12345678,d0\n rts'
    metadata=dict(seeded_code_entrypoints=[dict(hunk=0,addr=128,name='bank'),dict(hunk=0,addr=192,name='replacement')])
    metadata.update(extra or {})
    return cursor_artifact(tmp_path,body,regions=False,metadata_extra=metadata)


def verify(artifact,raw,tmp_path):
    text=artifact.inline_source_text_with_profile()[0]
    assert c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',text)[0]==raw
    source=tmp_path/'output.s';source.write_text(text);out=tmp_path/'vasm.bin'
    vasm=Path(__file__).resolve().parents[1]/'tools/vasmm68k_mot.exe'
    subprocess.run([str(vasm),'-m68000','-no-opt','-Fbin','-quiet','-o',str(out),str(source)],check=True,capture_output=True)
    assert out.read_bytes()==raw


def test_absolute_long_operand_installation_is_conditional_and_exact(tmp_path):
    artifact,raw=fixture(tmp_path,'lea.l $1080.l,a0\n move.l #$10C0,2(a0)')
    try:
        s=artifact.analysis_payload()[0]['sections'][0];record,=s['conditional_controls']
        assert record['admitted'] and record['jump_offset']==128 and record['operand_offset']==130
        assert record['target_offset']==192 and record['stored_target_address']==0x10A0
        assert not record['execution_proven'] and not record['installer_state_propagated']
        assert not record['writer_order_known'] and not record['writers_complete']
        assert not any(e['source_offset']==record['writer_offset']and e['target_offset']==192 for e in s['edges'])
        assert raw[130:134]==bytes.fromhex('000010a0')
        verify(artifact,raw,tmp_path)
    finally:artifact.close()


def test_divergent_writers_are_distinct_not_a_last_writer_selection(tmp_path):
    artifact,raw=fixture(tmp_path,'tst.w d0\n beq.b other\n lea.l $1080.l,a0\n move.l #$10C0,2(a0)\n rts\nother:\n lea.l $1080.l,a0\n move.l #$10A0,2(a0)')
    try:
        rows=artifact.analysis_payload()[0]['sections'][0]['conditional_controls']
        assert len(rows)==2 and all(r['admitted']for r in rows)
        assert {r['target_offset']for r in rows}=={160,192}
        assert all(r['observed_writers_to_operand']==2 for r in rows)
        verify(artifact,raw,tmp_path)
    finally:artifact.close()


def test_unknown_later_write_is_retained_as_an_alternative(tmp_path):
    artifact,raw=fixture(tmp_path,'lea.l $1080.l,a0\n move.l #$10C0,2(a0)\n move.l d0,2(a0)')
    try:
        rows=artifact.analysis_payload()[0]['sections'][0]['conditional_controls']
        assert len(rows)==2 and sum(r['admitted']for r in rows)==1
        unknown=next(r for r in rows if not r['admitted'])
        assert unknown['value_address']is None and unknown['target_offset']is None
        assert unknown['reason']=='stored value is unknown'
        assert all(r['observed_writers_to_operand']==2 for r in rows)
        verify(artifact,raw,tmp_path)
    finally:artifact.close()


@pytest.mark.parametrize('store,reason',[
    ('move.w #$10C0,2(a0)','exactly cover'),
    ('move.b #$C0,3(a0)','exactly cover'),
    ('move.l #$10C0,(a0)','exactly cover'),
    ('move.l #$10C0,4(a0)','exactly cover'),
    ('move.l #$10C1,2(a0)','unaligned'),
    ('move.l #$10C2,2(a0)','instruction interior'),
    ('move.l #$1040,2(a0)','established instruction start'),
])
def test_partial_opcode_interior_and_unowned_targets_refuse(tmp_path,store,reason):
    artifact,raw=fixture(tmp_path,'lea.l $1080.l,a0\n '+store)
    try:
        rows=artifact.analysis_payload()[0]['sections'][0]['conditional_controls'];assert rows
        assert not any(r['admitted']for r in rows)
        assert any(reason in r['reason']for r in rows)
        verify(artifact,raw,tmp_path)
    finally:artifact.close()


@pytest.mark.parametrize('installer',[
    'lea.l $1080.l,a0\n movea.l a1,a0\n move.l #$10C0,2(a0)',
    'lea.l $1080.l,a0\n jsr $10A0.l\n move.l #$10C0,2(a0)',
])
def test_unknown_destination_and_call_clobber_never_guess(tmp_path,installer):
    artifact,raw=fixture(tmp_path,installer)
    try:
        assert not artifact.analysis_payload()[0]['sections'][0]['conditional_controls']
        verify(artifact,raw,tmp_path)
    finally:artifact.close()


def test_join_does_not_choose_one_divergent_value(tmp_path):
    artifact,raw=fixture(tmp_path,'tst.w d1\n beq.b other\n move.l #$10C0,d0\n bra.b join\nother:\n move.l #$10A0,d0\njoin:\n lea.l $1080.l,a0\n move.l d0,2(a0)')
    try:
        row,=artifact.analysis_payload()[0]['sections'][0]['conditional_controls']
        assert not row['admitted'] and row['value_address']is None
        assert row['reason']=='stored value is unknown'
        verify(artifact,raw,tmp_path)
    finally:artifact.close()


def test_known_invalid_value_is_not_rendered_as_unknown(tmp_path):
    artifact,raw=fixture(tmp_path,'lea.l $1080.l,a0\n move.l #$FFFFFFFF,2(a0)')
    try:
        row,=artifact.analysis_payload()[0]['sections'][0]['conditional_controls']
        assert not row['admitted'] and row['value_address']==0xFFFFFFFF
        verify(artifact,raw,tmp_path)
    finally:artifact.close()


@pytest.mark.parametrize('owned',['target','patch'])
def test_structured_ownership_is_never_decoded_or_promoted(tmp_path,owned):
    start,end=(192,200)if owned=='target'else(128,134)
    entries=[dict(hunk=0,addr=128,name='bank')]if owned=='target'else[dict(hunk=0,addr=192,name='replacement')]
    artifact,raw=fixture(tmp_path,'lea.l $1080.l,a0\n move.l #$10C0,2(a0)',dict(
        seeded_code_entrypoints=entries,
        seeded_entities=[dict(type='data',hunk=0,addr=start,end=end,unit='byte',name='owned_payload')]))
    try:
        s=artifact.analysis_payload()[0]['sections'][0]
        assert not any(r['admitted']for r in s['conditional_controls'])
        assert not any(r['start_offset']<=start<r['end_offset']for r in s['accepted_code_runs'])
        if owned=='target':assert any(r['reason']=='target has structured data ownership'for r in s['conditional_controls'])
        verify(artifact,raw,tmp_path)
    finally:artifact.close()


def test_competing_policy_view_never_chooses_smallest_binding(tmp_path):
    artifact,raw=fixture(tmp_path,'lea.l $1080.l,a0\n move.l #$10C0,2(a0)',dict(execution_views=[
        dict(source_start=0,source_end=202,base_addr=0x1000,name='identity'),
        dict(source_start=128,source_end=134,base_addr=0x2080,name='competing')]))
    try:
        rows=artifact.analysis_payload()[0]['sections'][0]['conditional_controls']
        assert rows and not any(r['admitted']for r in rows)
        assert any('competing'in r['reason']for r in rows)
        verify(artifact,raw,tmp_path)
    finally:artifact.close()


@pytest.mark.parametrize('installer',[
    'lea.l $1080.l,a0\n move.l $00C0.l,2(a0)',
    'move.l $00C0.l,d1\n lea.l $1080.l,a0\n move.l d1,2(a0)',
    'movea.l $0080.l,a0\n move.l #$10C0,2(a0)',
])
def test_memory_operand_address_is_never_its_loaded_value(tmp_path,installer):
    artifact,raw=fixture(tmp_path,installer)
    try:
        rows=artifact.analysis_payload()[0]['sections'][0]['conditional_controls']
        assert not any(r['admitted']for r in rows)
        assert all(r['value_address']is None for r in rows)
        verify(artifact,raw,tmp_path)
    finally:artifact.close()


def test_proven_register_address_transport_is_supported(tmp_path):
    artifact,raw=fixture(tmp_path,'lea.l $10C0.l,a1\n move.l a1,d1\n lea.l $1080.l,a0\n move.l d1,2(a0)')
    try:
        row,=artifact.analysis_payload()[0]['sections'][0]['conditional_controls']
        assert row['admitted']and row['target_offset']==192
        verify(artifact,raw,tmp_path)
    finally:artifact.close()


def test_numeric_code_match_in_raw_storage_is_only_a_candidate(tmp_path):
    artifact,raw=fixture(tmp_path,'move.l #$10C0,$1040.l')
    try:
        row,=artifact.analysis_payload()[0]['sections'][0]['conditional_controls']
        assert row['kind']=='numeric_code_address_store_candidate'
        assert not row['admitted'] and row['conditional']is None and row['condition']is None
        assert row['jump_offset']is None and row['operand_offset']is None
        assert row['operand_size']is None and row['observed_writers_to_operand']is None
        assert row['target_offset']==192
        verify(artifact,raw,tmp_path)
    finally:artifact.close()


def test_implicit_stack_pointer_effect_does_not_reuse_stale_destination(tmp_path):
    artifact,raw=fixture(tmp_path,'lea.l $1080.l,a7\n pea $00.l\n move.l #$10C0,2(a7)')
    try:
        assert not artifact.analysis_payload()[0]['sections'][0]['conditional_controls']
        verify(artifact,raw,tmp_path)
    finally:artifact.close()

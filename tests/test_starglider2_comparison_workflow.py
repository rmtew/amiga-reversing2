"""Cheap comparison guards plus opt-in original-CPU and model-layout fixtures."""
import json
import os
from pathlib import Path

import pytest
from amiga_reversing.tools import compare_starglider2 as comparison

ROOT=Path(__file__).resolve().parents[1]
SPEC=json.loads((ROOT/'targets/starglider2_retail/comparison_spec.json').read_text())

def test_snapshot_identity_tracks_content_and_backend_not_timestamps(tmp_path,monkeypatch):
    monkeypatch.delenv('AMIGA_C_BACKEND_DLL_ROOT',raising=False)
    target=tmp_path/'targets/test';target.mkdir(parents=True)
    meta=target/'target_metadata.json';meta.write_text('{}')
    first=comparison.annotation_identity(tmp_path,'test');meta.touch()
    assert comparison.annotation_identity(tmp_path,'test')==first
    meta.write_text('{"changed":true}')
    second=comparison.annotation_identity(tmp_path,'test');assert second!=first
    backend=tmp_path/'src/build/platform_file_lib.dll';backend.parent.mkdir(parents=True);backend.write_bytes(b'fixture')
    assert comparison.annotation_identity(tmp_path,'test')!=second
    local=comparison.annotation_identity(tmp_path,'test')
    other=tmp_path/'other';alternative=other/'src/build/platform_file_lib.dll'
    alternative.parent.mkdir(parents=True);alternative.write_bytes(b'other-backend')
    monkeypatch.setenv('AMIGA_C_BACKEND_DLL_ROOT',str(other))
    assert comparison.annotation_identity(tmp_path,'test')!=local

def test_exact_range_requires_both_direction_uniqueness():
    data=bytes(range(96));zero=bytearray(96)
    rows,_=comparison.unique_ranges(data,b'prefix!!'+data+b'!',zero,bytearray(105))
    assert rows==[(0,8,96)]
    rows,_=comparison.unique_ranges(data,data+data,zero,bytearray(192));assert rows==[]

def test_prefix_or_code_overlap_is_not_a_full_data_match():
    data=bytes(range(96));other=bytearray(data);other[64]^=1
    rows,_=comparison.unique_ranges(data,bytes(other),bytearray(96),bytearray(96))
    assert not any(x<=64<x+n for x,y,n in rows)
    rows,_=comparison.unique_ranges(data,data,bytearray(96),bytearray(b'\1'*96));assert rows==[]

def row(immediate=7,register='D0',width=2):
    return dict(source_offset=0,mnemonic='move',text='move.w',size=4,
                operand_facts=[dict(operand_index=0,access='immediate',width_bytes=width,immediate_value=immediate),
                               dict(operand_index=1,access='register_write',width_bytes=width,direct_register=register)])

def test_normalisation_does_not_erase_constants_registers_or_widths():
    original=comparison.operation_form(row(),{}, {},None)
    assert original!=comparison.operation_form(row(immediate=6),{}, {},None)
    assert original!=comparison.operation_form(row(register='D1'),{}, {},None)
    assert original!=comparison.operation_form(row(width=1),{}, {},None)

def test_native_code_data_overlap_is_refused():
    data=b'12345678';facts=dict(instructions=[dict(section_index=0,source_offset=0,size=4,bytes=data[:4].hex())],
        ownership=[dict(status_name='accepted',kind_name='structured_data',start_offset=2,end_offset=8)])
    with pytest.raises(ValueError,match='overlap'):comparison.masks(data,facts)

def test_spec_keeps_code_data_tiers_and_release_identities_separate():
    counts={str(k):sum(n for x,y,n,kind in SPEC['code_ranges'] if kind==k) for k in (1,2,3)}
    assert counts=={'1':60514,'2':3600,'3':52}
    assert SPEC['frozen']['code_bytes']==64166
    assert SPEC['frozen']['exact_nonpadding_noncode_bytes']==236000
    assert SPEC['frozen']['typed_data_correspondence_bytes']==13080
    assert sum(n for x,y,n,k in SPEC['typed_data_extra_ranges'])==735
    assert [p['bytes'] for p in SPEC['payloads']]==[412736,419308]

fixtures=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='bind hash-pinned main inputs and set SGII_LINKED_FIXTURES=1')
def images():
    from amiga_reversing.disasm.game_catalog import load_family,materialize
    family=load_family(ROOT,'starglider2')
    return [materialize(ROOT,'starglider2',family['targets'][t]['artifact']).read_bytes() for t in comparison.TARGETS]

@fixtures
def test_st_model_source_extents_and_symbolic_pointer_rendering():
    _,data=images();headers=set();coordinates=set();vertices=set()
    for index in range(104):
        h=int.from_bytes(data[102964+4*index:102968+4*index],'big')-4096;headers.add(h)
        words=int.from_bytes(data[h+4:h+6],'big');count=int.from_bytes(data[h:h+2],'big')+1
        p=int.from_bytes(data[h+14:h+18],'big')-4096;v=int.from_bytes(data[h+10:h+14],'big')-4096
        assert 0<p<p+2*words<=len(data) and 0<v<v+8*count<=len(data)
        coordinates.update(range(p,p+2*words));vertices.update(range(v,v+8*count))
    assert len(headers)==103 and len(coordinates)==6046 and len(vertices)==12560
    assert not coordinates&vertices
    source=(Path(os.environ['SGII_RETAIL_RENDERED_SOURCE'])).read_text()
    assert 'dc.l model_type_000_coordinate_words' in source
    assert 'dc.l model_type_000_vertex_reference_records' in source
    assert 'dc.l model_type_000_header' in source
    assert 'st_plane_interleave_source_words' in source and 'type37_spawn_attempt_count' in source

@fixtures
@pytest.mark.parametrize('gate,initial,quota',[(0,7,2),(128,0,2),(128,1,2),(128,2,2),(128,65535,2),(128,32766,32767),(128,32767,2),(128,65534,65535)])
def test_original_type37_counter_preserves_word_gate_and_bpl_overflow(gate,initial,quota):
    from amiga_reversing.disasm.mapped_execution import MappedExecution
    outcomes=[]
    updated=(initial+1)&65535 if gate&128 else initial
    admitted=bool(gate&128) and not ((quota-updated)&0x8000)
    for data,entry,counter in zip(images(),(0x18140,0x19a00),(0x18950,0x1a210)):
        cpu=MappedExecution(0x80000,project_root=ROOT,register_seed=0xdeadbeef)
        cpu.seed(4096,data);cpu.seed(0x70000,bytes(4096));cpu.cpu.a[6]=0x70000;cpu.cpu.a[7]=0x76000
        cpu.seed(0x70a7c,bytes((gate,)));cpu.seed(0x70a7a,quota.to_bytes(2,'big'))
        cpu.seed(counter,initial.to_bytes(2,'big')+b'\x77\x88');cpu.allow_write(counter,2);cpu.allow_write(0x75fc0,64)
        trace=cpu.run(entry,entry+(32 if admitted else 28),16)
        assert int.from_bytes(cpu.read(counter,2),'big')==updated
        assert cpu.read(counter+2,2)==b'\x77\x88'
        outcomes.append((updated,admitted,trace['steps']))
    assert outcomes[0]==outcomes[1]

@fixtures
def test_original_reset_touches_counter_not_adjacent_orbit_offset():
    from amiga_reversing.disasm.mapped_execution import MappedExecution
    for data,entry,counter in zip(images(),(0x17db0,0x19670),(0x18950,0x1a210)):
        cpu=MappedExecution(0x80000,project_root=ROOT);cpu.seed(4096,data)
        cpu.seed(counter,b'\x00\x7b\x77\x88');cpu.allow_write(counter,2)
        cpu.run(entry,entry+6,2);assert cpu.read(counter,4)==b'\0\0\x77\x88'

@fixtures
def test_original_st_plane_converter_matches_every_bounded_source_byte():
    from amiga_reversing.disasm.mapped_execution import MappedExecution
    _,data=images();lo,hi=0x4f426,0x53dc6;source=data[lo:hi]
    expected=bytearray()
    for offset in range(0,len(source),4):
        a=int.from_bytes(source[offset:offset+2],'big')
        b=int.from_bytes(source[offset+2:offset+4],'big')
        result=0
        for bit in range(15,-1,-1):
            result=(result<<2)|(((a>>bit)&1)<<1)|((b>>bit)&1)
        expected.extend(result.to_bytes(4,'big'))
    cpu=MappedExecution(0x80000,project_root=ROOT,register_seed=0xdeadbeef)
    cpu.seed(0x3bd9c,data[0x3ad9c:0x3adee]);cpu.seed(lo+4096,source)
    cpu.allow_write(lo+4096,len(source))
    trace=cpu.run(0x3bd9c,0x3bdee,600000)
    assert cpu.read(lo+4096,len(source))==expected
    assert trace['steps']==558379

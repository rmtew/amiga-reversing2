"""Counted model streams and bounded execution of their original ST consumers."""
import os
from pathlib import Path

import pytest

from amiga_reversing.tools.compare_starglider2 import face_stream,model_streams

ROOT=Path(__file__).resolve().parents[1]
fixtures=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='Requires the two catalogue-bound SGII main payloads')


def test_face_count_and_arity_do_not_use_a_source_terminator():
    data=bytes.fromhex('8301000000080010ffff')
    parsed=face_stream(data,0,1,3)
    assert parsed['end']==8 and parsed['records'][0]['vertices']==[0,8,16]
    with pytest.raises(ValueError):face_stream(data,0,2,3)
    with pytest.raises(ValueError,match='Truncated'):face_stream(data[:7],0,1,3)
    with pytest.raises(ValueError,match='vertex offset'):face_stream(bytes.fromhex('820100010008'),0,1,2)
    with pytest.raises(ValueError,match='zero/one'):face_stream(bytes.fromhex('8001'),0,1,1)


def test_main_and_extra_consumers_have_different_arity_masks():
    data=bytes.fromhex('8801')+bytes(16)
    with pytest.raises(ValueError,match='zero/one'):face_stream(data,0,1,1)
    assert len(face_stream(data,0,1,1,extra=True)['records'][0]['vertices'])==8


def inputs():
    from amiga_reversing.disasm.game_catalog import load_family,materialize
    family=load_family(ROOT,'starglider2')
    targets=('amiga_raw_starglider2_game','starglider2_retail')
    return [materialize(ROOT,'starglider2',family['targets'][t]['artifact']).read_bytes() for t in targets]


def run_main_consumer(data,stream,*,all_visible=True,truncate=False):
    from amiga_reversing.disasm.mapped_execution import MappedExecution
    cpu=MappedExecution(0x80000,project_root=ROOT,register_seed=0xdeadbeef)
    cpu.seed(0x4b6c,data[0x3b6c:0x3ca2]);start,end=stream['start'],stream['end']
    cpu.seed(start+4096,data[start:end-(2 if truncate else 0)])
    cpu.seed(0x70000,bytes(4096));cpu.allow_write(0x70000,4096);cpu.cpu.a[6]=0x70000
    cpu.seed(0x701f0,bytes([int(all_visible)]));cpu.seed(0x70756,b'\0\1')
    cpu.seed(0x58bc,b'\0\0');cpu.seed(0x52d6,b'\0\0');cpu.allow_write(0x52d6,2)
    cpu.seed(0xe145,b'\0');cpu.allow_write(0xe145,1)
    cpu.seed(0x60000,bytes(8192));cpu.allow_write(0x60000,8192)
    cpu.seed(0x63000,bytes(8192));cpu.allow_write(0x63000,8192)
    cpu.seed(0x7ee00,bytes(512));cpu.allow_write(0x7ee00,512)
    cpu.cpu.a[0]=0x60000;cpu.cpu.a[4]=start+4096;cpu.cpu.a[5]=0x63000;cpu.cpu.a[7]=0x7f000
    cpu.cpu.d[0]=stream['count']-1
    trace=cpu.run(0x4b6c,0x4ca2,20000)
    assert cpu.cpu.a[4]==end+4096
    expected=bytearray();selected=0
    for record in stream['records']:
        if not all_visible and not record['header']&32768:continue
        selected+=1;color=record['header']&255
        expected.extend((color if color<128 else color+65280).to_bytes(2,'big'))
        for value in record['vertices']:expected.extend(value.to_bytes(2,'big'))
        expected.extend(b'\xff\xff')
    assert cpu.cpu.a[5]==0x63000+len(expected)
    assert cpu.read(0x63000,len(expected))==expected
    assert int.from_bytes(cpu.read(0x52d6,2),'big')==selected
    return trace


def run_extra_consumer(data,stream):
    from amiga_reversing.disasm.mapped_execution import MappedExecution
    cpu=MappedExecution(0x80000,project_root=ROOT,register_seed=0xdeadbeef)
    cpu.seed(0x50f2,data[0x40f2:0x42c4]);start,end=stream['start'],stream['end']
    cpu.seed(start+4096,data[start:end]);cpu.seed(0x70000,bytes(4096));cpu.allow_write(0x70000,4096)
    cpu.cpu.a[6]=0x70000;cpu.seed(0x49c0,b'\0\0');cpu.allow_write(0x49c0,2)
    work=bytearray(8192)
    for offset in range(0,len(work),8):work[offset:offset+8]=bytes.fromhex('001100220033fedc')
    cpu.seed(0x60000,work);cpu.seed(0x63000,bytes(8192));cpu.allow_write(0x63000,8192)
    cpu.seed(0x66000,bytes(512));cpu.allow_write(0x66000,512)
    cpu.cpu.a[0]=0x60000;cpu.cpu.a[3]=0x66000;cpu.cpu.a[4]=0x63000;cpu.cpu.a[5]=start+4096
    cpu.cpu.d[0]=stream['count']-1
    trace=cpu.run(0x50f2,0x52c4,10000)
    expected=b''.join(bytes.fromhex('7fe00000')+bytes.fromhex('00110022')*len(r['vertices'])+b'\xff\xff' for r in stream['records'])
    assert cpu.cpu.a[5]==end+4096 and cpu.read(0x63000,len(expected))==expected
    assert cpu.cpu.a[3]==0x66000+4*stream['count']
    return trace


@fixtures
def test_all_st_stored_face_bounds_against_both_original_consumer_paths():
    a,b=inputs();amiga,st=model_streams(a,96628),model_streams(b,102964)
    assert len(st)==103 and st[0]['ordinals']==[0,1]
    total=0;records=0;extra=0
    for left,right in zip(amiga,st):
        for kind in ('main','extra'):
            if kind not in right:continue
            x,y=left[kind],right[kind]
            assert a[x['start']:x['end']]==b[y['start']:y['end']]
            total+=y['end']-y['start'];records+=y['count']
            if kind=='main':
                run_main_consumer(b,y);run_main_consumer(b,y,all_visible=False)
            else:run_extra_consumer(b,y);extra+=1
    assert total==14438 and records==1630 and extra==45
    with pytest.raises(ValueError,match='unknown read/fetch'):
        run_main_consumer(b,st[0]['main'],truncate=True)


def select_variant(data,header,selector):
    from amiga_reversing.disasm.mapped_execution import MappedExecution
    cpu=MappedExecution(0x80000,project_root=ROOT,register_seed=0xdeadbeef)
    cpu.seed(0x4a7e,data[0x3a7e:0x3a9c]);cpu.seed(header+4096+18,data[header+18:header+22])
    table=int.from_bytes(data[header+18:header+22],'big')
    if selector==1 and table:cpu.seed(table,data[table-4096:table-4096+4])
    cpu.seed(0x70000,bytes(4096));cpu.allow_write(0x70000,4096)
    cpu.seed(0x60003,bytes([selector]));cpu.cpu.a[4]=0x60000;cpu.cpu.a[6]=0x70000;cpu.cpu.a[0]=header+4096+18
    cpu.run(0x4a7e,0x4a9c,20)
    return int.from_bytes(cpu.read(0x70024,4),'big')


def read_variant_triple(data,view,offset,*,truncate=False):
    from amiga_reversing.disasm.mapped_execution import MappedExecution
    cpu=MappedExecution(0x80000,project_root=ROOT,register_seed=0xdeadbeef)
    cpu.seed(0x4cb4,data[0x3cb4:0x3cd4]);cpu.seed(0x60000,b'\0'*6+b'\x80\0')
    cpu.seed(0x61000,b'\x00\x11\x00\x22\x00\x33'+offset.to_bytes(2,'big',signed=True))
    cpu.seed(0x70024,(view['start']+4096).to_bytes(4,'big'))
    cpu.seed(view['start']+4096,data[view['start']:view['end']-(1 if truncate else 0)])
    cpu.cpu.a[3]=0x60000;cpu.cpu.a[4]=0x61000;cpu.cpu.a[6]=0x70000
    cpu.run(0x4cb4,0x4cd4,20)
    values=[cpu.cpu.d[i]&65535 for i in (1,2,3)]
    expected=[int.from_bytes(data[view['start']+offset+i:view['start']+offset+i+2],'big') for i in (0,2,4)] if offset>=0 else [17,34,51]
    assert values==expected


@fixtures
def test_first_variant_pointer_and_complete_reference_read_footprints():
    a,b=inputs();amiga,st=model_streams(a,96628),model_streams(b,102964);count=0;size=0
    for left,right in zip(amiga,st):
        if 'variant_first' not in right:
            assert select_variant(b,right['header'],0)==0
            assert select_variant(b,right['header'],1)==0
            continue
        count+=1;x=left['variant_first'];y=right['variant_first'];size+=y['end']-y['start']
        assert a[x['start']:x['end']]==b[y['start']:y['end']]
        assert select_variant(b,right['header'],0)==0
        assert select_variant(b,right['header'],1)==y['start']+4096
        for offset in y['offsets']:read_variant_triple(b,y,offset)
        read_variant_triple(b,y,-1)
    assert count==33 and size==2398
    view=st[0]['variant_first']
    with pytest.raises(ValueError,match='unknown read/fetch'):read_variant_triple(b,view,max(view['offsets']),truncate=True)
    # Selector 2 must not succeed with only the proved one-entry prefix seeded.
    with pytest.raises(ValueError,match='unknown read/fetch'):select_variant(b,st[0]['header'],2)

"""Bounded gameplay selector producers, rather than model-viewer assumptions."""
import os
from functools import cache
import pytest
from test_starglider2_retail_model_headers import image
from amiga_reversing.disasm.mapped_execution import MappedExecution
from amiga_reversing.tools.compare_starglider2 import model_streams,bounded_variants

pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail inputs')
# type, original first-phase entry, post-selector continuation, threshold, rule
CYCLES=((7,0x8bf4,0x8c1e,24,'negative'),(18,0x8bc6,0x901c,24,'equal'),
        (27,0x8c08,0x8c1e,40,'equal'),(35,0x8be0,0x8c1e,23,'negative'),
        (41,0x8a40,0x901c,20,'equal'),(49,0x89d4,0x81e6,12,'equal'))
ACTOR,APP,STACK,RETURN=0x60000,0x70000,0xf0000,0xff000

@cache
def shared_bytes():
    st,amiga=image('st'),image('amiga')
    assert st[:2]==amiga[:2] and st[3:]==amiga[3:] and st[2]==0 and amiga[2]==128
    return st  # These tested instructions are identical; run each case once.

def machine(kind):
    d=shared_bytes();c=MappedExecution(0x100000,register_seed=0xdeadbeef);c.seed(0x1000,d)
    c.seed(APP,bytes(0x3000));c.allow_write(APP,0x3000)
    c.seed(ACTOR,kind.to_bytes(2,'big')+bytes(66));c.allow_write(ACTOR,68)
    c.seed(0x61000,bytes(68));c.seed(APP+0x700,(0x61000).to_bytes(4,'big'))
    c.seed(STACK,RETURN.to_bytes(4,'big'));c.allow_write(STACK-256,256);c.allow_write(0xe145,1)
    c.cpu.a[0]=ACTOR;c.cpu.a[3]=0x195cc;c.cpu.a[4]=0x18b8e;c.cpu.a[6]=APP;c.cpu.a[7]=STACK;c.cpu.d[0]=kind
    return c

@cache
def qualified_model(kind):
    d=shared_bytes();m=next(m for m in model_streams(d,0x19234) if kind in m['ordinals'])
    return m,bounded_variants(d,m,0xdcee)

def select(c,kind):
    """Execute the original pointer consumer with only its proved table mapped."""
    d=shared_bytes();m,p=qualified_model(kind);selector=c.read(ACTOR+3,1)[0]
    reader=MappedExecution(0x100000,register_seed=0xdeadbeef)
    reader.seed(0x4a7e,d[0x3a7e:0x3a9c]);reader.seed(m['header']+4096+18,d[m['header']+18:m['header']+22])
    table=m['variant_first']['table'];reader.seed(table+4096,d[table:table+4*len(p['views'])])
    reader.seed(ACTOR+3,bytes([selector]));reader.seed(APP+0x24,bytes(4));reader.allow_write(APP+0x24,4)
    reader.cpu.a[0]=m['header']+4096+18;reader.cpu.a[4]=ACTOR;reader.cpu.a[6]=APP
    reader.run(0x4a7e,0x4a9c,20);pointer=int.from_bytes(reader.read(APP+0x24,4),'big')
    if selector:assert pointer==next(v['start']+4096 for v in p['views'] if v['selector']==selector)
    else:assert pointer==0

@pytest.mark.parametrize('kind,start,stop,threshold,rule',CYCLES)
def test_all_byte_states_follow_the_actual_cycle_comparison(kind,start,stop,threshold,rule):
    c=machine(kind);d=shared_bytes()
    assert 0x803e+int.from_bytes(d[0x703e+2*kind:0x7040+2*kind],'big',signed=True)==start
    for value in range(256):
        c.seed(ACTOR+3,bytes([value]));c.cpu.a[0]=ACTOR;c.run(start,stop,12)
        incremented=(value+1)&255
        # BMI tests N alone, unlike BLT's N xor V signed relation.
        reset=not ((incremented-threshold)&128) if rule=='negative' else incremented==threshold
        expected=0 if reset else incremented
        assert c.read(ACTOR+3,1)[0]==expected
    # Normal states are closed and all selected pointers fit the qualified table.
    for value in range(threshold):
        c.seed(ACTOR+3,bytes([value]));c.cpu.a[0]=ACTOR;c.run(start,stop,12)
        assert c.read(ACTOR+3,1)[0]<threshold;select(c,kind)
    # No rule should be described as a universal unsigned clamp.
    c.seed(ACTOR+3,b'\xb0');c.cpu.a[0]=ACTOR;c.run(start,stop,12)
    assert c.read(ACTOR+3,1)==b'\xb1'
    with pytest.raises(ValueError,match='unknown read/fetch'):select(c,kind)

@pytest.mark.parametrize('kind,threshold',[(18,24),(41,20),(49,12)])
def test_fresh_initializer_and_both_dispatch_phases_preserve_selected_cycles(kind,threshold):
    c=machine(kind);c.run(0x19728,0x1974c,200)
    assert c.read(ACTOR+3,1)==bytes(1) and c.read(ACTOR+0x1e,1)==b'\xff'
    seen={0};select(c,kind)
    for _ in range(threshold*2):
        c.cpu.a[0]=ACTOR;c.run(0x8002,0x81e6,3000);select(c,kind)
        before=c.read(ACTOR+3,1);c.cpu.a[0]=ACTOR;c.run(0x8210,0x83b0,3000)
        assert c.read(ACTOR+3,1)==before and c.read(ACTOR,2)==kind.to_bytes(2,'big')
        seen.add(before[0])
    assert seen==set(range(threshold))

def test_type65_mode_one_selects_final_variant_and_other_modes_cycle_six():
    c=machine(65);c.run(0x19728,0x1974c,100);assert c.read(ACTOR+3,1)==bytes(1)
    for mode in range(256):
        c.seed(ACTOR+0x1c,bytes([mode]))
        for value in range(7):
            c.seed(ACTOR+3,bytes([value]));c.cpu.a[0]=ACTOR;c.run(0x89aa,0x81e6,15)
            assert c.read(ACTOR+3,1)[0]==(6 if mode==1 else value+1 if value<5 else 0)
            select(c,65)
    c.seed(ACTOR+0x1c,b'\0');c.seed(ACTOR+3,b'\x80');c.cpu.a[0]=ACTOR;c.run(0x89aa,0x81e6,15)
    assert c.read(ACTOR+3,1)==b'\x81'


def test_normal_render_actor_type_word_is_not_the_initializer_low_byte_domain():
    # The loader stores the full source WORD, but masks the initializer index.
    c=machine(0);record=0x68000
    c.seed(record,bytes.fromhex('801200000000000000000000'));c.cpu.a[1]=record;c.cpu.d[4]=0xffffffff
    c.run(0x19712,0x19728,12)
    assert c.read(ACTOR,2)==bytes.fromhex('8012') and c.cpu.d[0]==18
    # The rendering path has no matching AND #255; a claimed global 0..103
    # type domain cannot be inferred from that initializer mask.


def test_checked_source_uses_partial_actor_fields_at_qualified_consumers():
    from pathlib import Path
    source=(Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered/retail-shared.s').read_text()
    assert 'cycle_type7_variant_with_negative_difference_test:' in source
    assert 'cycle_type35_variant_with_negative_difference_test:' in source
    assert 'move.b SG2ActorModelPrefix_vertex_variant_selector(a4),d1' in source
    assert 'move.b SG2ActorModelPrefix_model_scale_shift(a4),d1' in source
    assert 'clr.b SG2ActorModelPrefix_vertex_variant_selector(a0)' in source
    initializer=source.split('set_world_placement_scale_phase_and_variant:',1)[1].split('skip_object_type_initialization:',1)[0]
    assert 'SG2ActorModelPrefix_model_scale_shift(a0)' in initializer
    assert 'SG2ActorModelPrefix_retirement_phase_or_negative(a0)' in initializer
    assert 'SG2ActorModelPrefix_vertex_variant_selector(a0)' in initializer

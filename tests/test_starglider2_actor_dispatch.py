"""Original actor dispatch and selected gameplay selector lifetimes."""
import os
from pathlib import Path
import pytest
from test_starglider2_model_streams import inputs,fixtures,ROOT


def dispatch(data,type_id,*,flags=0,active=True,expected=None):
    from amiga_reversing.disasm.mapped_execution import MappedExecution
    cpu=MappedExecution(0x80000,project_root=ROOT,register_seed=0xdeadbeef)
    cpu.seed(0x8210,data[0x7210:0x7230]);cpu.seed(0x8230,data[0x7230:0x7358])
    actor=bytearray(32);actor[:2]=type_id.to_bytes(2,'big');actor[2]=flags;actor[30]=255 if active else 0
    cpu.seed(0x60000,actor);cpu.cpu.a[0]=0x60000
    if expected is None:
        if not active:expected=0x8358
        elif not type_id:expected=0x8370
        elif flags&128:expected=0x83b0
        else:
            offset=((type_id*2)&65535);offset=offset if offset<32768 else offset-65536
            value=int.from_bytes(data[0x7230+offset:0x7232+offset],'big',signed=True);expected=0x8230+value
    result=cpu.run(0x8210,expected,20)
    return result


@fixtures
def test_actor_dispatch_qualified_storage_domain_and_bypass_paths():
    _,data=inputs();targets=set()
    for type_id in range(148):
        result=dispatch(data,type_id);targets.add(result['stop_pc'])
        dispatch(data,type_id,flags=128);dispatch(data,type_id,active=False)
    assert len(targets)==24  # The zero/free path is also a table destination.
    with pytest.raises(ValueError,match='unknown read/fetch'):
        dispatch(data,148,expected=0x8230)
    # ADD.W wraps before the signed WORD index is used. No universal ID guard.
    assert dispatch(data,0x8001)['stop_pc']==dispatch(data,1)['stop_pc']


def first_dispatch(data,type_id,*,flags=0,active=True,state=6,expected=None):
    from amiga_reversing.disasm.mapped_execution import MappedExecution
    cpu=MappedExecution(0x80000,project_root=ROOT,register_seed=0xdeadbeef)
    cpu.seed(0x8002,data[0x7002:0x703e]);cpu.seed(0x803e,data[0x703e:0x7166])
    actor=bytearray(32);actor[:2]=type_id.to_bytes(2,'big');actor[2]=flags;actor[28]=state;actor[30]=255 if active else 0
    cpu.seed(0x60000,actor);cpu.cpu.a[0]=0x60000
    if expected is None:
        if not active:expected=0x8190
        elif flags&4:expected=0x8166
        elif flags&8:expected=0x817e
        elif not type_id:expected=0x81aa
        elif flags&128 or not state:expected=0x81e6
        else:
            offset=(type_id*2)&65535;offset=offset if offset<32768 else offset-65536
            expected=0x803e+int.from_bytes(data[0x703e+offset:0x7040+offset],'big',signed=True)
    return cpu.run(0x8002,expected,25)


@fixtures
def test_first_phase_dispatch_has_separate_state_and_gravity_bypasses():
    _,data=inputs()
    for type_id in range(148):
        first_dispatch(data,type_id)
        first_dispatch(data,type_id,flags=128);first_dispatch(data,type_id,flags=4)
        first_dispatch(data,type_id,flags=8);first_dispatch(data,type_id,flags=12)
        first_dispatch(data,type_id,active=False);first_dispatch(data,type_id,state=0)
    with pytest.raises(ValueError,match='unknown read/fetch'):
        first_dispatch(data,148,expected=0x803e)
    assert first_dispatch(data,0x8001)['stop_pc']==first_dispatch(data,1)['stop_pc']


def lifecycle_cpu(data,type_id):
    from amiga_reversing.disasm.mapped_execution import MappedExecution
    from amiga_reversing.tools.compare_starglider2 import model_streams,bounded_variants
    cpu=MappedExecution(0x80000,project_root=ROOT,register_seed=0xdeadbeef)
    fragments=[(0x7002,0x703e),(0x7210,0x7230),(0x703e,0x7166),(0x7230,0x7358),
        (0x18728,0x1874c),(0x18ae0,0x18afa),(0x18c64,0x18c7c),(0x19228,0x1922e),
        (0x1676,0x1692),(0x7f1a,0x7fa8),(0x9894,0x98da),(0x8ed4,0x8f0e),
        (0x3a7e,0x3a9c),(0x3cc8,0x3cce)]
    for lo,hi in fragments:cpu.seed(lo+4096,data[lo:hi])
    for source,size in [(0x185cc+type_id,1),(0x17b8e+type_id,1),(100266+4*type_id,4)]:
        cpu.seed(source+4096,data[source:source+size])
    actor=bytearray(68);actor[:2]=type_id.to_bytes(2,'big');cpu.seed(0x60000,actor);cpu.allow_write(0x60000,68)
    cpu.seed(0x70060,bytes(8));cpu.allow_write(0x70060,8)
    cpu.seed(0x7006c,bytes(4));cpu.allow_write(0x7006c,4)
    cpu.seed(0xe145,b'\0');cpu.allow_write(0xe145,1)
    cpu.seed(0x77e00,bytes(512));cpu.allow_write(0x77e00,512)
    cpu.cpu.a[0]=0x60000;cpu.cpu.a[3]=0x195cc;cpu.cpu.a[4]=0x18b8e;cpu.cpu.a[6]=0x70000
    cpu.cpu.a[7]=0x78000;cpu.cpu.d[0]=type_id
    cpu.run(0x19728,0x1974c,80)
    model=next(m for m in model_streams(data,102964) if type_id in m['ordinals'])
    proof=bounded_variants(data,model,0xdcee);table=model['variant_first']['table']
    cpu.seed(model['header']+4096+18,data[model['header']+18:model['header']+22])
    cpu.seed(table+4096,data[table:table+4*len(proof['views'])])
    for view in proof['views']:cpu.seed(view['start']+4096,data[view['start']:view['end']])
    cpu.seed(0x70024,bytes(4));cpu.allow_write(0x70024,4)
    return cpu,model,proof


def consume_current_variant(cpu,model,proof):
    selector=cpu.read(0x60003,1)[0];cpu.cpu.a[0]=model['header']+4096+18;cpu.cpu.a[4]=0x60000
    cpu.run(0x4a7e,0x4a9c,20);pointer=int.from_bytes(cpu.read(0x70024,4),'big')
    if not selector:assert pointer==0;return
    view=next(v for v in proof['views'] if v['selector']==selector)
    assert pointer==view['start']+4096
    for offset in view['offsets']:
        cpu.cpu.a[1]=pointer;cpu.cpu.d[4]=offset;cpu.run(0x4cc8,0x4cce,2)


def update_phase(cpu,data,type_id,phase):
    table=0x703e if phase==1 else 0x7230;start=0x8002 if phase==1 else 0x8210
    finish=0x81e6 if phase==1 else 0x83b0
    target=table+4096+int.from_bytes(data[table+2*type_id:table+2*type_id+2],'big',signed=True)
    cpu.cpu.a[0]=0x60000;cpu.run(start,target,25)
    if target!=finish:cpu.run(target,finish,100)


@fixtures
def test_type19_fresh_initialization_and_complete_selector_cycle():
    _,data=inputs();cpu,model,proof=lifecycle_cpu(data,19)
    assert cpu.read(0x60003,1)==b'\0' and cpu.read(0x6001f,1)==b'\1'
    assert cpu.read(0x6001c,1)==b'\4' and cpu.read(0x6001e,1)==b'\xff'
    seen=set();selected=set()
    while True:
        state=(cpu.read(0x60003,1)[0],cpu.read(0x6001f,1)[0])
        if state in seen:break
        seen.add(state);selected.add(state[0]);consume_current_variant(cpu,model,proof)
        update_phase(cpu,data,19,1);update_phase(cpu,data,19,2)
    assert selected==set(range(15)) and 15 not in selected
    assert cpu.read(0x60000,3)==b'\0\x13\0'
    # The equality tests do not clamp an invalid externally supplied selector.
    cpu.seed(0x60003,b'\x10');cpu.seed(0x6001f,b'\1')
    update_phase(cpu,data,19,1);assert cpu.read(0x60003,1)==b'\x11'
    with pytest.raises(ValueError,match='unknown read/fetch'):consume_current_variant(cpu,model,proof)


@fixtures
def test_type4_two_phase_updates_preserve_the_fresh_selector_contract():
    _,data=inputs();cpu,model,proof=lifecycle_cpu(data,4)
    assert cpu.read(0x60003,1)==b'\x1d' and cpu.read(0x6001c,1)==b'\6'
    assert cpu.read(0x6001e,1)==b'\xff'
    intermediate=set();final=set()
    for selector in (29,30):
        for mission_flag in (0,255):
            cpu.seed(0x60003,bytes([selector]));cpu.seed(0x70daa,bytes([mission_flag]))
            update_phase(cpu,data,4,1);between=cpu.read(0x60003,1)[0];intermediate.add(between)
            assert between==selector-int(bool(mission_flag));consume_current_variant(cpu,model,proof)
            update_phase(cpu,data,4,2);value=cpu.read(0x60003,1)[0];final.add(value)
            assert value==(between if between==30 else between+1);consume_current_variant(cpu,model,proof)
            assert cpu.read(0x60000,3)==b'\0\4\0' and cpu.read(0x6001c,1)==b'\6'
    assert intermediate=={28,29,30} and final=={29,30}
    cpu.seed(0x60003,b'\x1f');cpu.seed(0x70daa,b'\0')
    update_phase(cpu,data,4,1);update_phase(cpu,data,4,2)
    assert cpu.read(0x60003,1)==b'\x20'  # Saturation is not an arbitrary-state guard.
    with pytest.raises(ValueError,match='unknown read/fetch'):consume_current_variant(cpu,model,proof)


@fixtures
def test_type_indexed_vertical_thresholds_preserve_order_and_inverted_pairs():
    from amiga_reversing.disasm.mapped_execution import MappedExecution
    _,data=inputs();ids=(7,13,16,18,21,27,28,29,31,32,33,35,41,45);inverted=0
    for type_id in ids:
        low=int.from_bytes(data[0x1834c+2*type_id:0x1834e+2*type_id],'big',signed=True)
        high=int.from_bytes(data[0x1841e+2*type_id:0x18420+2*type_id],'big',signed=True)
        inverted+=low>high
        for height in {low-1,low,high,high+1,(low+high)//2}:
            cpu=MappedExecution(0x80000,project_root=ROOT,register_seed=0xdeadbeef)
            cpu.seed(0xa6a0,data[0x96a0:0x972e]);cpu.seed(0x1934c+2*type_id,data[0x1834c+2*type_id:0x1834e+2*type_id])
            cpu.seed(0x1941e+2*type_id,data[0x1841e+2*type_id:0x18420+2*type_id])
            actor=bytearray(68);actor[:2]=type_id.to_bytes(2,'big');actor[8:12]=height.to_bytes(4,'big',signed=True);actor[46:48]=b'\x12\x34'
            cpu.seed(0x60000,actor);cpu.allow_write(0x6002e,2);cpu.seed(0xe145,b'\0');cpu.allow_write(0xe145,1);cpu.cpu.a[0]=0x60000
            cpu.run(0xa6a0,0xa6d4,35)
            expected=5 if height<=low else -5 if height>=high else 0x1234
            assert int.from_bytes(cpu.read(0x6002e,2),'big',signed=True)==expected
    assert inverted==4  # These are ordered predicates, not a sorted clamp interval.


@fixtures
def test_native_dispatch_rendering_uses_proved_callback_and_table_symbols():
    source=(Path(os.environ['SGII_RETAIL_RENDERED_SOURCE'])).read_text()
    assert 'dc.w advance_type4_variant_and_release_links-actor_second_phase_dispatch_offsets' in source
    assert 'dc.w update_type19_variant_ping_pong-actor_first_phase_dispatch_offsets' in source
    assert 'lea.l actor_positive_y_velocity_thresholds.l,a1' in source

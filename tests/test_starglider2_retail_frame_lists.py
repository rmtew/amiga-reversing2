"""Original retail list snapshot and its station/actor update dependencies.

Reuses the earlier Amiga distance oracle, with actual retail addresses. CPU
slices establish list lifetime and call order, not physical frame timing.
"""
import os,struct
from pathlib import Path
import pytest
from test_starglider2_retail_neutron import machine,APP,POOL,STACK,RETURN,shared_bytes
from test_starglider2_retail_workspace import put,get
from tests.test_starglider2_homing_updates import signed32

pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail payloads')

def setup(records,origin=(0,0,0)):
    c=machine();c.seed(POOL,bytes(17000))
    for i,(kind,xyz) in enumerate(records):
        at=POOL+68*i;put(c.memory,at,kind,2);c.seed(at+28,b'\x80\0\xff')
        for off,value in zip((4,8,12),xyz):put(c.memory,at+off,value)
    put(c.memory,APP+0x172,len(records),2)
    put(c.memory,APP+0x6fc,0x0fffffff)
    for off,value in zip((0x710,0x714,0x718),origin):put(c.memory,APP+off,value)
    c.seed(APP+0x77c,b'\0');return c

def partition(c):
    c.cpu.a[6]=APP;c.cpu.a[7]=STACK;c.run(0x4158,RETURN,40000)

def pointers(c,field,count):
    return [get(c.memory,get(c.memory,APP+field)+4*i) for i in range(get(c.memory,APP+count,2))]

@pytest.mark.parametrize('kind,limit',((1,0x3a00),(128,0x08000000),(146,32767)))
@pytest.mark.parametrize('axis',range(3))
@pytest.mark.parametrize('case',('zero','limit','over','negative_limit','below','wrap_threshold','over_threshold','under_threshold','period','negative_period','min_long'))
def test_original_partition_wrap_boundaries_and_partial_stores(kind,limit,axis,case):
    period=0x10000000;threshold=period-limit
    delta={'zero':0,'limit':limit,'over':limit+1,'negative_limit':-limit,'below':-limit-1,
           'wrap_threshold':threshold,'over_threshold':threshold+1,'under_threshold':-threshold-1,
           'period':period,'negative_period':-period,'min_long':-0x80000000}[case]
    xyz=[0,0,0];xyz[axis]=delta;c=setup([(kind,xyz),(0,(0,0,0))])
    for off in (22,24,26,50,52,54):put(c.memory,POOL+off,0x5a5a,2)
    expected=bytearray(c.read(POOL,68));accepted=True
    for component,off in ((0,22),(2,26),(1,24)):
        value=xyz[component];magnitude=signed32(-value) if value<0 else value
        if component!=1 and magnitude>threshold:projected=value+period if value<0 else value-period
        else:
            if (component==1 and not -limit<=value<=limit) or (component!=1 and magnitude>limit):accepted=False;break
            projected=value
        put(expected,off,projected,2)
        if kind<128:put(expected,off+28,projected,2)
    partition(c)
    assert c.read(POOL,68)==expected
    assert pointers(c,0x6c8,0x75e)==([POOL] if accepted else [])
    assert pointers(c,0x6b8,0x75c)==([] if accepted else [POOL])
    assert get(c.memory,APP+0x772,2)==1 and get(c.memory,APP+0x6d4)==APP+0xea8
    assert get(c.memory,APP+0xea4)==POOL+68

@pytest.mark.parametrize('count',(0,1,2,250))
def test_slot_count_gate_only_skips_one_not_zero(count):
    c=setup([]);put(c.memory,APP+0x172,count,2)
    stop=0x42aa if count==1 else 0x4194
    c.run(0x4158,stop,25)
    assert c.cpu.d[7]&65535==(count-1)&65535
    # Zero would enter a 65536-iteration DBF traversal; stop before it.


def test_all_250_slots_build_reverse_near_far_lists_and_forward_free_stack():
    records=[(0 if i%3==0 else 1,(0 if i%3==1 else 20000,0,0)) for i in range(250)]
    c=setup(records);partition(c)
    free=[POOL+68*i for i in range(250) if i%3==0]
    assert pointers(c,0x6c8,0x75e)==[POOL+68*i for i in reversed(range(250)) if i%3==1]
    assert pointers(c,0x6b8,0x75c)==[POOL+68*i for i in reversed(range(250)) if i%3==2]
    assert get(c.memory,APP+0x772,2)==len(free)
    assert c.read(APP+0xea4,4*len(free))==struct.pack('>'+str(len(free))+'I',*free)
    assert get(c.memory,APP+0x6d4)==APP+0xea4+4*len(free)
    assert c.read(APP+0x6598,4)==b'\xcc'*4

@pytest.mark.parametrize('inside',(0,1))
@pytest.mark.parametrize('flags',(0,64))
@pytest.mark.parametrize('selected',(0,1,2,3,255))
@pytest.mark.parametrize('room',(0,1,2,3,254))
def test_structure_filter_uses_byte_difference_and_keeps_rejected_actor_distant(inside,flags,selected,room):
    c=setup([(1,(0,0,0)),(0,(0,0,0))]);c.seed(APP+0x77c,bytes([inside]));c.seed(APP+0x77e,bytes([selected]))
    c.seed(POOL+2,bytes([flags]));c.seed(POOL+37,bytes([room]));partition(c)
    difference=(selected-room)&255;magnitude=(-difference)&255 if difference&128 else difference
    admitted=not inside or not flags&64 or not selected or magnitude in (0,1)
    assert pointers(c,0x6c8,0x75e)==([POOL] if admitted else [])

@pytest.mark.parametrize('kind',(1,72,84,103,128))
@pytest.mark.parametrize('marker',(0,1,128))
def test_special_subset_is_only_near_types_72_84_103_with_nonzero_marker(kind,marker):
    c=setup([(kind,(0,0,0)),(0,(0,0,0))]);c.seed(POOL+34,bytes([marker]));partition(c)
    count=int(kind in (72,84,103) and marker!=0)
    assert get(c.memory,APP+0x788,2)==count
    assert get(c.memory,APP+0x6bc)==APP+0x232c-4*count
    if count:assert get(c.memory,APP+0x2328)==POOL
    assert c.cpu.a[5]==68  # USP scratch exchange restores the record stride.


def test_station_allocated_after_list_snapshot_is_updated_only_after_next_partition():
    c=setup([(0,(0,0,0)) for _ in range(250)]);partition(c)
    assert get(c.memory,APP+0x772,2)==250
    c.seed(APP+0xa7d,b'\xff');put(c.memory,APP+0x868,52,2)
    header=int.from_bytes(shared_bytes()[0x19234+99*4:0x19238+99*4],'big');c.allow_write(header+2,2)
    c.run(0x349ea,0x34ad4,2500);station=POOL+249*68
    assert get(c.memory,station,2)==99 and get(c.memory,APP+0x772,2)==249
    assert pointers(c,0x6c8,0x75e)==[] and pointers(c,0x6b8,0x75c)==[]
    c.seed(APP+0x7e9,b'\xff');c.cpu.a[7]=STACK;c.run(0x7fdc,RETURN,50)
    assert get(c.memory,APP+0x9b0)==0  # No list entry, hence no publication callback.
    origin=tuple(get(c.memory,station+off) for off in (4,8,12))
    for off,value in zip((0x710,0x714,0x718),origin):put(c.memory,APP+off,value)
    partition(c);assert pointers(c,0x6c8,0x75e)==[station]
    c.cpu.a[7]=STACK;c.run(0x7fdc,RETURN,1000)
    assert get(c.memory,APP+0x9b0)==station and c.read(APP+0xa7e,1)==b'\xff'
    # Moving the supplied view origin out of the station range changes which
    # original callback runs; no new allocation or artificial list is supplied.
    put(c.memory,APP+0x710,origin[0]+1000000);partition(c)
    assert pointers(c,0x6b8,0x75c)==[station]
    c.cpu.a[7]=STACK;c.run(0x7fdc,RETURN,1000)
    assert get(c.memory,APP+0x9b0)==0 and c.read(APP+0xa7e,1)==b'\0'


def test_main_loop_call_order_and_bridges_are_original_shared_instructions():
    raw=shared_bytes()
    def target(pc):
        off=pc-0x1000;assert raw[off:off+2]==b'\x61\0'
        return pc+2+int.from_bytes(raw[off+2:off+4],'big',signed=True)
    # Exact call sites and destinations, not names inferred from instruction
    # shape. The list builder is nested in the first scene-build call.
    calls=((0x12b4,0x3df4),(0x12c6,0x34da),(0x12d8,0x33f2),(0x12ea,0x1824),
           (0x12fc,0x340a),(0x1314,0x7fdc),(0x1318,0x71b4),(0x132a,0x33e6))
    for pc,destination in calls:assert target(pc)==destination
    for bridge,destination in ((0x33f2,0x34748),(0x340a,0x30f68),(0x33e6,0xb568)):
        off=bridge-0x1000;assert raw[off:off+6]==b'\x4e\xf9'+destination.to_bytes(4,'big')
    assert target(0x3f28)==0x4158 and target(0x3f3a)==0x4338
    # CPU executes the actual BSR and preserves its real return address.
    c=setup([]);c.seed(int.from_bytes(raw[0x2a2:0x2a6],'big'),APP.to_bytes(4,'big'));c.allow_write(0xe144,2)
    c.cpu.a[7]=STACK;c.run(0x12a0,0x3df4,10)
    assert get(c.memory,c.cpu.a[7])==0x12b8

@pytest.mark.parametrize('kind',range(148))
def test_every_bounded_distance_table_entry_is_read_as_a_long_not_a_pointer(kind):
    c=setup([(kind,(0,0,0)),(0,(0,0,0))]);c.cpu.a[4]=POOL;c.cpu.a[0]=0x18bf8
    c.run(0x4194,0x41d4,30) if kind else None
    if not kind:return  # A free slot takes the branch before the table read.
    limit=get(shared_bytes(),0x17bf8+4*kind)
    assert c.cpu.d[5]==limit and c.cpu.d[6]==(-limit)&0xffffffff
    assert c.cpu.d[3]==(0x10000000-limit)&0xffffffff


def test_rendered_source_exposes_the_partition_and_list_lifetime_contract():
    value=os.getenv('SGII_RETAIL_RENDERED_SOURCE')
    if not value:pytest.skip('set SGII_RETAIL_RENDERED_SOURCE to regenerated source')
    text=Path(value).read_text()
    for name in ('partition_world_actor_lists:','publish_partitioned_actor_list_cursors:',
                 'collect_unused_actor_on_free_stack:','update_partitioned_world_actors:',
                 'actor_near_distance_limits:','SG2FrameListWorkspace_nearby_object_count(a6)',
                 'SG2ModelCoordinateActor_origin_relative_x(a4)'):
        assert name in text

@pytest.mark.parametrize('kind',(1,128))
@pytest.mark.parametrize('flags',(0,2))
@pytest.mark.parametrize('phase',(0,128,255))
def test_original_transform_collects_contacts_before_visibility_rejection(kind,flags,phase):
    c=setup([(kind,(0,0,1000)),(0,(0,0,0))]);c.seed(POOL+2,bytes([flags]));c.seed(POOL+30,bytes([phase]))
    c.seed(APP+0x77c,b'\1');c.seed(APP+0x106,struct.pack('>9h',16384,0,0,0,16384,0,0,0,16384))
    # Explicit supplied positive model extent; inside-structure mode skips the
    # later outside-screen projection. No claim about ordinary flight inputs.
    c.seed(0x5930+kind*2,b'\0\1');partition(c)
    c.cpu.a[7]=STACK;c.run(0x4338,RETURN,1000)
    assert tuple(get(c.memory,POOL+off,2)for off in (22,24,26))==(0,0,1000)
    assert pointers(c,0x6d0,0x762)==([POOL] if phase&128 else [])
    assert pointers(c,0x6cc,0x760)==([POOL] if kind>=128 or not flags&2 else [])


def test_transform_reverses_near_snapshot_order_and_does_not_repartition_new_type():
    c=setup([(1,(0,0,100)),(1,(0,0,200)),(0,(0,0,0))])
    c.seed(APP+0x77c,b'\1');c.seed(APP+0x106,struct.pack('>9h',16384,0,0,0,16384,0,0,0,16384));c.seed(0x5932,b'\0\1')
    partition(c);assert pointers(c,0x6c8,0x75e)==[POOL+68,POOL]
    c.cpu.a[7]=STACK;c.run(0x4338,RETURN,1000)
    assert pointers(c,0x6cc,0x760)==[POOL,POOL+68] and pointers(c,0x6d0,0x762)==[POOL,POOL+68]
    put(c.memory,POOL+136,1,2);c.cpu.a[7]=STACK;c.run(0x4338,RETURN,1000)
    assert pointers(c,0x6cc,0x760)==[POOL,POOL+68]

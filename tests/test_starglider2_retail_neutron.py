"""Retail carried/released neutron state and the connected actor retirement path.

Reuse established arithmetic expectations with actual retail instructions and
explicit RAM. A nonzero global reference is not an ownership guarantee.
"""
import os
from pathlib import Path
import pytest
from test_starglider2_retail_variant_cycles import shared_bytes,APP,ACTOR,STACK,RETURN
from test_starglider2_retail_world_placement import spawn_machine
from test_starglider2_retail_workspace import put,get
from tests.test_starglider2_neutron_state import negative32
from tests.test_starglider2_homing_updates import signed32
from tests.test_starglider2_scan_acquisition import signed16,project

pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
STATION,OTHER,POOL=0x61000,0x62000,APP+0x2330

def machine():
    c=spawn_machine();c.seed(APP+0x3000,bytes(0x3598));c.allow_write(APP,0x6598);c.seed(APP+0x6598,b'\xcc'*4);c.seed(0x68004,b'\xcc'*8);c.allow_write(0x68000,12)
    c.seed(ACTOR,b'\x4c'*68);put(c.memory,ACTOR,98,2);c.seed(ACTOR+30,bytes([255,0]))
    c.seed(STATION,bytes(68));c.allow_write(STATION,68)
    for off,value in ((0xa76,ACTOR),(0x720,120)):put(c.memory,APP+off,value)
    for off in (0x744,0x746,0x748):put(c.memory,APP+off,0,2)
    for off,value in ((0x77d,128),(0xa7e,0),(0xae3,0),(0xae4,0),(0xb47,1)):c.seed(APP+off,bytes([value]))
    put(c.memory,APP+0x7c4,0,2);put(c.memory,0xe0c2,0)
    c.allow_write(0xe0c0,0x50);c.cpu.a[0]=ACTOR
    return c

def update(c):c.cpu.a[0]=ACTOR;c.run(0x38062,RETURN,5000)

def velocity(c,speed):
    raw=shared_bytes();angles=[get(c.memory,APP+o,2)for o in (0x744,0x746,0x748)]
    s0,c0,s1,c1=[int.from_bytes(raw[p+2*(a&4095):p+2*(a&4095)+2],'big')for p,a in ((0x14808,angles[0]),(0x15008,angles[0]),(0x14808,angles[1]),(0x15008,angles[1]))]
    scale=(speed+200)&65535
    return scale,[(-project(project(scale,s1),c0))&65535,(-project(scale,s0))&65535,project(project(scale,c1),c0)&65535]

@pytest.mark.parametrize('space',(0,1,128))
@pytest.mark.parametrize('y',(-1000,-122,-121,-120,0,0x7fffffff))
@pytest.mark.parametrize('vy',(-1,0,1))
def test_released_surface_double_y_step_and_n_only_ground_test(space,y,vy):
    c=machine();c.seed(ACTOR+31,b'\xff');c.seed(APP+0x77d,bytes([space]))
    for off,value in ((4,65535),(8,y),(12,0)):put(c.memory,ACTOR+off,value)
    for off,value in ((44,1),(46,vy),(48,-1),(16,3),(18,123),(20,65535),(36,5)):put(c.memory,ACTOR+off,value,2)
    update(c);after_y=(y+vy*(1 if space>=128 else 2))&0xffffffff
    ground=space<128 and not negative32(after_y-0xffffff88)
    assert [get(c.memory,ACTOR+off)for off in (4,8,12)]==[0,after_y,65535]
    assert c.read(APP+0xbb6,1)==bytes([255 if ground else 0])
    assert get(c.memory,ACTOR+46,2)==((vy+1)&65535 if space<128 and not ground else vy&65535)
    assert get(c.memory,ACTOR+36,2)==(5 if ground else 4)
    assert get(c.memory,ACTOR+16,2)==(3 if ground else (3-8)&4095)
    assert get(c.memory,ACTOR+20,2)==(65535 if ground else (65535-8)&4095)
    assert get(c.memory,ACTOR+18,2)==123 and c.read(ACTOR+30,1)==bytes([0 if ground else 255])

@pytest.mark.parametrize('near',(0,1,128))
@pytest.mark.parametrize('construction',(51,52,53))
@pytest.mark.parametrize('updates',(0,1,32768,65535))
def test_station_attraction_and_wrapped_countdown_preserve_old_arithmetic(near,construction,updates):
    c=machine();c.seed(ACTOR+31,b'\xff');c.seed(APP+0xa7e,bytes([near]));put(c.memory,APP+0x868,construction,2)
    put(c.memory,APP+0x9b0,STATION)
    for off,value in ((4,1),(8,-1000),(12,65535)):put(c.memory,ACTOR+off,value)
    for off in (44,46,48):put(c.memory,ACTOR+off,0,2)
    for off,value in ((4,64),(8,-2001),(12,-64)):put(c.memory,STATION+off,value)
    put(c.memory,ACTOR+36,updates,2);update(c);expected=[1,-1000,65535]
    if near>=128 and construction!=52:expected=[(a-(signed32(a-b)>>5))&0xffffffff for a,b in zip(expected,(64,-2001,-64))]
    assert [get(c.memory,ACTOR+off)for off in (4,8,12)]==[v&0xffffffff for v in expected]
    remaining=(updates-1)&65535
    assert get(c.memory,ACTOR+36,2)==remaining and c.read(ACTOR+30,1)==bytes([0 if remaining&32768 else 255])

@pytest.mark.parametrize('space',(0,1,128))
@pytest.mark.parametrize('reference',(0,ACTOR,OTHER,0xffffffff))
@pytest.mark.parametrize('world_y',(-241,-240,-239,0x7fffffff))
def test_carried_global_is_nonnull_not_identity_and_ground_resets_requests(space,reference,world_y):
    c=machine();c.seed(APP+0x77d,bytes([space]));put(c.memory,APP+0xa76,reference);put(c.memory,APP+0x708,world_y)
    for off,value in ((0x744,65535),(0x746,4097),(0x748,32768)):put(c.memory,APP+off,value,2)
    before=c.read(ACTOR,68);update(c)
    if not reference:
        expected=bytearray(before);expected[:2]=bytes(2)
        assert c.read(ACTOR,68)==expected and get(c.memory,APP+0x720)==20
        assert c.read(APP+0xb47,1)==b'\1' and c.read(APP+0xae4,1)==b'\0';return
    y=(world_y+120)&0xffffffff;ground=space<128 and not negative32(y-0xffffff88)
    assert [get(c.memory,ACTOR+off)for off in (4,8,12)]==[10000,y,20000]
    assert [get(c.memory,ACTOR+off,2)for off in (16,18,20)]==[65535,4097,32768]
    assert get(c.memory,APP+0xa76)==(0 if ground else reference)
    assert get(c.memory,APP+0x720)==(20 if ground else 120)
    assert c.read(APP+0xb47,1)==bytes([0 if ground else 1]) and c.read(APP+0xae4,1)==bytes([255 if ground else 0])
    assert c.read(APP+0xae3,1)==b'\0' and get(c.memory,APP+0x7c4,2)==(200 if ground else 0)

@pytest.mark.parametrize('offset',(69,70,120,0x7fffffff,0x80000000,0xffffffff))
@pytest.mark.parametrize('reference',(0,ACTOR))
@pytest.mark.parametrize('speed',(0,32768,65535))
@pytest.mark.parametrize('inventory',(1,255))
def test_launch_clears_inventory_before_pointer_guard_and_preserves_n_only_offset_gate(offset,reference,speed,inventory):
    c=machine();put(c.memory,APP+0x720,offset);put(c.memory,APP+0xa76,reference)
    c.seed(APP+0xb47,bytes([inventory]));put(c.memory,APP+0x75a,speed,2);before=c.read(ACTOR,68)
    c.run(0x79c0,RETURN,5000);allowed=not negative32(offset-70);launched=allowed and bool(reference)
    assert c.read(APP+0xb47,1)==bytes([0 if allowed else inventory])
    assert get(c.memory,APP+0x7c4,2)==(200 if launched else 0)
    assert get(c.memory,APP+0x720)==(20 if launched else offset)
    assert get(c.memory,APP+0xa76)==(0 if launched else reference)
    assert c.read(APP+0xae3,2)==bytes([0,255 if launched else 0])
    if not launched:assert c.read(ACTOR,68)==before;return
    scale,v=velocity(c,speed)
    assert get(c.memory,ACTOR+32,2)==scale and get(c.memory,ACTOR+36,2)==1000
    assert [get(c.memory,ACTOR+off,2)for off in (44,46,48)]==v
    assert [get(c.memory,ACTOR+off)for off in (4,8,12)]==[(10000+signed16(v[0]))&65535,(-1000+signed16(v[1])+offset)&0xffffffff,(20000+signed16(v[2]))&65535]
    assert c.read(ACTOR+30,2)==b'\xff\xff' and c.read(ACTOR+52,16)==before[52:]

@pytest.mark.parametrize('space',(0,1,128))
@pytest.mark.parametrize('inside',(0,1,128))
@pytest.mark.parametrize('projectors',(0,1,128))
@pytest.mark.parametrize('minis',(0,1,65535))
def test_actual_launch_guard_precedence_before_any_actor_store(space,inside,projectors,minis):
    c=machine();c.seed(APP+0x77d,bytes([space]));c.seed(APP+0x77c,bytes([inside]));c.seed(APP+0xaa7,bytes([projectors]));put(c.memory,APP+0xa7a,minis,2)
    guard=space>=128 and inside<128;stop=0x7a4e if guard and projectors else 0x7a7c if guard and minis else 0x79e4
    before=c.read(ACTOR,68);c.run(0x79c0,stop,40)
    assert c.read(ACTOR,68)==before and c.read(APP+0xb47,1)==b'\1'

@pytest.mark.parametrize('player_tag',(30,0x11e))
def test_ground_detonation_retires_full_pool_except_exact_player_tag_then_recycles_bomb(player_tag):
    c=machine();c.seed(ACTOR+31,b'\xff');c.seed(APP+0x77d,b'\0');put(c.memory,ACTOR+8,-120)
    for off in (44,46,48):put(c.memory,ACTOR+off,0,2)
    pool=bytearray(b'\xcc'*17000);tags=(0,player_tag,75,98,147)
    for i in range(250):put(pool,68*i,tags[i%5],2);pool[68*i+30]=i&255
    c.seed(POOL,pool);wanted=bytearray(pool)
    for i in range(250):
        if get(pool,68*i,2)!=30:wanted[68*i+30]=0
    guard_before=c.read(POOL-4,4),c.read(POOL+17000,4);update(c)
    assert c.read(POOL,17000)==wanted and (c.read(POOL-4,4),c.read(POOL+17000,4))==guard_before
    assert c.read(ACTOR+30,1)==b'\0' and c.read(APP+0xbb6,1)==b'\xff'
    assert get(c.memory,APP+0x772,2)==2 and get(c.memory,APP+0xa76)==ACTOR
    limit=shared_bytes()[0x17e48+98]
    for _ in range(limit+1):c.cpu.a[0]=ACTOR;c.cpu.a[7]=STACK;c.run(0x8190,0x81e6,100)
    assert c.read(ACTOR,68)==bytes(30)+b'\xff'+bytes(37)
    assert get(c.memory,APP+0x772,2)==3 and get(c.memory,0x68004)==ACTOR
    # Recycling itself does not repair a global alias to this slot.
    assert get(c.memory,APP+0xa76)==ACTOR


def test_station_pull_does_not_validate_a_nonnull_reference_before_dereferencing():
    c=machine();c.seed(ACTOR+31,b'\xff');c.seed(APP+0xa7e,b'\x80')
    put(c.memory,APP+0x868,51,2);put(c.memory,APP+0x9b0,0)
    for off in (44,46,48):put(c.memory,ACTOR+off,0,2)
    with pytest.raises(ValueError,match='unknown read/fetch'):update(c)


def test_allocated_bomb_launch_countdown_detonation_and_recycle_keep_distinct_lifetimes():
    c=machine();put(c.memory,APP+0xa76,0);c.seed(APP+0xae3,b'\xff')
    c.run(0x3493a,0x349ea,500)
    assert get(c.memory,APP+0xa76)==ACTOR and get(c.memory,APP+0x772,2)==1
    assert c.read(ACTOR,4)==bytes.fromhex('00624c00') and c.read(ACTOR+30,2)==b'\xff\0'
    c.run(0x79c0,RETURN,500)
    assert get(c.memory,APP+0xa76)==0 and c.read(ACTOR+30,2)==b'\xff\xff'
    assert get(c.memory,APP+0x772,2)==1 and c.read(APP+0xb47,1)==b'\0'
    for _ in range(1000):c.cpu.a[7]=STACK;update(c)
    assert get(c.memory,ACTOR+36,2)==0 and c.read(ACTOR+30,1)==b'\xff'
    assert c.read(APP+0xbb6,1)==b'\0'
    c.cpu.a[7]=STACK;update(c)
    assert get(c.memory,ACTOR+36,2)==65535 and c.read(ACTOR+30,1)==b'\0'
    assert c.read(APP+0xbb6,1)==b'\xff' and get(c.memory,APP+0x772,2)==1
    for _ in range(shared_bytes()[0x17e48+98]+1):
        c.cpu.a[0]=ACTOR;c.cpu.a[7]=STACK;c.run(0x8190,0x81e6,100)
    assert c.read(ACTOR,68)==bytes(30)+b'\xff'+bytes(37)
    assert get(c.memory,APP+0x772,2)==2 and get(c.memory,APP+0xa76)==0

@pytest.mark.parametrize('phase',(1,2))
def test_original_type98_dispatch_reaches_the_same_carried_update_in_both_phases(phase):
    c=machine();c.seed(ACTOR+2,b'\0');c.seed(ACTOR+28,b'\1');before=c.read(ACTOR,68)
    c.run(0x8002 if phase==1 else 0x8210,0x81e6 if phase==1 else 0x83b0,300)
    expected=bytearray(before)
    for off,value in ((4,10000),(8,-880),(12,20000)):put(expected,off,value)
    expected[16:22]=bytes(6)
    assert c.read(ACTOR,68)==expected and get(c.memory,APP+0xa76)==ACTOR

@pytest.mark.parametrize('phase',(0,1,2,255))
@pytest.mark.parametrize('retract',(0,128))
def test_reference_service_detonates_only_phase_one_before_adjusting_offset(phase,retract):
    c=machine();c.seed(ACTOR+30,bytes([phase]));c.seed(APP+0xae4,bytes([retract]))
    c.run(0x348e0,0x349ea,5000)
    assert get(c.memory,APP+0xa76)==(0 if phase==1 else ACTOR)
    assert get(c.memory,APP+0x720)==(118 if retract>=128 else 120)
    assert c.read(APP+0xb47,1)==b'\1' and get(c.memory,ACTOR,2)==98
    assert c.read(APP+0xbb6,1)==bytes([255 if phase==1 else 0])
    assert get(c.memory,APP+0x772,2)==2

@pytest.mark.parametrize('spawn',(0,255))
@pytest.mark.parametrize('retract',(0,255))
def test_empty_inventory_requests_retraction_without_recycling_or_touching_actor(spawn,retract):
    c=machine();c.seed(APP+0xb47,b'\0');c.seed(APP+0xae3,bytes([spawn]));c.seed(APP+0xae4,bytes([retract]));before=c.read(ACTOR,68)
    c.run(0x79c0,RETURN,500)
    assert get(c.memory,APP+0xa76)==0 and c.read(APP+0xae3,2)==b'\0\xff'
    assert c.read(ACTOR,68)==before and get(c.memory,APP+0x720)==120 and get(c.memory,APP+0x772,2)==2

@pytest.mark.parametrize('retract',(0,1,128,255))
@pytest.mark.parametrize('offset',(0,19,20,21,22,119,120,121,0x7fffffff,0x80000000))
def test_extension_service_keeps_long_wrap_n_only_clamps_and_exact_minimum_retraction(retract,offset):
    c=machine();c.seed(APP+0xae4,bytes([retract]));put(c.memory,APP+0x720,offset)
    c.run(0x348e0,0x349ea,500)
    value=(offset+(-2 if retract>=128 else 2))&0xffffffff;bound=20 if retract>=128 else 120
    clamp=negative32(value-bound)if retract>=128 else not negative32(value-bound)
    if clamp:value=bound
    removed=retract>=128 and value==20
    assert get(c.memory,APP+0x720)==value and get(c.memory,APP+0xa76)==(0 if removed else ACTOR)
    assert c.read(APP+0xae4,1)==bytes([0 if removed else retract])
    assert get(c.memory,ACTOR,2)==(0 if removed else 98) and c.read(ACTOR+30,1)==b'\xff'
    assert c.read(APP+0xb47,1)==b'\1' and get(c.memory,APP+0x772,2)==2


def test_committed_source_types_the_neutron_callback_without_promoting_global_ownership():
    import json
    target=Path(__file__).resolve().parents[1]/'targets/starglider2_retail'
    s=(target/'rendered/retail-shared.s').read_text();metadata=json.loads((target/'target_metadata.json').read_text())
    assert 'tst.b SG2NeutronBomb_released_motion_negative_flag(a0)' in s
    assert 'subq.w #1,SG2NeutronBomb_service_countdown(a0)' in s
    assert 'move.w SG2ActorModelPrefix_velocity_y(a0),d3' in s
    assert 'st.b SG2NeutronBomb_released_motion_negative_flag(a2)' in s
    for name in ('update_nearby_neutron_bomb','update_distant_neutron_bomb'):
        body=s.split(name+':',1)[1].split('advance_neutron_bomb_state:',1)[0]
        assert 'dc.b' not in body and 'move.b' in body
    prefix=next(x for x in metadata['custom_structs'] if x['name']=='SG2WorkspaceReferencePrefix')
    for name in ('carried_neutron_bomb_reference','nearby_space_station_reference'):
        field=next(f for f in prefix['fields'] if f['name']==name)
        assert field['value_kind']=='scalar' and not field.get('pointer_struct')

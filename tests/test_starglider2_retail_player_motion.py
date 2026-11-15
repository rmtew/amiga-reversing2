"""Original retail player controls and real tunnel-pose consumption.

Reuse the earlier fixed-width oracles with retail addresses. These CPU slices
and supplied states do not prove full frame timing or arbitrary world inputs.
"""
import os,struct
from pathlib import Path
import pytest
from test_starglider2_retail_neutron import machine,APP,STACK,RETURN,shared_bytes
from test_starglider2_retail_workspace import put,get
from test_starglider2_retail_special_contacts import transition,enable_original_pool_rebuild,OBJECT,STRUCT
from tests.test_starglider2_control_normalization import signed,normalized_controls
from tests.test_starglider2_motion_integration import expected_vector,integrate_expected

pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
EJECT,SPIN,AFTER,HOLD=0x3b4c6,0x3b628,0x3b62a,0x3b614
YAW,PITCH,THROTTLE,TARGET,SPEED=0x7a2,0x7a4,0x7a8,0x758,0x75a

def setup():
    c=machine();c.seed(EJECT,b'\0');c.seed(SPIN,b'\xff\xff');c.seed(APP+0xbb9,b'\xff')
    c.allow_write(SPIN,4);c.allow_write(HOLD,2);return c

def call(c,start=0x30f68,stop=RETURN,steps=1000):
    c.cpu.a[6]=APP;c.cpu.a[7]=STACK;return c.run(start,stop,steps)

@pytest.mark.parametrize('eject',(0,127,128,255))
@pytest.mark.parametrize('free',(0,1,128,255))
@pytest.mark.parametrize('pose',(0,1,254,255))
@pytest.mark.parametrize('spin',(0,32767,32768,65535))
def test_mode_priority_is_signed_then_nonzero_then_signed_word(eject,free,pose,spin):
    c=setup();c.seed(EJECT,bytes([eject]));c.seed(APP+0xbb9,bytes([free]));c.seed(APP+0xbba,bytes([pose]));put(c.memory,SPIN,spin,2)
    before=c.read(APP,0xbbc)
    stop=RETURN if eject&128 else 0x3119e if not free&128 else 0x311f6 if pose else 0x31172 if spin<32768 else 0x30f90
    call(c,stop=stop,steps=30);assert c.read(APP,0xbbc)==before

@pytest.mark.parametrize('pose',range(256))
def test_direct_pose_continuation_keeps_zero_entry_distinct_from_normal_caller(pose):
    c=setup();c.seed(APP+0xbba,bytes([pose]));fields=(YAW,PITCH,0x744,0x746,0x748)
    for off in fields:put(c.memory,APP+off,0x1234,2)
    call(c,0x311f6)
    expected=(0,0,0,0,0) if pose==255 else (0,0,0,2048,0) if pose==254 else (0x1234,1020,1020,0x1234,0x1234)
    assert tuple(get(c.memory,APP+off,2)for off in fields)==expected and c.read(APP+0xbba,1)==bytes([pose])

@pytest.mark.parametrize('phase',(0,2,4090,1,4095))
def test_settling_halves_signed_controls_and_only_exact_zero_reenables_free_flight(phase):
    c=setup();fields=(YAW,PITCH,0x7a6,THROTTLE,TARGET,SPEED);initial=(-32768,-1,1,3,-3,32767)
    for off,value in zip(fields,initial):put(c.memory,APP+off,value,2)
    put(c.memory,APP+0x744,phase,2);c.seed(APP+0xbb9,b'\x11');call(c,0x3119e)
    result=(phase+6)&4095
    assert get(c.memory,APP+0x744,2)==result and c.read(APP+0xbb9,1)==bytes([255 if result==0 else 17])
    assert [get(c.memory,APP+off,2)for off in fields]==[(v>>1)&65535 for v in initial]

@pytest.mark.parametrize('count',(0,1,2,63,64,32767,32768,65535))
def test_spin_decrements_before_sign_test_and_restores_unmasked_word(count):
    c=setup();put(c.memory,SPIN,count,2);put(c.memory,AFTER,0xfedc,2);put(c.memory,APP+0x748,4095,2)
    call(c,0x31172);n=signed(count-1)
    assert get(c.memory,SPIN,2)==(65535 if n<0 else n)
    assert get(c.memory,APP+0x748,2)==(0xfedc if n<0 else (4095+64)&4095)

@pytest.mark.parametrize('pitch',(-32768,-1601,-1600,-49,-48,-1,0,1,48,49,1600,1601,32767))
@pytest.mark.parametrize('speed',(-32768,-480,-479,-1,0,1,32767))
def test_normal_controls_reuse_original_clamps_and_dead_band(pitch,speed):
    c=setup();put(c.memory,APP+PITCH,pitch,2);put(c.memory,APP+THROTTLE,speed,2);put(c.memory,APP+YAW,-1,2)
    call(c,0x30ff2,0x310c0)
    p,s,r,step,target,bias=normalized_controls(pitch,speed,yaw=-1)
    assert [get(c.memory,APP+off,2)for off in (PITCH,THROTTLE,0x748,0x1c8,TARGET)]==[v&65535 for v in (p,s,r,step,target)]

@pytest.mark.parametrize('dock,phase,clamp,hold',((0,0,0,0),(1,29,0,0),(255,30,0,0),(1,31,1,0),(0,0,1,0),(0,0,0,65535)))
@pytest.mark.parametrize('pitch,bias',((-1,2),(0,1),(9,255),(1601,2)))
def test_exit_bias_follows_height_step_and_braking_uses_pre_increment_speed(dock,phase,clamp,hold,pitch,bias):
    c=setup()
    for off,value in ((PITCH,pitch),(THROTTLE,-479),(0x796,phase)):put(c.memory,APP+off,value,2)
    for off,value in ((0x7ec,dock),(0x786,bias),(0x7e4,clamp)):c.seed(APP+off,bytes([value]))
    put(c.memory,HOLD,hold,2);call(c,0x30ff2,0x310c0)
    p,s,r,step,target,b=normalized_controls(pitch,-479,dock=dock,phase=phase,bias=bias,clamp=clamp,hold=hold)
    assert [get(c.memory,APP+off,2)for off in (PITCH,THROTTLE,0x1c8,TARGET)]==[v&65535 for v in (p,s,step,target)]
    assert c.read(APP+0x786,1)==bytes([b])

@pytest.mark.parametrize('current,target',((-32768,32767),(-1,0),(0,1),(1,0),(5,6),(6,5),(16,1),(24,1),(25,1),(100,479),(479,100),(32767,-32768)))
@pytest.mark.parametrize('space',(0,128))
def test_speed_adjustment_keeps_n_only_word_comparisons(current,target,space):
    c=setup();put(c.memory,APP+SPEED,current,2);put(c.memory,APP+TARGET,target,2);c.seed(APP+0x77d,bytes([space]));expected=current&65535
    if target&65535!=current&65535:
        if signed(target-current)>=0:
            expected=(current+6)&65535
            if signed(target-expected)>=0:expected=target&65535
        else:
            expected=(current-16)&65535 if space&128 else (current-24)&65535
            if not space&128 and signed(expected)<0:expected=(expected-16)&65535
            if signed(expected)<0:expected=0
    call(c,0x30f96,0x30fcc);assert get(c.memory,APP+SPEED,2)==expected

@pytest.mark.parametrize('angles',((0,0,0),(1,1023,2048),(4095,4096,65535),(32768,32767,1)))
@pytest.mark.parametrize('speed',(-32768,-1,0,1,32767))
def test_original_motion_helper_keeps_each_fixed_point_multiply_stage(angles,speed):
    c=setup()
    for off,value in zip((0x744,0x746,0x748),angles):put(c.memory,APP+off,value,2)
    tables=tuple(get(c.memory,APP+off)for off in (0x44,0x48));expected,scratch=expected_vector(c.memory,angles,speed,tables=tables)
    c.cpu.d[3]=0xabcd0000|(speed&65535);call(c,0x38bd4)
    assert list(c.cpu.d[4:7])==expected and [get(c.memory,APP+off,2)for off in range(0x164,0x16e,2)]==scratch

@pytest.mark.parametrize('side',(0,1))
def test_real_tunnel_entry_pose_is_consumed_before_contact_service_clears_it(side):
    c=transition();enable_original_pool_rebuild(c);c.seed(APP+0xbb9,b'\xff');c.seed(STRUCT+36,bytes([side]));c.seed(EJECT,b'\0');c.seed(SPIN,b'\xff\xff')
    c.cpu.a[0]=OBJECT;c.cpu.a[2]=STRUCT;c.cpu.a[6]=APP;c.run(0xb93a,RETURN,200000)
    assert c.read(APP+0xbb9,1)==b'\xff' and c.read(APP+0xbba,1)==bytes([255 if not side else 254])
    call(c);assert [get(c.memory,APP+o,2)for o in (0x744,0x746,0x748)]==[0,2048 if side else 0,0]
    # The motion consumer retains the pose; the later real contact service
    # clears it. Explicit empty contact count is valid after the new pool.
    put(c.memory,APP+0x762,0,2);call(c,0xb568)
    assert c.read(APP+0xbba,1)==b'\0'
    call(c);assert c.cpu.a[7]==STACK+4  # Original vector helper and guard pass.


def test_real_surface_return_pose_then_normal_controls_apply_exit_bias():
    c=transition();enable_original_pool_rebuild(c);c.seed(APP+0xbb9,b'\xff');c.seed(EJECT,b'\0');c.seed(SPIN,b'\xff\xff')
    put(c.memory,APP+0x798,19,2);put(c.memory,APP+0x70c,20600);c.seed(APP+0x77c,b'\xff');c.cpu.a[2]=STRUCT;c.run(0xbdba,RETURN,200000)
    call(c);assert get(c.memory,APP+PITCH,2)==get(c.memory,APP+0x744,2)==1020
    put(c.memory,APP+0x762,0,2);call(c,0xb568);call(c)
    assert get(c.memory,APP+PITCH,2)==1010 and get(c.memory,APP+0x744,2)==505
    assert get(c.memory,APP+0x1c8,2)==(-63)&65535 and c.read(APP+0x786,1)==b'\x65'

@pytest.mark.parametrize('world_y',(-0x80000000,-121,-120,-119,0,0x7fffffff))
@pytest.mark.parametrize('space',(0,128))
@pytest.mark.parametrize('dock',(0,1))
def test_heading_and_height_use_pre_bias_step_with_original_n_only_ground_guard(world_y,space,dock):
    c=setup();put(c.memory,APP+PITCH,1601,2);put(c.memory,APP+THROTTLE,-100,2);c.seed(APP+0x786,b'\2');c.seed(APP+0x7ec,bytes([dock]))
    call(c,0x30ff2,0x310c0);assert get(c.memory,APP+0x1c8,2)==(-100)&65535
    put(c.memory,APP+0x708,world_y);c.seed(APP+0x77d,bytes([space]));put(c.memory,APP+0x16c,-257,2);put(c.memory,APP+0x746,4090,2)
    call(c,0x310c0,0x31104)
    assert get(c.memory,APP+0x746,2)==(4090 if dock else (4090+(-257>>(6 if space&128 else 8)))&4095)
    moved=not dock and not space&128 and signed(world_y+120,32)>=0
    assert get(c.memory,APP+0x708)==(world_y-100 if moved else world_y)&0xffffffff

@pytest.mark.parametrize('impulse',(-32768,-3,-2,-1,0,1,2,3,32767))
@pytest.mark.parametrize('fixed',(0,255))
def test_damage_impulse_decay_and_fixed_or_control_aim_keep_word_behavior(impulse,fixed):
    c=setup();control=-32768
    for off,value in ((0x78e,impulse),(0x748,65535),(PITCH,control),(YAW,control),(0x19c,32767),(0x19e,-32768)):put(c.memory,APP+off,value,2)
    c.seed(APP+0x7e6,bytes([fixed]));call(c,0x31104)
    assert get(c.memory,APP+0x748,2)==(65535+impulse)&65535
    assert get(c.memory,APP+0x78e,2)==(impulse+(2 if impulse<0 else -2 if impulse>0 else 0))&65535
    x=0 if fixed else control>>2;y=0 if fixed else signed(-control)>>3
    assert [get(c.memory,APP+off,2)for off in (0x76a,0x76c,0x766,0x768)]==[v&65535 for v in (x,y,x+32767,y-32768)]

@pytest.mark.parametrize('collision',(0,127,128,255))
@pytest.mark.parametrize('mask',(0,65535,0xffffff,0xffffffff,0x80000001))
def test_actual_world_service_integrates_signed_words_twice_then_wraps_only_xz(collision,mask):
    c=setup();world=(0x7fffffff,0xffffffff,0x80000000);motion=(-32768,-1,32767)
    for off,value in zip((0x704,0x708,0x70c),world):put(c.memory,APP+off,value)
    for off,value in zip((0x74a,0x74c,0x74e),motion):put(c.memory,APP+off,value,2)
    put(c.memory,APP+0x6fc,mask);c.seed(APP+0x7ce,bytes([collision]));put(c.memory,APP+TARGET,123,2);put(c.memory,APP+SPEED,456,2)
    call(c,0x359c6,0x35a06)
    assert [get(c.memory,APP+off)for off in (0x704,0x708,0x70c)]==integrate_expected(world,motion,mask,collision)
    assert get(c.memory,APP+TARGET,2)==(0 if collision&128 else 123)
    assert get(c.memory,APP+SPEED,2)==(0 if collision&128 else 456)


def test_motion_publish_then_later_collision_integration_then_zero_motion():
    c=setup();put(c.memory,APP+SPEED,20,2);put(c.memory,APP+TARGET,20,2);c.seed(APP+0x7ce,b'\xff')
    before=tuple(get(c.memory,APP+off)for off in (0x704,0x708,0x70c));call(c)
    motion=[get(c.memory,APP+off,2)for off in (0x74a,0x74c,0x74e)];assert any(motion)
    assert tuple(get(c.memory,APP+off)for off in (0x704,0x708,0x70c))==before
    mask=get(c.memory,APP+0x6fc);call(c,0x359c6,0x35a06)
    assert [get(c.memory,APP+off)for off in (0x704,0x708,0x70c)]==integrate_expected(before,motion,mask,255)
    assert get(c.memory,APP+TARGET,2)==get(c.memory,APP+SPEED,2)==0
    call(c);assert c.read(APP+0x74a,6)==bytes(6)
    # Separate original service calls, not an asserted full-frame trace: the
    # main loop runs world service before producing the next motion vector.


def test_retail_instruction_guard_is_observed_before_motion_stores():
    c=setup();assert c.read(0x3a5e,2)==b'\x4a\x50'
    c.cpu.d[4],c.cpu.d[5],c.cpu.d[6]=1,2,3;call(c,0x30fdc,0x30ff2)
    assert c.read(APP+0x74a,6)==struct.pack('>3H',1,2,3)
    c=setup();c.seed(0x3a5e,b'\0\0');before=c.read(APP+0x74a,6);call(c,0x30fdc,0x30fb2,4)
    assert c.read(APP+0x74a,6)==before


def test_rendered_player_motion_fields_and_real_guard_are_retained():
    path=os.getenv('SGII_RETAIL_RENDERED_SOURCE')
    if not path:pytest.skip('set SGII_RETAIL_RENDERED_SOURCE to regenerated source')
    text=Path(path).read_text()
    for name in ('update_player_flight_controls:','apply_structure_contact_pose_continuation:',
                 'build_player_motion_vector:','integrate_signed_player_motion_words:',
                 'SG2PlayerMotionWorkspace_rotation_0_control_accumulator(a6)',
                 'player_rotation2_spin_steps:','player_rotation2_after_spin:'):
        assert name in text
    assert 'cmpi.w #19024,$00003A5E.l' in text

@pytest.mark.parametrize('bonus,speed,enabled,field,space',(
    (0,1,1,128,128),(15900,300,1,128,128),(16000,300,1,128,128),(32767,300,1,128,128),
    (0,0,1,0,128),(1,0,1,0,128),(16000,1,0,128,128),(-32768,0,1,128,128),
    (15999,300,1,127,128),(16000,299,1,255,128),(16000,300,1,128,0)))
def test_space_service_orders_field_notice_before_bonus_ramp_and_motion(bonus,speed,enabled,field,space):
    c=setup();put(c.memory,APP+0xa74,bonus,2);put(c.memory,APP+SPEED,speed,2);put(c.memory,APP+0x9ae,enabled,2)
    c.seed(APP+0xa9d,bytes([field]));c.seed(APP+0x77d,bytes([space]));c.seed(APP+0xbb6,b'\x55');c.allow_write(0x3b62c,2);c.seed(0x3b62c,b'\x12\x34')
    old=(0x7fffffff,0xffffffff,0x80000000);motion=(-32768,-1,32767)
    for off,value in zip((0x704,0x708,0x70c),old):put(c.memory,APP+off,value)
    for off,value in zip((0x74a,0x74c,0x74e),motion):put(c.memory,APP+off,value,2)
    mask=get(c.memory,APP+0x6fc);expected_bonus=bonus&65535;expected_field=field;gray=0x1234;sound=0x55
    if space&128:
        if field&128:
            if signed(bonus-16000)<0 or signed(speed-300)<0:expected_field=255
            else:expected_field=0;gray=15;sound=255
        if not speed&65535 or not enabled:
            expected_field=255;expected_bonus=(bonus-300)&65535
            if signed(expected_bonus)<0:expected_bonus=0
        else:
            expected_bonus=(bonus+100)&65535
            if signed(expected_bonus-16000)>=0:expected_bonus=16000
    call(c,0x35952,0x35a06)
    assert get(c.memory,APP+0xa74,2)==expected_bonus and c.read(APP+0xa9d,1)==bytes([expected_field])
    assert get(c.memory,0x3b62c,2)==gray and c.read(APP+0xbb6,1)==bytes([sound])
    assert [get(c.memory,APP+off)for off in (0x704,0x708,0x70c)]==(integrate_expected(old,motion,mask,0)if space&128 else list(old))

@pytest.mark.parametrize('angles',((0,0,0),(65535,4096,1024)))
@pytest.mark.parametrize('entry',(0x38bb8,0x38bc6))
def test_object_motion_entry_uses_the_same_qualified_vector_body(angles,entry):
    c=setup()
    for off,value in zip((16,18,20),angles):put(c.memory,OBJECT+off,value,2)
    tables=tuple(get(c.memory,APP+off)for off in (0x44,0x48));expected,_=expected_vector(c.memory,angles,479,tables=tables)
    c.cpu.a[0]=OBJECT;c.cpu.a[2]=OBJECT;c.cpu.d[3]=479;call(c,entry);assert list(c.cpu.d[4:7])==expected

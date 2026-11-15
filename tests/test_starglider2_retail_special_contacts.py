"""Original retail structure profiles, transition gates and tower-link effects.

Supplied record backing and conditional profile selectors are explicit. No
complete transition, arbitrary pointer safety or full-mission claim follows.
"""
import os,struct
from pathlib import Path
import pytest
from test_starglider2_retail_contacts import setup as contact_machine,OUTER,INNER,LIST,APP,STACK,RETURN,POS,shared_bytes,response,player
from test_starglider2_retail_workspace import put,get
from tests.test_starglider2_structure_profiles import expected,position_at
from tests.test_starglider2_scan_acquisition import signed16
from tests.test_starglider2_corner_depot_links import corner_bounds,corner_expected
from tests.test_starglider2_type90_service import reference as service_reference

pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
OBJECT,STRUCT=OUTER,INNER
TABLES=((0xc448,0xc460),(0xc478,0xc490))

def setup(selector=0,family=0,kind=1):
    c=contact_machine(outer=kind,inner=66 if family==0 else 67)
    c.seed(STRUCT+2,b'\x40');put(c.memory,STRUCT+40,selector,2);put(c.memory,STRUCT+4,10000);put(c.memory,STRUCT+12,20000)
    put(c.memory,APP+0x700,OBJECT);put(c.memory,APP+0x6fc,65535)
    for off,value in ((44,32768),(46,65535),(48,1)):put(c.memory,OBJECT+off,value,2)
    c.seed(APP+0x7e4,b'\0');c.allow_write(0x3b614,2);return c

def profile(c,selector,family,position,is_player):
    c.cpu.a[2]=STRUCT
    if is_player:
        for off,value in zip((0x704,0x708,0x70c),position):put(c.memory,APP+off,value)
        c.cpu.a[1],c.cpu.a[3]=TABLES[family];c.run(0xbb56,RETURN,500)
        return tuple(get(c.memory,APP+off)for off in (0x704,0x708,0x70c))
    for off,value in zip((4,8,12),position):put(c.memory,OBJECT+off,value)
    response(c,'outer');return tuple(get(c.memory,OBJECT+off)for off in (4,8,12))

@pytest.mark.parametrize('family',range(2))
@pytest.mark.parametrize('selector',range(6))
@pytest.mark.parametrize('difference',(-501,-500,0,500,501))
def test_player_profile_thresholds(family,selector,difference):
    c=setup(selector,family);p=position_at(c.memory,selector,family,difference,tables=TABLES)
    result,_,clamp,yclamp=expected(c.memory,selector,family,p,True,tables=TABLES)
    assert profile(c,selector,family,p,True)==result
    assert c.read(APP+0x7e4,1)==bytes([255 if clamp or yclamp else 0])

@pytest.mark.parametrize('family',range(2))
@pytest.mark.parametrize('selector',(1,2,3,5))
@pytest.mark.parametrize('cross',(-65537,-65536,-1,0,1,65535,65536,65537))
def test_only_x_slope_truncates_shifted_correction_to_word(family,selector,cross):
    c=setup(selector,family);p=position_at(c.memory,selector,family,1000,cross=cross,tables=TABLES)
    assert profile(c,selector,family,p,True)==expected(c.memory,selector,family,p,True,tables=TABLES)[0]

@pytest.mark.parametrize('family',range(2))
@pytest.mark.parametrize('selector',range(6))
@pytest.mark.parametrize('kind',(1,84,103))
@pytest.mark.parametrize('difference',(-551,-550,0,550,551))
def test_object_profiles_and_type_scoped_velocity_reflection(family,selector,kind,difference):
    c=setup(selector,family,kind);p=position_at(c.memory,selector,family,difference,y=-1000,tables=TABLES)
    result,axis,clamp,_=expected(c.memory,selector,family,p,False,tables=TABLES)
    assert profile(c,selector,family,p,False)==result
    velocities=[32768,65535,1]
    if kind in (84,103) and clamp:
        index=0 if axis=='x'else 2;velocities[index]=(-velocities[index])&65535
    assert [get(c.memory,OBJECT+o,2)for o in (44,46,48)]==velocities

@pytest.mark.parametrize('is_player',(False,True))
@pytest.mark.parametrize('y',(-0x80000000,-2769,-2768,-2760,-591,-590,-589,-411,-410,-409,0,1,0x7fffffff))
def test_asymmetric_vertical_clamps(is_player,y):
    c=setup(kind=103);p=position_at(c.memory,0,0,0,y=y,tables=TABLES)
    result,_,_,yclamp=expected(c.memory,0,0,p,is_player,tables=TABLES)
    assert profile(c,0,0,p,is_player)==result
    if not is_player:assert get(c.memory,OBJECT+46,2)==(1 if yclamp else 65535)

@pytest.mark.parametrize('response_flag',(0,255))
@pytest.mark.parametrize('motion',((1,2,3),(-1,-2,-3),(32767,-32768,-1)))
def test_player_motion_prefix_sign_extends_words_before_doubling(response_flag,motion):
    c=setup();c.seed(APP+0x7ce,bytes([response_flag]));start=(65535,0x7fffffff,1)
    for off,value in zip((0x704,0x708,0x70c),start):put(c.memory,APP+off,value)
    for off,value in zip((0x74a,0x74c,0x74e),motion):put(c.memory,APP+off,value,2)
    c.cpu.a[2]=STRUCT;c.cpu.a[1],c.cpu.a[3]=TABLES[0];c.run(0xbb06,0xbb56,100)
    sign=-1 if response_flag else 1;result=[(a+sign*2*b)&0xffffffff for a,b in zip(start,motion)];result[0]&=65535;result[2]&=65535
    assert [get(c.memory,APP+off)for off in (0x704,0x708,0x70c)]==result

@pytest.mark.parametrize('kind',(48,66,67,68,69,70,85,92,94))
def test_structure_selection_recognizes_nine_types_and_copies_room_byte(kind):
    c=setup();put(c.memory,APP+0x762,1,2);c.seed(LIST,STRUCT.to_bytes(4,'big'));put(c.memory,STRUCT,kind,2);c.seed(STRUCT+37,b'\xfe')
    c.allow_write(0x3b614,2);c.seed(0x3b614,b'\x12\x34');c.cpu.a[2]=OBJECT;c.run(0xba20,0xbaac,200)
    assert c.cpu.a[2]==STRUCT and c.cpu.a[0]==OBJECT and c.read(APP+0x77e,1)==b'\xfe' and c.read(0x3b614,2)==b'\0\0'

@pytest.mark.parametrize('records,selected',(
    (((66,(1,2,3),1),(67,(2,2,2),2)),1),(((66,(1,1,1),1),(67,(2,2,2),2)),0),
    (((2,(0,0,0),0),(66,(20,0,0),1)),1),(((66,(1,1,1),1),(67,(-32768,0,0),2)),1)))
def test_structure_selection_last_tie_and_word_neg_minimum(records,selected):
    c=setup();put(c.memory,APP+0x762,len(records),2)
    for i,(kind,xyz,room)in enumerate(records):
        at=STRUCT+96*i;c.seed(at,bytes(68));put(c.memory,LIST+4*i,at);put(c.memory,at,kind,2);c.seed(at+37,bytes([room]))
        for off,value in zip((22,24,26),xyz):put(c.memory,at+off,value,2)
    c.allow_write(0x3b614,2);c.cpu.a[2]=OBJECT;c.run(0xba20,0xbaac,300)
    assert c.cpu.a[2]==STRUCT+96*selected

@pytest.mark.parametrize('kind,excluded',((65,6),(63,9)))
@pytest.mark.parametrize('variant',(0,5,6,7,8,9,10,255))
@pytest.mark.parametrize('durability',(1,128))
def test_player_gate_and_door_only_skip_exact_variants(kind,excluded,variant,durability):
    c=setup();_,other=player(c,'outer',kind,durability);c.seed(other+3,bytes([variant]));response(c,'outer')
    skipped=variant==excluded
    assert get(c.memory,APP+0x6f0)==(0xffffffff if skipped else 0)
    assert c.read(APP+0x7cf,1)==bytes([0 if skipped else 3]) and c.read(APP+0x7ce,1)==bytes([0 if skipped else 255])
    assert c.read(other+30,1)==bytes([0 if not skipped and durability<128 else 255])

@pytest.mark.parametrize('kind',(63,65))
@pytest.mark.parametrize('variant',(0,3,4,6,9,127,128,255))
def test_nonplayer_door_uses_signed_greater_than_three_but_gate_uses_exact_six(kind,variant):
    c=setup(kind=1);put(c.memory,STRUCT,kind,2);c.seed(STRUCT+3,bytes([variant]));response(c,'outer')
    blocked=(3<variant<128) if kind==63 else variant==6
    assert c.read(OBJECT+30,1)==bytes([255 if blocked else 0])


def tower(kind=90,orientation=0,actor=30):
    c=setup(kind=actor);put(c.memory,STRUCT,kind,2);c.seed(STRUCT+2,b'\0');put(c.memory,STRUCT+18,orientation,2)
    put(c.memory,OBJECT+4,11801 if orientation else 10000);put(c.memory,OBJECT+12,20000);return c

@pytest.mark.parametrize('power',(0,65534,65535))
@pytest.mark.parametrize('shield',(0,65534,65535))
@pytest.mark.parametrize('weapon',(0,65534,65535))
@pytest.mark.parametrize('speed',(0,1,32768,65535))
def test_zero_orientation_resource_order_word_carries_and_bonus(power,shield,weapon,speed):
    c=tower();before=(power,shield,weapon)
    for off,value in zip((0x774,0x776,0x794),before):put(c.memory,APP+off,value,2)
    put(c.memory,APP+0x75a,speed,2);put(c.memory,APP+0x6ec,-1)
    result,bonus=service_reference(before,(speed*2)&65535,0xffffffff)
    response(c,'outer')
    assert tuple(get(c.memory,APP+off,2)for off in (0x774,0x776,0x794))==tuple(result)
    assert get(c.memory,APP+0x6ec)==bonus
    assert c.read(APP+0x209,1)==b'\xff'

@pytest.mark.parametrize('power',(0,65135,65136,65535))
@pytest.mark.parametrize('orientation',(1,65535))
def test_nonzero_orientation_adds_wrapping_400_only_to_player_power(power,orientation):
    c=tower(orientation=orientation)
    for off,value in ((0x774,power),(0x776,123),(0x794,456)):put(c.memory,APP+off,value,2)
    response(c,'outer')
    assert [get(c.memory,APP+off,2)for off in (0x774,0x776,0x794)]==[(power+400)&65535,123,456]
    assert c.read(APP+0x209,1)==b'\0'

@pytest.mark.parametrize('kind',(4,90,93,96,97))
def test_tower_actor_exclusions_precede_link_and_resource_effects(kind):
    c=tower(actor=kind);put(c.memory,STRUCT+56,0x68080);put(c.memory,APP+0x774,123,2)
    # Link backing intentionally absent: a filter must return before reading it.
    response(c,'outer');assert get(c.memory,APP+0x774,2)==123 and c.read(APP+0x209,1)==b'\0'

NODE,NEXT,LAST=0x61200,0x61300,0x61400

def node(c,at,kind=90,link=0):
    b=bytearray(b'\x55'*68);put(b,0,kind,2);put(b,60,link);c.seed(at,b);c.allow_write(at,68);return b

@pytest.mark.parametrize('orientation',(0,1))
@pytest.mark.parametrize('kind',(0,1,90,93,65535))
@pytest.mark.parametrize('delta',(-1,0,1))
def test_type93_threshold_and_orientation_specific_link_mutations(orientation,kind,delta):
    c=tower(kind=93,orientation=orientation,actor=1);before=node(c,NODE,kind);put(c.memory,STRUCT+56,NODE)
    put(c.memory,OBJECT+(4 if orientation else 12),(10000 if orientation else 20000)+1800+delta)
    response(c,'outer');result=bytearray(before)
    if delta>=0:
        if orientation and kind:put(result,60,0)
        elif not orientation and kind==90:result[3]=0;result[34]=result[40]=255
    assert c.read(NODE,68)==result

@pytest.mark.parametrize('orientation',(0,1))
@pytest.mark.parametrize('height',(-1001,-1000,0))
@pytest.mark.parametrize('across',(-201,-200,-199,0,200,201))
def test_type90_chain_strip_has_strict_lower_inclusive_upper_and_height_gate(orientation,height,across):
    c=tower(orientation=orientation,actor=1);before=node(c,NODE);put(c.memory,STRUCT+56,NODE);put(c.memory,OBJECT+8,height)
    put(c.memory,OBJECT+(12 if orientation else 4),(20000 if orientation else 10000)+across)
    put(c.memory,OBJECT+(4 if orientation else 12),(10000+1800 if orientation else 20000-1800))
    response(c,'outer');result=bytearray(before)
    if height>=-1000 and -200<across<=200:result[3]=0;result[34]=result[40]=255
    assert c.read(NODE,68)==result


def test_type90_chain_marks_forward_nodes_until_first_wrong_type_and_preserves_other_bytes():
    c=tower(actor=1);a=node(c,NODE,90,NEXT);b=node(c,NEXT,90,LAST);last=node(c,LAST,99)
    put(c.memory,STRUCT+56,NODE);put(c.memory,STRUCT+60,NEXT);put(c.memory,OBJECT+12,18000)
    response(c,'outer');a[3]=0;a[34]=a[40]=255;b[40]=255
    assert c.read(NODE,68)==a and c.read(NEXT,68)==b and c.read(LAST,68)==last


def test_type90_cyclic_forward_links_have_no_implicit_iteration_guard():
    c=tower(actor=1);node(c,NODE,90,NODE);put(c.memory,STRUCT+56,NODE);put(c.memory,STRUCT+60,NODE);put(c.memory,OBJECT+12,18000)
    c.cpu.a[0]=OBJECT;c.cpu.a[2]=STRUCT;c.cpu.a[6]=POS;c.cpu.a[7]=STACK
    r=c.run(0xb93a,0xb904,500,expected_stop='limit')
    assert r['stop']=='instruction_limit' and 0xc2fe<=c.cpu.pc<0xc318 and c.cpu.a[7]==STACK-60


def transition():
    c=setup(kind=30);put(c.memory,STRUCT,48,2)
    for off,value in ((0x704,10000),(0x708,-290),(0x70c,20000)):put(c.memory,APP+off,value)
    put(c.memory,APP+0x744,201,2);put(c.memory,APP+0x798,3,2);put(c.memory,APP+0x6fc,-1);put(c.memory,APP+0xa76,0)
    c.seed(APP+0x77c,b'\0');c.seed(APP+0x77d,b'\0');c.seed(APP+0x77e,b'\x7b');c.seed(APP+0xbba,b'\7');c.allow_write(0xe144,2)
    c.allow_write(0xc4d8,1)
    return c

def enable_original_pool_rebuild(c):
    for at,size in ((0x1a1f8,4),(0x1a1fc,4),(0x1a224,1),(0x1a210,4)):c.allow_write(at,size)

@pytest.mark.parametrize('rotation',(-32768,-201,-200,0,200,201,32767))
@pytest.mark.parametrize('difference',(-65536,-711,-710,-1,0,710,711,32768))
def test_entry_heading_and_cross_gate_preserve_low_word_aliases(rotation,difference):
    c=transition();put(c.memory,APP+0x744,rotation,2);put(c.memory,APP+0x704,10000-difference)
    allowed=(((-rotation if rotation<0 else rotation)&65535)>200 and signed16(-difference if difference<0 else difference)<=710)
    c.cpu.a[0]=OBJECT;c.cpu.a[2]=STRUCT;c.run(0xb93a,0xbf10 if allowed else 0xb9ae,200)

@pytest.mark.parametrize('orientation',(0,1))
@pytest.mark.parametrize('difference',(-65536,-1,575,576,32767,32768,65535,65536,66112))
def test_exit_threshold_is_signed_low_word_after_original_motion_prefix(orientation,difference):
    c=transition();put(c.memory,STRUCT+18,orientation,2)
    put(c.memory,APP+0x70c,20000+(-difference if orientation else difference));c.cpu.a[2]=STRUCT
    c.run(0xbdba,0xbe22 if signed16(difference)>575 else 0xbaec,100)

@pytest.mark.parametrize('surface',(0,3,15))
@pytest.mark.parametrize('side',(0,1))
def test_complete_original_entry_rebuilds_interior_pool_without_replacing_the_constructor(surface,side):
    from test_starglider2_retail_world_placement import catalogue
    c=transition();enable_original_pool_rebuild(c);put(c.memory,APP+0x798,surface,2);c.seed(STRUCT+36,bytes([side]))
    c.cpu.a[0]=OBJECT;c.cpu.a[2]=STRUCT;c.cpu.a[6]=POS;c.run(0xb93a,RETURN,200000)
    world=(surface+16)&31;m=next(m for m in catalogue()['unique_maps']if world in m['indices'])
    assert get(c.memory,APP+0x798,2)==world and c.read(APP+0x77c,1)==b'\xff'
    assert c.read(APP+0xbba,1)==bytes([255 if side==0 else 254])
    assert get(c.memory,APP+0x700)==APP+0x2330 and get(c.memory,APP+0x2330,2)==30
    assert get(c.memory,APP+0x772,2)==249-m['count'] and get(c.memory,APP+0x172,2)==250
    assert c.cpu.a[6]==APP and c.cpu.a[7]==STACK+4 and c.read(APP+0x6598,4)==b'\xcc'*4

@pytest.mark.parametrize('interior',(16,19,31))
def test_complete_original_exit_rebuilds_surface_pool_and_returns_to_caller(interior):
    c=transition();enable_original_pool_rebuild(c);put(c.memory,APP+0x798,interior,2);put(c.memory,APP+0x70c,20600)
    c.seed(APP+0x77c,b'\xff');c.cpu.a[2]=STRUCT;c.run(0xbdba,RETURN,200000)
    assert get(c.memory,APP+0x798,2)==(interior-16)&15 and c.read(APP+0x77c,1)==b'\0'
    assert get(c.memory,APP+0x700)==APP+0x2330 and get(c.memory,APP+0x2330,2)==30
    assert c.read(APP+0xbba,1)==b'\2' and c.read(APP+0x786,1)==b'\x66'
    assert c.cpu.a[7]==STACK+4 and c.read(APP+0x6598,4)==b'\xcc'*4

@pytest.mark.parametrize('bomb',(0,1,0x80000000))
def test_exit_snapshots_only_nonnull_bomb_presence_before_rebuilding_pool(bomb):
    c=transition();put(c.memory,APP+0x798,19,2);put(c.memory,APP+0xa76,bomb);c.cpu.a[2]=STRUCT
    c.run(0xbe22,0xbe9c,150)
    assert c.read(0xc4d8,1)==bytes([255 if bomb else 0])
    assert get(c.memory,APP+0x798,2)==3 and get(c.memory,APP+0x6fc)==get(shared_bytes(),0x17f62+4*3)


def test_contact_link_request_drives_original_type90_to_type93_and_restore_inhibit():
    c=tower(actor=1);c.seed(NODE,bytes(68));c.allow_write(NODE,68);put(c.memory,NODE,90,2);put(c.memory,NODE+12,12000)
    put(c.memory,STRUCT+56,NODE);put(c.memory,OBJECT+12,18000);response(c,'outer')
    assert c.read(NODE+34,1)==c.read(NODE+40,1)==b'\xff'
    c.cpu.a[0]=NODE;c.cpu.a[6]=APP;c.run(0x89ee,0x81e6,100)
    assert get(c.memory,NODE,2)==93 and get(c.memory,NODE+12)==8000 and c.read(NODE+3,1)==b'\0'
    # Independent supplied flag changes distinguish both restore gates; they
    # do not claim an untraced writer clears these flags in ordinary gameplay.
    c.seed(NODE+40,b'\0');c.run(0x8a20,0x81e6,30);assert get(c.memory,NODE,2)==93
    c.seed(NODE+34,b'\0');c.run(0x8a20,0x81e6,30);assert get(c.memory,NODE,2)==90 and get(c.memory,NODE+12)==12000


def test_rendered_special_handlers_keep_distinct_profile_and_tower_record_views():
    path=os.getenv('SGII_RETAIL_RENDERED_SOURCE')
    if not path:pytest.skip('set SGII_RETAIL_RENDERED_SOURCE to regenerated source')
    text=Path(path).read_text()
    for name in ('constrain_player_to_structure_contacts:','filter_linked_type93_contact_actors:',
                 'filter_type90_contact_actor_ids:','apply_object_structure_profile_constraints:',
                 'world_horizontal_wrap_masks:','wide_structure_profile_x_offsets:',
                 'carried_bomb_presence_snapshot:','SG2EnergyTower_alternate_form_request(a4)',
                 'SG2StructureWorkspace_player_motion_x(a6)'):
        assert name in text

@pytest.mark.parametrize('orientation',(0,1))
@pytest.mark.parametrize('delta',(-100,0,100))
@pytest.mark.parametrize('kind',(None,1,84,103))
@pytest.mark.parametrize('edge',range(5))
def test_corner_bounds_keep_distinct_player_absolute_and_object_signed_slopes(orientation,delta,kind,edge):
    c=setup(kind=1 if kind is None else kind);put(c.memory,STRUCT,92,2);put(c.memory,STRUCT+18,orientation,2)
    lower,upper,z=corner_bounds(orientation,delta,kind is None);x=(lower-1,lower,lower+1,upper,upper+1)[edge];y=-500 if kind is None else -1000
    ex,ey,vx,retired,_,side=corner_expected(x,y,lower,upper,kind)
    if kind is None:
        for off,value in zip((0x704,0x708,0x70c),(x,y,z)):put(c.memory,APP+off,value)
        c.cpu.a[2]=STRUCT;c.run(0xbca6,RETURN,300)
        assert tuple(get(c.memory,APP+off)for off in (0x704,0x708,0x70c))==(ex,ey,z&0xffffffff)
        assert c.read(APP+0x7e4,1)==bytes([0 if side=='none'else 255])
    else:
        for off,value in zip((4,8,12),(x,y,z)):put(c.memory,OBJECT+off,value)
        put(c.memory,OBJECT+44,65535,2);response(c,'outer')
        assert tuple(get(c.memory,OBJECT+off)for off in (4,8,12))==(ex,ey,z&0xffffffff)
        assert get(c.memory,OBJECT+44,2)==vx and c.read(OBJECT+30,1)==bytes([0 if retired else 255])

@pytest.mark.parametrize('selector',(0,1))
@pytest.mark.parametrize('service',(0,255))
@pytest.mark.parametrize('delta',(575,576,65536+576,-1,32768))
def test_depot_player_approaches_copy_service_byte_and_snap_to_same_positive_z(selector,service,delta):
    c=setup(selector,kind=30);put(c.memory,STRUCT,94,2);c.seed(STRUCT+38,bytes([service]));z=20000-delta if selector else 20000+delta
    for off,value in zip((0x704,0x708,0x70c),(10000,-500,z)):put(c.memory,APP+off,value)
    put(c.memory,APP+0x6d8,0xcafe,2);c.cpu.a[2]=STRUCT;c.run(0xbd0e,0xbaec,200);snap=signed16(delta)>575
    assert get(c.memory,APP+0x6c2,2)==service and get(c.memory,APP+0x70c)==(20570 if snap else z)&0xffffffff
    assert c.read(APP+0x7ce,1)==bytes([255 if snap else 0]) and c.read(APP+0x7cf,1)==bytes([3 if snap else 0])
    assert get(c.memory,APP+0x6d8,2)==(63 if snap and not selector else 0xcafe)

@pytest.mark.parametrize('kind',(1,84,103))
@pytest.mark.parametrize('delta',(455,456))
@pytest.mark.parametrize('velocity',(1,65535,32768))
def test_depot_object_reverses_velocity_before_profile_for_all_three_types(kind,delta,velocity):
    c=setup(kind=kind);put(c.memory,STRUCT,94,2);put(c.memory,OBJECT+12,20000+delta);put(c.memory,OBJECT+48,velocity,2)
    c.cpu.a[0]=OBJECT;c.cpu.a[2]=STRUCT;c.cpu.a[6]=POS;c.run(0xb93a,0xbff8,300);snap=delta>455
    assert get(c.memory,OBJECT+12)==(20450 if snap else 20000+delta)
    assert get(c.memory,OBJECT+48,2)==((-velocity)&65535 if snap else velocity)

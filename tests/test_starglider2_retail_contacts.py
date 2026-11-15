"""Retail contact-list consumer, original geometry and ordered response effects.

Reuse the older Amiga arithmetic oracle with independently checked retail
addresses. Explicit records and list backing are preconditions, not a complete
mission or universal type/domain/lifetime proof.
"""
import os,struct
from pathlib import Path
import pytest
from test_starglider2_retail_neutron import machine,APP,STACK,RETURN,shared_bytes
from test_starglider2_retail_workspace import put,get
from test_starglider2_retail_frame_lists import setup as pool_setup,partition,pointers,POOL
from tests.test_starglider2_contact_eligibility import geometry

pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
OUTER,INNER,LIST=0x60000,0x61000,0x68000
H,NEG,POS=0x18918,0x189ea,0x18abc
TABLES=(H,NEG,POS)

def setup(outer=2,inner=1,scale=3,x=0,z=0,y=0):
    c=machine()
    for at,kind in ((OUTER,outer),(INNER,inner)):
        b=bytearray(68);put(b,0,kind,2);b[29]=scale;b[30]=255;c.seed(at,b);c.allow_write(at,68)
    put(c.memory,OUTER+50,x,2);put(c.memory,OUTER+54,z,2);put(c.memory,OUTER+8,y)
    c.seed(LIST,struct.pack('>II',OUTER,INNER));put(c.memory,APP+0x6d0,LIST);put(c.memory,APP+0x762,2,2)
    raw=shared_bytes();base=int.from_bytes(raw[0x2a2:0x2a6],'big');c.allow_write(base,4);c.seed(base,APP.to_bytes(4,'big'))
    return c

def geometry_stop(c,*,outer=2,inner=1,scale=3,x=0,z=0,y=0):
    admitted=geometry(c.memory,outer,inner,scale,x,z,y,tables=TABLES)
    c.run(0xb568,0xb67c if admitted else 0xb904,300)
    assert c.cpu.a[6]==POS;return admitted

@pytest.mark.parametrize('axis',('x','z','y'))
@pytest.mark.parametrize('delta',(-1,0,1))
@pytest.mark.parametrize('sign',(-1,1))
def test_inclusive_edges_and_signed_vertical_side_selection(axis,delta,sign):
    c=setup();radius=(get(c.memory,H+4,2)>>3)+(get(c.memory,H+2,2)>>3)
    height=((get(c.memory,NEG+2,2)>>3)+(get(c.memory,POS+4,2)>>3)) if sign<0 else ((get(c.memory,POS+2,2)>>3)+(get(c.memory,NEG+4,2)>>3))
    xyz=dict(x=0,z=0,y=0);xyz[axis]=sign*((height if axis=='y' else radius)+delta)
    c=setup(**xyz);assert geometry_stop(c,**xyz)==(delta<=0)

@pytest.mark.parametrize('scale',(0,1,15,16,31,32,63,64))
@pytest.mark.parametrize('extent',(1,32767,65535))
def test_original_word_sum_wrap_and_logical_long_shifts(scale,extent):
    c=setup(scale=scale)
    for table in TABLES:
        for kind in (1,2):c.seed(table+2*kind,extent.to_bytes(2,'big'))
    geometry_stop(c,scale=scale)

@pytest.mark.parametrize('axis',('x','z','y'))
@pytest.mark.parametrize('value',(-32768,32767,-0x80000000,0x7fffffff))
def test_wrapped_absolute_separation_is_not_unbounded_geometry(axis,value):
    xyz=dict(x=0,z=0,y=0);xyz[axis]=value;c=setup(scale=0,**xyz);geometry_stop(c,scale=0,**xyz)

@pytest.mark.parametrize('side',('outer','inner'))
@pytest.mark.parametrize('phase',(0,127,128,255))
@pytest.mark.parametrize('flags',(0,8))
def test_flag3_bypasses_phase_gate_at_its_actual_side_of_geometry(side,phase,flags):
    c=setup();at=OUTER if side=='outer' else INNER;c.seed(at+2,bytes([flags]));c.seed(at+30,bytes([phase]))
    eligible=bool(flags&8 or phase&128);c.run(0xb568,0xb67c if eligible else 0xb908 if side=='outer' else 0xb904,300)

@pytest.mark.parametrize('kind',(95,128,145))
def test_inner_extent_read_precedes_later_type_exclusion(kind):
    c=setup(inner=kind,scale=0);c.run(0xb568,0xb5e6,100)
    assert c.cpu.d[1]&65535==get(c.memory,H+2*kind,2)
    # E.g. type145 reads negative-Y entry40, beyond the horizontal owner.
    c.run(0xb5e6,0xb904,200)

@pytest.mark.parametrize('count',(0,1,2,3,32768,65535))
def test_count_subtract_two_uses_word_n_flag_before_borrowing_workspace_register(count):
    c=setup();put(c.memory,APP+0x762,count,2);put(c.memory,APP+0x6c2,0xabcd,2);c.seed(APP+0xbba,b'\xff');c.seed(APP+0x7cf,b'\4')
    skip=bool(((count-2)&65535)&32768);c.run(0xb568,RETURN if skip else 0xb58a,25)
    assert get(c.memory,APP+0x6c2,2)==0 and c.read(APP+0xbba,1)==b'\0' and c.read(APP+0x7cf,1)==b'\4'
    assert c.cpu.a[6]==APP


def player(c,side,kind,durability=1,marker=0,inside=0,space=0,steps=0,actor=30):
    player,other=(OUTER,INNER) if side=='outer' else (INNER,OUTER)
    put(c.memory,player,actor,2);put(c.memory,other,kind,2);c.seed(other+28,bytes([durability]));c.seed(other+34,bytes([marker]));c.seed(other+30,b'\xff');c.seed(other+2,b'\x28')
    for off,value in ((0x77c,inside),(0x77d,space),(0x7cf,steps),(0x7ce,0),(0x7e4,255)):c.seed(APP+off,bytes([value]))
    put(c.memory,APP+0x6f0,-1);put(c.memory,APP+0x6d8,0x1234,2);return player,other

def response(c,side):
    c.cpu.a[0]=OUTER;c.cpu.a[2]=INNER;c.cpu.a[6]=POS;c.cpu.a[7]=STACK
    d,a=list(c.cpu.d),list(c.cpu.a);c.run(0xb93a if side=='outer' else 0xb932,0xb904,400)
    assert list(c.cpu.d)==d and list(c.cpu.a)==a

@pytest.mark.parametrize('side',('outer','inner'))
@pytest.mark.parametrize('kind',(2,12,84,91,98,103))
@pytest.mark.parametrize('marker',(0,255))
@pytest.mark.parametrize('durability',(0,1,128,255))
def test_common_player_hit_marker_exceptions_and_saved_context(side,kind,marker,durability):
    c=setup();_,other=player(c,side,kind,durability,marker);response(c,side)
    hit=kind!=91 and (kind==2 or not marker)
    assert get(c.memory,APP+0x6f0)==(0 if hit else 0xffffffff)
    assert get(c.memory,APP+0x6d8,2)==(kind if hit else 0x1234)
    assert c.read(other+30,1)==bytes([0 if hit and durability<128 else 255])
    assert c.read(other+2,1)==bytes([0x20 if hit and durability<128 else 0x28])
    assert c.read(other+28,1)==bytes([durability]) and c.read(APP+0x7e4,1)==b'\0'
    assert c.read(APP+0x7cf,1)==bytes([4 if hit and durability>=128 else 0])
    assert c.read(APP+0x7ce,1)==bytes([255 if hit and durability>=128 else 0])

@pytest.mark.parametrize('kind',(2,84))
@pytest.mark.parametrize('inside',(0,1))
@pytest.mark.parametrize('space',(0,1))
@pytest.mark.parametrize('steps',(0,1,255))
def test_solid_response_requires_surface_outside_and_idle_counter(kind,inside,space,steps):
    c=setup();player(c,'outer',kind,128,inside=inside,space=space,steps=steps);response(c,'outer')
    hit=kind==84 or not inside;started=hit and not inside and not space and not steps
    assert get(c.memory,APP+0x6f0)==(0 if hit else 0xffffffff)
    assert c.read(APP+0x7cf,1)==bytes([4 if started else steps]) and c.read(APP+0x7ce,1)==bytes([255 if started else 0])

@pytest.mark.parametrize('durability',(0,1,2,127,128,255))
def test_nonplayer_common_response_retains_zero_to_ff_wrap(durability):
    c=setup();p,other=player(c,'outer',2,durability,actor=90);response(c,'outer')
    active=durability<128;remaining=(durability-1)&255
    assert c.read(other+28,1)==bytes([remaining if active else durability])
    assert c.read(other+30,1)==bytes([0 if active and not remaining else 255])
    assert c.read(p+30,1)==bytes([0 if active else 255])

@pytest.mark.parametrize('steps',(0,1,2,4,128,255))
@pytest.mark.parametrize('inside',(0,1))
def test_response_counter_ages_per_completed_pair_pass_not_display_frame(steps,inside):
    c=setup();c.seed(APP+0x7cf,bytes([steps]));c.seed(APP+0x7ce,b'\xff');c.seed(APP+0x77c,bytes([inside]));c.seed(APP+0x7e4,b'\xff')
    c.cpu.d[7]=0;c.cpu.a[6]=POS;c.run(0xb908,0xba20 if inside else RETURN,100)
    value=(steps-1)&255 if steps else 0
    assert c.read(APP+0x7cf,1)==bytes([value]) and c.read(APP+0x7ce,1)==bytes([0 if not value or value&128 else 255])
    assert c.read(APP+0x7e4,1)==bytes([255 if inside else 0])


def test_complete_pair_pass_ages_new_solid_response_immediately():
    c=setup();player(c,'outer',2,128);c.run(0xb568,RETURN,500)
    assert c.read(APP+0x7cf,1)==b'\3' and c.read(APP+0x7ce,1)==b'\xff'
    assert get(c.memory,APP+0x6f0)==0 and get(c.memory,APP+0x6d8,2)==2 and c.cpu.a[6]==APP

@pytest.mark.parametrize('side',('outer','inner'))
@pytest.mark.parametrize('kind',(2,37,98,99))
@pytest.mark.parametrize('tracking',(0,255))
@pytest.mark.parametrize('durability',(0,1,128,255))
def test_original_type12_retirement_awards_and_station_counter_exceptions(side,kind,tracking,durability):
    c=setup();target,projectile=(OUTER,INNER) if side=='outer' else (INNER,OUTER)
    put(c.memory,target,kind,2);c.seed(target+28,bytes([durability]));c.seed(target+2,b'\x28');put(c.memory,projectile,12,2);c.seed(projectile+34,bytes([tracking]))
    put(c.memory,APP+0x5c,0xfff0,2);put(c.memory,APP+0x6e4,-1);put(c.memory,APP+0xa7a,1,2)
    c.cpu.a[0]=OUTER;c.cpu.a[2]=INNER;c.run(0xb720 if side=='outer' else 0xb842,0xb7e2 if side=='outer' else 0xb904,200)
    eligible=kind==37 or not durability&128;award=eligible and bool(tracking) and kind not in (98,99);retire=eligible and (not tracking or award)
    assert c.read(target+30,1)==bytes([0 if retire else 255]) and c.read(target+28,1)==bytes([durability])
    assert c.read(target+2,1)==bytes([0x20 if retire else 0x28])
    assert get(c.memory,APP+0x6e4)==(0 if award else 0xffffffff)
    assert get(c.memory,APP+0x5c,2)==((0xfff0+get(shared_bytes(),0x18074+2*kind,2))&65535 if award else 0xfff0)
    assert get(c.memory,APP+0xa7a,2)==(0 if award and kind==37 else 1)

@pytest.mark.parametrize('side',('outer','inner'))
@pytest.mark.parametrize('tracking',(0,255))
@pytest.mark.parametrize('tag',(0,254,255))
@pytest.mark.parametrize('durability',(2,3,127))
def test_surviving_laser_damage_tags_skip_zero_and_phase_shortcut_is_distinct(side,tracking,tag,durability):
    c=setup();target,projectile=(OUTER,INNER) if side=='outer' else (INNER,OUTER)
    put(c.memory,target,2,2);c.seed(target+28,bytes([durability]));c.seed(target+2,b'\x28');put(c.memory,projectile,103,2);c.seed(projectile+34,bytes([tracking]))
    c.seed(APP+0xda6+2,bytes([tag]));put(c.memory,APP+0x6e4,-1)
    c.cpu.a[0]=OUTER;c.cpu.a[2]=INNER;c.run(0xb73a if side=='outer' else 0xb85e,0xb7e2 if side=='outer' else 0xb904,200)
    assert c.read(target+28,1)==bytes([durability-1]) and c.read(target+2,1)==b'\x2c'
    assert c.read(target+30,1)==bytes([255 if tracking else 0])
    assert c.read(APP+0xda8,1)==bytes([((tag+1)&255 or 1) if tracking else tag])
    assert get(c.memory,APP+0x6e4)==(0 if tracking else 0xffffffff)


def test_real_pool_to_contact_lists_to_retirement_then_next_list_snapshot():
    c=pool_setup([(30,(0,0,1000)),(2,(0,0,1000))]+[(0,(0,0,0))]*248)
    raw=shared_bytes();base=int.from_bytes(raw[0x2a2:0x2a6],'big');c.seed(base,APP.to_bytes(4,'big'))
    c.seed(POOL+68+28,b'\1');c.seed(APP+0x106,struct.pack('>9h',16384,0,0,0,16384,0,0,0,16384))
    c.allow_write(0x5930,208);c.cpu.a[7]=STACK;c.run(0x49f8,RETURN,150000)
    partition(c);c.cpu.a[7]=STACK;c.run(0x4338,RETURN,1500)
    assert pointers(c,0x6d0,0x762)==[POOL,POOL+68] and get(c.memory,APP+0x772,2)==248
    c.cpu.a[7]=STACK;c.run(0xb568,RETURN,600)
    assert get(c.memory,APP+0x6d8,2)==2 and get(c.memory,APP+0x6f0)==1
    assert c.read(POOL+68+30,1)==b'\0' and get(c.memory,APP+0x772,2)==248
    # The contact snapshot itself is unchanged; only the next scene collection
    # removes the now-retiring actor. The world-update list still owns it.
    assert pointers(c,0x6d0,0x762)==[POOL,POOL+68]
    partition(c);c.cpu.a[7]=STACK;c.run(0x4338,RETURN,1500)
    assert pointers(c,0x6d0,0x762)==[POOL] and pointers(c,0x6c8,0x75e)==[POOL+68,POOL]
    c.cpu.a[0]=POOL+68;c.cpu.a[7]=STACK;c.run(0x8002,0x81e6,200)
    assert c.read(POOL+68+30,1)==b'\1' and get(c.memory,APP+0x772,2)==248


def test_rendered_contact_context_stops_before_a6_becomes_extent_table():
    path=os.getenv('SGII_RETAIL_RENDERED_SOURCE')
    if not path:pytest.skip('set SGII_RETAIL_RENDERED_SOURCE to regenerated source')
    text=Path(path).read_text()
    for name in ('process_object_contact_pairs:','dispatch_model_pair_contact_response:',
                 'model_horizontal_contact_extents:','model_negative_y_contact_extents:',
                 'model_positive_y_contact_extents:','object_destruction_bcd_awards:',
                 'SG2ContactWorkspace_contact_response_passes_remaining(a6)',
                 'SG2ContactActor_pre_view_relative_x(a0)'):
        assert name in text
    block=text.split('load_contact_list_before_borrowing_extent_tables:',1)[1].split('restore_workspace_after_contact_pair_loops:',1)[0]
    assert 'lea.l model_positive_y_contact_extents.l,a6' in block
    assert '$0(a6,d3.w)' in block  # Table arithmetic must not become workspace fields.

@pytest.mark.parametrize('count',(2,3,4,16))
def test_original_nested_dbf_walk_visits_each_unordered_list_pair_once(count):
    c=setup();actors=[OUTER+68*i for i in range(count)]
    for at in actors:
        b=bytearray(68);put(b,0,95,2);b[30]=255;c.seed(at,b)
    c.seed(LIST,struct.pack('>'+str(count)+'I',*actors));put(c.memory,APP+0x762,count,2)
    c.run(0xb568,0xb5dc,100);pairs=[]
    while True:
        outer=c.cpu.a[0];inner=get(c.memory,c.cpu.a[3]);pairs.append((outer,inner))
        c.run(0xb5dc,0xb904,150);assert c.cpu.a[2]==inner
        if c.cpu.d[6]&65535:c.run(0xb904,0xb5dc,1)
        else:
            c.run(0xb904,0xb908,1)
            if not c.cpu.d[7]&65535:c.run(0xb908,RETURN,100);break
            c.run(0xb908,0xb5dc,100)
    assert pairs==[(a,b) for i,a in enumerate(actors[:-1]) for b in actors[i+1:]]
    assert c.cpu.a[6]==APP
    assert all(c.read(at+30,1)==b'\xff' for at in actors)


def test_pair_walk_has_no_implicit_pointer_identity_deduplication():
    c=setup();put(c.memory,OUTER,95,2);c.seed(LIST,struct.pack('>II',OUTER,OUTER));c.run(0xb568,0xb664,150)
    assert c.cpu.a[0]==c.cpu.a[2]==OUTER


def test_all_104_model_extent_rows_are_original_word_data_with_separate_trailing_bytes():
    c=setup()
    for kind in range(104):
        put(c.memory,OUTER,kind,2);c.cpu.a[6]=APP;c.cpu.a[7]=STACK;c.run(0xb568,0xb5dc,100)
        assert c.cpu.d[4]&65535==get(c.memory,H+2*kind,2)>>3
        assert c.cpu.d[5]==get(c.memory,NEG+2*kind,2)>>3
        assert c.cpu.d[3]==get(c.memory,POS+2*kind,2)>>3
    assert all(c.read(table+208,2)==b'\0\0' for table in TABLES)


def test_logical_destruction_award_index103_reads_next_owner_without_extending_table():
    c=setup();put(c.memory,OUTER,103,2);put(c.memory,INNER,12,2);c.seed(INNER+34,b'\xff')
    put(c.memory,APP+0x5c,0xffff,2);put(c.memory,APP+0x6e4,-1)
    # Poison only the next physical owner, not a fabricated 104th award element.
    c.seed(0x19074+206,b'\x12\x34');c.cpu.a[0]=OUTER;c.cpu.a[2]=INNER
    c.run(0xb720,0xb7e2,200)
    assert get(c.memory,APP+0x5c,2)==0x1233 and get(c.memory,APP+0x6e4)==0

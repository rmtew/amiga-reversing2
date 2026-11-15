"""Retail actor-address witnesses, finite child choices and selector lifetimes.

Reuse the old launcher/rocket/retirement oracles with actual retail bytes.
Records, lists and stationary player state are explicit inputs, not global
allocation-capacity, pointer-lifetime or frame-timing claims.
"""
import os,struct
from pathlib import Path
import pytest
from amiga_reversing.disasm.mapped_execution import MappedExecution
from test_starglider2_retail_variant_cycles import shared_bytes,machine,APP,ACTOR
from test_starglider2_retail_world_placement import model_domains
from tests.test_starglider2_scan_acquisition import project,signed16

pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='private retail payloads')
CHILD,PLAYER,OTHER,FREE=0x62000,0x61000,0x63000,0x68000
# Actual type-indexed near/far dispatch entries, thresholds and rearm delays.
PROFILES={'near_air':(5,1,0x9ffa,70,300),'far_air':(5,2,0xa8e8,40,900),
          'near_ground':(46,1,0xa2cc,70,300),'far_ground':(46,2,0xaa30,70,300)}
AIR=(13,18,21,31,32,33,34,45);GROUND=(1,9,15,39);DROPS=(100,101,102,83)

def store(c,address,value,width=4):c.seed(address,(value&((1<<(8*width))-1)).to_bytes(width,'big'))
def get(c,address,width=4):return int.from_bytes(c.read(address,width),'big')
def put(record,offset,value,width=4):record[offset:offset+width]=(value&((1<<(8*width))-1)).to_bytes(width,'big')

def setup(profile='near_air',*,dirty=0,yaw=0,choice=0,free=71,poison=False):
    kind,phase,entry,reserve,rearm=PROFILES[profile];c=machine(kind)
    c.seed(CHILD,bytes([dirty])*68);c.allow_write(CHILD,68);c.seed(OTHER,bytes(68));c.allow_write(OTHER,68)
    for offset,value in ((4,1000),(8,-100),(12,0)):store(c,ACTOR+offset,value)
    for offset,value in ((16,0x7fff),(18,yaw),(20,0x8000),(50,1024)):store(c,ACTOR+offset,value,2)
    store(c,ACTOR+28,6,1);store(c,ACTOR+30,255,1)
    store(c,APP+0x44,0x15808);store(c,APP+0x48,0x16008);store(c,APP+0x6fc,0x1ffff)
    store(c,FREE,CHILD);c.allow_write(FREE,16);store(c,APP+0x6d4,FREE+4);store(c,APP+0x772,free,2)
    # ROL(0x12340000,3) has zero low WORD; the retained high WORD must not
    # become part of the child's WORD type or the choice-table index.
    store(c,APP+0x60,0x12340000 if poison else 0);store(c,APP+0x64,0xfff9^choice)
    c.cpu.a[0]=ACTOR;c.cpu.a[2]=OTHER
    return c

def run_profile(c,profile):
    kind,phase,entry,_,_=PROFILES[profile];c.cpu.a[0]=ACTOR
    c.run(entry,0x81e6 if phase==1 else 0x83b0,1000)

def header(c,actor,kind):
    c.cpu.a[4]=actor;c.cpu.d[0]=kind;store(c,0x49c0,0,2)
    store(c,APP+0x24,0xffffffff);c.run(0x4a42,0x4ab0,100)
    return get(c,APP+0x24)

def expected_child(c,profile,dirty,yaw,choice):
    raw=shared_bytes();ground=PROFILES[profile][0]==46;far=PROFILES[profile][1]==2
    kind=(GROUND if ground else AIR)[choice];out=bytearray([dirty]*68)
    put(out,0,kind,2);out[42]=46 if ground else 5;out[3]=0
    out[29]=3 if ground else raw[0x17b8e+kind];out[28]=6 if ground else raw[0x185cc+kind]
    put(out,4,1000);put(out,12,0);out[30]=255;put(out,60,ACTOR)
    scale=int.from_bytes(raw[0x184f0+2*kind:0x184f2+2*kind],'big');put(out,32,scale,2)
    out[43]=1;out[41]=100
    if ground:
        put(out,8,-5);put(out,16,0x7fff,2);put(out,18,yaw+1024,2);put(out,20,0x8000,2)
        out[2]=(out[2]|128)&~16;out[40]=170
        if kind==9:
            put(out,36,3,2);put(out,38,100,2)
            if not far:put(out,8,-4)
        index=2*((yaw+1024)&4095)
        sine=int.from_bytes(raw[0x14808+index:0x1480a+index],'big')
        cosine=int.from_bytes(raw[0x15008+index:0x1500a+index],'big')
        put(out,44,-project(scale,sine),2);put(out,48,project(scale,cosine),2)
    else:
        put(out,8,-20);put(out,18,3072,2);put(out,20,1,2)
        put(out,36,1022,2);put(out,38,0,2);put(out,46,-5,2);out[2]|=160
    return out


@pytest.mark.parametrize('profile',PROFILES)
def test_actual_dispatch_tables_bind_the_four_controller_entries(profile):
    kind,phase,entry,_,_=PROFILES[profile];raw=shared_bytes();base=0x803e if phase==1 else 0x8230
    assert base+int.from_bytes(raw[base-4096+2*kind:base-4096+2*kind+2],'big',signed=True)==entry
    c=setup(profile);c.cpu.a[0]=ACTOR;c.run(0x8002 if phase==1 else 0x8210,entry,30)
    assert c.cpu.a[0]==ACTOR


@pytest.mark.parametrize('profile,choice',[(p,n)for p in PROFILES for n in range(4 if 'ground'in p else 8)])
@pytest.mark.parametrize('dirty,yaw,poison',[(0,0,False),(255,65535,True)])
def test_real_allocators_publish_only_finite_choice_types_and_clear_variant(profile,choice,dirty,yaw,poison):
    c=setup(profile,dirty=dirty,yaw=yaw,choice=choice,poison=poison);expected=expected_child(c,profile,dirty,yaw,choice)
    before=bytearray(c.read(ACTOR,68));kind=int.from_bytes(expected[:2],'big')
    before[40]=255;before[42]=kind;put(before,60,CHILD)
    if profile=='far_ground':before[41]=255
    run_profile(c,profile)
    assert c.read(CHILD,68)==expected and c.read(ACTOR,68)==before
    assert get(c,APP+0x772,2)==70 and get(c,APP+0x6d4)==FREE
    assert get(c,APP+0x60)==0xfff9^choice
    assert get(c,APP+0x64)==(0x91a00000 if poison else 0)|choice
    assert c.read(CHILD+3,1)==b'\0' and 0<kind<104
    assert header(c,CHILD,kind)==0  # Original consumer selects the base frame.


@pytest.mark.parametrize('profile',PROFILES)
@pytest.mark.parametrize('free',[0,40,41,70,71,65535])
def test_unsigned_reserve_gate_precedes_child_write_and_rng(profile,free):
    c=setup(profile,dirty=0xa5,free=free);parent=c.read(ACTOR,68);child=c.read(CHILD,68)
    _,phase,entry,reserve,_=PROFILES[profile];c.run(entry,0x2676 if free>reserve else (0x81e6 if phase==1 else 0x83b0),100)
    assert c.read(ACTOR,68)==parent and c.read(CHILD,68)==child
    assert get(c,APP+0x772,2)==free-int(free>reserve)
    assert get(c,APP+0x6d4)==FREE+(0 if free>reserve else 4)
    assert get(c,APP+0x60)==0 and get(c,APP+0x64)==0xfff9


@pytest.mark.parametrize('profile',PROFILES)
def test_original_parent_cycle_from_spawn_through_release_and_rearm(profile):
    c=setup(profile,choice=0);run_profile(c,profile);ground='ground'in profile;maximum=7 if ground else 19
    assert c.read(ACTOR+3,1)==b'\0'
    for i in range(maximum):
        run_profile(c,profile);assert get(c,ACTOR+3,1)==i+1
        assert header(c,ACTOR,PROFILES[profile][0])!=0
    if not ground:
        for _ in range(28):run_profile(c,profile)
        run_profile(c,profile);assert c.read(ACTOR+40,1)==b'\0' and not(get(c,CHILD+2,1)&128)
    else:
        run_profile(c,profile);assert not(get(c,CHILD+2,1)&128)
        # Child disappearance is an explicit stimulus for this parent-only
        # witness; it is not a claim about the child's complete update lifetime.
        store(c,CHILD,0,2)
        run_profile(c,profile);maximum-=1
    for _ in range(maximum):run_profile(c,profile)
    assert c.read(ACTOR+3,1)==b'\0'
    assert get(c,ACTOR+38,2)==PROFILES[profile][4]
    assert get(c,APP+0x772,2)==70  # Release does not recycle the child here.


@pytest.mark.parametrize('phase',[6,7])
def test_near_ground_null_link_retains_the_incoming_a2_instead_of_proving_actor_ownership(phase):
    c=setup('near_ground');store(c,ACTOR+3,phase,1);store(c,ACTOR+40,255,1);store(c,ACTOR+60,0)
    c.seed(OTHER,b'\xff'*68);before=bytearray(c.read(OTHER,68));c.cpu.a[2]=OTHER
    run_profile(c,'near_ground')
    if phase==7:before[2]&=127
    assert c.cpu.a[2]==OTHER and c.read(OTHER,68)==before


@pytest.mark.parametrize('recycle,stop,final_phase',[(0x81aa,0x81e6,255),(0x8370,0x83b0,0)])
def test_recycle_then_buzz_spawn_preserves_cleared_selector_and_base_model(recycle,stop,final_phase):
    c=setup();c.seed(CHILD,b'\xa5'*68);c.cpu.a[0]=CHILD
    store(c,APP+0x772,50,2);store(c,APP+0x6d4,FREE)
    c.run(recycle,stop,100);expected=bytearray(68);expected[30]=final_phase
    assert c.read(CHILD,68)==expected and get(c,APP+0x772,2)==51 and get(c,FREE)==CHILD
    store(c,ACTOR,33,2);store(c,ACTOR+28,6,1);store(c,ACTOR+30,255,1)
    c.cpu.a[0]=ACTOR;c.run(0x91d4,0x81e6,100)
    assert c.read(CHILD,4)==b'\0\x06\0\0' and get(c,APP+0x772,2)==50
    assert model_domains()[6] is None and header(c,CHILD,6)==0


@pytest.mark.parametrize('choice',range(4))
@pytest.mark.parametrize('dirty',[0,255])
def test_actual_type44_dispatch_allocates_base_model_resource_drop(choice,dirty):
    c=setup(choice=choice,dirty=dirty,free=51);store(c,ACTOR,44,2);store(c,ACTOR+28,2,1)
    store(c,ACTOR+60,0);store(c,ACTOR+56,0);c.cpu.a[0]=ACTOR
    parent=bytearray(c.read(ACTOR,68));expected=bytearray(c.read(CHILD,68))
    expected[44:50]=parent[44:50];expected[4:16]=parent[4:16];put(expected,0,DROPS[choice],2)
    expected[28:31]=bytes((2,6,255));put(expected,60,-1);parent[28]=parent[30]=0
    c.run(0x8002,0x81e6,200)
    assert c.read(CHILD,68)==expected and c.read(ACTOR,68)==parent
    kind=get(c,CHILD,2);assert kind==DROPS[choice] and get(c,CHILD+3,1)==dirty
    assert get(c,ACTOR+30,1)==get(c,ACTOR+28,1)==0
    assert get(c,APP+0x772,2)==50 and get(c,APP+0x6d4)==FREE
    assert model_domains()[kind] is None and header(c,CHILD,kind)==0


@pytest.mark.parametrize('selector',[0,255])
@pytest.mark.parametrize('parent_y',[-100,0x7ffffff0,0xfffffff8])
def test_buzz_factory_preserves_dirty_selector_but_model6_has_no_variant_table(selector,parent_y):
    c=setup(dirty=selector,free=51);store(c,ACTOR,33,2);store(c,ACTOR+8,parent_y);c.cpu.a[0]=ACTOR
    parent=bytearray(c.read(ACTOR,68));expected=bytearray(c.read(CHILD,68))
    expected[44:50]=parent[44:50];expected[4:16]=parent[4:16];put(expected,8,parent_y+20)
    put(expected,0,6,2);expected[28:31]=bytes((2,6,255));expected[42]=33;put(expected,60,-1);parent[42]=6
    c.run(0x91d4,0x81e6,100)
    assert c.read(CHILD,68)==expected and c.read(ACTOR,68)==parent
    assert get(c,CHILD,2)==6 and get(c,CHILD+3,1)==selector
    assert model_domains()[6] is None and header(c,CHILD,6)==0


@pytest.mark.parametrize('profile',PROFILES)
def test_attached_cycle_is_not_a_global_variant_clamp(profile):
    from test_starglider2_retail_variant_cycles import select
    c=setup(profile);store(c,ACTOR+3,200,1);store(c,ACTOR+40,255,1);store(c,ACTOR+60,CHILD)
    store(c,CHILD,13,2);run_profile(c,profile)
    assert get(c,ACTOR+3,1)==201
    with pytest.raises(ValueError,match='unknown read/fetch'):select(c,PROFILES[profile][0])


@pytest.mark.parametrize('kind',[1,9,15])
@pytest.mark.parametrize('shift',[0,6,255])
@pytest.mark.parametrize('dirty',[0,255])
def test_shared_laser_factory_proves_a2_actor_writes_and_clears_animated_model_selector(kind,shift,dirty):
    c=setup(dirty=dirty,free=26);raw=shared_bytes();store(c,ACTOR,kind,2);store(c,ACTOR+29,shift,1)
    store(c,APP+0xda6+kind,1,1);c.cpu.a[0]=ACTOR
    expected=bytearray(c.read(CHILD,68));parent=bytearray(c.read(ACTOR,68))
    height=signed16(int.from_bytes(raw[0x18210+2*kind:0x18212+2*kind],'big'))>>(shift&63)
    put(expected,0,72,2);expected[3]=0;expected[28:31]=bytes((1,4,255));expected[34]=0;expected[42]=kind
    put(expected,4,1000);put(expected,8,-100+height);put(expected,12,0)
    for at,value in ((16,0),(18,1024),(20,0),(32,-100),(36,100),(46,0)):put(expected,at,value,2)
    sine=int.from_bytes(raw[0x15008:0x1500a],'big');cosine=int.from_bytes(raw[0x15808:0x1580a],'big')
    put(expected,44,-project(-100,sine),2);put(expected,48,project(-100,cosine),2);parent[42]=72
    c.run(0x9f0e,0x81e6,200)
    assert c.read(CHILD,68)==expected and c.read(ACTOR,68)==parent
    assert get(c,APP+0x772,2)==25 and get(c,APP+0x6d4)==FREE
    assert model_domains()[72]==1 and header(c,CHILD,72)==0


def test_laser_allocation_motion_retirement_and_recycle_is_a_closed_local_selector_lifetime():
    c=setup(free=26);store(c,ACTOR,1,2);store(c,ACTOR+8,-100000);store(c,APP+0xda6+1,1,1)
    c.cpu.a[0]=ACTOR;c.run(0x9f0e,0x81e6,200)
    assert get(c,CHILD,2)==72 and get(c,CHILD+36,2)==100 and c.read(CHILD+3,1)==b'\0'
    x,z=get(c,CHILD+4),get(c,CHILD+12);y=get(c,CHILD+8)
    vx,vz=signed16(get(c,CHILD+44,2)),signed16(get(c,CHILD+48,2))
    raw=shared_bytes()
    for tick in range(1,101):
        c.cpu.a[0]=CHILD;c.run(0x8002,0x81e6,200)
        x,z=(x+vx)&0x1ffff,(z+vz)&0x1ffff
        assert (get(c,CHILD+4),get(c,CHILD+8),get(c,CHILD+12))==(x,y,z)
        assert get(c,CHILD+36,2)==100-tick and get(c,CHILD+30,1)==(255 if tick<100 else 0)
        assert get(c,CHILD+3,1)==tick&1 and get(c,APP+0x772,2)==25
    limit=raw[0x17e48+72];assert limit<128
    for age in range(limit):
        c.cpu.a[0]=CHILD;c.run(0x8002,0x81e6,200)
        assert get(c,CHILD+30,1)==age+1 and get(c,APP+0x772,2)==25
    c.cpu.a[0]=CHILD;c.run(0x8002,0x81e6,200)
    expected=bytearray(68);expected[30]=255
    assert c.read(CHILD,68)==expected and get(c,APP+0x772,2)==26
    assert get(c,APP+0x6d4)==FREE+4 and get(c,FREE)==CHILD


@pytest.mark.parametrize('kind',[72,103])
def test_live_projectile_update_masks_the_stored_selector_to_one_for_every_byte_input(kind):
    c=machine(kind);raw=shared_bytes();store(c,ACTOR+28,1,1);store(c,ACTOR+30,255,1);store(c,APP+0x77d,128,1)
    entry=0x803e+int.from_bytes(raw[0x703e+2*kind:0x7040+2*kind],'big',signed=True)
    assert entry==0x95a8 and model_domains()[kind]==1
    c.cpu.a[0]=ACTOR;c.run(0x8002,entry,30)
    for value in range(256):
        store(c,ACTOR+3,value,1);c.cpu.a[0]=ACTOR;c.run(entry,0x9602,100)
        assert get(c,ACTOR+3,1)==(value+1)&1
        assert header(c,ACTOR,kind)==(0 if (value+1)&1==0 else get(c,APP+0x24))


@pytest.mark.parametrize('profile',['near_ground','far_ground'])
def test_allocated_ground_child_releases_its_actual_parent_after_170_near_services(profile):
    c=setup(profile,choice=1);run_profile(c,profile)
    assert get(c,CHILD,2)==9 and get(c,CHILD+60)==ACTOR and get(c,ACTOR+60)==CHILD
    y=get(c,CHILD+8)
    for _ in range(8):run_profile(c,profile)
    assert get(c,ACTOR+3,1)==7 and not(get(c,CHILD+2,1)&128)
    raw=shared_bytes();target=0x803e+int.from_bytes(raw[0x703e+18:0x7040+18],'big',signed=True)
    assert target==0x9b58
    for count in range(170):
        c.cpu.a[0]=CHILD;c.run(0x8002,0x81e6,300)
        assert get(c,CHILD+40,1)==169-count
        assert get(c,ACTOR+40,1)==(255 if count<169 else 0)
        assert get(c,CHILD+8)==y and get(c,CHILD+3,1)==0
    assert get(c,CHILD+60)==0 and get(c,ACTOR+60)==CHILD
    for _ in range(7):run_profile(c,profile)
    assert get(c,ACTOR+3,1)==0 and get(c,ACTOR+38,2)==300
    assert get(c,APP+0x772,2)==70  # Link release and slot recycling are distinct.


@pytest.mark.parametrize('entry,end',[(0x8190,0x819e),(0x8358,0x8364)])
def test_retirement_table_148_entry_prefix_has_a_word_index_and_byte_values(entry,end):
    raw=shared_bytes();table=raw[0x17e48:0x17edc]
    c=MappedExecution(0x100000,register_seed=0x12345678)
    c.seed(entry,raw[entry-4096:end-4096]);c.seed(0x18e48,table);c.seed(ACTOR,bytes(68));c.cpu.a[0]=ACTOR
    for kind,value in enumerate(table):
        store(c,ACTOR,kind,2);c.run(entry,end,5)
        assert c.cpu.d[0]&65535==value and c.cpu.d[0]>>16==0x1234
    for kind in (148,0x8001):
        invalid=MappedExecution(0x100000,register_seed=0x12345678)
        invalid.seed(entry,raw[entry-4096:end-4096]);invalid.seed(0x18e48,table)
        invalid.seed(ACTOR,kind.to_bytes(2,'big'));invalid.cpu.a[0]=ACTOR
        with pytest.raises(ValueError,match='unknown read/fetch'):invalid.run(entry,end,5)


@pytest.mark.parametrize('near',[True,False])
def test_recycler_publication_order_is_checked_before_final_record_clear(near):
    c=setup();c.seed(CHILD,b'\xa5'*68);c.cpu.a[0]=CHILD
    store(c,APP+0x772,50,2);store(c,APP+0x6d4,FREE);store(c,FREE,0x11111111)
    c.run(0x81aa if near else 0x8370,0x81d2 if near else 0x838c,100)
    if near:
        assert c.read(CHILD,68)==bytes(68)
        assert get(c,APP+0x772,2)==50 and get(c,FREE)==0x11111111
    else:
        before=bytearray(b'\xa5'*68);before[3]=0;before[30]=255
        assert c.read(CHILD,68)==before
        assert get(c,APP+0x772,2)==51 and get(c,FREE)==CHILD
    c.run(0x81d2 if near else 0x838c,0x81e6 if near else 0x83b0,100)
    expected=bytearray(68);expected[30]=255 if near else 0
    assert c.read(CHILD,68)==expected and get(c,APP+0x772,2)==51 and get(c,FREE)==CHILD


@pytest.mark.parametrize('profile',PROFILES)
@pytest.mark.parametrize('cooldown',[1,32768,65535])
def test_launcher_cooldown_decrement_returns_before_any_new_allocation(profile,cooldown):
    c=setup(profile,dirty=0xa5);store(c,ACTOR+38,cooldown,2)
    parent=bytearray(c.read(ACTOR,68));child=c.read(CHILD,68);put(parent,38,cooldown-1,2)
    run_profile(c,profile)
    assert c.read(ACTOR,68)==parent and c.read(CHILD,68)==child
    assert get(c,APP+0x772,2)==71 and get(c,APP+0x64)==0xfff9


def test_checked_source_names_proved_copy_fields_but_not_the_retained_a2_case():
    source=(Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered/retail-shared.s').read_text()
    assert 'move.w SG2ActorModelPrefix_velocity_x(a0),SG2ActorModelPrefix_velocity_x(a2)' in source
    assert 'move.l SG2ActorModelPrefix_world_z(a0),SG2ActorModelPrefix_world_z(a2)' in source
    assert 'toggle_projectile_variant_and_integrate:' in source
    for bank in ('airborne_spawn_model_type_choices','ground_spawn_model_type_choices','retirement_resource_drop_type_choices'):
        assert bank+':' in source and bank+'.l,a1' in source
    released=source.split('release_nearby_type46_using_current_a2:',1)[1].split('update_type34_first_phase_motion:',1)[0]
    assert 'bclr.b #7,$0002(a2)' in released
    assert 'SG2ActorModelPrefix_flags(a2)' not in released

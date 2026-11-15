"""Retail station/projector reference producers and bounded cleanup witnesses.

Original instructions and explicit list/record inputs distinguish ownership
from nonnull tests and MOVEA-preserved condition codes. No mission-wide or
arbitrary loaded-state lifetime guarantee is inferred.
"""
import os,struct
import pytest
from test_starglider2_retail_neutron import machine,APP,ACTOR,STATION,POOL,STACK,RETURN,shared_bytes
from test_starglider2_retail_workspace import put,get
from tests.test_starglider2_scan_acquisition import signed16

pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
PART,CHILD,LIST=0x62000,0x63000,0x68200
HEADER=int.from_bytes(shared_bytes()[0x19234+99*4:0x19238+99*4],'big') if os.getenv('SGII_LINKED_FIXTURES')=='1' else 0

def station(c,address=STATION):
    data=bytearray(68);put(data,0,99,2);data[28]=128;data[30]=255
    put(data,16,65530,2);put(data,18,4090,2)
    for off,value in ((4,1000),(8,-2000),(12,3000)):put(data,off,value)
    c.seed(address,data);c.allow_write(address,68);return data

def spawn(c,stop=0x34ad4):
    c.allow_write(HEADER+2,2);c.run(0x349ea,stop,2500)

def callback(c,near=True,address=STATION):
    c.cpu.a[0]=address;c.cpu.a[7]=STACK
    c.run(0x8002 if near else 0x8210,0x81e6 if near else 0x83b0,1000)

@pytest.mark.parametrize('free,distant',((0,0),(0,1),(1,0),(1,65535),(2,0),(65535,0)))
@pytest.mark.parametrize('steps',(-1,0,1,52,53,32767,-32768))
def test_actual_station_request_scans_pool_and_preserves_partial_allocation_and_header_mutation(free,distant,steps):
    c=machine();c.seed(STATION,b'\x15'*68);put(c.memory,APP+0x772,free,2);put(c.memory,APP+0x6d4,0x68004)
    c.seed(0x68000,STATION.to_bytes(4,'big'));put(c.memory,APP+0x75c,distant,2);put(c.memory,APP+0x6b8,LIST);c.seed(LIST,STATION.to_bytes(4,'big'))
    c.seed(APP+0xa7d,b'\xff');put(c.memory,APP+0x868,steps,2);before=c.read(HEADER,24)
    spawn(c);admitted=free>1 or distant!=0
    assert c.read(APP+0xa7d,1)==bytes([0 if admitted else 255])
    assert get(c.memory,APP+0x772,2)==(free-1 if free>1 else free)
    assert get(c.memory,APP+0x6d4)==(0x68000 if free>1 else 0x68004)
    assert get(c.memory,APP+0x6b8)==LIST and get(c.memory,APP+0x75c,2)==distant
    if admitted:
        expected=bytearray(b'\x15'*68);put(expected,0,99,2);expected[3]=0
        expected[4:16]=struct.pack('>III',0x2255100,0xfeced300,0x1374780);expected[16:22]=struct.pack('>HHH',3840,0,0)
        expected[28]|=128;expected[29]=shared_bytes()[0x17b8e+99];expected[30]=255;put(expected,36,200,2)
        assert c.read(STATION,68)==expected
        expected_header=bytearray(before);put(expected_header,2,52-max(0,steps),2);assert c.read(HEADER,24)==expected_header
    else:assert c.read(STATION,68)==b'\x15'*68 and c.read(HEADER,24)==before
    assert get(c.memory,APP+0x9b0)==0  # Allocation does not publish the nearby reference.

@pytest.mark.parametrize('slot',(0,1,249))
@pytest.mark.parametrize('phase',(0,255))
def test_any_existing_full_word_type99_suppresses_request_even_while_retiring(slot,phase):
    c=machine();c.seed(APP+0xa7d,b'\xff');put(c.memory,POOL+68*slot,99,2);c.seed(POOL+68*slot+30,bytes([phase]))
    before=c.read(POOL,17000),c.read(HEADER,24);spawn(c)
    assert c.read(APP+0xa7d,1)==b'\0' and get(c.memory,APP+0x772,2)==2
    assert (c.read(POOL,17000),c.read(HEADER,24))==before

@pytest.mark.parametrize('near',(False,True))
@pytest.mark.parametrize('charge',(-1,0,4))
@pytest.mark.parametrize('cycle',(0,128))
@pytest.mark.parametrize('construction',(-1,52))
def test_type99_dispatch_publishes_or_clears_station_reference_after_the_real_state_helper(near,charge,cycle,construction):
    c=machine();before=station(c);put(c.memory,APP+0x9c4,charge,2);c.seed(APP+0xa7c,bytes([cycle]));put(c.memory,APP+0x868,construction,2)
    put(c.memory,APP+0x9b0,0xffffffff);c.seed(APP+0xa7e,b'\x55');callback(c,near)
    expected=bytearray(before)
    if charge==-1 and cycle>=128:
        put(expected,16,((65530+16)&4095)|1,2);put(expected,18,(4090+16)&4095,2);expected[34]=1
    elif charge!=-1:put(expected,18,(4090+(16 if construction==-1 else 8))&4095,2)
    assert c.read(STATION,68)==expected
    assert get(c.memory,APP+0x9b0)==(STATION if near else 0) and c.read(APP+0xa7e,1)==bytes([255 if near else 0])
    assert c.cpu.a[0]==STATION

@pytest.mark.parametrize('phase',(0,6,7,15,255))
@pytest.mark.parametrize('free',(0,1,2,3,65535))
@pytest.mark.parametrize('dirty',(0,204))
def test_station_emission_proves_actual_child_address_unsigned_reserve_and_record_role(phase,free,dirty):
    c=machine();before=station(c);before[34]=phase;c.seed(STATION,before)
    put(c.memory,APP+0x9c4,-1,2);c.seed(APP+0xa7c,b'\x80');put(c.memory,APP+0x772,free,2)
    c.seed(0x68000,CHILD.to_bytes(4,'big'));c.seed(CHILD,bytes([dirty])*68);c.allow_write(CHILD,68)
    callback(c);newphase=(phase+1)&7;emitted=newphase==0 and free>2
    assert c.read(STATION+34,1)==bytes([newphase])
    assert get(c.memory,APP+0x9b0)==STATION and get(c.memory,APP+0x772,2)==(free-1 if emitted else free)
    if not emitted:assert c.read(CHILD,68)==bytes([dirty])*68;return
    expected=bytearray([dirty])*68;put(expected,0,146,2)
    radius=int.from_bytes(shared_bytes()[0x17eb2+18*4:0x17eb6+18*4],'big')
    for off in (34,54):put(expected,off,radius)
    expected[4:16]=before[4:16];expected[30]=255;expected[28]|=128;put(expected,16,50,2);expected[31]=0
    assert c.read(CHILD,68)==expected and get(c.memory,APP+0x6d4)==0x68000

@pytest.mark.parametrize('slot',range(56))
def test_rebuild_selection_publishes_the_allocated_projector_and_growth_clears_only_its_alias(slot):
    raw=shared_bytes();body=get(raw,0x39aec+2*slot,2);kind=get(raw,0x39a7c+2*slot,2)
    assert body==14-slot//8 and kind==75+slot%8
    c=machine();c.seed(APP+0x77d,b'\0');c.seed(APP+0x77c,b'\0');put(c.memory,APP+0x830,body,2);put(c.memory,APP+0x858,slot,2)
    c.seed(APP+0xaa9,bytes(56));c.seed(APP+0xaa9+slot,b'\xff');c.seed(PART,b'\xcc'*68);c.allow_write(PART,68);c.seed(0x68000,PART.to_bytes(4,'big'))
    c.run(0x366e2,0x367d2,600)
    expected=bytearray(b'\xcc'*68);put(expected,0,kind,2);template=0x38448+(kind-75)*10
    expected[4:8]=raw[template+2:template+6];expected[12:16]=raw[template+6:template+10];expected[8:12]=bytes(4);expected[16:22]=bytes(6)
    expected[28]|=128;expected[29]=12;expected[30]=255;expected[3]=expected[31]=0
    assert c.read(PART,68)==expected and get(c.memory,APP+0x85a)==PART and get(c.memory,APP+0x85e,2)==kind
    assert get(c.memory,APP+0x772,2)==1
    c.seed(APP+0xa7c,b'\x80');c.seed(APP+0xaa8,b'\1');default=raw[0x17b8e+kind]
    calls=0
    while get(c.memory,APP+0x85e,2):c.run(0x363bc,0x36426,100);calls+=1;assert calls<=24
    assert calls==2*(12-default)+1 and get(c.memory,APP+0x85a)==0
    expected[29]=default;assert c.read(PART,68)==expected and get(c.memory,APP+0x772,2)==1


def growth(c,kind=75,pointer=PART,scale=12,record_tag=75):
    c.seed(APP+0xa7c,b'\x80');c.seed(APP+0x77d,b'\0');c.seed(APP+0xaa8,b'\1');put(c.memory,APP+0x830,8,2)
    put(c.memory,APP+0x85e,kind,2);put(c.memory,APP+0x85a,pointer);c.seed(PART,bytes(68));put(c.memory,PART,record_tag,2);c.seed(PART+29,bytes([scale]));c.allow_write(PART,68)


def test_growth_movea_is_not_a_null_guard_and_global_tag_is_not_an_identity_check():
    c=machine();growth(c,pointer=0);c.run(0x363bc,0x36402,100)
    assert c.cpu.a[0]==0 and not c.cpu.sr&4  # Z comes from the nonzero type WORD, not MOVEA.
    with pytest.raises(ValueError,match='unknown read/fetch'):c.run(0x36402,0x36426,50)
    c=machine();growth(c,record_tag=98);c.run(0x363bc,0x36426,100)
    assert get(c.memory,PART,2)==98 and c.read(PART+29,1)==b'\x0b'
    c=machine();growth(c,kind=0,pointer=0);c.run(0x363bc,0x36426,100)
    assert get(c.memory,APP+0x85a)==0

@pytest.mark.parametrize('listed_bomb',(False,True))
def test_actual_station_publication_cleanup_and_recycle_bound_the_neutron_null_reference_case(listed_bomb):
    c=machine();bomb,base,spare=POOL+68,POOL+136,POOL+204
    pool=bytearray(17000)
    for i in range(250):put(pool,68*i,30 if not i else 1,2);pool[68*i+28]=1;pool[68*i+30]=255
    for at in (68,136,204):pool[at:at+68]=bytes(68)
    c.seed(POOL,pool);c.seed(0x67ffc,struct.pack('>III',spare,bomb,base));c.allow_write(0x67ffc,12)
    put(c.memory,APP+0x6d4,0x68008);put(c.memory,APP+0x772,3,2);c.seed(APP+0xa7d,b'\xff')
    put(c.memory,APP+0x868,51,2);put(c.memory,APP+0x9c4,4,2);c.seed(APP+0xa7c,b'\x80')
    spawn(c);assert get(c.memory,base,2)==99 and get(c.memory,APP+0x772,2)==2
    callback(c,address=base);assert get(c.memory,APP+0x9b0)==base and c.read(APP+0xa7e,1)==b'\xff'
    # Supplied damage state, then the original retirement counter up to the
    # service boundary. No full mission or physical-frame claim follows.
    c.seed(base+30,b'\0');limit=shared_bytes()[0x17e48+99]
    for _ in range(limit-1):c.cpu.a[0]=base;c.cpu.a[7]=STACK;c.run(0x8190,0x81e6,100)
    assert c.read(base+30,1)==bytes([limit-1])
    put(c.memory,APP+0xa76,0);c.seed(APP+0xae3,b'\xff');c.cpu.a[7]=STACK
    c.run(0x3493a,0x349ea,500);c.run(0x79c0,RETURN,500)
    assert get(c.memory,bomb,2)==98 and get(c.memory,APP+0x772,2)==1
    c.cpu.a[0]=bomb;c.cpu.a[7]=STACK;c.run(0x38062,RETURN,500)
    assert get(c.memory,bomb+36,2)==999 and get(c.memory,APP+0x9b0)==base
    addresses=[base,bomb] if listed_bomb else [base]
    c.seed(LIST,b''.join(a.to_bytes(4,'big')for a in addresses));put(c.memory,APP+0x6c8,LIST);put(c.memory,APP+0x75e,len(addresses),2)
    c.run(0x3698e,0x36c44,5000)
    assert get(c.memory,APP+0x9b0)==0 and c.read(APP+0xa7e,1)==b'\xff'
    assert get(c.memory,APP+0x868,2)==52 and c.read(APP+0xa7d,1)==b'\xff'
    assert get(c.memory,APP+0x772,2)==1
    assert c.read(bomb+30,1)==bytes([0 if listed_bomb else 255])
    c.cpu.a[0]=bomb;c.cpu.a[7]=STACK;c.run(0x8002,0x81e6,500)
    assert get(c.memory,bomb+36,2)==(999 if listed_bomb else 998)
    # The alias was cleared before the station slot is actually returned.
    for _ in range(2):c.cpu.a[0]=base;c.cpu.a[7]=STACK;c.run(0x8190,0x81e6,100)
    assert get(c.memory,base,2)==0 and get(c.memory,APP+0x772,2)==2 and get(c.memory,APP+0x9b0)==0
    if not listed_bomb:
        # Counterexample outside the completed-cleanup invariant: active bomb,
        # stale nearby flag, no station backing and a non-52 construction step.
        put(c.memory,APP+0x868,51,2);c.cpu.a[0]=bomb;c.cpu.a[7]=STACK
        with pytest.raises(ValueError,match='unknown read/fetch'):c.run(0x8002,0x81e6,500)

@pytest.mark.parametrize('tag',(0,30,0x11e,98,128,146,0x8001))
@pytest.mark.parametrize('phase',(0,255))
def test_station_cleanup_uses_low_type_byte_and_live_phase_but_exact_player_word(tag,phase):
    c=machine();station(c);c.seed(STATION+30,bytes([shared_bytes()[0x17e48+99]-1]))
    part=bytearray(b'\xff'*68);put(part,0,tag,2);part[30]=phase;c.seed(PART,part);c.allow_write(PART,68)
    c.seed(LIST,struct.pack('>II',STATION,PART));put(c.memory,APP+0x75e,2,2);put(c.memory,APP+0x6c8,LIST);put(c.memory,APP+0x9b0,STATION)
    c.run(0x3698e,0x36c44,5000)
    expected=bytearray(part)
    if not tag&128 and phase>=128 and tag!=30:expected[2]&=~12;expected[28]=expected[30]=0
    assert c.read(PART,68)==expected and get(c.memory,APP+0x9b0)==0
    assert get(c.memory,APP+0x772,2)==2

@pytest.mark.parametrize('cycle',(0,128))
@pytest.mark.parametrize('free',(3,4))
@pytest.mark.parametrize('seeds',((0,0),(0x12345678,0x9abcdef0)))
def test_phase_one_station_loss_damages_56_flags_and_emits_one_expanding_child(cycle,free,seeds):
    from tests.test_starglider2_palette_priority import rng
    c=machine();before=station(c);c.seed(STATION+30,b'\1');put(c.memory,APP+0x9b0,STATION)
    c.seed(APP+0xa7c,bytes([cycle]));c.seed(APP+0xaa9,b'\xff'*56);put(c.memory,APP+0x75e,1,2)
    c.seed(LIST,STATION.to_bytes(4,'big'));put(c.memory,APP+0x6c8,LIST)
    put(c.memory,APP+0x772,free,2);c.seed(0x68000,CHILD.to_bytes(4,'big'));c.seed(CHILD,bytes(68));c.allow_write(CHILD,68)
    put(c.memory,APP+0x60,seeds[0]);put(c.memory,APP+0x64,seeds[1]);a,b=seeds;wanted=bytearray(b'\xff'*56)
    for i in range(55,-1,-1):
        a,b=rng(a,b)
        if not b&3:wanted[i]=0
    c.run(0x3698e,0x36c44,5000)
    assert c.read(APP+0xaa9,56)==wanted and c.read(APP+0xbb6,1)==b'\xff'
    assert get(c.memory,APP+0x9b0)==STATION and get(c.memory,APP+0x772,2)==free-(free>3)
    if free>3:
        expected=bytearray(68);put(expected,0,146,2);expected[3]=0;expected[31]=255
        put(expected,34,1);put(expected,54,1);put(expected,60,64,2);expected[30]=255;expected[28]=128
        a,b=rng(a,b);delta=(b&1023)-512
        for off in (4,8,12):put(expected,off,get(before,off)+delta)
        a,b=rng(a,b);put(expected,18,(b&31)+2,2)
        assert c.read(CHILD,68)==expected
    else:assert c.read(CHILD,68)==bytes(68)
    assert [get(c.memory,APP+off)for off in (0x60,0x64)]==[a,b]


def test_original_world_pool_station_loss_child_expansion_and_recycle_preserve_distinct_ownership():
    from tests.test_starglider2_palette_priority import rng
    c=machine()
    for at,size in ((0x1a1f8,4),(0x1a1fc,4),(0x1a224,1),(0x1a210,4)):c.allow_write(at,size)
    c.cpu.a[7]=STACK;c.run(0x19650,RETURN,150000);initial_free=get(c.memory,APP+0x772,2)
    base=get(c.memory,get(c.memory,APP+0x6d4)-4)
    c.seed(APP+0xa7d,b'\xff');put(c.memory,APP+0x868,51,2);put(c.memory,APP+0x9c4,4,2)
    c.cpu.a[7]=STACK;spawn(c);callback(c,address=base)
    assert get(c.memory,base,2)==99 and get(c.memory,APP+0x9b0)==base
    child=get(c.memory,get(c.memory,APP+0x6d4)-4);c.seed(base+30,b'\1');c.seed(APP+0xa7c,b'\x80')
    c.seed(LIST,base.to_bytes(4,'big'));put(c.memory,APP+0x6c8,LIST);put(c.memory,APP+0x75e,1,2)
    c.run(0x3698e,0x36c44,5000)
    assert get(c.memory,child,2)==146 and get(c.memory,APP+0x772,2)==initial_free-2
    assert POOL<=base<POOL+17000 and POOL<=child<POOL+17000 and base!=child
    initial_delay=get(c.memory,child+18,2);assert 2<=initial_delay<=33
    steps=0;raw=shared_bytes()
    while get(c.memory,child,2):
        expected=bytearray(c.read(child,68));delay=(get(expected,18,2)-1)&65535;put(expected,18,delay,2)
        if delay&32768:
            remaining=(get(expected,60,2)-1)&65535;put(expected,60,remaining,2)
            if remaining&32768:put(expected,0,0,2)
            else:
                a,b=rng(get(c.memory,APP+0x60),get(c.memory,APP+0x64))
                put(expected,18,65535,2);put(expected,54,get(expected,54)+100)
                index=get(expected,16,2);expected[20]=raw[0x39f64+index];expected[21]=raw[0x39f82+index];put(expected,16,(index+1)&31,2)
        c.cpu.a[0]=child;c.cpu.a[7]=STACK;c.run(0x8002,0x81e6,500)
        assert c.read(child,68)==expected;steps+=1;assert steps<=100
    assert steps==initial_delay+65 and get(c.memory,APP+0x9b0)==base
    assert get(c.memory,APP+0x772,2)==initial_free-2
    c.cpu.a[0]=child;c.cpu.a[7]=STACK;c.run(0x8002,0x81e6,100)
    assert c.read(child,68)==bytes(30)+b'\xff'+bytes(37)
    assert get(c.memory,APP+0x772,2)==initial_free-1 and get(c.memory,APP+0x9b0)==base


def test_regular_station_child_mode_moves_z_without_treating_colour_words_as_rotation():
    c=machine();before=station(c);c.seed(STATION+34,b'\7');put(c.memory,APP+0x9c4,-1,2);c.seed(APP+0xa7c,b'\x80')
    put(c.memory,APP+0x772,3,2);c.seed(0x68000,CHILD.to_bytes(4,'big'));c.seed(CHILD,bytes(68));c.allow_write(CHILD,68)
    callback(c);expected=bytearray(c.read(CHILD,68));assert get(expected,0,2)==146 and expected[31]==0
    put(expected,12,get(expected,12)+400)
    c.cpu.a[0]=CHILD;c.cpu.a[7]=STACK;c.run(0x8002,0x81e6,300)
    assert c.read(CHILD,68)==expected and get(c.memory,CHILD+16,2)==50

@pytest.mark.parametrize('index',(30,31))
def test_expansion_colour_window_aliases_secondary_start_and_mutable_notice_word(index):
    c=machine();child=bytearray(68);put(child,0,146,2);child[28]=128;child[30]=child[31]=255
    put(child,16,index,2);put(child,18,0,2);put(child,60,1,2);put(child,54,1)
    c.seed(CHILD,child);c.allow_write(CHILD,68);c.seed(0x3afa0,bytes.fromhex('3567'))
    c.cpu.a[0]=CHILD;c.cpu.a[7]=STACK;c.run(0x8002,0x81e6,500)
    assert c.read(CHILD+20,2)==bytes([shared_bytes()[0x39f82+index-30],(0x35,0x67)[index-30]])
    assert get(c.memory,CHILD+16,2)==(index+1)&31 and get(c.memory,CHILD+54)==101
    assert c.read(0x3afa0,2)==bytes.fromhex('3567')


def test_committed_views_keep_reference_and_nonmodel_colour_roles_distinct():
    import json
    from pathlib import Path
    target=Path(__file__).resolve().parents[1]/'targets/starglider2_retail'
    source=(target/'rendered/retail-shared.s').read_text();metadata=json.loads((target/'target_metadata.json').read_text())
    regular=source.split('publish_regular_station_energy_spheroid_type:',1)[1].split('select_station_rotation_from_charge_state:',1)[0]
    assert 'move.w #$32,SG2EnergySpheroidRecord_colour_sequence_index(a4)' in regular
    assert 'SG2ActorModelPrefix_rotation_0(a4)' not in regular
    assert 'move.w #$40,SG2EnergySpheroidRecord_expansion_steps_remaining(a4)' in source
    assert 'move.w d2,SG2STModelHeader_face_count(a0)' in source
    assert 'branch_on_prior_type_zero_flag_after_movea:' in source
    assert 'SG2NeutronWorkspace_pending_transient_event_sound' in source
    assert 'SG2NeutronWorkspace_detonation_sound_request' not in source
    prefix=next(s for s in metadata['custom_structs'] if s['name']=='SG2WorkspaceReferencePrefix')
    for name in ('growing_projector_part_reference','nearby_space_station_reference'):
        f=next(f for f in prefix['fields'] if f['name']==name)
        assert f['value_kind']=='scalar' and not f.get('pointer_struct')
    for name,start,end in [('energy_spheroid_primary_colour_sequence',0x39f64,0x39f82),('energy_spheroid_secondary_colour_sequence',0x39f82,0x39fa0)]:
        assert any(e['name']==name and e['addr']==start and e['end']==end for e in metadata['seeded_entities'])

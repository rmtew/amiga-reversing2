"""Retail placement-source bounds, original constructors and linked type changes.

RAM, body index and PRNG seeds are explicit inputs. These checks do not prove
all gameplay allocations, writes or selector lifetimes.
"""
import os,struct
from functools import cache
from pathlib import Path
import pytest
from amiga_reversing.disasm.mapped_execution import MappedExecution
from amiga_reversing.tools.starglider2_world_maps import audit,type94_service_byte
from amiga_reversing.tools.compare_starglider2 import model_streams,bounded_variants
from test_starglider2_retail_variant_cycles import shared_bytes,machine,ACTOR,APP,select
from test_starglider2_retail_model_headers import image

pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='private catalogue-bound retail images')
POOL,FREE,STACK,RETURN=APP+0x2330,APP+0xea4,0xf0000,0xff000

@cache
def catalogue():return audit(shared_bytes())

@cache
def model_domains():
    d=shared_bytes();out={}
    for m in model_streams(d,0x19234):
        count=len(bounded_variants(d,m,0xdcee)['views']) if 'variant_first' in m else None
        for n in m['ordinals']:out[n]=count
    return out


def test_both_retail_catalogues_have_the_same_bounded_placement_source():
    a,b=audit(image('amiga')),catalogue()
    for key in ('pointer_table','unique_maps','type_domain','depot_services'):assert a[key]==b[key]
    assert a['profile']==b['profile']=='retail-shared'
    assert len(b['unique_maps'])==14 and b['unique_placement_records']==1139
    assert b['map_bytes']==12864 and b['max_original_map_records']==155
    domain=b['type_domain'];assert domain['reader_words_outside_model_id_range']==[0x130]
    assert max(t for t in domain['model_path_reader_words'] if t<104)==102
    assert domain['special_draw_reader_words']==list(range(128,146))


@pytest.mark.parametrize('world',range(32))
@pytest.mark.parametrize('random_seed',[(0,0),(0x12345678,0xabcdef01)])
def test_original_retail_world_constructor_preserves_pool_and_fresh_selector_bounds(world,random_seed):
    d=shared_bytes();c=MappedExecution(0x100000,register_seed=0xdeadbeef);c.seed(0x1000,d)
    c.seed(APP,bytes(0x8000));c.allow_write(APP,0x8000)
    # Named mutable source globals, not a blanket permission to modify code.
    for at,size in ((0x1a1f8,4),(0x1a1fc,4),(0x1a224,1),(0x1a210,4)):c.allow_write(at,size)
    c.seed(POOL-4,bytes([0xcc])*17008);c.seed(APP+0x798,world.to_bytes(2,'big'))
    c.seed(APP+0x60,struct.pack('>II',*random_seed))
    enabled=bool(random_seed[0]);c.seed(APP+0xa7c,bytes([128 if enabled else 0]));c.seed(APP+0xa7a,(3).to_bytes(2,'big'));c.seed(APP+0xa83,bytes([128 if enabled else 0]))
    c.seed(APP+0x44,struct.pack('>II',0x15808,0x16008))
    c.seed(STACK,RETURN.to_bytes(4,'big'));c.allow_write(STACK-256,256)
    c.cpu.a[6]=APP;c.cpu.a[7]=STACK;c.run(0x19650,RETURN,150000)
    m=next(m for m in catalogue()['unique_maps'] if world in m['indices']);placed=m['count'];free=249-placed
    assert c.read(POOL-4,4)==c.read(POOL+17000,4)==b'\xcc'*4
    assert c.read(APP+0x700,4)==POOL.to_bytes(4,'big') and c.read(POOL,2)==b'\0\x1e'
    assert int.from_bytes(c.read(APP+0x772,2),'big')==free
    assert int.from_bytes(c.read(APP+0x6d4,4),'big')==FREE+free*4
    assert c.read(APP+0x172,2)==(250).to_bytes(2,'big')
    assert c.read(FREE,4*free)==b''.join((POOL+68*(placed+1+i)).to_bytes(4,'big') for i in range(free))
    assert c.read(POOL+68*(placed+1),68*free)==bytes(68*free)
    orbit_attempts=0
    for index in range(placed+1):
        actor=c.read(POOL+68*index,68);kind=int.from_bytes(actor[:2],'big')
        if kind&128:assert 128<=kind<=145;continue
        assert kind in model_domains()  # Not inferred from the initializer mask.
        variants=model_domains()[kind]
        if variants is not None:assert actor[3]<=variants,(world,index,kind,actor[3])
        if index:
            source=m['start']-4096+(index-1)*m['stride'];tag=int.from_bytes(d[source:source+2],'big')
            expected=tag&255 if world>=16 else tag
            if expected&255==48:
                expected=48
                assert actor[36]==(0 if world>=16 else tag>>8)
            if expected==37:
                orbit_attempts+=1;expected=37 if enabled and orbit_attempts<=3 else 0
            if expected==98:expected=98 if enabled else 0
            if expected==94:assert actor[38]==type94_service_byte(tag>>8,world)
            assert kind==expected
    assert int.from_bytes(c.read(0x1a210,2),'big')==(orbit_attempts if enabled else 0)


@pytest.mark.parametrize('interior,tag',[(False,0x12),(False,0x8012),(True,0x8012),(True,0x015e),(True,0x0455)])
def test_retail_reader_preserves_or_extracts_header_before_initializer(interior,tag):
    c=machine(tag&255);d=shared_bytes();record=0x68000;c.seed(ACTOR,b'\xa5'*68)
    c.seed(record,struct.pack('>HIIHHH',tag,0xfedcba98,0x7fffffff,0x1234,0xfedc,0x8001))
    c.cpu.a[1]=record;c.cpu.d[4]=0 if interior else 0xffffffff
    c.run(0x19712,0x1974a,60);actor=c.read(ACTOR,68);kind=tag&255
    assert int.from_bytes(actor[:2],'big')==(kind if interior and tag>>8 else tag)
    assert actor[3]==0 and actor[28:31]==bytes((d[0x185cc+kind],d[0x17b8e+kind],255))
    assert actor[4:8]==bytes.fromhex('fedcba98') and actor[12:16]==bytes.fromhex('7fffffff')
    assert c.cpu.a[1]==record+(16 if interior else 10)
    assert c.cpu.a[5]==int.from_bytes(d[0x187aa+4*kind:0x187ae+4*kind],'big')
    if interior:
        assert actor[8:12]==bytes.fromhex('fffffc18') and actor[36:38]==bytes.fromhex('1234')
        assert actor[40:42]==bytes.fromhex('fedc') and actor[18:20]==bytes.fromhex('8001')
        if tag>>8:assert actor[38]==tag>>8 and actor[2]&128==0
        else:assert actor[2]&128


@pytest.mark.parametrize('low',range(16))
@pytest.mark.parametrize('high',range(4))
@pytest.mark.parametrize('linked',[False,True])
def test_type90_random_variant_and_type93_round_trip_preserve_the_linked_contract(low,high,linked):
    c=machine(90);value=low|(high<<14)
    # For this one PRNG call, the supplied seed produces this exact low WORD.
    c.seed(APP+0x60,bytes(4));c.seed(APP+0x64,(0xfff9^value).to_bytes(4,'big'))
    c.seed(ACTOR+0x28,bytes([int(linked)]));c.seed(ACTOR+12,(10000).to_bytes(4,'big'))
    c.run(0x89ee,0x81e6,70)
    assert c.read(ACTOR,2)==(93 if linked else 90).to_bytes(2,'big')
    assert c.read(ACTOR+3,1)[0]==(0 if linked else low+high)
    assert int.from_bytes(c.read(ACTOR+12,4),'big')==(6000 if linked else 10000)
    select(c,90)  # Both the random range and linked reset fit type90's table.
    if linked:
        assert model_domains()[93] is None
        c.seed(ACTOR+0x28,b'\0');c.seed(ACTOR+0x22,b'\0');c.cpu.a[0]=ACTOR
        c.run(0x8a20,0x81e6,20)
        assert c.read(ACTOR,2)==(90).to_bytes(2,'big') and c.read(ACTOR+3,1)==b'\0'
        assert int.from_bytes(c.read(ACTOR+12,4),'big')==10000


def test_type93_restore_is_gated_and_does_not_repair_arbitrary_selector_state():
    for a,b in ((0,1),(1,0),(1,1)):
        c=machine(93);c.seed(ACTOR+0x22,bytes([a]));c.seed(ACTOR+0x28,bytes([b]));c.run(0x8a20,0x81e6,20)
        assert c.read(ACTOR,2)==(93).to_bytes(2,'big')
    c=machine(93);c.seed(ACTOR+3,b'\xff');c.run(0x8a20,0x81e6,20)
    assert c.read(ACTOR,2)==(90).to_bytes(2,'big') and c.read(ACTOR+3,1)==b'\xff'
    with pytest.raises(ValueError,match='unknown read/fetch'):select(c,90)


def test_older_amiga_audit_remains_a_separate_qualified_profile():
    from test_starglider2_model_streams import inputs
    old=audit(inputs()[0])
    assert old['profile']=='older-amiga' and old['pointer_table']['start']==0x2f9fc
    assert old['unique_placement_records']==1139 and old['constructor']==0x17d90


def spawn_machine():
    c=machine(98);c.seed(ACTOR,b'\x4c'*68);c.seed(APP+0x44,struct.pack('>II',0x15808,0x16008))
    for offset,value in ((0x704,10000),(0x708,0xfffffc18),(0x70c,20000),(0x720,120),(0xa76,0x61000),(0x6fc,0xffff)):
        c.seed(APP+offset,value.to_bytes(4,'big'))
    c.seed(APP+0x75a,(100).to_bytes(2,'big'));c.seed(0x68000,ACTOR.to_bytes(4,'big'))
    c.seed(APP+0x6d4,(0x68004).to_bytes(4,'big'));c.seed(APP+0x772,(2).to_bytes(2,'big'))
    return c


@pytest.mark.parametrize('control_byte',[0,1,128,255])
@pytest.mark.parametrize('cooldown',[0,1,65535])
def test_dynamic_type98_spawn_gates_and_resets_dirty_variant_state(control_byte,cooldown):
    c=spawn_machine();c.seed(APP+0xae3,bytes([control_byte]));c.seed(APP+0x7c4,cooldown.to_bytes(2,'big'))
    before=c.read(ACTOR,68);c.run(0x3493a,0x349bc,300);created=control_byte>=128 and cooldown==0
    assert int.from_bytes(c.read(APP+0xa76,4),'big')==(ACTOR if created else 0x61000)
    assert c.read(APP+0xae3,1)[0]==(0 if created else control_byte)
    if not created:assert c.read(ACTOR,68)==before;return
    actor=c.read(ACTOR,68)
    assert actor[:4]==bytes.fromhex('00624c00') and actor[28:32]==bytes.fromhex('0105ff00')
    assert actor[34]==255 and actor[32:34]==(300).to_bytes(2,'big')
    assert actor[36:40]==bytes.fromhex('03e80000') and actor[52:]==b'\x4c'*16
    assert c.read(APP+0x772,2)==b'\0\1' and c.read(APP+0x6d4,4)==(0x68000).to_bytes(4,'big')
    assert model_domains()[98] is None  # This new type uses its base model.
    from tests.test_starglider2_scan_acquisition import project,signed16
    raw=shared_bytes();sine=int.from_bytes(raw[0x14808:0x1480a],'big');cosine=int.from_bytes(raw[0x15008:0x1500a],'big')
    velocity=[(-project(project(300,sine),cosine))&65535,(-project(300,sine))&65535,project(project(300,cosine),cosine)&65535]
    assert list(struct.unpack('>3H',actor[44:50]))==velocity
    expected=[(10000+signed16(velocity[0]))&65535,(-1000+120+signed16(velocity[1]))&0xffffffff,(20000+signed16(velocity[2]))&65535]
    assert [int.from_bytes(actor[o:o+4],'big')for o in (4,8,12)]==expected


@pytest.mark.parametrize('free',[0,1,2,65535])
@pytest.mark.parametrize('distant,nearby',[(0,0),(2,0),(0,2)])
def test_dynamic_type98_fallback_selection_retains_original_unsigned_gate(free,distant,nearby):
    c=spawn_machine();c.seed(APP+0xae3,b'\xff');c.seed(APP+0x772,free.to_bytes(2,'big'))
    c.seed(APP+0x75c,distant.to_bytes(2,'big'));c.seed(APP+0x75e,nearby.to_bytes(2,'big'))
    c.seed(APP+0x6b8,(0x68100).to_bytes(4,'big'));c.seed(0x68100,(0x61000).to_bytes(4,'big'))
    c.seed(APP+0x6c8,(0x68200).to_bytes(4,'big'));c.seed(0x68200,(0x62000).to_bytes(4,'big'))
    for at in (0x61000,0x62000):c.seed(at,b'\x4c'*68);c.allow_write(at,68)
    chosen=ACTOR if free>1 else 0x61000 if distant else 0x62000 if nearby else 0
    c.run(0x3493a,0x349bc,300)
    assert int.from_bytes(c.read(APP+0xa76,4),'big')==chosen
    assert c.read(APP+0x772,2)==(free-1 if free>1 else free).to_bytes(2,'big')
    assert c.read(APP+0x6d4,4)==(0x68000 if free>1 else 0x68004).to_bytes(4,'big')
    if chosen:assert c.read(chosen,4)==bytes.fromhex('00624c00')


@pytest.mark.parametrize('control_byte',[0,1,128,255])
@pytest.mark.parametrize('offset',[19,20,21])
def test_dynamic_type98_retraction_clears_type_only_at_exact_minimum(control_byte,offset):
    c=spawn_machine();c.seed(APP+0xa76,ACTOR.to_bytes(4,'big'));c.seed(ACTOR,(98).to_bytes(2,'big'))
    c.seed(APP+0xae4,bytes([control_byte]));c.seed(APP+0x720,offset.to_bytes(4,'big'));before=c.read(ACTOR,68)
    c.run(0x349bc,0x349ea,30);removed=control_byte>=128 and offset==20
    assert c.read(ACTOR,68)==(bytes(2)+before[2:] if removed else before)
    assert int.from_bytes(c.read(APP+0xa76,4),'big')==(0 if removed else ACTOR)
    assert c.read(APP+0xae4,1)[0]==(0 if removed else control_byte)


def test_rendered_placement_pointers_and_constructor_fields_are_symbolic():
    import re
    source=(Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered/retail-shared.s').read_text()
    tail=source.split('world_placement_stream_pointers:',1)[1]
    table=re.split(r'(?m)^\w+:',tail,maxsplit=1)[0]
    indices=[int(x)for x in re.findall(r'dc.l world_placement_map_(\d+)',table)]
    expected=[min(m['indices'])for world in range(32)for m in catalogue()['unique_maps']if world in m['indices']]
    assert indices==expected
    assert 'SG2WorldConstructionContext_world_layout_index(a6)' in source
    assert 'SG2WorldConstructionContext_neutron_bomb_ready_flag(a6)' in source
    assert 'clr.b SG2ActorModelPrefix_vertex_variant_selector(a2)' in source

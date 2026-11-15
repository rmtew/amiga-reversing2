"""Retail cursor/bulk save transforms using the older independent RAM oracle.

Original instructions and explicit saved RAM are tested. Disk acceptance,
normal-save reachability and universal pointer lifetimes are separate claims.
"""
import os
from pathlib import Path
import pytest
from amiga_reversing.disasm.mapped_execution import MappedExecution
from test_starglider2_retail_variant_cycles import shared_bytes
from tests.test_starglider2_workspace_rebasing import FIXED,ARRAYS,model_transform

pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
STACK,RETURN=0xf0000,0xff000
FIXED_OFFSETS=(0x6b4,0x6c4,0x6b8,0x6bc,0x6c8,0x6cc,0x6d0,0x6d4,0x700,0xa76,0x832,0x838,0x83c,0x85a,0x9b0)
ARRAY_OFFSETS=(0xea4,0x128c,0x1678,0x1a64,0x1e50,0x223c)
LAYOUT={**dict(zip(FIXED,FIXED_OFFSETS)),**dict(zip((n for n,_ in ARRAYS),ARRAY_OFFSETS)),
        'released_object_tracking_references':0xa02,'world_object_pool':0x2330,'app_SIZEOF':0x6598}

def put(memory,address,value,width=4):memory[address:address+width]=(value&((1<<(width*8))-1)).to_bytes(width,'big')
def get(memory,address,width=4):return int.from_bytes(memory[address:address+width],'big')

def machine(base):
    c=MappedExecution(0x100000,register_seed=0xdeadbeef);c.seed(0x1000,shared_bytes())
    c.seed(base-8,bytes((i*37+i//256)&255 for i in range(0x6598+16)))
    c.allow_write(base,0x6598);c.seed(STACK,RETURN.to_bytes(4,'big'));c.allow_write(STACK-64,64)
    c.cpu.a[6]=base;c.cpu.a[7]=STACK
    return c

def supplied(c,base):
    values=(0,0xffffffff,base,base-1,base+2,base+68,1,0x80000000,0xfffffffc)
    for i,off in enumerate(FIXED_OFFSETS):put(c.memory,base+off,values[i%len(values)])
    for (_,count),off in zip(ARRAYS,ARRAY_OFFSETS):
        for i in range(count):put(c.memory,base+off+4*i,values[i%len(values)])
    for i in range(10):put(c.memory,base+0xa02+4*i,values[i%len(values)])
    for i in range(250):
        record=base+0x2330+68*i;c.memory[record+1]=(0,127,128,255)[i%4]
        for j,off in enumerate((56,60)):put(c.memory,record+off,values[(i+j)%len(values)])

def expected(before,base,absolute):
    result=model_transform(before,LAYOUT,base,absolute)
    # The older oracle's supplied examples never use zero in these optional
    # slots. Retail guards are tested explicitly, rather than generalised away.
    for off in (0xa76,0x85a,0x9b0):
        if not get(before,base+off):put(result,base+off,0)
    result[base+0xbbb]=255 if absolute else 0
    return result

@pytest.mark.parametrize('base',(0x70000,0x70004,0x90000))
@pytest.mark.parametrize('absolute',(False,True))
def test_retail_bulk_cursor_spans_and_guarded_actor_links_match_old_oracle(base,absolute):
    c=machine(base);supplied(c,base);before=bytes(c.memory);d,a=list(c.cpu.d),list(c.cpu.a)
    c.run(0x1073a if absolute else 0x1063e,RETURN,15000)
    assert bytes(c.memory)==expected(before,base,absolute)
    assert c.cpu.d[0]==base and c.cpu.d[1]==(d[1]&0xffff0000)|65535
    assert list(c.cpu.d)[2:]==d[2:] and list(c.cpu.a)[1:7]==a[1:7]
    assert c.cpu.a[0]==base+0x6598 and c.cpu.a[7]==STACK+4

@pytest.mark.parametrize('absolute',(False,True))
@pytest.mark.parametrize('value',(0,0xffffffff,0x70000,0x6ffff))
def test_optional_reference_guards_and_reserved_relative_collisions(absolute,value):
    base=0x70000;c=machine(base);supplied(c,base)
    for off in (0xa76,0x85a,0x9b0):put(c.memory,base+off,value)
    for i in range(10):put(c.memory,base+0xa02+4*i,value)
    before=bytes(c.memory);c.run(0x1073a if absolute else 0x1063e,RETURN,15000)
    assert bytes(c.memory)==expected(before,base,absolute)

@pytest.mark.parametrize('base',(0x70000,0x70004,0x90000))
def test_roundtrip_retains_original_sentinel_collisions(base):
    c=machine(base);supplied(c,base);before=bytes(c.memory)
    c.run(0x1063e,RETURN,15000);relative=expected(before,base,False)
    assert bytes(c.memory)==relative
    c.cpu.a[7]=STACK;c.run(0x1073a,RETURN,15000)
    assert bytes(c.memory)==expected(relative,base,True)
    lost=[]
    for i in range(250):
        record=base+0x2330+i*68
        if before[record+1]&128:continue
        for off in (56,60):
            at=record+off
            if get(before,at) in (base,base-1):
                lost.append(at);assert get(c.memory,at)==(get(before,at)-base)&0xffffffff
    assert len(lost)>20

@pytest.mark.parametrize('record_index',(0,1,249))
@pytest.mark.parametrize('tag',(0,1,12,30,128,0xffff))
def test_actual_saved_prefix_copy_calls_restore_without_validating_player_tag(record_index,tag):
    base=0x70000;c=machine(base);source=0x431f4;prefix,size=0x6b4,0x5ee4
    saved=bytearray(size);record=0x2330+68*record_index
    put(saved,0x700-prefix,record);put(saved,record-prefix,tag,2)
    rotations=bytes.fromhex('01230abc0fff');saved[record-prefix+16:record-prefix+22]=rotations
    c.seed(source,saved);c.cpu.a[0]=base+prefix;c.cpu.a[1]=source;c.cpu.d[1]=0x17b8
    before=bytes(c.memory);c.run(0xfff6,0x10876,30000)
    assert c.read(base, prefix)==before[base:base+prefix]
    assert c.read(base+0x6598,8)==before[base+0x6598:base+0x65a0]
    assert get(c.memory,base+0x700)==base+record
    assert get(c.memory,base+record,2)==tag and c.read(base+record+16,6)==rotations
    assert c.read(source,size)==saved and c.read(base+0xbbb,1)==b'\xff'

@pytest.mark.parametrize('direction',(0,1,127,128,255))
def test_original_projector_network_broadcast_walks_exactly_250_records(direction):
    base=0x70000;c=machine(base);pool=base+0x2330
    tags=(0,74,75,76,77,78,79,80,81,82,83,0x14b,0xff4b)
    before=bytearray(c.read(pool,17000));wanted=bytearray(before)
    for i in range(250):
        kind=tags[i%len(tags)];put(before,i*68,kind,2);before[i*68+31]=i&255
    wanted[:]=before
    for i in range(250):
        if 75<=get(before,68*i,2)<=82:wanted[68*i+31]=direction
    c.seed(pool,before);c.seed(base+0xaa7,bytes([direction]));guards=c.read(pool-4,4),c.read(pool+17000,4)
    c.run(0x3683e,RETURN,5000)
    assert c.read(pool,17000)==wanted
    assert (c.read(pool-4,4),c.read(pool+17000,4))==guards
    assert c.cpu.a[0]==pool+17000

@pytest.mark.parametrize('discarded_return',(0x12ec,0x12345678,0xffffff00))
def test_save_abort_restores_pointers_before_discarding_its_return_and_disk_call(discarded_return):
    base=0x70000;c=machine(base);supplied(c,base);before=bytes(c.memory)
    c.seed(STACK,discarded_return.to_bytes(4,'big')+bytes.fromhex('a55af00d'))
    c.allow_write(STACK,4);c.run(0x101c6,0x10876,16000)
    result=expected(before,base,True)
    assert c.read(base-8,0x65a8)==result[base-8:base+0x65a0]
    assert c.cpu.d[1]==discarded_return and c.cpu.a[7]==STACK
    assert c.read(STACK,8)==bytes.fromhex('000101d0a55af00d')

@pytest.mark.parametrize('body',(8,14))
@pytest.mark.parametrize('free',(0,1,2,5,9,65535))
@pytest.mark.parametrize('presence',(0,1,8,255))
@pytest.mark.parametrize('complete',(0,128))
def test_projector_templates_bound_indexed_presence_and_allocate_actual_lifo_children(body,free,presence,complete):
    base=0x70000;c=machine(base);stack,records=0x68000,[0x62000+68*i for i in range(9)]
    for i,at in enumerate(records):
        c.seed(stack+4*i,at.to_bytes(4,'big'));c.seed(at,b'\xcc'*68);c.allow_write(at,68)
    cursor=stack+4*free if free<=9 else stack+36
    for off,value,width in ((0x830,body,2),(0x772,free,2),(0x6d4,cursor,4),(0x872,0xdeadbeef,4),(0x876,0xdeadbeef,4)):
        put(c.memory,base+off,value,width)
    c.seed(base+0xaa7,bytes([complete]));c.seed(base+0xaa9+8*(14-body),bytes(255 if presence>>i&1 else 0 for i in range(8)))
    c.run(0x37f88,RETURN,1000)
    selected=[i for i in range(8) if presence>>i&1][:max(0,(free if free<32768 else free-65536)-1)]
    assert get(c.memory,base+0x772,2)==free-len(selected)
    assert get(c.memory,base+0x6d4)==cursor-4*len(selected)
    data=shared_bytes()
    for j,i in enumerate(selected):
        at=records[free-1-j];kind=75+i;template=0x38448+10*i
        expected=bytearray(b'\xcc'*68);put(expected,0,kind,2);expected[3]=0
        expected[4:8]=data[template+2:template+6];expected[8:12]=bytes(4)
        expected[12:16]=data[template+6:template+10];expected[16:22]=bytes(6)
        expected[28]|=128;expected[29]=data[0x17b8e+kind];expected[30]=255;expected[31]=1 if complete&128 else 0
        assert c.read(at,68)==expected
    for at in records[:free-len(selected)] if free<=9 else records:assert c.read(at,68)==b'\xcc'*68
    assert [get(c.memory,base+off)for off in (0x872,0x876)]==([0x7000,0x7000]if 3 in selected else [0xdeadbeef]*2)

def test_committed_source_inherits_actor_fields_and_keeps_representation_views_scoped():
    s=(Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered/retail-shared.s').read_text()
    constructor=s.split('initialize_projector_part_without_full_record_clear:',1)[1].split('skip_unspawned_projector_template_coordinates:',1)[0]
    assert 'move.l (a1)+,SG2ActorModelPrefix_world_x(a4)' in constructor
    assert 'move.b #$0,SG2ProjectorPart_network_animation_step(a4)' in constructor
    assert 'move.b d2,SG2ProjectorPart_network_animation_step(a0)' in s
    assert 'SG2ActorModelPrefix_network_animation_step' not in s
    assert 'SG2WorkspaceReferencePrefix_carried_neutron_bomb_reference(a6)' in s
    assert 'broadcast_neutron_gate_variant_step' not in s
    assert 'projector_part_placement_templates:' in s

"""Original retail pickup and depot transfers over bounded supplied RAM.

These CPU witnesses retain original signed-byte behavior and source-table writes.
They do not establish live pickup, all service-index bounds or actor lifetime.
"""
import pytest
from test_starglider2_retail_inventory import base,APP,STACK,COUNTS,POINTERS
from test_starglider2_retail_workspace import put,get
from tests.test_starglider2_tractor_state import signed

D=0x195a
ACTOR=0x88000
FLAGS=0x3ae84
DELIVERED=APP+0xb4d
INGREDIENTS=0x3aa74
REQUIRED,REWARD=0x3aa2e,0x3aa37
STOP=0x34358+D
pytestmark=pytest.mark.skipif(__import__('os').getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')

def enter(platform='st',kind=102,count=0):
 c=base(platform);c.seed(ACTOR,b'\xa5'*68);c.allow_write(ACTOR,68);put(c.memory,ACTOR,kind,2)
 for n in range(3):put(c.memory,ACTOR+4+4*n,0);put(c.memory,APP+0x704+4*n,0)
 put(c.memory,APP+0x838,ACTOR);c.memory[COUNTS+kind]=count;c.cpu.a[0]=ACTOR;c.cpu.d[0]=ord('C');return c

def pickup(c,start=0x355d2,stop=0x3577e):c.run(start+D,stop+D,20000)

def prepare_service(c,index):
 put(c.memory,APP+0x6c2,index,2);c.memory[APP+0x77c]=255;c.memory[APP+0xa85:APP+0xa91]=bytes(12)
 for address in (0x3b622,0x3aa72,0x3b61d):c.allow_write(address,1)
 c.seed(POINTERS-4,b'\xcc'*32)

def exchange(c,index):
 prepare_service(c,index+3);c.run(0x3425a+D,STOP,20000)

def message(c,index,completed):
 template=0x39fe6 if completed else 0x39fda
 a,b,z=[get(c.memory,template+4*n)for n in range(3)]
 names=0xf380;required=c.memory[REQUIRED+index];reward=c.memory[REWARD+index]
 return [a,b,get(c.memory,names+4*required),z,get(c.memory,names+4*reward),0xffffffff]

@pytest.mark.parametrize('platform,kind', [('st',n)for n in range(104)if n not in (12,91)]+[('amiga',n)for n in (8,98,102)])
def test_real_collect_key_uses_original_type_flags_then_retires_only_admitted_targets(platform,kind):
 c=enter(platform,kind);before=c.read(ACTOR,68);free=get(c.memory,APP+0x772,2)
 if kind==98:c.allow_write(FLAGS+98,1)
 pickup(c)
 accepted=not(c.memory[FLAGS+kind]&128)
 # The type98 write deliberately changes the exclusion-table byte before the ordinary count increment.
 assert c.memory[COUNTS+kind]==int(accepted)
 expected=bytearray(before)
 if accepted:expected[:2]=b'\0\0'
 if kind==8:expected[0x22]=0
 assert c.read(ACTOR,68)==expected
 assert c.memory[APP+0xa9f]==(255 if accepted else 0) and c.memory[APP+0xaa0]==(10 if accepted else 0)
 assert get(c.memory,APP+0x838)==ACTOR and get(c.memory,APP+0x772,2)==free
 assert c.cpu.a[7]==STACK
 if kind==8:assert c.memory[APP+0xa80]==255

@pytest.mark.parametrize('axis',range(3))
@pytest.mark.parametrize('distance',(2999,3000,-2999,-3000,-2147483648))
def test_key_axis_gate_precedes_eligibility(axis,distance):
 c=enter();put(c.memory,ACTOR+4+4*axis,distance&0xffffffff)
 target=0x3562c if distance in (3000,-3000,-2147483648)else 0x3564e
 pickup(c,stop=target);assert get(c.memory,ACTOR,2)==102 and c.memory[COUNTS+102]==0

@pytest.mark.parametrize('count',(0,1,2,3,127,128,255))
def test_general_pickup_population_gate_and_direct_increment_are_distinct(count):
 c=enter(count=count);pickup(c);accepted=count<=2
 assert c.memory[COUNTS+102]==(count+1 if accepted else count)
 assert get(c.memory,ACTOR,2)==(0 if accepted else 102)
 c=enter(count=count);pickup(c,start=0x356ec)
 next_count=(count+1)&255;accepted=next_count<128
 assert c.memory[COUNTS+102]==(next_count if accepted else 127)
 assert get(c.memory,ACTOR,2)==(0 if accepted else 102)

@pytest.mark.parametrize('kind',(12,91))
@pytest.mark.parametrize('count',(3,4,126,127,128,255))
def test_weapon_pickup_uses_signed_compare_and_stops_before_hud_helper(kind,count):
 c=enter(kind=kind,count=count);n=(count+1)&255;accepted=signed(n,8)<=4
 target=(0x35720 if kind==12 else 0x35740)if accepted else 0x3576e
 pickup(c,stop=target)
 assert c.memory[COUNTS+kind]==(n if accepted else count) and get(c.memory,ACTOR,2)==kind

@pytest.mark.parametrize('inside',(0,127,128,255))
@pytest.mark.parametrize('enabled',(0,128))
@pytest.mark.parametrize('owned',(0,1))
def test_bomb_pickup_keeps_phase_specific_write_base_and_clear_loop(inside,enabled,owned):
 c=enter(kind=98,count=owned);c.memory[APP+0x77c]=inside;c.memory[APP+0xa84]=enabled
 c.memory[DELIVERED:DELIVERED+104]=b'\xa5'*104
 for off in (0xa7f,0xa82,0xa83):c.memory[APP+off]=255
 c.memory[APP+0x7ea]=16;c.memory[APP+0xae4]=255;c.allow_write(FLAGS+98,1)
 accepted=inside<128 or(owned==0 and enabled>=128)
 destination=(FLAGS if inside<128 else DELIVERED+104)+98;prior=c.memory[destination]
 pickup(c,start=0x3567a,stop=0x356de if accepted else 0x3576e)
 assert c.memory[destination]==(1 if accepted else prior) and c.memory[COUNTS+98]==owned
 assert c.read(DELIVERED,104)==(bytes(104)if accepted and inside>=128 else b'\xa5'*104)
 assert [c.memory[APP+o]for o in (0xa7f,0xa82,0xa83)]==([0]*3 if accepted and inside>=128 else[255]*3)
 assert c.memory[APP+0xae3]==(255 if accepted else 0) and c.memory[APP+0xae4]==(0 if accepted else 255)

@pytest.mark.parametrize('platform,index,owned,other',
 [('st',i,a,b)for i in range(9)for a,b in ((0,0),(1,0),(1,1),(1,2),(2,0))]+[('amiga',0,1,0)])
def test_original_trade_tables_guard_total_then_exchange_one_and_build_complete_message(platform,index,owned,other):
 c=base(platform);required=c.memory[REQUIRED+index];reward=c.memory[REWARD+index]
 assert c.read(REQUIRED,9)==bytes((24,55,51,71,10,73,11,3,24))
 assert c.read(REWARD,9)==bytes((100,83,101,102,38,29,87,73,100))
 c.memory[COUNTS+required]=owned;c.memory[COUNTS]=other;expected=bytearray(c.read(COUNTS,104))
 completed=owned!=0 and owned+other<3
 if completed:expected[required]-=1;expected[reward]+=1
 exchange(c,index)
 assert c.read(COUNTS,104)==expected
 assert [get(c.memory,POINTERS+4*n)for n in range(6)]==message(c,index,completed)
 assert c.read(POINTERS-4,4)==c.read(POINTERS+24,4)==b'\xcc'*4 and c.cpu.a[7]==STACK

@pytest.mark.parametrize('count',(0,1,126,127,128,254,255))
def test_trade_reward_direct_increment_is_n_only_clamp(count):
 c=base();reward=c.memory[REWARD];c.memory[COUNTS+reward]=count
 c.cpu.a[0]=COUNTS;c.cpu.a[3]=REWARD;c.cpu.d[0]=0;c.cpu.a[1]=POINTERS;c.cpu.a[2]=REQUIRED;c.cpu.a[4]=0xf380
 c.run(0x342a8+D,STOP,20000)
 n=(count+1)&255;assert c.memory[COUNTS+reward]==(127 if n&128 else n)

@pytest.mark.parametrize('platform',('amiga','st'))
@pytest.mark.parametrize('kind',(102,101,100,83,29,73,38,87))
def test_actual_key_pickup_then_depot_service_moves_one_ingredient_to_delivered_array(platform,kind):
 c=enter(platform,kind);pickup(c,start=0x355d2 if kind==73 else 0x354e2);assert c.memory[COUNTS+kind]==1 and get(c.memory,ACTOR,2)==0
 prepare_service(c,1);c.run(0x3416a+D,STOP,20000)
 assert c.memory[COUNTS+kind]==0 and c.memory[DELIVERED+kind]==1
 assert c.memory[APP+0xa86]==255 and c.memory[APP+0xa92]==1
 assert get(c.memory,APP+0x838)==ACTOR and get(c.memory,APP+0x772,2)==0
 # A second frame in the same visit does not debit another ingredient.
 c.memory[COUNTS+kind]=2;c.run(0x3416a+D,STOP,20000)
 assert c.memory[COUNTS+kind]==2 and c.memory[DELIVERED+kind]==1 and c.memory[APP+0xa92]==1

@pytest.mark.parametrize('owned',(1,127,128,255))
@pytest.mark.parametrize('delivered',(0,126,127,128,255))
def test_ingredient_transfer_debits_one_with_original_signed_byte_clamps(owned,delivered):
 c=base();prepare_service(c,1);k=c.memory[INGREDIENTS]
 c.memory[COUNTS+k]=owned;c.memory[DELIVERED+k]=delivered;c.run(0x341da+D,STOP,20000)
 debit=(owned-1)&255;credit=(delivered+1)&255
 assert c.memory[COUNTS+k]==(0 if debit&128 else debit)
 assert c.memory[DELIVERED+k]==(127 if credit&128 else credit)

@pytest.mark.parametrize('mask',(0,1,2,4,8,16,32,64,128,0x55,0xaa,0xfe,0xff))
def test_service_delivery_marks_professor_and_builds_missing_ingredient_list(mask):
 c=base();prepare_service(c,1);c.memory[APP+0xa7f]=255;c.memory[APP+0xa80]=255
 ingredients=c.read(INGREDIENTS,8)
 for n,k in enumerate(ingredients):c.memory[COUNTS+k]=int(bool(mask&(1<<n)))
 c.run(0x3416a+D,0x343fc+D,20000)
 assert c.memory[APP+0xa80]==0 and c.memory[APP+0xa81]==255
 assert [c.memory[COUNTS+k]for k in ingredients]==[0]*8
 assert [c.memory[DELIVERED+k]for k in ingredients]==[int(bool(mask&(1<<n)))for n in range(8)]
 expected=[0x3a6f6]+[get(c.memory,0x39fba+4*n)for n in range(7,-1,-1)if not(mask&(1<<n))]+[0xffffffff]
 assert [get(c.memory,POINTERS+4*n)for n in range(len(expected))]==expected
 assert c.memory[APP+0xa82]==(255 if mask==255 else 0)

@pytest.mark.skipif(not __import__('os').getenv('SGII_RETAIL_VASM'),reason='external vasm is the only source build dependency')
def test_compiled_pickup_depot_symbols_keep_code_data_and_workspace_identities(tmp_path):
 import os,struct,subprocess
 from pathlib import Path
 from test_starglider2_retail_model_headers import image
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered'
 names=['test_tractor_collect_key','retire_collected_actor_before_frame_recycling','service_current_structure_visit','transfer_carried_ingredients_into_depot_storage','object_collect_exclusion_flags','depot_trade_required_model_types','depot_trade_reward_model_types','neutron_bomb_ingredient_model_types','SG2PickupDepotWorkspace_delivered_model_counts_prefix','SG2EmmaTransport_taymar_radio_enabled_flag']
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(names)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert r.returncode==0,r.stdout+r.stderr
 data=out.read_bytes();assert data[:-40]==image('st')
 assert struct.unpack('>10I',data[-40:])==(0x36f2c,0x370b0,0x35ac4,0x35b34,0x3ae84,0x3aa2e,0x3aa37,0x3aa74,0xb4d,34)

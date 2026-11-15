"""Retail order, readiness and bomb creation through original CPU continuations.

Stock, location and key bytes are explicit fixture inputs. Display/save handoffs
are boundaries, not UI, disk-save or live mission-completion claims.
"""
import os
import pytest
from test_starglider2_retail_inventory import base,APP,STACK,COUNTS
from test_starglider2_retail_pickup_depot import D,ACTOR,DELIVERED,INGREDIENTS,pickup
from test_starglider2_retail_workspace import put,get

pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
FREE,DISTANT=0x90000,0x91000
TIMER,TABLE=APP+0x9c2,0x3aa52
STATE,INDEX,MASK,TICK,PAUSE=0x3aa64,0x3aa6a,0x3aa6c,0x3aa6e,0x3aa70
SERVICE=0x34172+D
HANDLERS=[p+D for p in (0x3446a,0x344e0,0x3450e,0x3458c)]
DISPLAY=0x3b67e

def setup(platform='st',free=2,distant=0,inside=255,body=3):
 c=base(platform);c.allow_write(STATE,14);c.seed(ACTOR,b'\xa5'*68);c.allow_write(ACTOR,68)
 c.seed(FREE,ACTOR.to_bytes(4,'big'));put(c.memory,APP+0x6d4,FREE+4);put(c.memory,APP+0x772,free,2)
 c.seed(DISTANT,ACTOR.to_bytes(4,'big'));put(c.memory,APP+0x6b8,DISTANT);put(c.memory,APP+0x75c,distant,2)
 c.memory[APP+0xa81]=255;c.memory[APP+0x77c]=inside;put(c.memory,APP+0x830,body,2)
 put(c.memory,APP+0xa72,0,2);put(c.memory,TIMER,0,2)
 return c

def ready(c):c.run(0x340ac+D,SERVICE,2000)

def expected_record():
 b=bytearray(b'\xa5'*68);b[:2]=(98).to_bytes(2,'big')
 for o,v in ((4,0xa71e),(8,0xfffffea2),(12,0x14d12)):b[o:o+4]=v.to_bytes(4,'big')
 b[16:22]=bytes(6);b[28]=0xa5|128;b[30]=255;b[3]=0;b[29]=5;b[2]|=128
 return b

@pytest.mark.parametrize('delivered,already_ready,countdown,elapsed',[(0,0,0,False),(127,0,0,False),(128,128,0,False),(255,255,0,False),(128,0,0,True),(255,0,1,False),(255,0,2,False),(255,0,0x8000,False),(255,0,0x8001,True),(255,0,0xffff,True)])
def test_timer_uses_signed_flags_and_postdecrement_n_without_ingredient_gate(delivered,already_ready,countdown,elapsed):
 c=setup();c.memory[APP+0xa81]=delivered;c.memory[APP+0xa83]=already_ready;put(c.memory,TIMER,countdown,2)
 before=c.read(ACTOR,68);ready(c)
 active=delivered>=128 and already_ready<128
 assert get(c.memory,TIMER,2)==(get(c.memory,TABLE,2)if elapsed else(countdown-1)&65535 if active else countdown)
 assert c.memory[APP+0xa83]==(255 if elapsed else already_ready)
 assert c.read(ACTOR,68)==(expected_record()if elapsed else before)
 assert c.memory[APP+0xa7f]==c.memory[APP+0xa82]==0

@pytest.mark.parametrize('index',range(9))
def test_all_nine_bounded_timer_words_are_read_at_word_stride(index):
 c=setup(inside=0);put(c.memory,APP+0xa72,index,2);ready(c)
 assert c.read(TABLE,18)==bytes.fromhex('400040004000400020002000200020002000')
 assert get(c.memory,TIMER,2)==get(c.memory,TABLE+2*index,2) and c.memory[APP+0xa83]==255
 assert c.read(ACTOR,68)==b'\xa5'*68

@pytest.mark.parametrize('platform,free,distant,spawn', [('st',0,0,False),('st',0,1,True),('st',1,0,False),('st',1,1,True),('st',1,65535,True),('st',2,0,True),('st',65535,0,True),('amiga',2,0,True),('amiga',1,1,True)])
def test_bomb_creation_pops_reserve_or_borrows_distant_pointer_without_full_record_reset(platform,free,distant,spawn):
 c=setup(platform,free=free,distant=distant);ready(c);pop=spawn and free>1
 assert c.read(ACTOR,68)==(expected_record()if spawn else b'\xa5'*68)
 assert get(c.memory,APP+0x772,2)==(free-1 if pop else free)
 assert get(c.memory,APP+0x6d4)==FREE+(0 if pop else 4)
 assert get(c.memory,APP+0x75c,2)==distant and get(c.memory,APP+0x6b8)==DISTANT
 assert c.memory[APP+0xa83]==(255 if spawn else 0) and get(c.memory,TIMER,2)==0x4000
 assert c.cpu.a[7]==STACK

@pytest.mark.parametrize('inside,body',[(0,3),(127,3),(128,2),(255,4)])
def test_ready_can_be_published_without_a_world_actor_outside_required_location(inside,body):
 c=setup(inside=inside,body=body,free=0);ready(c)
 assert c.memory[APP+0xa83]==255 and c.read(ACTOR,68)==b'\xa5'*68 and get(c.memory,APP+0x772,2)==0

@pytest.mark.parametrize('token', (0,0x59,0x4e,0xa0,0x12340059,0xffff004e))
def test_order_choice_uses_low_token_byte_and_resets_only_yes_no_state(token):
 c=setup();c.memory[APP+0xa7f]=0x55;c.cpu.d[0]=token
 for p in (INDEX,MASK,TICK,PAUSE):put(c.memory,p,0x7777,2)
 b=token&255;choice=b in (0x59,0x4e);stop=(0x354da+D if b==0xa0 else DISPLAY if choice else 0x3466c+D)
 c.run(0x3460e+D,stop,2000)
 for p,v in ((INDEX,0),(MASK,31 if b==0x59 else 15),(PAUSE,2),(TICK,0)):assert get(c.memory,p,2)==(v if choice else 0x7777)
 assert c.memory[APP+0xa7f]==(255 if b==0x59 else 0 if b==0x4e else 0x55)
 if choice:assert c.cpu.a[1]==get(c.memory,0x394ba+4*(33 if b==0x59 else 34)) and c.cpu.a[7]==STACK-4

@pytest.mark.parametrize('platform,key,yes',[('st',0x15,True),('st',0x36,False),('amiga',0x15,True),('amiga',0x36,False)])
def test_actual_shared_key_poll_supplies_order_choice(platform,key,yes):
 c=setup(platform);c.memory[APP+0x203]=key;c.memory[APP+0xa7f]=0;put(c.memory,0x27be,APP)
 c.run(0x345f2+D,DISPLAY,3000)
 assert c.memory[APP+0xa7f]==(255 if yes else 0) and c.memory[APP+0x203]==0
 assert get(c.memory,MASK,2)==(31 if yes else 15)

@pytest.mark.parametrize('order,owned,ejected',[(128,0,0),(255,0,0),(0,1,0),(0,255,0),(0,0,128)])
def test_order_and_owned_bomb_bypass_key_poll_while_ejection_uses_existing_token(order,owned,ejected):
 c=setup();c.memory[APP+0xa7f]=order;c.memory[COUNTS+98]=owned;c.memory[0x3b4c6]=ejected
 c.memory[APP+0x203]=0x36;c.cpu.d[0]=ord('Y')
 c.run(0x345f2+D,DISPLAY if ejected else 0x3466c+D,2000)
 assert c.memory[APP+0x203]==0x36 and c.memory[APP+0xa7f]==(255 if ejected else order)

@pytest.mark.parametrize('complete,aboard,delivered,tick',[(False,0,0,31),(True,0,0,31),(False,0,128,31),(True,0,255,31),(True,255,0,31),(False,0,127,0)])
def test_four_dialogue_states_require_tick_wrap_and_keep_delivery_sign(complete,aboard,delivered,tick):
 c=setup();c.memory[APP+0xa7f]=255;c.memory[APP+0xa80]=aboard;c.memory[APP+0xa81]=delivered
 put(c.memory,APP+0x6c2,1,2);put(c.memory,TICK,tick,2);put(c.memory,STATE,0x7777,2)
 kinds=c.read(INGREDIENTS,8)
 for k in kinds if complete else kinds[:1]:c.memory[DELIVERED+k]=255
 state=2*int(aboard>=128 or delivered>=128)+int(complete);stop=HANDLERS[state]if tick==31 else 0x34a62+D
 c.run(0x34358+D,stop,3000)
 assert c.memory[APP+0xa80]==0 and c.memory[APP+0xa81]==(255 if aboard>=128 else delivered)
 assert get(c.memory,TICK,2)==(tick+1)&31 and get(c.memory,STATE,2)==(state if tick==31 else 0x7777)
 assert c.memory[APP+0xa82]==(255 if complete else 0)

@pytest.mark.parametrize('state,is_ready,offset',[(0,0,0),(0,0,12),(1,0,0),(1,0,8),(2,0,0),(2,0,16),(2,128,0),(2,128,16),(3,0,0),(3,128,0),(3,0,12),(3,255,12)])
def test_dialogue_lists_and_sentinels_keep_collection_enable_scoped_to_complete_delivery(state,is_ready,offset):
 c=setup();c.memory[APP+0xa83]=is_ready;c.allow_write(0x3aa72,1);c.memory[0x3aa72]=255;put(c.memory,APP+0x9c0,offset,2)
 tables=(0x39f56,0x39f66,0x39f72 if is_ready<128 else 0x39fa6,0x39f86 if is_ready<128 else 0x39f96)
 table=tables[state];pointer=get(c.memory,table+offset)
 c.run(HANDLERS[state],DISPLAY,2000)
 expected=pointer if pointer!=0xffffffff else get(c.memory,0x394ba+0x8c)
 assert c.cpu.a[1]==expected and c.memory[APP+0xa84]==(255 if state==3 else 0)
 assert get(c.memory,APP+0x9c0,2)==(0 if pointer==0xffffffff else offset)
 assert c.memory[0x3aa72]==(1 if pointer==0xffffffff and state==2 else 255)


def test_professor_delivery_can_start_bomb_before_ingredients_but_collection_remains_gated():
 c=setup();c.memory[APP+0xa81]=0;c.memory[APP+0xa80]=255;c.memory[APP+0xa7f]=255
 put(c.memory,APP+0x6c2,1,2);put(c.memory,TICK,31,2)
 c.run(0x34358+D,HANDLERS[2],3000)
 assert c.memory[APP+0xa81]==255 and c.memory[APP+0xa82]==c.memory[APP+0xa84]==0
 ready(c);assert c.memory[APP+0xa83]==255 and get(c.memory,ACTOR,2)==98
 put(c.memory,APP+0x838,ACTOR)
 # Place the CPU fixture player at the original created actor's coordinates.
 for o in (4,8,12):put(c.memory,APP+0x700+o,get(c.memory,ACTOR+o))
 c.cpu.d[0]=ord('C');pickup(c);assert get(c.memory,ACTOR,2)==98 and c.memory[COUNTS+98]==0
 for k in c.read(INGREDIENTS,8):c.memory[DELIVERED+k]=1
 put(c.memory,TICK,31,2);c.run(0x34358+D,HANDLERS[3],3000)
 c.run(HANDLERS[3],0x345be+D,1000);assert c.memory[APP+0xa84]==255
 c.cpu.d[0]=ord('C');pickup(c);assert get(c.memory,ACTOR,2)==0 and c.memory[COUNTS+98]==1
 assert c.read(DELIVERED,104)==bytes(104)
 assert [c.memory[APP+o]for o in (0xa7f,0xa82,0xa83,0xa84)]==[0]*4

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='external vasm is the only source build dependency')
def test_compiled_taymar_symbols_bind_original_code_data_and_countdown_slot(tmp_path):
 import struct,subprocess
 from pathlib import Path
 from test_starglider2_retail_model_headers import image
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered'
 names=['advance_taymar_bomb_readiness','initialize_ready_neutron_bomb_record','borrow_first_distant_record_for_ready_bomb','taymar_dialogue_state_handlers','taymar_offer_dialogue_pointers','taymar_order_dialogue_pointers','station_sequence_bomb_spawn_countdowns','SG2PickupDepotWorkspace_neutron_bomb_spawn_countdown']
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(names)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert r.returncode==0,r.stdout+r.stderr
 data=out.read_bytes();assert data[:-32]==image('st')
 assert struct.unpack('>8I',data[-32:])==(0x35a06,0x35a7c,0x35a6e,0x35db4,0x39e96,0x39ed6,0x3aa52,0x9c2)

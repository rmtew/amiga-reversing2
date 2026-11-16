"""Original pirate dispatch, theft and drop consumers with constructed state.

No natural-playthrough, global inventory domain or actor ownership/lifetime
proof. The existing independent prefix oracles are reused through address maps.
"""
import ctypes,os
import pytest
from tests import test_starglider2_pirate_raid as old
from tests.test_starglider2_text_editor import state,run,put,get,APP,INPUT,STACK,RETURN
from test_starglider2_retail_input import program
from test_starglider2_retail_encounters import rng,word,PHASE,GAP,BURST
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
FIELDS=dict(free_object_count=0x772,free_object_stack_cursor=0x6d4,model_type_population_counts=0xae5,neutron_bomb_ingredient_model_types=0x3aa74,projector_rebuild_part_types=0x3aa7c,pirate_destruction_drop_choices=0x3b496,SG2PirateShip_raid_attempt_mod8_index=38)
END=0x3b6a2

@pytest.fixture(params=('amiga','st'))
def machine(request,monkeypatch):
 image=program(request.param);raw=image[0];m=(ctypes.c_uint8*0xa1000)();ctypes.memmove(ctypes.addressof(m)+4096,raw,len(raw))
 def retail_run(image,m,c,stops,*args,**kw):
  c.pc+=0x1954;run(image,m,c,{p+0x1954 for p in stops},*args,**kw);c.pc-=0x1954
 monkeypatch.setattr(old,'run',retail_run)
 return image,m

@pytest.mark.parametrize('xyz',((999,0,0),(1000,0,0),(1000,1000,0),(1000,0,1000),(0x80000000,0,0),(0xffffffff,0,0)))
def test_raid_distance_signs_reuse_original_independent_oracle(machine,xyz):
 image,m=machine;old.test_raid_distance_gates_use_result_sign_not_signed_order(image,m,*xyz)

@pytest.mark.parametrize('phase',(0,7,65535))
def test_attempt_mod8_gate_precedes_randomness(machine,phase):
 image,m=machine;old.test_raid_attempt_counter_masks_before_random_gate(image,m,FIELDS,phase)

@pytest.mark.parametrize('draw,free',((0,20),(0,21),(1,65535),(0xfffffff8,65535)))
def test_theft_gate_keeps_random_low_bits_and_unsigned_free_reserve(machine,draw,free):
 image,m=machine;old.test_first_random_gate_and_unsigned_free_threshold_precede_selection(image,m,FIELDS,draw,free)

@pytest.mark.parametrize('choice,quantity',((0,0),(1,1),(4,128),(7,255)))
def test_doubled_byte_selector_can_read_next_owner_and_select_zero(machine,choice,quantity):
 image,m=machine;old.test_doubled_byte_selector_crosses_into_next_owner_and_can_publish_zero_tag(image,m,FIELDS,choice,quantity)

@pytest.mark.parametrize('choice,free,velocity',((0,21,(16,65515,40)),(2,20,(16,65515,40)),(2,21,(16,65515,40)),(10,65535,(32768,32767,65535))))
def test_drop_prefix_preserves_original_repeated_x_store(machine,choice,free,velocity):
 image,m=machine;old.test_loot_prefix_keeps_three_stores_to_x_and_other_child_bytes(image,m,FIELDS,choice,free,velocity)

PARENT,CHILD,DROP,FREE=INPUT+0x1000,INPUT+0x1044,INPUT+0x1088,INPUT+0x200

def setup_lifecycle(m):
 put(m,APP+0x44,0x15808);put(m,APP+0x48,0x16008);put(m,APP+0x6fc,65535)
 for off,value in((0x704,1000),(0x708,2000),(0x70c,3000)):put(m,APP+off,value)
 for i,p in enumerate((DROP,CHILD,PARENT)):put(m,FREE+4*i,p)
 put(m,APP+0x6d4,FREE+12);word(m,APP+0x772,153);word(m,APP+0x830,1);word(m,APP+0x75a,1)
 put(m,APP+0x60,0);put(m,APP+0x64,1);word(m,PHASE,3);word(m,GAP,65535);word(m,BURST,1)


def dispatch(image,m,parent=PARENT):
 c=state(m,0x8002);c.a[0]=parent;run(image,m,c,{0x3870e});assert c.a[0]==parent;return c


def test_encounter_spawn_through_real_dispatch_theft_and_admitted_drop(machine):
 image,m=machine;setup_lifecycle(m);word(m,0x391e8,0);c=state(m,0x34fd8);run(image,m,c,{0x3524c},limit=2000)
 assert get(m,PARENT,2)==40 and get(m,APP+0x772,2)==152
 # Explicit constructed approach/stock/damage states;normal inputs are not claimed.
 for off,value in((0x704,get(m,PARENT+4)-2000),(0x708,get(m,PARENT+8)),(0x70c,get(m,PARENT+12))):put(m,APP+off,value&0xffffffff)
 m[PARENT+28]=5;m[PARENT+2]=0;word(m,PARENT+32,0);word(m,PARENT+36,1);word(m,PARENT+38,7)
 for off in(44,46,48):word(m,PARENT+off,0)
 put(m,APP+0x60,0);put(m,APP+0x64,1);m[APP+0xae5+100]=3
 c=dispatch(image,m);run(image,m,c,{END},limit=5000)
 assert get(m,CHILD,2)==100 and get(m,CHILD+60)==PARENT and m[APP+0xae5+100]==2
 assert get(m,APP+0x772,2)==151 and get(m,APP+0x6d4)==FREE+4 and m[PARENT+30]==255
 m[PARENT+28]=2
 for off,value in((44,16),(46,65515),(48,40)):word(m,PARENT+off,value)
 put(m,APP+0x60,0);put(m,APP+0x64,11);c=dispatch(image,m);run(image,m,c,{END},limit=5000)
 assert get(m,DROP,2)==100 and get(m,DROP+60)==0xffffffff
 assert (get(m,DROP+44,2),get(m,DROP+46,2),get(m,DROP+48,2))==(10,0,0)
 assert m[PARENT+28]==0 and m[PARENT+30]==0 and get(m,PARENT,2)==40
 assert get(m,APP+0x772,2)==150 and get(m,APP+0x6d4)==FREE

@pytest.mark.parametrize('right,free',((9,21),(11,20)))
def test_skipped_drop_leaves_parent_active_and_children_unchanged(machine,right,free):
 image,m=machine;word(m,PARENT,40);m[PARENT+28]=2;m[PARENT+30]=255
 put(m,APP+0x60,0);put(m,APP+0x64,right);word(m,APP+0x772,free);put(m,APP+0x6d4,FREE+4);put(m,FREE,DROP)
 m[DROP:DROP+68]=b'\xa5'*68;before=bytes(m[PARENT:PARENT+68]);c=dispatch(image,m);run(image,m,c,{END},limit=3000)
 assert bytes(m[PARENT:PARENT+68])==before and bytes(m[DROP:DROP+68])==b'\xa5'*68
 assert get(m,APP+0x772,2)==free and get(m,APP+0x6d4)==FREE+4


def ready_raid(m,stock,step=16):
 word(m,PARENT,40);m[PARENT+28]=5;m[PARENT+30]=255;put(m,PARENT+4,2000)
 word(m,PARENT+18,4000);word(m,PARENT+36,1);word(m,PARENT+38,7);word(m,PARENT+40,step)
 put(m,APP+0x44,0x15808);put(m,APP+0x48,0x16008);put(m,APP+0x6fc,65535)
 put(m,FREE,CHILD);put(m,APP+0x6d4,FREE+4);word(m,APP+0x772,21);put(m,APP+0x60,0);put(m,APP+0x64,1);m[APP+0xae5+100]=stock

@pytest.mark.parametrize('stock,remaining',((1,0),(128,127),(255,0)))
def test_completed_theft_debits_inventory_with_original_byte_sign_clamp(machine,stock,remaining):
 image,m=machine;ready_raid(m,stock);c=dispatch(image,m);run(image,m,c,{END},limit=5000)
 assert get(m,CHILD,2)==100 and m[APP+0xae5+100]==remaining and get(m,APP+0x772,2)==20
 assert m[CHILD+42]==72 and m[PARENT+42]==0 and m[PARENT+30]==255

@pytest.mark.parametrize('step',(16,65520))
def test_missing_inventory_falls_back_to_actual_laser_constructor(machine,step):
 image,m=machine;ready_raid(m,0,step);c=dispatch(image,m);run(image,m,c,{END},limit=5000)
 parent_yaw=(4000+(step if step<32768 else step-65536))&4095
 expected=(parent_yaw+(1280 if step<32768 else -1280))&4095
 assert get(m,CHILD,2)==72 and get(m,CHILD+18,2)==expected and get(m,PARENT+18,2)==parent_yaw
 assert get(m,APP+0x772,2)==20 and get(m,APP+0x6d4)==FREE
 assert m[CHILD+30]==255 and m[PARENT+42]==72

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_pirate_dispatch_body_fields_and_drop_table(tmp_path):
 import struct,subprocess
 from pathlib import Path
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered';source=(directory/'retail-shared.s').read_text()
 symbols={'update_nearby_pirate_ship':0x3870e,'dispatch_nearby_pirate_ship_update':0x862c,'nearby_pirate_update_bridge':0xb4a0,'pirate_destruction_drop_choices':0x3b496,'copy_pirate_drop_velocity_with_repeated_x_stores':0x38a00,'SG2PirateShip_raid_approach_updates_or_negative':36,'SG2PirateShip_raid_attempt_mod8_index':38,'SG2PirateShip_paired_heading_rotation_step':40,'SG2InventoryWorkspace_model_type_population_counts':0xae5,'SG2PirateWorkspace_pending_bcd_score_addend':0x5c}
 assert 'SG2PirateShip_raid_attempt_mod8_index(a0)'in source
 block=source.split('update_nearby_pirate_ship:',1)[1].split('pirate_raid_measure_player_x_delta:',1)[0]
 assert 'cmpi.b #2,'in block and 'dc.b'not in block,block
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert r.returncode==0,r.stdout+r.stderr
 raw=out.read_bytes();size=4*len(symbols)
 assert raw[:-size]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-size:])==tuple(symbols.values())

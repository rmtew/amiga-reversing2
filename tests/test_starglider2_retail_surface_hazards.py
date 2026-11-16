"""Retail surface hazards and original type-47 dispatch over supplied states.

These CPU checks use explicit body, contact, pool and random state. They do not
prove natural encounter frequency, valid recycled-slot lifetimes or timing.
"""
import ctypes,os,struct
import pytest
from tests import test_starglider2_planet_hazards as oracle
from tests.test_starglider2_text_editor import state,run,put,get,APP
from test_starglider2_retail_input import program
from tests.test_starglider2_control_normalization import signed
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
FIELDS={k:APP+v for k,v in (
 ('selected_celestial_body_index',0x830),('inside_structure_flag',0x77c),('last_player_contact_type',0x6d8),
 ('free_object_count',0x772),('free_object_stack_cursor',0x6d4),('player_world_x',0x704),('player_world_y',0x708),('player_world_z',0x70c),
 ('icarus_power_reserve',0x774),('weapon_energy_reserve',0x794),('icarus_shield_strength',0x776),
 ('pending_transient_event_sound',0xbb6),('horizontal_world_wrap_mask',0x6fc),('shared_random_state_a',0x60),('shared_random_state_b',0x64))}
FIELDS.update(event_message_pointers=0x394ba,object_name_pointers=0xf380,player_rotation2_spin_steps=0x3b628,SG2_ROTATION2_SPIN_START_STEPS=64,update_nearby_falling_type47=0x386be)
FIELDS.update({'SG2ObjectCore_'+n:o for n,o in (('world_x',4),('world_y',8),('world_z',12),('retirement_phase_or_negative',30),('vertex_variant_selector',3),('durability_or_negative',28),('model_scale_shift',29))})
FIELDS.update({'SG2WorldObject_velocity_'+n:o for n,o in (('x',44),('y',46),('z',48))})

@pytest.fixture(params=('amiga','st'))
def machine(request,monkeypatch):
 image=program(request.param);m=(ctypes.c_uint8*0xa1000)();ctypes.memmove(ctypes.addressof(m)+4096,image[0],len(image[0]))
 def retail_run(image,m,c,stops,*args,**kw):
  if c.pc==0x386be:run(image,m,c,{0x3b6a2},*args,**kw);return
  c.pc+=0x195c;run(image,m,c,{p+0x195c for p in stops},*args,**kw);c.pc-=0x195c
 monkeypatch.setattr(oracle,'run',retail_run)
 for k,v in dict(COUNTER=0x391ea,QUEUE=0xe0c6,BLANK=0xe0fa).items():monkeypatch.setattr(oracle,k,v)
 return image,m,FIELDS

@pytest.mark.parametrize('body,inside,contact,seeds',((1,0,20,(0,0)),(8,127,20,(0,0)),(8,128,20,(0,0xfff9)),(8,0,19,(0,0)),(8,0,20,(0,0)),(8,0,21,(0,0xfff9)),(65535,0,20,(0,0))))
def test_broadway_sign_gate_random_sampling_and_exact_contact(machine,body,inside,contact,seeds):
 oracle.test_broadway_uses_sign_gate_then_random_or_exact_contact(*machine,body,inside,contact,seeds)

@pytest.mark.parametrize('body,free,phase,seeds',((8,11,3,(0,0xfff9)),(1,10,3,(0,0xfff9)),(1,11,2,(0,0xfff9)),(1,11,3,(0,0)),(1,11,3,(0,0xfff9)),(1,65535,65535,(0,0xfff9)),(1,0,32768,(0,0))))
def test_dante_unsigned_capacity_modulo_counter_and_sample_boundary(machine,body,free,phase,seeds):
 oracle.test_dante_counter_only_advances_after_body_and_unsigned_free_gates(*machine,body,free,phase,seeds)

@pytest.mark.parametrize('seeds,origin',(((0,0),(0,0)),((0,0xfff9),(0x7fffffff,0x80000000)),((0xffffffff,0x12345678),(0xffffffff,12345))))
def test_spawn_uses_two_further_random_steps_and_preserves_unwritten_actor_bytes(machine,seeds,origin):
 oracle.test_dante_spawn_consumes_two_more_random_values_and_retains_velocity(*machine,seeds,origin)

@pytest.mark.parametrize('delta,origin,y,reserve',(((0,0),(0,0),-501,0),((0,0),(0,0),-500,65530),((-4096,4095),(0x7fffffff,0x80000000),-499,0),((-1,1),(0,0),2147483647,65535),((4095,4095),(0,0),-2147483648,1),((1,0),(0,0),0,65530)))
def test_spawn_reward_keeps_low_word_distance_y_gate_and_saturation(machine,delta,origin,y,reserve):
 oracle.test_dante_recharge_uses_low_word_distance_and_independent_saturation(*machine,delta,origin,y,reserve)

@pytest.mark.parametrize('y,velocity',((-121,0),(-120,0),(-119,-1),(0,-32768),(-2147483648,-1),(2147483647,32767),(-121,32767)))
def test_falling_update_y_gate_precedes_horizontal_wrap_and_gravity(machine,y,velocity):
 oracle.test_type47_vertical_gate_precedes_horizontal_wrap_and_gravity(*machine,y,velocity)

@pytest.mark.parametrize('body',(1,8))
def test_shared_hazard_surface_branch_reaches_body_event_and_dante_spawn_dispatch(machine,body):
 image,m,f=machine;m[APP+0x77d]=0;put(m,APP+0x830,body,2);put(m,APP+0x77c,0,1);put(m,APP+0x6d8,20,2)
 oracle.set_rng(m,f,0,0xfff9);put(m,0x391ea,3,2);put(m,APP+0x772,11,2);put(m,APP+0x6d4,oracle.FREE+4);put(m,oracle.FREE,oracle.OBJ)
 m[oracle.OBJ:oracle.OBJ+68]=b'\x5a'*68
 put(m,oracle.OBJ+44,(-3)&65535,2);put(m,oracle.OBJ+46,(-128)&65535,2);put(m,oracle.OBJ+48,2,2)
 put(m,APP+0x704,1234);put(m,APP+0x70c,5678);put(m,APP+0x708,(-500)&0xffffffff)
 put(m,APP+0x774,65530,2);put(m,APP+0x794,100,2);put(m,APP+0x776,65535,2);put(m,APP+0x6fc,0x1ffff)
 put(m,APP+0x7ae,1,2);put(m,APP+0x7b4,33,2);put(m,0xe0c6,0x12345678)
 c=state(m,0x34c6e);seen=[];run(image,m,c,{0x3572c},lambda pc:seen.append(pc)if pc in(0x3524c,0x355a8,0x355f6,0x35628,0x35688)else None,limit=2000)
 assert 0x3524c in seen and 0x355a8 in seen and 0x355f6 in seen and m[APP+0xaa5]==0
 steps=1 if body==8 else 3;seeds=(0,0xfff9)
 for _ in range(steps):seeds=oracle.rng(*seeds)
 oracle.assert_rng(m,f,seeds)
 if body==8:
  assert get(m,0x3b628,2)==64 and m[APP+0xbb6]==255 and get(m,APP+0x772,2)==11
  assert [get(m,0xe0c6+4*i)for i in range(3)]==[get(m,0x394ba+56*4),0xe0fa,get(m,0x394ba+35*4)]
  return
 obj=oracle.OBJ;assert get(m,obj,2)==47 and get(m,APP+0x772,2)==10 and get(m,0x391ea,2)==0
 assert bytes(m[obj+44:obj+50])==bytes.fromhex('fffdff800002')
 dx=abs(signed(get(m,obj+4)-1234,32));dz=abs(signed(get(m,obj+12)-5678,32));reward=((8192-((3*max(dx,dz)+min(dx,dz))>>1))&65535)>>5
 assert [get(m,APP+off,2)for off in(0x774,0x794,0x776)]==[min(65535,v+reward)for v in(65530,100,65535)]
 # Supply the next nearby snapshot and run the real main-loop actor BSR.
 # The fresh positive phase takes ageing/recycling, not active motion.
 refs=0x88100;put(m,refs,obj);put(m,APP+0x6c8,refs);put(m,APP+0x75e,1,2);put(m,APP+0x75c,0,2);m[APP+0x7e9]=255
 saved=bytes(m[obj:obj+68]);assert image[0][0x18e48-4096+47]==10
 for phase in range(2,11):
  assert m[obj+30]==phase;c=state(m,0x1314);seen=[]
  run(image,m,c,{0x1318},lambda pc:seen.append(pc),limit=1000)
  assert 0x8002 in seen and 0x386be not in seen
  if phase<10:
   expected=bytearray(saved);expected[30]=phase+1;assert bytes(m[obj:obj+68])==expected
  else:
   expected=bytearray(68);expected[30]=255;assert bytes(m[obj:obj+68])==expected
 assert get(m,APP+0x772,2)==11 and get(m,APP+0x6d4)==oracle.FREE+4 and get(m,oracle.FREE)==obj
 oracle.assert_rng(m,f,seeds)


def test_type47_dispatch_tables_reach_conditional_motion_and_distant_setter(machine):
 image,m,f=machine;obj=oracle.OBJ;put(m,obj,47,2);m[obj+30]=255;m[obj+28]=1
 put(m,obj+4,1234);put(m,obj+8,(-20)&0xffffffff);put(m,obj+12,5678)
 put(m,obj+44,(-3)&65535,2);put(m,obj+46,(-128)&65535,2);put(m,obj+48,2,2);put(m,APP+0x6fc,0x1ffff)
 # Three identical handler preambles exist. Qualify this one through the real
 # type47 first-phase table, branch stub and absolute bridge, then execute it.
 raw=image[0];table=0x803e;stub=table+struct.unpack_from('>h',raw,table-4096+2*47)[0];assert stub==0x84bc
 bridge=stub+10+struct.unpack_from('>h',raw,stub-4096+10)[0];assert bridge==0xb4b2 and raw[bridge-4096:bridge-4096+2]==b'\x4e\xf9'
 assert struct.unpack_from('>I',raw,bridge-4096+2)[0]==0x386be
 x,z=get(m,obj+4),get(m,obj+12);refs=0x88100;put(m,refs,obj);put(m,APP+0x6c8,refs);put(m,APP+0x75e,1,2);put(m,APP+0x75c,0,2);m[APP+0x7e9]=255
 c=state(m,0x1314);seen=[]
 run(image,m,c,{0x1318},lambda pc:seen.append(pc),limit=1000)
 assert stub in seen and bridge in seen
 assert 0x386be in seen and get(m,obj+8)==((-20-128)&0xffffffff)
 assert [get(m,obj+off)for off in(4,12)]==[(x-3)&0x1ffff,(z+2)&0x1ffff]
 assert get(m,obj+46,2)==((-128+8)&65535)and m[obj+30]==255

 # The separate distant-partition table reaches a short setter, not motion.
 # This is a distinct supplied dispatch, not two updates in one normal frame.
 table=0x8230;stub=table+struct.unpack_from('>h',raw,table-4096+2*47)[0];assert stub==0x84c8
 bridge=stub+10+struct.unpack_from('>h',raw,stub-4096+10)[0];assert bridge==0xb49a
 assert raw[bridge-4096:bridge-4096+2]==b'\x4e\xf9'and struct.unpack_from('>I',raw,bridge-4096+2)[0]==0x38704
 put(m,APP+0x75e,0,2);put(m,APP+0x75c,1,2);put(m,APP+0x6b8,refs)
 c=state(m,0x1314);before=bytearray(m[obj:obj+68]);before[30]=9;seen=[]
 run(image,m,c,{0x1318},lambda pc:seen.append(pc),limit=1000)
 assert stub in seen and bridge in seen and 0x38704 in seen and 0x386be not in seen
 assert bytes(m[obj:obj+68])==before


def test_retail_text_names_identify_the_two_gated_bodies(machine):
 image,m,f=machine
 for index,prefix in ((1,b'Dante -'),(8,b'Broadway-')):
  at=get(m,f['object_name_pointers']+4*(128+index));assert bytes(m[at:at+len(prefix)])==prefix

@pytest.mark.parametrize('space',(0,1,128,255))
def test_surface_event_entry_requires_zero_not_only_a_nonnegative_space_byte(machine,space):
 image,m,f=machine;m[APP+0x77d]=space;put(m,0x391ea,0x1234,2);oracle.set_rng(m,f,0x12345678,0xabcdef01)
 c=state(m,0x3524c);run(image,m,c,{0x355a8,0x35262},limit=10)
 assert c.pc==(0x355a8 if space==0 else 0x35262)and m[APP+0xaa5]==space
 assert get(m,0x391ea,2)==0x1234;oracle.assert_rng(m,f,(0x12345678,0xabcdef01))

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_surface_hazard_symbols_decode_the_executed_handlers(tmp_path):
 import subprocess
 from pathlib import Path
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered';source=(directory/'retail-shared.s').read_text()
 symbols={'gate_broadway_invertor_bomb_event':0x355a8,'gate_dante_type47_spawn':0x355f6,'choose_dante_spawn_offsets_from_two_prng_steps':0x35628,'add_word_to_icarus_reserves_with_saturation':0x356dc,'update_nearby_falling_type47':0x386be,'set_type47_second_phase_retirement_nine':0x38704,'dispatch_type47_first_phase':0x84bc,'dispatch_type47_second_phase':0x84c8,'dante_spawn_phase_mod4':0x391ea}
 block=source.split('update_nearby_falling_type47:',1)[1].split('set_type47_second_phase_retirement_nine:',1)[0]
 assert 'dc.b'not in block and 'SG2ActorModelPrefix_velocity_y(a0)'in block and 'addq.w #8,'in block
 assert 'dispatch_type47_first_phase-actor_first_phase_dispatch_offsets'in source
 assert 'dispatch_type47_second_phase-actor_second_phase_dispatch_offsets'in source
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert r.returncode==0,r.stdout+r.stderr
 raw=out.read_bytes();n=4*len(symbols);assert raw[:-n]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-n:])==tuple(symbols.values())

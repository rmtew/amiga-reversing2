"""Actual animation producers feed narrowly mapped original period readers.

Normal initialization and supplied live records qualify local cycles. Other
writers and forged byte states are not covered by that lifetime contract.
"""
import os
import pytest
from amiga_reversing.disasm.mapped_execution import MappedExecution
from test_starglider2_retail_actor_spawns import setup,run_profile,PROFILES,ACTOR,CHILD,store,get
from test_starglider2_retail_variant_cycles import shared_bytes
from test_starglider2_retail_sound import address
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
BASE=address(0x4d09e);VOL=address(0x4d09c);RAMP=address(0x4d12e);TYPE=address(0x39ce0)
TABLES={5:(0x4eadc,20,0x4dc10,0x4dc4c),46:(0x4eadc,18,0x4dc10,0x4dc4c),17:(0x4eb08,10,0x4dde6,0x4df1e),19:(0x4eb1c,16,0x4de20,0x4df1e),36:(0x4eb3c,24,0x4de46,0x4df1e)}

def reader(kind,words=None):
 raw=shared_bytes();table,count,entry,stop=TABLES[kind];c=MappedExecution(0x100000,register_seed=0xdeadbeef)
 size=(words if words is not None else count)*2
 c.seed(table,raw[table-4096:table-4096+size])
 end=0x4dc6c if kind in (5,46)else(0x4de20 if kind==17 else 0x4de46 if kind==19 else 0x4de6c)
 c.seed(entry,raw[entry-4096:end-4096]);c.seed(TYPE,kind.to_bytes(2,'big'))
 for at,value in((BASE,500),(VOL,30),(RAMP,5)):
  c.seed(at,value.to_bytes(2,'big'));c.allow_write(at,2)
 c.seed(ACTOR+3,b'\0');c.cpu.a[2]=ACTOR
 return c

def consume(c,kind,variant):
 table,_,entry,stop=TABLES[kind];c.seed(ACTOR+3,bytes([variant]));c.cpu.a[2]=ACTOR
 skip=kind in (5,46)and variant in (0,9)
 c.run(entry,0x4dc68 if skip else stop,100)
 if not skip:
  expected=int.from_bytes(shared_bytes()[table-4096+2*variant:table-4096+2*variant+2],'big')
  assert get(c,BASE,2)==expected
 return None if skip else get(c,BASE,2)

@pytest.mark.parametrize('kind,maximum,steps',((17,8,20),(19,14,60),(36,23,50)))
def test_fresh_initializer_and_real_dispatch_keep_period_reads_inside_mapped_words(kind,maximum,steps):
 c=setup();store(c,ACTOR,kind,2);c.cpu.d[0]=kind;c.run(0x19728,0x1974c,300)
 assert get(c,ACTOR+3,1)==0
 sound=reader(kind);seen={0};consume(sound,kind,0)
 for _ in range(steps):
  c.cpu.a[0]=ACTOR;before=get(c,ACTOR+3,1)
  stop=0x81e6 if kind==19 else 0x950c
  if kind==36 and 1<=(before+1)&255<=14:stop=0x81e6
  c.run(0x8002,stop,500)
  variant=get(c,ACTOR+3,1);assert variant<=maximum;seen.add(variant);consume(sound,kind,variant)
  if stop!=0x81e6:
   c.run(stop,0x81e6,1000);assert get(c,ACTOR+3,1)==variant
  c.cpu.a[0]=ACTOR;c.run(0x8210,0x83b0,1000)
  assert get(c,ACTOR+3,1)==variant
 assert seen==set(range(maximum+1))

@pytest.mark.parametrize('profile',PROFILES)
def test_actual_launcher_cycle_reads_bounded_period_words_through_release_and_close(profile):
 kind=PROFILES[profile][0];c=setup(profile);sound=reader(kind);seen={0};run_profile(c,profile)
 maximum=7 if kind==46 else 19
 for i in range(maximum):
  run_profile(c,profile);variant=get(c,ACTOR+3,1);assert variant==i+1;seen.add(variant)
  consume(sound,kind,variant)
 if kind==5:
  assert consume(sound,kind,18)==consume(sound,kind,19)==0
  for _ in range(29):run_profile(c,profile)
 else:
  run_profile(c,profile);store(c,CHILD,0,2);run_profile(c,profile);maximum-=1
 for _ in range(maximum):
  run_profile(c,profile);variant=get(c,ACTOR+3,1);consume(sound,kind,variant)
 assert get(c,ACTOR+3,1)==0 and seen==set(range((7 if kind==46 else 19)+1))

@pytest.mark.parametrize('kind,variant',((17,128),(19,255),(36,128),(5,18)))
def test_sound_reader_refuses_unmapped_signed_index_or_unproved_tail(kind,variant):
 c=reader(kind,words=18 if kind==5 else None);c.seed(ACTOR+3,bytes([variant]));_,_,entry,stop=TABLES[kind]
 with pytest.raises(ValueError,match='unknown read/fetch'):c.run(entry,stop,100)

def test_names_are_backed_by_the_retail_object_name_table():
 raw=shared_bytes()
 for kind,name in((17,b'Horatio'),(19,b'Pulsing Pyramids'),(36,b'Pac-Worm')):
  at=int.from_bytes(raw[0xe380+4*kind:0xe384+4*kind],'big')-4096
  assert raw[at:raw.index(0,at)]==name

@pytest.mark.parametrize('x,z,evasion,counter,upper',[
 (801,701,0,2,0),(800,701,0,2,0),(801,700,0,2,0),(32768,701,0,2,0),
 (801,701,2,33,0),(801,701,1,1,0),(801,701,0,513,0x12340000),(801,701,0,0,0x12340000)])
def test_connected_horizontal_steering_reuses_existing_word_and_byte_mask_oracle(x,z,evasion,counter,upper):
 from tests.test_starglider2_animal_motion import check_shared_steering_contract
 from test_starglider2_retail_sound import machine,program,APP
 m,_=machine('st')
 fields={n:APP+off for n,off in [('player_object_reference',0x700),('visible_objects_cursor',0x6cc),('visible_object_count',0x760),('free_object_stack_cursor',0x6d4),('ai_type12_projectile_request',0x7ed)]}
 fields['continue_primary_object_update_loop']=0x81e6
 check_shared_steering_contract(program('st'),m,fields,x,z,evasion,counter,upper,entry=0x950c,heading_stop=0xacbc,heading_table_base=0x15604)

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='external vasm is the source build dependency')
def test_compiled_animation_and_heading_symbols_bind_the_qualified_contracts(tmp_path):
 import struct,subprocess
 from pathlib import Path
 from test_starglider2_retail_model_headers import image
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered'
 symbols={'update_horatio_vertex_cycle_and_drag':0x92d8,'advance_pac_worm_vertex_and_motion_phase':0x8a5a,'initialize_horatio_heading_and_motion':0x19c4a,'initialize_pac_worm_heading_and_motion':0x19dca,'integrate_and_steer_horizontal_actor':0x950c,'heading_with_player_as_reference':0xaf9c,'atan_integer_ratio_words':0x15604,'paula_type5_closing_period_tail':0x4eb00,'SG2HorizontalSteeringActor_proximity_evasion_countdown':38,'SG2HorizontalSteeringActor_pre_view_relative_x':50,'SG2VertexOscillator_vertex_variant_step':31}
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 result=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert result.returncode==0,result.stdout+result.stderr
 raw=out.read_bytes();size=4*len(symbols)
 assert raw[:-size]==image('st')and struct.unpack('>'+str(len(symbols))+'I',raw[-size:])==tuple(symbols.values())

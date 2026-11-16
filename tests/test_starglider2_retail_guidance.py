"""Original guidance and bounded target-slot lifetimes with supplied game state.

These witnesses execute real selectors, constructors, updates and recycling.
They do not claim a complete match replay or that every normal frame ordering
permits slot reuse before a missile observes its target's retirement.
"""
import os,struct
import pytest
from test_starglider2_retail_weapons import machine,execute
from test_starglider2_retail_input import program
from tests.test_starglider2_text_editor import state,run,put,get,APP,RETURN
from tests import test_starglider2_homing_updates as h
from tests import test_starglider2_gbml_targeting as g
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
CONTINUE,UPDATE,ANIMATE=0x81e6,0x96a0,0x9686
F={n:APP+off for n,off in [('player_object_reference',0x700),('player_world_y',0x708),('visible_object_count',0x760),('visible_objects_cursor',0x6cc),('model_type_target_selection_tags_prefix',0xda6),('free_object_count',0x772),('free_object_stack_cursor',0x6d4),('ai_type12_projectile_request',0x7ed),('sine_lookup_pointer',0x44),('cosine_lookup_pointer',0x48),('space_environment_flag',0x77d)]}
F.update(continue_primary_object_update_loop=CONTINUE,try_ai_projectile_attack_if_aligned=0x9772,object_projectile_spawn_y_offsets=0x19210,object_default_motion_words=0x194f0)

def setup(platform='st',**kw):
 m,_=machine(platform);h.setup(m,**kw);put(m,APP+0x44,0x15808);put(m,APP+0x48,0x16008);return m

def update(m,platform='st',entry=UPDATE,upper=0):
 c=state(m,entry);c.a[0]=h.OBJECT;c.d[1]=upper;run(program(platform),m,c,{CONTINUE});return c

@pytest.mark.parametrize('tracking,budget',((0,0),(0,1),(0,2),(0,32768),(0,65535),(255,0),(255,1),(255,2),(255,32768),(255,65535)))
def test_mode_byte_selects_signed_or_unsigned_budget_retirement(tracking,budget):
 m=setup(tracking=tracking,budget=budget);update(m)
 retired=budget<=1 if tracking else h.signed16(budget)<=1
 assert m[h.OBJECT+30]==(0 if retired else 255) and get(m,h.OBJECT+36,2)==(budget-1)&65535
 assert get(m,h.OBJECT,2)==12 and get(m,h.OBJECT+60)==h.TARGET

@pytest.mark.parametrize('target',(0,0x80000000,0xffffffff))
def test_nonpositive_reference_skips_budget_and_tracking_after_motion(target):
 m=setup(target=target);update(m)
 assert get(m,h.OBJECT+36,2)==20 and get(m,h.OBJECT+38,2)==0 and m[h.OBJECT+30]==255
 assert [get(m,h.OBJECT+o)for o in(4,8,12)]==[65535,(-96)&0xffffffff,65534]

@pytest.mark.parametrize('platform,kind,phase',(('amiga',0,255),('st',1,0),('st',1,127),('amiga',65535,128),('st',65535,255)))
def test_target_checks_tag_zero_and_phase_sign_without_type_directory_validation(platform,kind,phase):
 m=setup(platform,kind=kind,phase=phase);update(m,platform)
 rejected=kind==0 or phase<128
 assert m[h.OBJECT+30]==(0 if rejected else 255)and get(m,h.OBJECT+36,2)==(20 if rejected else 19)

@pytest.mark.parametrize('tracking,y,ty',((0,-100,-400),(255,-100,-400),(0,-1701,-1701),(255,-9,100),(255,0x7fffffff,-1),(0,-0x80000000,0x7fffffff)))
def test_y_smoothing_and_thresholds_preserve_original_wrapped_long_arithmetic(tracking,y,ty):
 m=setup(tracking=tracking);put(m,h.OBJECT+8,y&0xffffffff);put(m,h.TARGET+8,ty&0xffffffff);put(m,APP+0x708,ty&0xffffffff)
 integrated=(y+4)&0xffffffff;result=(integrated+(h.signed32(ty-integrated)>>(5 if tracking else 2)))&0xffffffff
 retired=False
 if tracking:
  if h.signed32(result+10)>=0:result=(-10)&0xffffffff
 else:retired=h.signed32(result+1700)<0
 update(m);assert get(m,h.OBJECT+8)==result and m[h.OBJECT+30]==(0 if retired else 255)

@pytest.mark.parametrize('cadence,upper',((0,0),(6,0),(7,0),(65535,0),(7,0xffff0000),(7,0x12340000)))
def test_heading_uses_cached_xz_every_eighth_service_and_retains_divs_upper_words(cadence,upper):
 m=setup(cadence=cadence);delta=h.signed32(-400-(-96))>>5
 angle=h.heading(m,100,200,0,0,delta,upper,table_base=0x15604)&4095 if((cadence+1)&7)==0 else 1234
 expected=[(-h.project(900,get(m,0x15808+2*angle,2)))&65535,h.project(900,get(m,0x16008+2*angle,2))&65535]
 update(m,upper=upper)
 assert get(m,h.OBJECT+38,2)==(cadence+1)&7 and get(m,h.OBJECT+18,2)==angle
 assert [get(m,h.OBJECT+off,2)for off in(44,48)]==expected and get(m,h.OBJECT+46,2)==4


def test_animation_resets_only_exactly_five_and_does_not_clamp_arbitrary_bytes():
 m=setup(target=0)
 for value in range(256):
  h.setup(m,target=0);m[h.OBJECT+3]=value;update(m,entry=ANIMATE);n=(value+1)&255
  assert m[h.OBJECT+3]==(0 if n==5 else n)


def ai(platform='st',free=25):
 m,_=machine(platform);g.prepare(m,F);put(m,APP+0x44,0x15808);put(m,APP+0x48,0x16008);put(m,APP+0x6fc,0xffff);put(m,F['free_object_count'],free,2)
 return m

@pytest.mark.parametrize('order',([], [g.OBJ], [g.OBJ,g.TARGET], [g.PLAYER,g.TARGET], [g.TARGET,g.PLAYER]))
def test_visible_tag_selector_uses_first_match_and_excludes_only_own_address(order):
 m=ai();tag=0x37
 for a in(g.OBJ,g.PLAYER,g.TARGET):m[APP+0xda6+get(m,a,2)]=tag;m[a+30]=0
 for i,a in enumerate(order):put(m,g.LIST+4*i,a)
 put(m,APP+0x760,len(order),2);c=state(m,0xa506);c.a[0]=g.OBJ;c.d[0]=0xffff0000|tag;c.d[1]=0xabcd03ff
 run(program('st'),m,c,{RETURN});assert c.a[4]==next((a for a in order if a!=g.OBJ),g.PLAYER)and c.d[1]==0xabcd03ff

@pytest.mark.parametrize('platform,kind,yaw,aim,free',(('amiga',1,0,0,25),('st',23,4095,0,25),('st',23,0,99,25),('amiga',1,0,100,25),('st',23,0,0,24),('st',23,0,65535,25)))
def test_selected_target_constructor_preserves_partial_record_and_raw_yaw_gate(platform,kind,yaw,aim,free):
 m=ai(platform,free);put(m,g.OBJ,kind,2);put(m,g.OBJ+18,yaw,2);before=bytes(m[g.CHILD:g.CHILD+68]);expected=bytearray(before)
 difference=(aim-(yaw&4095))&65535;magnitude=(-difference)&65535 if difference&32768 else difference;accepted=free>24 and bool((magnitude-100)&32768)
 c=state(m,0xa536);c.a[0]=g.OBJ;c.a[4]=g.TARGET;c.d[1]=aim;run(program(platform),m,c,{CONTINUE})
 assert get(m,APP+0x772,2)==free-int(accepted)and get(m,APP+0x6d4)==g.FREE+(0 if accepted else 4)
 if not accepted:assert bytes(m[g.CHILD:g.CHILD+68])==before;return
 def field(off,x,n=2):expected[off:off+n]=(x&((1<<(8*n))-1)).to_bytes(n,'big')
 heading=(yaw-(2048 if get(m,0xae6c+2*kind,2)else 0))&4095;scale=get(m,0x194f0+50,2)
 for off,x,n in((0,25,2),(3,0,1),(28,2,1),(29,4,1),(30,255,1),(34,255,1),(42,kind,1),(16,0,2),(18,heading,2),(20,0,2),(36,100,2),(46,0,2),(32,scale,2),(60,g.TARGET,4)):field(off,x,n)
 for off in(4,12):expected[off:off+4]=bytes(m[g.OBJ+off:g.OBJ+off+4])
 field(8,get(m,g.OBJ+8)+h.signed16(get(m,0x19210+2*kind,2)),4)
 field(44,-h.project(scale,get(m,0x15808+2*heading,2)));field(48,h.project(scale,get(m,0x16008+2*heading,2)))
 assert bytes(m[g.CHILD:g.CHILD+68])==expected and m[g.OBJ+42]==25

@pytest.mark.parametrize('phase',(0,255))
def test_actual_gbml_scan_to_constructor_then_target_consumer_preserves_inactive_candidate(phase):
 m=ai();put(m,g.OBJ+18,3072,2);put(m,g.OBJ+36,513,2);m[APP+0xda6+23]=0x37;m[APP+0xda6+14]=0xc8;m[g.TARGET+30]=phase
 put(m,APP+0x760,1,2);put(m,g.LIST,g.TARGET);assert 0x803e+int.from_bytes(program('st')[0][0x703e+46:0x7040+46],'big',signed=True)==0x9d08
 c=state(m,0x9d08);c.a[0]=g.OBJ;run(program('st'),m,c,{CONTINUE})
 assert get(m,g.CHILD+60)==g.TARGET and get(m,g.CHILD+18,2)==3072 and get(m,g.CHILD+38,2)==0xa5a5 and get(m,g.OBJ+36,2)==512
 c=state(m,UPDATE);c.a[0]=g.CHILD;run(program('st'),m,c,{CONTINUE})
 assert m[g.CHILD+30]==(0 if phase<128 else 255)and get(m,g.CHILD+36,2)==(100 if phase<128 else 99)

@pytest.mark.parametrize('reuse',(False,True))
def test_target_slot_recycle_and_reuse_has_no_generation_identity_guard(reuse):
 m=ai(free=27);put(m,g.OBJ+18,3072,2)
 c=state(m,0xa536);c.a[0]=g.OBJ;c.a[4]=g.TARGET;c.d[1]=3072;run(program('st'),m,c,{CONTINUE})
 assert get(m,g.CHILD+60)==g.TARGET and get(m,APP+0x772,2)==26
 m[g.TARGET+30]=0;m[g.TARGET+2]=0;m[g.TARGET+28]=1;m[APP+0xae5+14]=1
 limit=get(m,0x18e48+14,1);assert limit<128
 for _ in range(limit+1):
  c=state(m,0x8002);c.a[0]=g.TARGET;run(program('st'),m,c,{CONTINUE})
 assert get(m,g.TARGET,2)==0 and get(m,APP+0x772,2)==27 and get(m,APP+0x6d4)==g.FREE+4 and get(m,g.FREE)==g.TARGET
 assert get(m,g.CHILD+60)==g.TARGET
 if reuse:
  m[APP+0xda6+23]=1;m[g.OBJ+29]=3
  for off,x in((4,1000),(8,-100),(12,200)):put(m,g.OBJ+off,x&0xffffffff)
  c=state(m,0x9f0e);c.a[0]=g.OBJ;run(program('st'),m,c,{CONTINUE})
  assert get(m,g.TARGET,2)==72 and m[g.TARGET+30]==255 and get(m,APP+0x772,2)==26
 c=state(m,UPDATE);c.a[0]=g.CHILD;run(program('st'),m,c,{CONTINUE})
 assert m[g.CHILD+30]==(255 if reuse else 0)and get(m,g.CHILD+36,2)==(99 if reuse else 100)
 assert get(m,g.CHILD+60)==g.TARGET  # Phase retirement did not clear the reference.


def test_original_near_dispatch_distinguishes_animation_and_plain_guidance_entries():
 raw=program('st')[0]
 for kind,entry in((12,ANIMATE),(25,UPDATE)):
  assert 0x803e+int.from_bytes(raw[0x703e+2*kind:0x7040+2*kind],'big',signed=True)==entry


def test_positive_reference_guard_does_not_establish_readable_record_backing():
 from amiga_reversing.disasm.mapped_execution import MappedExecution
 for target in(0xffffffff,0x8e000):
  m=setup(target=target);c=MappedExecution(0x100000,register_seed=0x12345678)
  c.seed(0x1000,program('st')[0]);c.seed(APP,bytes(m[APP:APP+0x1000]));c.seed(h.OBJECT,bytes(m[h.OBJECT:h.OBJECT+68]));c.allow_write(h.OBJECT,68);c.allow_write(0xe145,1)
  c.cpu.a[0]=h.OBJECT;c.cpu.a[6]=APP
  if target==0xffffffff:c.run(UPDATE,CONTINUE,100)
  else:
   with pytest.raises(ValueError,match='unknown read/fetch'):c.run(UPDATE,CONTINUE,100)

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='external vasm is the source build dependency')
def test_compiled_guidance_names_and_record_offsets_match_original_contracts(tmp_path):
 import subprocess
 from pathlib import Path
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered'
 names={'select_visible_object_by_type_tag':0xa506,'try_launch_missile_at_selected_visible_target':0xa536,'update_nearby_steered_projectile':UPDATE,'steer_projectile_toward_stored_target':0x970c,'update_gbml_heading_and_target_scan':0x9d08,'recompute_tracked_projectile_horizontal_motion':0xadc6,'projectile_heading_reversal_words':0xae6c,'object_projectile_spawn_y_offsets':0x19210,'SG2SteeredProjectile_stored_target_tracking_byte':34,'SG2SteeredProjectile_updates_remaining':36,'SG2SteeredProjectile_heading_update_cadence':38,'SG2SteeredProjectile_pre_view_relative_x':50,'SG2TargetingWorkspace_model_target_selection_tags_prefix':0xda6}
 asm,out=tmp_path/'symbols.s',tmp_path/'symbols.raw';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(names)+'\n')
 p=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert p.returncode==0,p.stdout+p.stderr
 raw=out.read_bytes();n=len(names)*4;assert raw[:-n]==program('st')[0]and struct.unpack('>'+str(len(names))+'I',raw[-n:])==tuple(names.values())
 text=(directory/'retail-shared.s').read_text();assert 'SG2SteeredProjectile_stored_target_tracking_byte(a0)'in text and 'SG2SteeredProjectile_heading_update_cadence(a0)'in text

"""Retail celestial dispatch and table contracts under supplied actor states.

These are bounded original-CPU checks,not natural orbits,whole game frames,
physical timing or universal selector/pointer-lifetime guarantees.
"""
import ctypes,os,struct
import pytest
from tests.test_starglider2_text_editor import state,run,put,get,APP,STACK
from tests.test_starglider2_control_normalization import signed
from test_starglider2_retail_input import program
from test_starglider2_retail_dispatch_tail import stage,actor,OBJ
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
ORBIT,PARENT,SOLICE,FAR_SOLICE=0x379ec,0x37b3a,0x38356,0x3843a
COUNTER,STEP,MASK,INC,SHIFT,RADIUS,PRECISION=0x391ec,0x39234,0x39258,0x39210,0x3927c,0x39404,0x3928e
LIGHTS,RGB,FORCE=0x3b054,0x3b094,0x3b621
NEAR={**{k:0x379a8 for k in range(129,134)},134:0x379b0,135:0x379b0,**{k:0x379b8 for k in range(136,143)},143:0x379c0,145:SOLICE}
FAR={**{k:0x379c8 for k in range(129,134)},134:0x379d0,135:0x379d0,**{k:0x379d8 for k in range(136,143)},143:0x379e0,145:FAR_SOLICE}

@pytest.fixture(params=('amiga','st'))
def machine(request):
 image=program(request.param);m=(ctypes.c_uint8*0xa1000)();ctypes.memmove(ctypes.addressof(m)+4096,image[0],len(image[0]));put(m,APP+0x44,0x15808);put(m,APP+0x48,0x16008);return image,m

def init(m,kind,at=OBJ,angle=4095):
 actor(m,at,kind);m[at+2]=0;put(m,at+46,3);put(m,at+50,(-7)&0xffffffff)
 if kind<145:put(m,APP+0x98c+2*(kind-128),angle,2)
 for off,value in((0x802,1000000),(0x806,2000000),(0x80a,3000000),(0x80e,4000000)):put(m,APP+off,value)
 return at

def projected(m,table,angle,radius,precision):
 # Independent integer formulation of signed16x16 -> wrapped32 -> high WORD.
 product=(signed((radius>>(precision&63))&65535)*signed(get(m,table+2*angle,2)))&0xffffffff
 high=signed(((product<<2)&0xffffffff)>>16);return(high<<(precision&63))&0xffffffff

def with_parent(m,kind,x,z):
 if kind<134:parent=(20000000,20000000)
 elif kind in(134,135):parent=(get(m,APP+0x802),get(m,APP+0x806))
 else:parent=(get(m,APP+0x80a),get(m,APP+0x80e))
 return tuple((v+p)&0xffffffff for v,p in zip((x,z),parent))

def expected_orbit(m,at):
 kind=get(m,at,2);index=kind-128
 for off,delta in((4,46),(12,50)):put(m,at+off,(get(m,at+off)+get(m,at+delta))&0xffffffff)
 if index in(3,4):
  for off,parent in((4,0x802 if index==3 else 0x80a),(12,0x806 if index==3 else 0x80e)):put(m,APP+parent,get(m,at+off))
 if index==5:return False
 counter=COUNTER+2*index;value=(get(m,counter,2)+get(m,STEP+2*index,2))&65535
 if m[FORCE]<128:value&=get(m,MASK+2*index,2)
 put(m,counter,value,2)
 if m[FORCE]<128 and value:return False
 angle=get(m,APP+0x98c+2*index,2);next_angle=(angle+get(m,INC+2*index,2))&4095;put(m,APP+0x98c+2*index,next_angle,2)
 radius=get(m,RADIUS+4*index);precision=get(m,PRECISION+4*index)
 def point(a):return with_parent(m,kind,projected(m,0x15808,a,radius,precision),projected(m,0x16008,a,radius,precision))
 old,new=point(angle),point(next_angle)
 for off,delta,now,later in zip((4,12),(46,50),old,new):put(m,at+off,now);put(m,at+delta,(signed(later-now,32)>>(m[SHIFT+index]&63))&0xffffffff)
 return True

@pytest.mark.parametrize('kind,counter,force,angle',((129,30,0,4095),(130,62,0,0),(131,1,0,1024),(132,65535,0,2048),(133,65535,255,1),(134,1,0,4095),(135,0,128,1023),(136,63,0,2047),(142,62,0,4095),(131,65535,255,4095)))
def test_orbit_whole_memory_recurrence_counter_mask_force_and_parent_cache(machine,kind,counter,force,angle):
 image,m=machine;init(m,kind,angle=angle);put(m,COUNTER+2*(kind-128),counter,2);m[FORCE]=force
 put(m,OBJ+4,0x7fffffff);put(m,OBJ+12,0x80000000);expected=bytearray(m);expected_orbit(expected,OBJ)
 c=state(m,ORBIT);c.a[0]=OBJ;run(image,m,c,{0xffffff00});expected[STACK-256:STACK+4]=bytes(m[STACK-256:STACK+4]);assert bytes(m)==expected

@pytest.mark.parametrize('kind',tuple(NEAR))
def test_actual_actor_snapshots_route_each_supported_near_and_far_celestial_type(machine,kind):
 image,m=machine;init(m,kind);m[FORCE]=0
 if kind==145:
  put(m,APP+0x862,512,2);put(m,APP+0x830,0,2);put(m,APP+0x758,0,2)
 for nearby in(True,False):
  if kind<143:
   expected=bytearray(m);expected_orbit(expected,OBJ)
  else:expected=bytearray(m)
  seen=stage(image,m,[OBJ]if nearby else[],[]if nearby else[OBJ]);assert (NEAR if nearby else FAR)[kind]in seen
  if kind<145:
   assert bytes(m[OBJ:OBJ+68])==expected[OBJ:OBJ+68]
   assert bytes(m[APP+0x802:APP+0x812])==expected[APP+0x802:APP+0x812]
   assert bytes(m[COUNTER:COUNTER+30])==expected[COUNTER:COUNTER+30]
   assert bytes(m[APP+0x98c:APP+0x9ae])==expected[APP+0x98c:APP+0x9ae]
  elif not nearby:assert bytes(m[OBJ:OBJ+68])==expected[OBJ:OBJ+68]and bytes(m[APP+0x862:APP+0x868])==expected[APP+0x862:APP+0x868]and get(m,RGB,2)==get(expected,RGB,2)


def test_parent_cache_is_published_before_recompute_and_observed_in_list_order(machine):
 image,m=machine;parent,moon=OBJ,OBJ+68;init(m,131,parent,1024);init(m,134,moon,0);m[FORCE]=255
 put(m,parent+4,123);put(m,parent+12,456)
 expected=bytearray(m);expected_orbit(expected,parent);expected_orbit(expected,moon)
 initial_parent_cache=bytes(m[APP+0x802:APP+0x80a]);seen=stage(image,m,[parent,moon]);assert 0x379a8 in seen and 0x379b0 in seen
 assert [get(m,APP+off)for off in(0x802,0x806)]==[126,449]
 assert bytes(m[parent:parent+136])==expected[parent:parent+136]
 # Reversed supplied membership makes the moon consume the old parent cache.
 # This demonstrates an ordering dependency,not a normal-game order invariant.
 m[parent:parent+136]=bytes(136);init(m,131,parent,1024);init(m,134,moon,0);put(m,parent+4,123);put(m,parent+12,456)
 assert bytes(m[APP+0x802:APP+0x80a])==initial_parent_cache
 expected=bytearray(m);expected_orbit(expected,moon);expected_orbit(expected,parent);stage(image,m,[moon,parent]);assert bytes(m[parent:parent+136])==expected[parent:parent+136]


def expected_solice(m,at):
 colour=get(m,APP+0x9c8,2)
 for a in(0x6c1c,0x6c44):put(m,a,colour,2)
 phase=get(m,APP+0x862,2);speed=get(m,APP+0x758,2)
 if speed:
  product=signed(get(m,0x15808+2*get(m,APP+0x746,2),2))*signed(speed);phase=(phase+(signed((product&0xffffffff)>>16)>>5))&4095
 drift=(m[APP+0xbb5]+1)&3;m[APP+0xbb5]=drift
 if not drift:phase=(phase-1)&4095
 put(m,APP+0x862,phase,2)
 for off,table,player in((8,0x15808,0x708),(4,0x16008,0x704)):
  value=projected(m,table,phase,25000,0);put(m,at+off,((signed(value,32)<<2)+get(m,APP+player))&0xffffffff)
 put(m,at+12,get(m,APP+0x70c));pointer=get(m,LIGHTS+4*get(m,APP+0x830,2))
 folded=(phase+1024)&4095
 if folded<2048:folded=2048-folded
 offset=(folded&2047)>>4&65534;put(m,RGB,get(m,pointer+offset,2)if pointer else 0,2)

@pytest.mark.parametrize('world,phase,speed,yaw,drift',((0,0,0,0,0),(1,1024,1,1024,3),(2,2048,32768,4095,255),(3,4095,32767,2048,2),(15,1,0,0,3),(3,3072,65535,3072,0)))
def test_solice_full_near_output_uses_original_signed_product_drift_and_bounded_curve(machine,world,phase,speed,yaw,drift):
 image,m=machine;init(m,145);put(m,APP+0x830,world,2);put(m,APP+0x862,phase,2);put(m,APP+0x758,speed,2);put(m,APP+0x746,yaw,2);m[APP+0xbb5]=drift;put(m,APP+0x9c8,0xface,2)
 for off,value in((0x704,0x7fffffff),(0x708,0x80000000),(0x70c,12345)):put(m,APP+off,value)
 expected=bytearray(m);expected_solice(expected,OBJ);c=state(m,SOLICE);c.a[0]=OBJ;run(image,m,c,{0x3b6a2});expected[STACK-256:STACK+4]=bytes(m[STACK-256:STACK+4]);assert bytes(m)==expected
 before=bytes(m);c=state(m,FAR_SOLICE);c.a[0]=OBJ;run(image,m,c,{0x3b68a});assert bytes(m)==before


def test_stored_curve_directory_has_only_null_or_three_complete_word_curves(machine):
 image,m=machine;values=[get(m,LIGHTS+4*i)for i in range(16)];assert set(values)=={0,0x3b096,0x3b116,0x3b196}
 assert all((i&2047)>>4&65534 in range(0,128,2)for i in range(4096))
 # Initial angle producer copies17WORDs;the orbit consumer subset here ends14.
 assert len(image[0][0x393e2-4096:0x39404-4096])==34


def test_original_partitioner_preserves_orbit_delta_longs_for_radial_actor(machine):
 image,m=machine;pool=APP+0x2330;init(m,131,pool,1024);put(m,APP+0x172,2,2);put(m,APP+0x6fc,0x0fffffff);m[FORCE]=0
 for off,value in((0x710,0),(0x714,0),(0x718,0)):put(m,APP+off,value)
 deltas=bytes(m[pool+46:pool+54]);c=state(m,0x4158);run(image,m,c,{0xffffff00},limit=10000)
 assert bytes(m[pool+46:pool+54])==deltas
 memberships=[]
 for count,cursor in((0x75e,0x6c8),(0x75c,0x6b8)):
  n=get(m,APP+count,2);base=get(m,APP+cursor);memberships.append([get(m,base+4*i)for i in range(n)])
 assert sum(pool in refs for refs in memberships)==1
 m[APP+0x7e9]=255;expected=bytearray(m);expected_orbit(expected,pool);c=state(m,0x1314);seen=set();run(image,m,c,{0x1318},seen.add,limit=5000)
 assert (NEAR if pool in memberships[0]else FAR)[131]in seen and bytes(m[pool:pool+68])==expected[pool:pool+68]

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_celestial_boundaries_phase_views_and_typed_curve_directory(tmp_path):
 import subprocess,json
 from pathlib import Path
 target=Path(__file__).resolve().parents[1]/'targets/starglider2_retail';directory=target/'rendered';text=(directory/'retail-shared.s').read_text();metadata=json.loads((target/'target_metadata.json').read_text())
 symbols=dict(update_nearby_planetary_bodies=0x379a8,update_distant_planetary_bodies=0x379c8,update_nearby_apogee_moons=0x379b0,update_distant_apogee_moons=0x379d0,update_nearby_millway_moons=0x379b8,update_distant_millway_moons=0x379d8,update_nearby_q_beta=0x379c0,update_distant_q_beta=0x379e0,update_nearby_solice_display=SOLICE,finish_distant_solice_update=FAR_SOLICE,advance_celestial_orbit_state=ORBIT,add_celestial_orbit_parent_offset=PARENT,SG2CelestialOrbitActor_delta_world_x=46,SG2CelestialOrbitActor_delta_world_z=50,SG2CelestialOrbitActor_SIZEOF=68,SG2OrbitParents_apogee_x=0,SG2OrbitParents_millway_x=8,SG2SoliceView_phase=0,SG2SoliceView_radius=2,world_solice_light_curve_pointers=LIGHTS)
 for name in list(symbols)[:12]:assert not text.split(name+':',1)[1].split('\n',2)[1].startswith('\tdc.'),name
 view=next(s for s in metadata['custom_structs']if s['name']=='SG2CelestialOrbitActor');assert view['base_struct']=='SG2RadialProjectionActor'
 for name,size in(('body_orbit_recompute_counters',30),('body_orbit_angle_increments',30),('body_orbit_counter_steps',30),('body_orbit_recompute_masks',30),('body_orbit_delta_shifts',15),('body_orbit_radius_precision_shifts',60),('body_orbit_radii',60),('solice_surface_rgb_curve_a',128),('solice_surface_rgb_curve_b',128),('solice_surface_rgb_curve_c',128)):
  item=next(e for e in metadata['seeded_entities']if e.get('name')==name and e.get('end')is not None);assert item['end']-item['addr']==size
 layout=next(x for x in metadata['data_block_layouts']if x['layout_id']=='retail-world-solice-light-curve-directory');assert layout['source_end']-layout['source_start']==64
 assert all('dc.l solice_surface_rgb_curve_'+x in text for x in('a','b','c'))
 # Do not turn adjacent unreferenced return fragments into code entries.
 assert not {0x379c4-4096,0x379e4-4096,0x379e8-4096}&{e['addr']for e in metadata['seeded_code_entrypoints']}
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 result=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True);assert result.returncode==0,result.stdout+result.stderr
 raw=out.read_bytes();n=4*len(symbols);assert raw[:-n]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-n:])==tuple(symbols.values())

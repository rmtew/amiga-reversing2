"""Remaining dispatch-backed retail actors under explicit RAM/list conditions.

Original actor-stage handoffs qualify entries. These are constructed CPU paths,
not natural encounters, whole-frame execution or exclusive pool ownership.
"""
import ctypes,os
import pytest
from tests.test_starglider2_text_editor import state,run,put,get,APP,INPUT,STACK,RETURN
from tests.test_starglider2_control_normalization import signed
from test_starglider2_retail_input import program
from test_starglider2_retail_encounters import rng
from tests import test_starglider2_volcano_lifecycle as volcano
from test_starglider2_retail_surface_hazards import FIELDS
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
OBJ,TARGET,FREE,REFS=0x85000,0x85200,0x84000,0x84100
MARKER,REMOVE,ASTEROID,VOLCANO=0x37440,0x374d4,0x374da,0x3843e

@pytest.fixture(params=('amiga','st'))
def machine(request):
 image=program(request.param);m=(ctypes.c_uint8*0xa1000)();ctypes.memmove(ctypes.addressof(m)+4096,image[0],len(image[0]));return image,m

def stage(image,m,near,far=()):
 m[APP+0x7e9]=255
 for actors,count,cursor,offset in((near,0x75e,0x6c8,0),(far,0x75c,0x6b8,128)):
  put(m,APP+count,len(actors),2);put(m,APP+cursor,REFS+offset)
  for n,actor in enumerate(actors):put(m,REFS+offset+4*n,actor)
 c=state(m,0x1314);seen=set();run(image,m,c,{0x1318},seen.add,limit=5000);return seen

def actor(m,at,kind):
 m[at:at+68]=bytes(68);put(m,at,kind,2);m[at+28]=128;m[at+30]=255
 for off,value in((4,100),(8,-1000),(12,200)):put(m,at+off,value&0xffffffff)

@pytest.mark.parametrize('space,present,count',((0,True,None),(128,True,None),(0,False,None),(0,True,0),(0,True,1),(0,True,128)))
def test_marker_whole_record_follow_or_shared_wrapping_shrink(machine,space,present,count):
 image,m=machine;actor(m,OBJ,95);actor(m,TARGET,1);put(m,APP+0x838,TARGET if present else 0);m[APP+0x77d]=space;put(m,APP+0x848,128)
 for off,value in((4,0x7fffffff),(8,0x80000000),(12,400)):put(m,OBJ+off,value)
 for off,value in((16,65530),(18,4090),(20,0xff80)):put(m,OBJ+off,value,2)
 m[OBJ+3]=15;m[OBJ+29]=255;expected=bytearray(m[OBJ:OBJ+68]);m[APP+0xa9f]=int(count is not None)
 if count is not None:
  m[APP+0xaa0]=count;left=(count-1)&255;retire=left>=128
  if not retire:expected[29]=0
 else:
  retire=not present
  if present:
   for off in(4,8,12):
    target=(get(m,TARGET+off)-(128 if off==8 and space<128 else 0))&0xffffffff;v=get(m,OBJ+off);put(expected,off,(v+(signed(target-v,32)>>3))&0xffffffff)
 if retire:put(expected,0,0,2)
 else:
  expected[3]=0
  for off,delta in((16,128),(18,2048),(20,128)):put(expected,off,(get(expected,off,2)+delta)&65535,2)
 c=state(m,MARKER);c.a[0]=OBJ;run(image,m,c,{0x3b6a2});assert bytes(m[OBJ:OBJ+68])==expected
 if count is not None:assert m[APP+0xaa0]==left


def test_marker_producer_feeds_real_near_and_far_actor_dispatch(machine):
 image,m=machine;actor(m,TARGET,1);put(m,APP+0x838,TARGET);put(m,APP+0x840,1,2);m[APP+0xaa4]=0
 put(m,APP+0x772,12,2);put(m,APP+0x6d4,FREE+8);put(m,FREE,OBJ+68);put(m,FREE+4,OBJ)
 m[OBJ:OBJ+136]=b'\x5a'*136;c=state(m,0x372a0);c.a[0]=TARGET;run(image,m,c,{0x373c2})
 assert [get(m,OBJ+i*68,2)for i in range(2)]==[95,95]and get(m,APP+0x772,2)==10 and get(m,APP+0x6d4)==FREE
 assert m[OBJ+34]==0 and m[OBJ+68+34]==0x5a
 # The producer preserves flags. Explicitly choose the unflagged service path;
 # this is a supplied-list actor-stage check, not a universal dirty-slot claim.
 for at in(OBJ,OBJ+68):m[at+2]=0
 seen=stage(image,m,[OBJ,OBJ+68]);assert MARKER in seen
 m[APP+0xa9f]=1;m[APP+0xaa0]=1
 seen=stage(image,m,[OBJ],[OBJ+68]);assert MARKER in seen and REMOVE in seen
 assert get(m,OBJ,2)==95 and get(m,OBJ+68,2)==0 and m[APP+0xaa0]==0
 seen=stage(image,m,[OBJ]);assert MARKER in seen and get(m,OBJ,2)==0 and m[APP+0xaa0]==255

@pytest.mark.parametrize('kind,durability,scale,free',((73,3,0,51),(74,2,9,51),(73,2,10,51),(74,2,0,50),(73,128,0,51),(74,2,128,51),(73,2,255,51)))
def test_asteroid_dispatch_motion_split_and_two_pop_one_decrement_contract(machine,kind,durability,scale,free):
 image,m=machine;actor(m,OBJ,kind);m[OBJ+28]=durability;m[OBJ+29]=scale;m[OBJ+2]=0;put(m,OBJ+36,31,2)
 for off,value in((44,-3),(46,32767),(48,-32768)):put(m,OBJ+off,value&65535,2)
 put(m,APP+0x772,free,2);put(m,APP+0x6d4,FREE+8);put(m,FREE,OBJ+136);put(m,FREE+4,OBJ+68)
 m[OBJ+68:OBJ+204]=b'\x5a'*136;put(m,APP+0x60,0);put(m,APP+0x64,0xfff9)
 before=bytes(m[OBJ:OBJ+68]);expected=bytearray(before);split=signed(durability,8)<=2;admitted=split and free>50 and signed(scale-10,8)<0
 if not split:
  for off,velocity in((4,-3),(8,32767),(12,-32768)):put(expected,off,(get(expected,off)+velocity)&0xffffffff)
  put(expected,16,64,2);put(expected,20,31,2)
 else:expected[28]=expected[30]=0;expected[2]&=~12
 seen=stage(image,m,[OBJ]);assert ASTEROID in seen and bytes(m[OBJ:OBJ+68])==expected
 assert get(m,APP+0x772,2)==free-int(admitted)and get(m,APP+0x6d4)==FREE+(0 if admitted else 8)
 if admitted:
  pair=(0,0xfff9);values=[]
  for _ in range(4):pair=rng(*pair);values.append(pair[1])
  for child,first in((OBJ+68,True),(OBJ+136,False)):
   out=bytearray(b'\x5a'*68);put(out,0,74,2)
   for i,off in enumerate((4,8,12)):
    delta=(values[i]&1023)-512;put(out,off,(get(before,off)+(delta if first else 0))&0xffffffff)
    if first:put(out,16+2*i,values[i]&1023,2)
    put(out,44+2*i,((delta>>6)*(1 if first else -1))&65535,2)
   for off,value in((28,3),(29,(scale+1)&255),(30,255),(42,73)):out[off]=value
   put(out,36,(values[3]&63)+10,2);assert bytes(m[child:child+68])==out
  assert (get(m,APP+0x60),get(m,APP+0x64))==pair
 else:assert bytes(m[OBJ+68:OBJ+204])==b'\x5a'*136

@pytest.fixture
def volcano_machine(machine,monkeypatch):
 image,m=machine;f=dict(FIELDS);f.update({k:APP+v for k,v in(('world_object_update_enabled_flag',0x7e9),('nearby_object_count',0x75e),('nearby_objects_cursor',0x6c8),('distant_object_count',0x75c),('distant_objects_cursor',0x6b8),('panel_fast_animation_request',0x209))})
 f.update(update_world_objects=0x7fdc,volcano_refill_updates_or_negative=0x3b4c4,world_reference_y_coordinates=0x18f02,SG2Volcano_face_colour_pair_index=38,SG2Volcano_eruption_colour_countdown_or_negative=34,SG2Volcano_eruption_attempt_mod4_index=36)
 def retail_run(image,m,c,stops,*args,**kwargs):
  translated=c.pc!=0x7fdc
  if translated:c.pc+=0x1954;stops={p+0x1954 for p in stops}
  run(image,m,c,stops,*args,**kwargs)
  if translated:c.pc-=0x1954
 monkeypatch.setattr(volcano,'run',retail_run);return image,m,f

@pytest.mark.parametrize('initial,timer',((0,0),(65535,1),(32768,128),(1,129)))
def test_volcano_actor_stage_alternates_six_face_bytes_with_original_timer_sign(machine,initial,timer):
 image,m=machine;actor(m,OBJ,88);put(m,OBJ+38,initial,2);m[OBJ+34]=timer;put(m,OBJ+36,0,2)
 for off in(4,8,12):put(m,OBJ+off,0)
 put(m,APP+0x704,1000);m[0x3b4c4]=255;faces=[0x29c02+10*i for i in range(6)];before=[bytes(m[a:a+10])for a in faces]
 phase=(initial+1)&1;left=(timer-1)&255;bank=0x3b2d8 if left<128 else 0x3b2cc;colours=[m[bank+2*i+phase]for i in range(6)]
 seen=stage(image,m,[OBJ]);assert VOLCANO in seen and get(m,OBJ+38,2)==phase and m[OBJ+34]==(left if left<128 else 255)
 for at,old,colour in zip(faces,before,colours):expected=bytearray(old);expected[1]=colour;assert bytes(m[at:at+10])==expected

@pytest.mark.parametrize('scale,old,kind',((0,0,'nearby'),(31,0x5a,'distant'),(64,255,'nearby')))
def test_volcano_real_spawn_to_type47_dispatch_reuses_checked_oracle(volcano_machine,scale,old,kind):
 volcano.test_complete_eruption_constructor_supplies_negative_phase_and_velocity(*volcano_machine,scale,old,kind)

@pytest.mark.parametrize('timer,reserves,y',((0,(0,0,0),0),(1,(65408,65472,65535),0x80000000),(128,(65535,65535,65535),0),(129,(1,2,3),0)))
def test_volcano_byte_refill_and_independent_saturation(volcano_machine,timer,reserves,y):
 volcano.test_refill_counter_is_one_byte_and_reserves_saturate_independently(*volcano_machine,timer,reserves,y)

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_dispatch_tail_entries_fields_and_bounded_data(tmp_path):
 import struct,subprocess,json
 from pathlib import Path
 target=Path(__file__).resolve().parents[1]/'targets/starglider2_retail';directory=target/'rendered';source=(directory/'retail-shared.s').read_text()
 symbols=dict(update_nearby_tractor_beam_marker=MARKER,remove_distant_tractor_beam_marker=REMOVE,update_nearby_asteroid=ASTEROID,update_nearby_volcano=VOLCANO,SG2Asteroid_rotation_2_spin_step=36,SG2Volcano_eruption_colour_countdown_or_negative=34,SG2Volcano_eruption_attempt_mod4_index=36,SG2Volcano_face_colour_pair_index=38,SG2TractorMarkerWorkspace_tractor_marker_lower_y_offset=0x848,volcano_face_colour_pairs_bank0=0x3b2cc,volcano_face_colour_pairs_bank1=0x3b2d8,volcano_refill_updates_or_negative=0x3b4c4)
 for name in list(symbols)[:4]:assert not source.split(name+':',1)[1].split('\n',2)[1].startswith('\tdc.'),name
 metadata=json.loads((target/'target_metadata.json').read_text())
 for name,size in(('volcano_face_colour_pairs_bank0',12),('volcano_face_colour_pairs_bank1',12),('volcano_eruption_velocity_x_choices',16),('volcano_eruption_velocity_z_choices',16),('volcano_refill_updates_or_negative',1)):
  item=next(e for e in metadata['seeded_entities']if e.get('name')==name and e.get('end')is not None);assert item['end']-item['addr']==size
 # Preserve the independently consumed atmosphere view,including its aliased
 # final byte,rather than silently narrowing an older supported classification.
 atmosphere=next(e for e in metadata['seeded_entities']if e.get('name')=='world_atmosphere_altitude_shifts');assert atmosphere['addr']==0x3b2bc-4096 and atmosphere['end']==0x3b2cd-4096
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert r.returncode==0,r.stdout+r.stderr
 raw=out.read_bytes();n=4*len(symbols);assert raw[:-n]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-n:])==tuple(symbols.values())

@pytest.mark.parametrize('phase,free,seeds',((0,11,(0,0xfff9)),(3,10,(0,0xfff9)),(3,11,(0,0))))
def test_volcano_eruption_rejects_before_pop_at_each_independent_gate(volcano_machine,phase,free,seeds):
 volcano.test_eruption_advances_mod4_before_random_then_unsigned_free_gate(*volcano_machine,phase,free,seeds)

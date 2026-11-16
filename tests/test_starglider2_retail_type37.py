"""Original retail mini-sentinel initialization, near/far updates and handoff.

Supplied actors, selectors, PRNG state and observer origins prove finite CPU
paths. They do not prove natural flight, all lifetimes or hardware timing.
"""
import ctypes,os,struct
import pytest
from tests.test_starglider2_text_editor import state,run,put,get,APP,INPUT,STACK,RETURN
from tests.test_starglider2_control_normalization import signed
from test_starglider2_retail_input import program
from test_starglider2_retail_encounters import rng
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
ACTOR=INPUT+0x1000;NEAR,FAR=0x37632,0x376a6

@pytest.fixture(params=('amiga','st'))
def machine(request):
 image=program(request.param);m=(ctypes.c_uint8*0xa1000)();ctypes.memmove(ctypes.addressof(m)+4096,image[0],len(image[0]));put(m,APP+0x44,0x15808);put(m,APP+0x48,0x16008)
 return image,m


def actor(m,address=ACTOR,angle=4095,increment=24,count=15):
 m[address:address+68]=bytes(68);put(m,address,37,2);m[address+28]=128;m[address+30]=255;m[address+31]=count
 put(m,address+36,angle,2);put(m,address+40,increment,2);put(m,address+16,4090,2);put(m,address+20,65535,2)
 for off,value in((4,1234),(8,5678),(12,9012)):put(m,address+off,value)


def coordinates(m,angle):
 values=[]
 for table,bias in((0x15808,36000000),(0x16008,20400000)):
  product=12287*signed(get(m,table+2*angle,2));scaled=signed(((product*4)&0xffffffff)>>16)
  values.append((bias+scaled)&0xffffffff)
 return values[0],(-20000000)&0xffffffff,values[1]


def near_actor(m,address):
 out=bytearray(m[address:address+68]);angle=(get(out,36,2)+2)&4095;put(out,36,angle,2)
 for off,value in zip((4,8,12),coordinates(m,angle)):put(out,off,value)
 increment=get(out,40,2);put(out,16,((get(out,16,2)+increment)&4095)|1,2);put(out,20,(get(out,20,2)+increment)&4095,2)
 countdown=(out[31]-1)&255
 if countdown&128:out[40]=(-out[40])&255;countdown=63
 out[31]=countdown;return out

@pytest.mark.parametrize('angle,increment,count,spin,seeds',((4095,24,15,0,(0,0)),(4094,0x0118,0,32767,(0,0)),(0,0xff18,128,0,(0,0)),(1,0x8018,129,0,(0,0)),(2047,0x0118,255,65535,(0,0)),(1,24,0,65535,(0,0xfff9)),(1,24,1,32768,(0,0xfff9))))
def test_near_orbit_word_rotations_high_byte_negation_and_spin_event_gate(machine,angle,increment,count,spin,seeds):
 image,m=machine;actor(m,angle=angle,increment=increment,count=count);put(m,0x3b628,spin,2);put(m,APP+0x60,seeds[0]);put(m,APP+0x64,seeds[1]);put(m,APP+0x7ae,1,2);put(m,APP+0x7b4,33,2);put(m,0xe0c6,0x12345678)
 expected_actor=near_actor(m,ACTOR);sampled=bool(spin&32768);next_rng=rng(*seeds)if sampled else seeds;event=sampled and not(next_rng[1]&4095)
 c=state(m,NEAR);c.a[0]=ACTOR;expected=bytearray(m);expected[ACTOR:ACTOR+68]=expected_actor
 put(expected,APP+0x60,next_rng[0]);put(expected,APP+0x64,next_rng[1])
 if event:
  put(expected,0x3b628,64,2);expected[APP+0xbb6]=255;put(expected,APP+0x7ae,3,2);put(expected,APP+0x7b4,0,2)
  for i,value in enumerate((get(m,0x394ba+56*4),0xe0fa,get(m,0x394ba+35*4))):put(expected,0xe0c6+4*i,value)
 run(image,m,c,{0x3b6a2});expected[STACK-256:STACK]=bytes(m[STACK-256:STACK]);assert bytes(m)==expected and c.a[7]==STACK

@pytest.mark.parametrize('angle',(0,4094,4095,65535))
def test_distant_update_only_advances_masked_orbit_without_position_or_rng(machine,angle):
 image,m=machine;actor(m,angle=angle,increment=0x0118,count=0);c=state(m,FAR);c.a[0]=ACTOR;expected=bytearray(m);put(expected,ACTOR+36,(angle+2)&4095,2)
 run(image,m,c,{0x3b68a});assert bytes(m)==expected

@pytest.mark.parametrize('gate,initial,quota',((0,7,2),(128,0,2),(128,1,2),(128,2,2),(128,65535,2),(128,32766,32767),(128,32767,2),(128,65534,65535)))
def test_initializer_reuses_independent_word_quota_and_n_only_admission(machine,gate,initial,quota):
 image,m=machine;actor(m);m[APP+0xa7c]=gate;put(m,APP+0xa7a,quota,2);put(m,0x1a210,initial,2)
 updated=(initial+1)&65535 if gate&128 else initial;admitted=bool(gate&128)and not((quota-updated)&32768)
 c=state(m,0x19a00);c.a[0]=ACTOR;run(image,m,c,{0x19a20,0x19a1c},limit=20)
 assert c.pc==(0x19a20 if admitted else 0x19a1c)and get(m,0x1a210,2)==updated


def test_admitted_initializer_reaches_the_near_orbit_helper_with_matching_record_layout(machine):
 image,m=machine;actor(m,angle=0,increment=0,count=0);m[APP+0xa7c]=128;put(m,APP+0xa7a,2,2);put(m,0x1a210,0,2);put(m,0x1a212,0,2);put(m,APP+0x60,0);put(m,APP+0x64,0xfff9)
 initial=get(m,0x1a214,2);c=state(m,0x19a00);c.a[0]=ACTOR;before_d=list(c.d);before_a=list(c.a)
 run(image,m,c,{RETURN},limit=500)
 assert list(c.d)==before_d and list(c.a)[:7]==before_a[:7]and c.a[7]==STACK+4
 assert get(m,ACTOR,2)==37 and get(m,ACTOR+36,2)==initial and get(m,ACTOR+40,2)==24 and m[ACTOR+31]==15 and m[ACTOR+28]&128
 assert [get(m,ACTOR+off)for off in(4,8,12)]==list(coordinates(m,initial))
 assert get(m,ACTOR+38,2)==16 and get(m,0x1a210,2)==1 and get(m,0x1a212,2)==2
 put(m,0x3b628,0,2);expected=near_actor(m,ACTOR);c=state(m,NEAR);c.a[0]=ACTOR;run(image,m,c,{0x3b6a2})
 assert bytes(m[ACTOR:ACTOR+68])==expected


def test_original_partitioner_hands_the_same_actor_between_far_and_near_updates(machine):
 image,m=machine;pool=APP+0x2330;actor(m,pool,angle=0,increment=0x0118,count=2);m[pool+2]=0;put(m,APP+0x172,2,2);put(m,APP+0x6fc,0x0fffffff);m[APP+0x77c]=0;m[APP+0x7e9]=255;put(m,0x3b628,0,2)
 for nearby in(False,True,False,True):
  # Observer origins are explicit per-snapshot inputs, not flight controls.
  for off,actor_off in((0x710,4),(0x714,8),(0x718,12)):
   value=get(m,pool+actor_off);put(m,APP+off,(value+(0 if nearby or actor_off!=4 else 1000000))&0xffffffff)
  c=state(m,0x4158);run(image,m,c,{RETURN},limit=5000)
  assert get(m,APP+(0x75e if nearby else 0x75c),2)==1 and get(m,APP+(0x75c if nearby else 0x75e),2)==0
  refs=get(m,APP+(0x6c8 if nearby else 0x6b8));assert get(m,refs)==pool
  expected=near_actor(m,pool)if nearby else bytearray(m[pool:pool+68])
  if not nearby:put(expected,36,(get(expected,36,2)+2)&4095,2)
  c=state(m,0x1314);seen=set();run(image,m,c,{0x1318},lambda pc:seen.add(pc),limit=3000)
  assert (NEAR if nearby else FAR)in seen and (FAR if nearby else NEAR)not in seen
  assert bytes(m[pool:pool+68])==expected


def test_default_eight_slot_quota_uses_only_the_eight_angle_prefix(machine):
 image,m=machine;m[APP+0xa7c]=255;put(m,APP+0xa7a,8,2);put(m,0x1a210,0,2);put(m,0x1a212,0,2)
 for i in range(9):
  at=ACTOR+68*i;actor(m,at,angle=0,increment=0,count=0);c=state(m,0x19a00);c.a[0]=at;run(image,m,c,{RETURN},limit=500)
  assert get(m,0x1a210,2)==i+1
  if i<8:assert get(m,at,2)==37 and get(m,at+36,2)==i*512 and get(m,0x1a212,2)==2*(i+1)
  else:assert get(m,at,2)==0 and get(m,0x1a212,2)==16


def test_retail_name_directory_identifies_type37(machine):
 image,m=machine;at=get(m,0xf380+37*4);assert bytes(m[at:at+19])==b'Egron Mini-Sentinel'

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_mini_sentinel_layout_keeps_byte_negation_and_near_far_entries(tmp_path):
 import subprocess,json
 from pathlib import Path
 target=Path(__file__).resolve().parents[1]/'targets/starglider2_retail';directory=target/'rendered';source=(directory/'retail-shared.s').read_text()
 symbols=dict(update_nearby_mini_sentinel=NEAR,advance_distant_mini_sentinel_orbit_angle=FAR,advance_mini_sentinel_orbit=0x376b4,SG2MiniSentinel_high_byte_negation_countdown=31,SG2MiniSentinel_orbit_angle=36,SG2MiniSentinel_rotation_increment=40,SG2MiniSentinel_SIZEOF=68,type37_initial_orbit_angle_words=0x1a214)
 assert 'neg.b SG2MiniSentinel_rotation_increment(a0)'in source and 'neg.w SG2MiniSentinel_rotation_increment(a0)'not in source
 for name in('update_nearby_mini_sentinel','advance_distant_mini_sentinel_orbit_angle','advance_mini_sentinel_orbit'):
  assert not source.split(name+':',1)[1].split('\n',2)[1].startswith('\tdc.'),name
 md=json.loads((target/'target_metadata.json').read_text());owner=next(e for e in md['seeded_entities']if e.get('name')=='type37_initial_orbit_angle_words'and e.get('end')is not None)
 assert owner['end']-owner['addr']==16 and owner['unit']=='word'
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert r.returncode==0,r.stdout+r.stderr
 raw=out.read_bytes();n=4*len(symbols);assert raw[:-n]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-n:])==tuple(symbols.values())

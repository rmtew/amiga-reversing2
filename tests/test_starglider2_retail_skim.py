"""Connected original launcher/pool/missile paths under explicit retail states.

CPU stage sequences are constructed tests, not natural gameplay or a complete
frame, collision, rendering, hardware-timing or universal-lifetime proof.
"""
import ctypes,os
import pytest
from tests.test_starglider2_text_editor import state,run,put,get,APP,INPUT,STACK,RETURN
from tests.test_starglider2_control_normalization import signed
from tests.test_starglider2_motion_integration import expected_vector
from test_starglider2_retail_input import program
from test_starglider2_retail_encounters import rng
from amiga_reversing.disasm.mapped_execution import MappedExecution
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
PARENT,CHILD,FREE=INPUT+0x1000,INPUT+0x1100,INPUT+0x200
LAUNCH,STATE,NEAR,FAR,LIFETIME=0x37704,0x377f2,0x3790e,0x37922,0x3792a
CLAIM,REFERENCE=0x3b620,0x3b624

@pytest.fixture(params=('amiga','st'))
def machine(request):
 image=program(request.param);m=(ctypes.c_uint8*0xa1000)();ctypes.memmove(ctypes.addressof(m)+4096,image[0],len(image[0]));put(m,APP+0x44,0x15808);put(m,APP+0x48,0x16008)
 return image,m


def record(m,at,kind):
 m[at:at+68]=bytes(68);put(m,at,kind,2);m[at+28]=128;m[at+30]=255
 for off,value in((4,1000),(8,-5000),(12,2000)):put(m,at+off,value&0xffffffff)


def frac(value,target,shift):return(value-(signed(value-target,32)>>shift))&0xffffffff

@pytest.mark.parametrize('near,climb,pursuit,xyz,yaw',((True,20,150,(0,-1000,1000),4090),(False,1,150,(0,2147483647,0),65535),(True,0,1,(-1,-3,0x7fffffff),1),(False,65535,0,(100,100,100),65535),(True,32768,0,(1,1,1),0),(False,0,32768,(0x80000000,0x7fffffff,1),9),(True,1,0,(0,0,0),0),(False,65535,65535,(0,0,0),0)))
def test_missile_climb_pursuit_retirement_and_near_only_yaw(machine,near,climb,pursuit,xyz,yaw):
 image,m=machine;record(m,CHILD,60);m[CHILD+2]=12;put(m,CHILD+36,climb,2);put(m,CHILD+38,pursuit,2);put(m,CHILD+18,yaw,2)
 for off,v in zip((4,8,12),xyz):put(m,CHILD+off,v&0xffffffff)
 for off,v in((0x704,7),(0x708,-7),(0x70c,11)):put(m,APP+off,v&0xffffffff)
 c=state(m,NEAR if near else FAR);c.a[0]=CHILD;expected=bytearray(m);left=(climb-1)&65535
 if left&32768:
  put(expected,CHILD+36,65535,2)
  for off,player in zip((4,8,12),(7,-7,11)):put(expected,CHILD+off,frac(get(m,CHILD+off),player&0xffffffff,2))
  remaining=(pursuit-1)&65535;put(expected,CHILD+38,remaining,2)
  if remaining&32768:expected[CHILD+30]=0;expected[CHILD+2]&=~12;expected[CHILD+28]=0
 else:
  put(expected,CHILD+36,left,2);put(expected,CHILD+8,(get(m,CHILD+8)+50)&0xffffffff)
 if near:put(expected,CHILD+18,(yaw+64)&4095,2)
 run(image,m,c,{0x3b6a2 if near else 0x3b68a});expected[STACK-256:STACK]=bytes(m[STACK-256:STACK]);assert bytes(m)==expected and c.a[7]==STACK

@pytest.mark.parametrize('flag,owner,follow,idle,seeds',((0,'other',0,9,(0,0)),(0,'other',65535,1,(0,0)),(0,'other',65535,0,(0,0xfff9)),(255,'other',1,9,(0,0)),(255,'self',1,9,(0,0)),(0,'none',32768,32768,(0,0))))
def test_launcher_follow_claim_idle_and_counter_transitions(machine,flag,owner,follow,idle,seeds):
 image,m=machine;record(m,PARENT,43);put(m,PARENT+36,follow,2);put(m,PARENT+38,idle,2);m[CLAIM]=flag;ref=PARENT if owner=='self'else CHILD if owner=='other'else 0;put(m,REFERENCE,ref)
 for off,value in((0x704,100),(0x708,-100),(0x70c,300),(0x60,seeds[0]),(0x64,seeds[1])):put(m,APP+off,value&0xffffffff)
 c=state(m,STATE);c.a[0]=PARENT;before=bytes(m[PARENT:PARENT+68]);next_rng=seeds;expected=bytearray(before);out_flag=flag;out_ref=ref
 if flag&128 and ref!=PARENT:action='evade'
 elif follow&32768:
  idle=(idle-1)&65535
  if idle&32768:
   idle=65535;next_rng=rng(*seeds);follow=(next_rng[1]&255)+64;action='none'
  else:action='evade'
 else:
  follow=(follow-1)&65535
  if follow&32768:
   follow=65535;out_flag=0;out_ref=0;next_rng=rng(*seeds);idle=((next_rng[1]&127)+63)&65535;action='evade'
  else:out_flag=255;out_ref=PARENT;action='follow'
 put(expected,36,follow,2);put(expected,38,idle,2)
 if action=='evade':
  for off,poff in((4,0x704),(8,0x708),(12,0x70c)):
   value=get(m,PARENT+off);put(expected,off,(value+(signed(value-get(m,APP+poff),32)>>4))&0xffffffff)
  put(expected,16,((get(m,PARENT+16,2)+32)&4095)|1,2);put(expected,20,(get(m,PARENT+20,2)+32)&4095,2)
 elif action=='follow':
  vector,_=expected_vector(m,[get(m,APP+off,2)for off in(0x744,0x746,0x748)],3072,tables=(0x15808,0x16008))
  for off,poff,v in zip((4,8,12),(0x704,0x708,0x70c),vector):
   target=(get(m,APP+poff)+signed(-v))&0xffffffff;put(expected,off,frac(get(m,PARENT+off),target,3))
  for off in(16,20):put(expected,off,(get(m,PARENT+off,2)+16)&4095,2)
 run(image,m,c,{RETURN});assert bytes(m[PARENT:PARENT+68])==expected and m[CLAIM]==out_flag and get(m,REFERENCE)==out_ref
 assert (get(m,APP+0x60),get(m,APP+0x64))==next_rng

@pytest.mark.parametrize('free,z,x,y,follow',((50,0,0,0,1),(51,0,0,0,1),(65535,1599,0,0,1),(51,1600,0,0,1),(51,65535,0,0,1),(51,0,1600,0,1),(51,0,0,1600,1),(51,0,32768,32768,1),(51,0,0,0,65535)))
def test_launch_admission_and_partial_child_initialization_after_state_helper(machine,free,z,x,y,follow):
 image,m=machine;record(m,PARENT,43);put(m,PARENT+36,follow,2)
 for off,v in((22,x),(24,y),(26,z)):put(m,PARENT+off,v,2)
 put(m,APP+0x772,free,2);put(m,APP+0x6d4,FREE+4);put(m,FREE,CHILD);m[CHILD-4:CHILD+72]=b'\x5a'*76
 put(m,APP+0x60,0);put(m,APP+0x64,94);m[CLAIM]=255;put(m,REFERENCE,PARENT)
 # NEG.W of -32768 remains $8000. Comparisons use N only.
 admitted=follow<32768 and signed(z)>=0 and signed(z-1600)<0 and signed(((-x)&65535 if x&32768 else x)-1600)<0 and signed(((-y)&65535 if y&32768 else y)-1600)<0 and free>50
 expected=bytearray(m[CHILD:CHILD+68]);c=state(m,LAUNCH+4);c.a[0]=PARENT
 if admitted:
  put(expected,0,60,2)
  for off in(4,8,12):put(expected,off,get(m,PARENT+off))
  for off,v in((16,1),(18,0),(20,0),(36,20),(38,150)):put(expected,off,v,2)
  for off,v in((28,10),(30,255),(29,7),(3,0),(42,43)):expected[off]=v
 run(image,m,c,{0x3b6a2});assert bytes(m[CHILD:CHILD+68])==expected and bytes(m[CHILD-4:CHILD])==bytes([0x5a])*4 and bytes(m[CHILD+68:CHILD+72])==bytes([0x5a])*4
 assert get(m,APP+0x772,2)==free-int(admitted)and get(m,APP+0x6d4)==FREE+(0 if admitted else 4)
 assert get(m,PARENT+36,2)==(65535 if admitted else follow)
 assert (m[CLAIM],get(m,REFERENCE))==((0,0)if admitted else(255,PARENT))
 if admitted:assert m[PARENT+42]==60 and m[APP+0xbb6]==255 and get(m,PARENT+38,2)==(rng(0,94)[1]&127)+64

@pytest.mark.parametrize('profile',('amiga','st'))
def test_actual_initializer_pool_spawn_dispatch_lifetime_and_recycle(profile):
 raw=program(profile)[0];c=MappedExecution(0x100000);c.seed(4096,raw);c.seed(APP,bytes(0x6598));c.allow_write(APP,0x6598)
 c.seed(STACK-512,bytes(516));c.allow_write(STACK-512,516);c.seed(STACK,(0xff000).to_bytes(4,'big'))
 c.allow_write(0xe145,1);c.allow_write(CLAIM,1);c.allow_write(REFERENCE,4)
 pool=APP+0x2330;put(c.memory,pool,43,2);c.seed(pool+28,b'\x80\x03\xff');put(c.memory,APP+0x172,250,2);put(c.memory,APP+0x6fc,0x0fffffff)
 put(c.memory,APP+0x44,0x15808);put(c.memory,APP+0x48,0x16008);put(c.memory,APP+0x60,0);put(c.memory,APP+0x64,94);c.seed(APP+0x7e9,b'\xff');c.seed(CLAIM,b'\0');c.seed(REFERENCE,bytes(4))
 c.cpu.a[6]=APP;c.cpu.a[7]=STACK;c.cpu.a[0]=pool;c.run(0x19de6,0xff000,500)
 assert get(c.memory,pool+36,2)==14
 for aoff,off in((0x704,4),(0x708,8),(0x70c,12)):
  value=get(c.memory,pool+off);put(c.memory,APP+aoff,value);put(c.memory,APP+aoff+12,value)
 origin=tuple(get(c.memory,APP+off)for off in(0x710,0x714,0x718))
 def partition(far=False):
  for off,value in zip((0x710,0x714,0x718),origin):put(c.memory,APP+off,(value+(1000000 if far and off==0x710 else 0))&0xffffffff)
  c.cpu.a[6]=APP;c.cpu.a[7]=STACK;c.run(0x4158,0xff000,40000)
 def actors(via=None):
  c.cpu.a[6]=APP;c.cpu.a[7]=STACK
  if via is not None:c.run(0x1314,via,20000);c.run(via,0x1318,20000)
  else:c.run(0x1314,0x1318,20000)
 partition();assert get(c.memory,APP+0x772,2)==249 and get(c.memory,APP+0x75e,2)==1
 child=get(c.memory,get(c.memory,APP+0x6d4)-4);assert child==pool+249*68
 actors(LAUNCH);assert get(c.memory,child,2)==60 and get(c.memory,APP+0x772,2)==248
 assert [get(c.memory,child+off,2)for off in(36,38)]==[20,150] # Not in this actor snapshot yet.
 assert get(c.memory,pool+38,2)==191 and get(c.memory,pool+36,2)==65535 and c.read(CLAIM,1)==b'\0'and get(c.memory,REFERENCE)==0
 birth=get(c.memory,child+8);yaw=get(c.memory,child+18,2)
 for tick in range(1,172):
  far=tick in(10,25);partition(far)
  refs=get(c.memory,APP+(0x6b8 if far else 0x6c8));count=get(c.memory,APP+(0x75c if far else 0x75e),2)
  assert child in[get(c.memory,refs+4*i)for i in range(count)]
  actors(FAR if far else NEAR if tick==1 else None)
  if tick<=20:assert get(c.memory,child+8)==(birth+50*tick)&0xffffffff and get(c.memory,child+38,2)==150
  else:assert get(c.memory,child+36,2)==65535 and get(c.memory,child+38,2)==((170-tick)&65535)
  assert get(c.memory,child+18,2)==(yaw+64*(tick-int(tick>=10)-int(tick>=25)))&4095
 assert c.read(child+28,1)==b'\0'and c.read(child+30,1)==b'\0'and c.read(child+2,1)[0]&12==0
 limit=raw[0x18e48-4096+60]
 for phase in range(limit+1):
  assert c.read(child+30,1)==bytes([phase]);partition();actors()
 assert get(c.memory,child,2)==0 and c.read(child+30,1)==b'\xff'and get(c.memory,APP+0x772,2)==249
 assert get(c.memory,get(c.memory,APP+0x6d4)-4)==child


def test_other_follow_claim_is_coordination_not_an_exclusive_launch_ownership_guard(machine):
 image,m=machine;record(m,PARENT,43);put(m,PARENT+36,1,2);put(m,PARENT+38,10,2);m[CLAIM]=255;put(m,REFERENCE,CHILD+0x100)
 put(m,APP+0x772,51,2);put(m,APP+0x6d4,FREE+4);put(m,FREE,CHILD);m[CHILD:CHILD+68]=bytes(68)
 c=state(m,LAUNCH);c.a[0]=PARENT;run(image,m,c,{0x3b6a2})
 assert get(m,CHILD,2)==60 and get(m,APP+0x772,2)==50 and m[CLAIM]==0 and get(m,REFERENCE)==0
 assert [get(m,CHILD+off)for off in(4,8,12)]==[get(m,PARENT+off)for off in(4,8,12)]


def test_retail_name_directory_identifies_launcher_and_missile(machine):
 image,m=machine
 for kind,name in((43,b'Skim Launcher Drone'),(60,b'Skim Missile')):
  at=get(m,0xf380+4*kind);assert bytes(m[at:at+len(name)])==name

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_skim_sources_share_collision_field_and_keep_timer_roles(tmp_path):
 import struct,subprocess
 from pathlib import Path
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered';source=(directory/'retail-shared.s').read_text()
 symbols=dict(update_nearby_skim_launcher_drone=LAUNCH,advance_skim_launcher_drone_state=STATE,update_nearby_skim_missile=NEAR,update_distant_skim_missile=FAR,advance_skim_missile_lifetime=LIFETIME,SG2ContactActor_collision_ignored_object_type=42,SG2SkimLauncherDrone_follow_phase_countdown=36,SG2SkimLauncherDrone_idle_phase_countdown=38,SG2SkimMissile_climb_updates_remaining=36,SG2SkimMissile_pursuit_updates_remaining=38,SG2SkimMissile_SIZEOF=68)
 for name in list(symbols)[:5]:assert not source.split(name+':',1)[1].split('\n',2)[1].startswith('\tdc.'),name
 assert 'move.w #$14,SG2SkimMissile_climb_updates_remaining(a2)'in source
 assert 'move.w #$96,SG2SkimMissile_pursuit_updates_remaining(a2)'in source
 assert 'move.b #$2B,SG2ContactActor_collision_ignored_object_type(a2)'in source
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert r.returncode==0,r.stdout+r.stderr
 raw=out.read_bytes();n=4*len(symbols);assert raw[:-n]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-n:])==tuple(symbols.values())

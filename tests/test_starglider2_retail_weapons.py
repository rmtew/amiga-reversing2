"""Retail weapon/scan contracts over supplied pools, targets and HUD buffers.

The live laser comparison qualifies one normal firing path. These CPU witnesses
cover additional boundaries; they do not establish arbitrary target lifetime,
all weapon lifetimes, hardware timing or normal acquisition of every fixture.
"""
import os,struct
import pytest
from test_starglider2_retail_input import memory,program
from tests.test_starglider2_text_editor import state,run,put,get,APP,RETURN
from tests import test_starglider2_scan_acquisition as scan
from tests import test_starglider2_homing_launch as homing
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')

class EarlierView:
 """Translate only proven source tables, never stored pointers or app fields."""
 def __init__(self,m):self.m=m
 def at(self,k):
  for a,b,n in((scan.LOOKUP,0x2c6b8,12000),(scan.HORIZONTAL,0x18918,210),(scan.VERTICAL,0x189ea,210),(homing.BACKUP,0x7b52,896),(homing.ORIGIN,0x7938,4),(homing.KEYS,0xdece,256),(0x7ec0,0x7ed2,54)):
   if a<=k<a+n:return k-a+b
  return k
 def key(self,k):
  if not isinstance(k,slice):return self.at(k)
  start=self.at(k.start);assert self.at(k.stop-1)==start+k.stop-k.start-1
  return slice(start,start+k.stop-k.start,k.step)
 def __getitem__(self,k):return self.m[self.key(k)]
 def __setitem__(self,k,v):self.m[self.key(k)]=v

def machine(platform):
 m=memory(platform);put(m,0x27be,APP);return m,EarlierView(m)
def execute(platform,m,pc,stops=(RETURN,),limit=10000):
 c=state(m,pc);run(program(platform),m,c,set(stops),limit=limit);return c

@pytest.mark.parametrize('platform',('amiga','st'))
@pytest.mark.parametrize('entry,source,kind',((0x721a,0x7ee6,84),(0x7226,0x7ef6,103)))
def test_profile_copy_consumes_seven_words_and_one_byte_before_energy_gate(platform,entry,source,kind):
 m,v=machine(platform);m[APP+0xae5+0x54]=1;m[0x7ed2:0x7ee5]=b'\xa5'*19;payload=bytes(m[source:source+15]);c=execute(platform,m,entry,(0x726e,))
 words=struct.unpack('>7H',payload[:14]);dest=(0x7ed2,0x7ee0,0x7ee2,0x7ed4,0x7ed8,0x7ed6,0x7eda)
 assert [get(m,p,2)for p in dest]==list(words) and get(m,0x7ee4,1)==payload[14]
 assert words[0]==kind and c.a[0]==source+15 and bytes(m[0x7edc:0x7ee0])==b'\xa5'*4

@pytest.mark.parametrize('platform',('amiga','st'))
@pytest.mark.parametrize('kind,energy,free',((84,0,3),(84,1,2),(84,511,0),(84,512,2),(103,255,2),(103,256,2),(103,65535,2)))
def test_energy_and_attempt_count_precede_failed_free_reserve(platform,kind,energy,free):
 m,v=machine(platform);put(m,0x7ed2,kind,2);put(m,0x7ee0,14,2);put(m,APP+0x794,energy,2);put(m,APP+0x772,free,2);put(m,APP+0x6d4,0x87654)
 for off,x in((0x766,0xff80),(0x768,0xffff),(0x76e,0xcafe),(0x770,0xbeef)):put(m,APP+off,x,2)
 put(m,APP+0x6dc,0xffffffff);c=execute(platform,m,0x726e,(0x73f2,RETURN))
 assert get(m,APP+0x772,2)==free and get(m,APP+0x6d4)==0x87654
 if not energy:assert c.pc==0x73f2 and get(m,APP+0x76e,2)==0xcafe and get(m,APP+0x6dc)==0xffffffff
 else:
  assert c.pc==RETURN and (get(m,APP+0x76e,2),get(m,APP+0x770,2))==(0xff80,0xffff)
  assert get(m,APP+0x794,2)==max(0,energy-(512 if kind==84 else 256))
  assert get(m,APP+0x6dc)==0 and get(m,APP+0x7c4,2)==14

@pytest.mark.parametrize('platform',('amiga','st'))
@pytest.mark.parametrize('records,aim',[
 ([scan.record()],(160,80)),([scan.record(flags=64)],(160,80)),
 ([scan.record(z=0)],(160,80)),([scan.record(z=-1)],(160,80)),
 ([scan.record(type_=84),scan.record(type_=3)],(160,80)),
 ([scan.record(type_=128,x=20000,cx=0,cy=0,radius=5)],(160,80)),
 ([scan.record(z=513),scan.record(type_=3,z=512)],(160,80)),
 ([scan.record(z=512),scan.record(type_=3,z=513)],(160,80)),
 ([scan.record(x=1000)],(0x7fff,80))])
def test_identity_scan_matches_existing_geometry_and_last_equal_depth_oracle(platform,records,aim):
 m,v=machine(platform);scan.setup(v,records,aim);expected=scan.reference(v,'identity',records,aim);c=state(m,0x740e);c.d[7]=len(records)
 run(program(platform),m,c,{RETURN});actual=tuple(get(m,APP+o,n)for o,n in((scan.TYPE,2),(scan.REF,4),(scan.SX,2),(scan.SY,2),(scan.DEPTH,2)))
 assert actual==expected and c.a[7]==scan.STACK+4

@pytest.mark.parametrize('platform,z',(('amiga',-513),('st',0),('st',512)))
def test_existing_lock_reprojects_without_revalidating_target_type_or_phase(platform,z):
 m,v=machine(platform);scan.setup(v,[scan.record(type_=30,x=123,y=-456,z=z,phase=0,flags=64)]);put(m,APP+scan.REF,scan.OBJECT)
 execute(platform,m,0x76ec)
 expected=(0x1111,0x2222)if z==0 else tuple((scan.project(x,get(m,0x2c6b8+scan.signed16(z&0xfffe),2))+origin)&65535 for x,origin in((123,160),(-456,80)))
 assert (get(m,APP+scan.SX,2),get(m,APP+scan.SY,2))==expected
 assert get(m,APP+scan.REF)==scan.OBJECT and get(m,APP+scan.TYPE,2)==77

@pytest.mark.parametrize('mode,icons,speed,angles',((0,1,0,(0,0,0)),(1,2,32767,(1024,2048,3072)),(2,2,65535,(65535,4097,32768))))
def test_real_homing_allocation_preserves_record_gaps_and_uses_original_motion(mode,icons,speed,angles):
 platform='amiga'if mode==0 else'st';m,v=machine(platform);flags=bytes(m[0x1002:0x1004]);homing.prepare(v,mode,icons=icons);m[0x1002:0x1004]=flags
 put(m,APP+0x44,0x15808);put(m,APP+0x48,0x16008);put(m,APP+0x75a,speed,2)
 for off,x in zip((0x744,0x746,0x748),angles):put(m,APP+off,x,2)
 terms=[get(m,base+2*(angle&4095),2)for base,angle in((0x15808,angles[0]),(0x16008,angles[0]),(0x15808,angles[1]),(0x16008,angles[1]))];s0,c0,s1,c1=terms;scale=(speed+500)&65535
 velocity=[(-scan.project(scan.project(scale,s1),c0))&65535,(-scan.project(scale,s0))&65535,scan.project(scan.project(scale,c1),c0)&65535]
 expected=bytearray(m[homing.OBJECT:homing.OBJECT+68])
 def field(off,value,width=2):expected[off:off+width]=value.to_bytes(width,'big')
 for off,x,n in((0,12,2),(29,3,1),(3,0,1),(28,0xcc|128,1),(30,255,1),(34,255,1),(36,400,2),(60,homing.TARGET,4),(32,scale,2)):field(off,x,n)
 for off,x in zip((16,18,20),(angles[0]|1,angles[1],angles[2])):field(off,x)
 for off,x in zip((44,46,48),velocity):field(off,x)
 for off,base,x in zip((4,8,12),(0x12345,0xfffffff0,0x23456),velocity):
  y=(base+scan.signed16(2*x))&0xffffffff;field(off,y if off==8 else y&0xffff,4)
 hud=homing.expected_hud(v,mode,icons);execute(platform,m,0x7602)
 assert bytes(m[homing.OBJECT:homing.OBJECT+68])==expected
 assert bytes(m[homing.FB:homing.FB+0x18000])==hud
 assert get(m,APP+homing.FREE,2)==2 and get(m,APP+0x6d4)==homing.POOL
 assert get(m,APP+homing.ICONS,2)==icons-1 and get(m,APP+0x7c4,2)==100

@pytest.mark.parametrize('platform',('amiga','st'))
def test_weapon_selector_is_a_five_entry_byte_offset_dispatch(platform):
 for index,target in enumerate((0x721a,0x7226,0x7596,0x7940,0x79c0)):
  m,v=machine(platform);m[APP+0x7ea]=4*index;m[0xdece+0x40]=255;m[APP+0x7f2]=0x40
  c=execute(platform,m,0x71b4,(target,));assert c.pc==target

@pytest.mark.parametrize('platform,kind,variant_sign,side_sign',(('amiga',84,1,1024),('st',84,1,-1024),('amiga',103,1,1024),('st',103,255,-1024)))
def test_full_projectile_constructor_copies_profile_and_preserves_unwritten_record_bytes(platform,kind,variant_sign,side_sign):
 m,v=machine(platform);obj=homing.OBJECT;pool=homing.POOL;m[obj:obj+68]=b'\xcc'*68
 put(m,APP+0x6d4,pool+4);put(m,pool,obj);put(m,APP+0x772,3,2);put(m,APP+0x794,65535,2);m[APP+0xae5+84]=1
 put(m,APP+0x6fc,0xffff);world=(0xffe0,0xfffffff0,0x1234);angles=(14,2048,1)
 for off,x in zip((0x704,0x708,0x70c),world):put(m,APP+off,x)
 for off,x in zip((0x744,0x746,0x748),angles):put(m,APP+off,x,2)
 put(m,APP+0x75a,5,2);put(m,APP+0xa74,7,2);put(m,0x7f06,side_sign&65535,2);m[0x7f05]=variant_sign
 m[0x2c24:0x2c36]=struct.pack('>9h',16384,0,0,0,16384,0,0,0,16384)
 source=0x7ee6 if kind==84 else 0x7ef6;profile=struct.unpack('>7HB',bytes(m[source:source+15]));scale=(12+profile[2])&65535
 velocity=(0,0,scan.signed16(scale)*16384>>16);variant=int(kind==103 and ((-variant_sign)&255)>=128)
 expected=bytearray(m[obj:obj+68])
 def f(off,x,n=2):expected[off:off+n]=(x&((1<<(8*n))-1)).to_bytes(n,'big')
 for off,x,n in((0,kind,2),(3,variant,1),(29,profile[7],1),(30,255,1),(28,1,1),(34,255,1),(36,100,2),(42,kind,1),(32,scale,2)):f(off,x,n)
 for off,x in zip((16,18,20),(angles[0]|1,angles[1],angles[2])):f(off,x)
 for off,x in zip((44,46,48),velocity):f(off,x)
 shift=(-200 if side_sign>0 else 200)
 for off,x in zip((4,8,12),((world[0]+shift)&65535,world[1],world[2])):f(off,x,4)
 execute(platform,m,0x721a if kind==84 else 0x7226)
 assert bytes(m[obj:obj+68])==expected
 assert get(m,APP+0x772,2)==2 and get(m,APP+0x6d4)==pool
 assert get(m,APP+0x6dc)==1 and get(m,APP+0x794,2)==65535-(512 if kind==84 else 256)
 assert get(m,0x4ea10,2)==profile[3] and get(m,0x4ea12,2)==profile[5]

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='external vasm is the source build dependency')
def test_compiled_weapon_contracts_match_original_addresses_and_field_widths(tmp_path):
 import subprocess
 from pathlib import Path
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered'
 names={'dispatch_selected_weapon_action':0x71b4,'load_projectile_profile_and_try_spawn':0x722e,'check_energy_before_projectile_attempt':0x726e,'select_reticle_target_candidate':0x740e,'update_locked_scan_target_projection':0x76ec,'type84_projectile_profile':0x7ee6,'type103_projectile_profile':0x7ef6,'weapon_action_dispatch_targets':0x7f1c,'try_launch_bouncing_bomb':0x7940,'SG2ProjectileProfile_SIZEOF':15,'SG2ProjectileProfile_model_scale_shift':14,'SG2WeaponWorkspace_scan_target_reference_unchecked':0x6b0,'SG2WeaponWorkspace_pilot_shots_fired':0x6dc,'SG2WeaponWorkspace_fire_key_scancode':0x7f2,'SG2PlayerProjectile_update_budget':36}
 asm,out=tmp_path/'symbols.s',tmp_path/'symbols.raw';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(names)+'\n')
 result=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert result.returncode==0,result.stdout+result.stderr
 raw=out.read_bytes();n=len(names)*4;assert raw[:-n]==program('st')[0]and struct.unpack('>'+str(len(names))+'I',raw[-n:])==tuple(names.values())
 text=(directory/'retail-shared.s').read_text()
 assert 'SG2WeaponWorkspace_scan_lock_refresh_countdown(a6)'in text
 assert 'SG2ProjectileProfile' in text and 'SG2PlayerProjectile_update_budget(a2)'in text

@pytest.mark.parametrize('platform',('amiga','st'))
@pytest.mark.parametrize('one_hand,direction,mouse,allowed',((0,0,0,False),(1,0,0,True),(1,1,0,False),(0,0,1,True)))
def test_joystick_fire_requires_one_hand_mode_and_directions_can_mean_throttle(platform,one_hand,direction,mouse,allowed):
 m,v=machine(platform);m[APP+0x7f1]=one_hand;put(m,APP+0x15c,direction,2);m[APP+0x1fd]=255;m[APP+0x201]=mouse
 c=execute(platform,m,0x71b4,(RETURN,0x721a))
 assert c.pc==(0x721a if allowed else RETURN)

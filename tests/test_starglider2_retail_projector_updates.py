"""Shared projector update handlers on both original retail CPUs.

Supplied active records and nearby lists prove conditional execution, not
normal-play lifetimes, universal selector bounds or renderer/timing fidelity.
"""
import ctypes,os,struct
import pytest
from tests.test_starglider2_text_editor import state,run,put,get,APP,INPUT
from tests.test_starglider2_control_normalization import signed
from test_starglider2_retail_input import program
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
ENTRIES={77:0x37e28,78:0x37e5c,79:0x37e90,80:0x37ea4,81:0x37ed8,82:0x37eee}
ACTOR=INPUT+0x1000

@pytest.fixture(params=('amiga','st'))
def machine(request):
 image=program(request.param);m=(ctypes.c_uint8*0xa1000)();ctypes.memmove(ctypes.addressof(m)+4096,image[0],len(image[0]));return image,m


def record(m,address,kind,variant=0,step=1):
 m[address:address+68]=bytes(68);put(m,address,kind,2);m[address+28]=128;m[address+30]=255;m[address+3]=variant;m[address+31]=step


def expect_step(m,at,kind,enabled):
 out=bytearray(m[at:at+68])
 if not enabled:return out
 if kind in(77,78,80):
  value=(out[3]+out[31])&255
  if value==10:out[31]=(-out[31])&255;value=9
  if value==255:out[31]=(-out[31])&255;value=0
  out[3]=value
 elif kind==79:out[3]=(out[3]+1)&7
 elif kind==81:put(out,18,(get(out,18,2)+16)&4095,2)
 return out

@pytest.mark.parametrize('kind,flag,variant,step',((77,0,9,1),(77,255,9,1),(78,128,0,255),(78,255,5,1),(80,255,255,1),(80,127,9,1),(77,255,10,0),(80,255,255,0),(78,255,254,1),(79,255,7,1),(79,255,255,255),(79,255,8,0),(79,127,255,1)))
def test_selector_updates_keep_exact_byte_sentinels_and_sign_gate(machine,kind,flag,variant,step):
 image,m=machine;record(m,ACTOR,kind,variant,step);m[APP+0xa7c]=flag
 c=state(m,ENTRIES[kind]);expected=bytearray(m);expected[ACTOR:ACTOR+68]=expect_step(m,ACTOR,kind,bool(flag&128));c.a[0]=ACTOR
 run(image,m,c,{0x3b6a2});assert bytes(m)==expected

@pytest.mark.parametrize('flag,angle',((255,4090),(128,65535),(0,65535),(127,0)))
def test_crew_quarters_turn_wraps_only_when_cycle_is_negative(machine,flag,angle):
 image,m=machine;record(m,ACTOR,81);put(m,ACTOR+18,angle,2);m[APP+0xa7c]=flag;c=state(m,ENTRIES[81]);c.a[0]=ACTOR;expected=bytearray(m);expected[ACTOR:ACTOR+68]=expect_step(m,ACTOR,81,bool(flag&128))
 run(image,m,c,{0x3b6a2});assert bytes(m)==expected


def sentinel_expected(m,at,flag,orbit,y,rotation):
 actor=bytearray(m[at:at+68]);next_orbit=orbit
 if flag&128:
  next_orbit=(orbit+32)&4095
  for off,table in((4,0x15808),(12,0x16008)):
   value=signed(get(m,table+2*next_orbit,2));scaled=signed(((2000*value*4)&0xffffffff)>>16)
   put(actor,off,(28672+scaled)&0xffffffff)
  height=-500 if signed(y+500,32)>=0 else(-3000 if signed(y+3000,32)<0 else y)
  put(actor,8,height&0xffffffff);put(actor,18,((rotation+32)&65535)|1,2)
 else:
  height=(y+1)&0xffffffff;put(actor,8,height if height else 0xffffffff)
 return actor,next_orbit

@pytest.mark.parametrize('flag,orbit,y,rotation',((255,4090,-500,65530),(128,0,-501,0),(255,2047,-3000,4095),(255,1,-3001,1),(255,0,-2147483648,0),(255,0,2147483647,0),(0,123,-2,999),(127,65535,-1,65535),(1,4,2147483647,1)))
def test_sentinel_trig_truncation_y_sign_gates_and_disabled_nonzero_increment(machine,flag,orbit,y,rotation):
 image,m=machine;record(m,ACTOR,82);m[APP+0xa7c]=flag;put(m,APP+0x87a,orbit,2);put(m,APP+0x708,y&0xffffffff);put(m,ACTOR+8,y&0xffffffff);put(m,ACTOR+18,rotation,2);put(m,APP+0x44,0x15808);put(m,APP+0x48,0x16008)
 expected_actor,next_orbit=sentinel_expected(m,ACTOR,flag,orbit,y,rotation);c=state(m,ENTRIES[82]);c.a[0]=ACTOR;expected=bytearray(m);expected[ACTOR:ACTOR+68]=expected_actor;put(expected,APP+0x87a,next_orbit,2)
 run(image,m,c,{0x3b6a2});assert bytes(m)==expected


def test_actual_actor_stage_reaches_all_six_projector_handlers(machine):
 image,m=machine;refs=INPUT+0x100
 for i,kind in enumerate(ENTRIES):
  at=ACTOR+68*i;record(m,at,kind,9 if kind in(77,78,80)else 7,1);put(m,refs+4*i,at)
 put(m,APP+0x6c8,refs);put(m,APP+0x75e,6,2);put(m,APP+0x75c,0,2);m[APP+0x7e9]=255;m[APP+0xa7c]=255
 put(m,APP+0x708,(-1000)&0xffffffff);put(m,APP+0x44,0x15808);put(m,APP+0x48,0x16008);put(m,APP+0x87a,4090,2)
 expected={ACTOR+68*i:expect_step(m,ACTOR+68*i,kind,True)for i,kind in enumerate(ENTRIES)if kind!=82}
 expected[ACTOR+68*5],orbit=sentinel_expected(m,ACTOR+68*5,255,4090,-1000,0)
 c=state(m,0x1314);seen=set();run(image,m,c,{0x1318},lambda pc:seen.add(pc),limit=5000)
 assert all(pc in seen for pc in ENTRIES.values())
 for at,value in expected.items():assert bytes(m[at:at+68])==value
 assert get(m,APP+0x87a,2)==orbit and get(m,APP+0x6c4)==refs+24

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_projector_handlers_are_code_and_share_existing_layouts(tmp_path):
 import subprocess
 from pathlib import Path
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered';source=(directory/'retail-shared.s').read_text()
 symbols=dict(update_nearby_projector_cover=0x37e28,update_nearby_projector_turret=0x37e5c,update_nearby_projector_fuel_crystals=0x37e90,update_nearby_projector_control_tower=0x37ea4,update_nearby_projector_crew_quarters=0x37ed8,update_nearby_projector_sentinel=0x37eee,SG2ProjectorUpdateWorkspace_projector_sentinel_orbit_angle=0x87a)
 for name in list(symbols)[:6]:
  block=source.split(name+':',1)[1].split('\n',2)[1]
  assert block.startswith('\ttst.b '),block
 assert 'SG2ProjectorPart_network_animation_step(a0)'in source
 assert 'SG2ProjectorUpdateWorkspace_projector_sentinel_orbit_angle(a6)'in source
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert r.returncode==0,r.stdout+r.stderr
 raw=out.read_bytes();n=4*len(symbols);assert raw[:-n]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-n:])==tuple(symbols.values())

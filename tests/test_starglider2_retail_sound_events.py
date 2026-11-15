"""Original event routing and bounded sample domains; no audio/timing claim."""
import os
import pytest
from test_starglider2_retail_sound import machine,trace,address,program,state,run,put,get,APP,RETURN,selection,transition
from tests import test_starglider2_bounce_effects as bounce
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')

@pytest.mark.parametrize('platform,space,y,vy,scale',[
 ('st',0,-30,1,21),('amiga',0,-30,1,20),('st',0,-30,1,19),('st',0,-1000,-1,21),
 ('st',128,-30,1,21),('st',0,-25,-32768,65535),('st',0,0x7fffffff,32764,32768),('amiga',1,-20,10,0)])
def test_retail_bounce_reuses_complete_record_and_event_oracle(platform,space,y,vy,scale):
 m,_=machine(platform)
 bounce.check_bounce_contract(program(platform),m,space,y,vy,scale,entry=0x38202,install_entry=0x1f32)

@pytest.mark.parametrize('platform',('amiga','st'))
@pytest.mark.parametrize('depth,generic',((1,0),(32768,0),(65535,128)))
def test_last_bounce_depth_reaches_real_platform_event_consumer(platform,depth,generic):
 m,view=machine(platform);bounce.prepare(view);run(program(platform),m,state(m,0x1f32),{RETURN})
 put(m,bounce.BOMB+8,0xffffffe7);put(m,bounce.BOMB+32,20,2)
 second=bounce.BOMB+128;m[second:second+68]=bytes(m[bounce.BOMB:bounce.BOMB+68]);put(m,second+26,depth,2)
 for record in (bounce.BOMB,second):
  c=state(m,0x38202);c.a[0]=record;run(program(platform),m,c,{RETURN})
  assert m[APP+0xae1]==255 and m[record+30]==0
 assert get(m,APP+0x860,2)==depth
 bounce.sound_setup(view);m[APP+0xbb6]=generic
 entry,stop=(0x4bcb8,0x4bdce)if platform=='amiga'else(0x4d36c,0x4d452)
 trace(platform,m,entry,stop)
 if platform=='amiga':
  actual=[m[APP+0xae1],m[APP+0xbb6],get(view,bounce.PV,2),get(view,bounce.PP,2),get(view,bounce.PA,2)]
  expected=bounce.paula_reference(1,255,generic,depth)
 else:
  actual=[m[APP+0xae1],m[APP+0xbb6],get(view,bounce.AV,2),get(view,bounce.AP,2),get(view,bounce.AD,2),get(view,bounce.AA,2)]
  expected=bounce.alternate_reference(1,255,generic,depth)
 assert actual==list(expected)

@pytest.mark.parametrize('platform',('amiga','st'))
def test_both_actor_partitions_dispatch_to_real_bounce_callbacks(platform):
 m,_=machine(platform)
 for entry,expected,finish,tag in ((0x8002,0x381e2,0x3b6a2,225),(0x8210,0x381f2,0x3b68a,226)):
  bounce.prepare(m);c=state(m,entry);c.a[0]=bounce.BOMB;m[bounce.BOMB+28]=6
  run(program(platform),m,c,{expected},limit=100)
  assert get(m,0xe145,1)==tag
  m[APP+0x77d]=128;run(program(platform),m,c,{finish},limit=500)
  assert get(m,0xe145,1)==tag-80

@pytest.mark.parametrize('platform',('amiga','st'))
def test_148_actor_tags_admit_only_bounded_object_sound_selectors(platform):
 m,view=machine(platform);admitted=[]
 for kind in range(148):
  r=selection.record(view,0,kind,phase=128,coords=(4000,0,0));selection.setup(view,[r])
  expected=selection.selection(view,[r],'paula'if platform=='amiga'else'alternate')[0]
  if platform=='amiga':
   c=state(m,address(0x4be58));run(program(platform),m,c,{address(0x4bf46),address(0x4c1a4)},limit=500);actual=c.pc==address(0x4bf46)
  else:
   c=state(m,address(0x4d452));run(program(platform),m,c,{address(0x4d53a)},limit=1000)
   actual=get(view,selection.ATYPE,2)==kind and view[selection.AFOUND]==255
  assert actual==bool(expected),kind
  if actual:admitted.append(kind)
 assert max(admitted)==(64 if platform=='amiga'else 49)
 assert all(k<71 for k in admitted)and 91 not in admitted

def test_filter_bound_does_not_extend_into_trailing_zero_bytes():
 m,view=machine('amiga');assert [view[selection.PFILTER+k]for k in (147,148,149)]==[255,0,0]
 r=selection.record(view,0,148,phase=128);selection.setup(view,[r])
 c=state(m,address(0x4be58));run(program('amiga'),m,c,{address(0x4bf46)},limit=100)
 assert get(view,selection.PREF)==r['address']and 148>=71

def test_sample_dma_views_are_bounded_aliases_not_71_independent_assets():
 m,view=machine('amiga');raw=program('amiga')[0];spans={}
 for kind in range(71):
  row=address(transition.DESC)+16*kind;base=get(m,row);words=get(m,row+4,2);start=base+6;end=start+2*words
  assert 4096<=base<start<=end<=4096+len(raw)
  spans.setdefault(base,[]).append((kind,start,end))
 assert len(spans)==9 and len(spans[0x5b8d8])==18
 assert spans[0x4ea76][0][2]>spans[0x4ea9e][0][0]
 assert {e for _,_,e in spans[0x5ff98]}=={0x623b0,0x623d8}


def test_empty_list_retains_selected_identity_but_reload_uses_static_sample_data():
 m,view=machine('amiga');selection.setup(view,[])
 put(view,selection.PREF,0xffffffff);put(view,selection.ATYPE,1,2)
 c=state(m,address(0x4be58));c.a[2]=0xffffffff
 run(program('amiga'),m,c,{address(0x4c5ac)},limit=100)
 assert get(view,selection.PREF)==0xffffffff and get(view,selection.ATYPE,2)==1
 transition.prepare(view,1,phase=7)
 # The interrupt reload uses the retained type and static descriptor, not A2.
 c=state(m,address(0x4c62c));c.a[2]=0xffffffff
 run(program('amiga'),m,c,{address(0x4c78e)},limit=1000)
 sample=get(view,transition.DESC+16)
 assert get(m,0xdff0d0)==sample+6 and get(m,0xdff0d4,2)==get(view,transition.DESC+20,2)

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='external vasm is the source build dependency')
def test_compiled_event_and_sample_symbols_preserve_both_input_contracts(tmp_path):
 import struct,subprocess
 from pathlib import Path
 from test_starglider2_retail_model_headers import image
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered'
 symbols={'update_nearby_bouncing_bomb':0x381e2,'update_distant_bouncing_bomb':0x381f2,'advance_bouncing_bomb_state':0x38202,'publish_bounce_sound_request_and_raw_relative_z':0x3827e,'SG2SoundActor_relative_z':26,'SG2SoundActor_motion_vector_scale':32,'SG2BouncingBomb_service_countdown':36,'paula_type1_sample_storage':0x5ff98,'paula_type30_short_sample_view':0x4ea9e,'paula_channel1_initial_sample_storage':0x5fbc8}
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 result=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert result.returncode==0,result.stdout+result.stderr
 raw=out.read_bytes();size=4*len(symbols)
 assert raw[:-size]==image('st')and struct.unpack('>'+str(len(symbols))+'I',raw[-size:])==tuple(symbols.values())

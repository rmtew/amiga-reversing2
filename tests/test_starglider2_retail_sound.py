"""Reuse qualified earlier sound contracts against original retail instructions.

Sparse RAM represents ports for CPU traces. Separate read-only machine runs
prove the two main-frame and interrupt entries; no PCM quality, DMA, interrupt
cadence, disk access or universal model/sample lifetime claim follows.
"""
import os
import pytest
from test_starglider2_retail_input import memory,program
from tests.test_starglider2_text_editor import state,run,put,get,APP,STACK,RETURN
from tests import test_starglider2_object_sound as selection
from tests import test_starglider2_sound_initialization as setup
from tests import test_starglider2_sample_transition as transition
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
DELTA=0x19ac
EXTERNAL={0xe103:0xe145,0xcf2c:0xcf58,0xd008:0xd034,0xd0c4:0xd0f0,0x3bd4c:0x3d6f8,0x2662:0x2676}


def address(old):
 if old in EXTERNAL:return EXTERNAL[old]
 for base in (0xcf2c,0xd008,0xd0c4):
  if base<=old<base+32:return old+0x2c
 if 0x4bc00<=old<0x65c40:return old+DELTA
 if 0x39600<=old<0x39d00:return old+0x194e
 return old


class EarlierAddresses:
 """Only earlier fixture addresses are translated; stored values stay intact."""
 def __init__(self,m):self.m=m
 def key(self,k):
  if not isinstance(k,slice):return address(k)
  start=address(k.start);assert address(k.stop-1)==start+k.stop-k.start-1
  return slice(start,start+k.stop-k.start,k.step)
 def __getitem__(self,k):return self.m[self.key(k)]
 def __setitem__(self,k,v):self.m[self.key(k)]=v


def machine(platform):
 m=memory(platform);put(m,0x27be,APP);return m,EarlierAddresses(m)


def trace(platform,m,pc,stop,stores=None,cpu=None):
 stores={address(k):(address(v[0]),v[1])for k,v in (stores or {}).items()};pending=None;events=[]
 def observe(at):
  nonlocal pending
  if pending is not None:
   dest,width=stores[pending];events.append((dest,width,get(m,dest,width)))
  pending=at if at in stores else None
 c=cpu or state(m,address(pc));run(program(platform),m,c,{address(stop)},observe,limit=30000)
 if pending is not None:
  dest,width=stores[pending];events.append((dest,width,get(m,dest,width)))
 return c,events


@pytest.mark.parametrize('backend,reverse',[('paula',False),('paula',True),('alternate',False),('alternate',True)])
def test_retail_candidate_selection_reuses_wrapped_metric_and_last_equal_oracle(backend,reverse):
 platform='amiga'if backend=='paula'else'st';m,view=machine(platform)
 rows=[selection.record(view,0,1,coords=(4000,0,0)),selection.record(view,1,3,coords=(-4000,0,0))]
 if reverse:rows.reverse()
 selection.setup(view,rows);chosen,metric,special,found=selection.selection(view,rows,backend)
 entry,stop=(0x4be58,0x4bf46)if backend=='paula'else(0x4d452,0x4d53a)
 trace(platform,m,entry,stop)
 assert get(view,selection.PREF if backend=='paula'else selection.AREF)==chosen['address']
 assert chosen['address']==rows[-1]['address'] and metric==1000


@pytest.mark.parametrize('platform,first,second',[('amiga',a,b)for a,b in ((0,0),(128,0),(0,128),(128,128),(127,1))]+[('st',a,b)for a,b in ((0,0),(128,0),(0,128),(128,128),(127,1))])
def test_event_sound_latches_have_platform_specific_consumption_order(platform,first,second):
 m,view=machine(platform);r=selection.record(view,0,3,phase=0);selection.setup(view,[r])
 m[APP+0xae1]=first;m[APP+0xbb6]=second;put(m,APP+0x860,4096,2)
 entry,stop=(0x4bc00,0x4bda4)if platform=='amiga'else(0x4d360,0x4d416)
 # Stop addresses correspond to the first common envelope-decay instruction.
 stop=0x4d750 if platform=='amiga'else 0x4edc2
 c=state(m,address(entry));run(program(platform),m,c,{stop},limit=1000)
 assert m[APP+0xae1]==(0 if first&128 else first)
 expected_second=second if platform=='st'and first&128 else(0 if second&128 else second)
 assert m[APP+0xbb6]==expected_second


def test_st_preserves_second_pending_event_until_the_following_frame():
 m,view=machine('st');r=selection.record(view,0,3,phase=0);selection.setup(view,[r]);put(m,APP+0x860,4096,2)
 m[APP+0xae1]=m[APP+0xbb6]=255
 for expected in (255,0):
  c=state(m,0x4ed0c);run(program('st'),m,c,{0x4edc2},limit=1000)
  assert m[APP+0xae1]==0 and m[APP+0xbb6]==expected


@pytest.mark.parametrize('kind,pause,modal,enabled',[(1,128,0,128),(3,0,0,128),(10,128,0,128),(3,0,128,128),(3,0,0,0)])
def test_psg_output_reuses_existing_precedence_and_byte_output_contract(kind,pause,modal,enabled):
 m,view=machine('st');setup.prepare(view);put(view,setup.TYPE,kind,2);view[setup.PAUSE]=pause;view[APP+0x6da]=modal;view[setup.ENABLE]=enabled
 _,events=trace('st',m,0x4d9bc,0x4db1e,setup.PORT_STORES)
 pairs=[(events[n][2],events[n+1][2])for n in range(0,len(events),2)]
 expected=0x78 if kind in (1,15)else 0 if pause&128 else 0x34
 if modal&128 or not enabled&128:expected=0
 elif kind==10:expected=254
 assert pairs[:6]==[(10,expected),(4,0xcd),(5,0xab),(8,0 if modal&128 or not enabled&128 else 0x45),(0,0x89),(1,0x67)]


@pytest.mark.parametrize('platform,d0',[('amiga',0),('amiga',0xffffffff),('st',0x12345678)])
def test_sound_initializers_keep_distinct_ports_prefixes_and_software_reset_scope(platform,d0):
 m,view=machine(platform);setup.prepare(view);put(view,setup.TYPE,77,2)
 c=state(m,address(0x4dedc if platform=='amiga'else 0x4df8e));c.d[0]=d0
 before=list(c.d),list(c.a);before_state=[get(view,a,2)for a in (setup.PVOL,setup.PPER,setup.ENV,setup.STARVOL,setup.EVENTVOL)]
 _,events=trace(platform,m,0,RETURN,setup.PAULA_STORES if platform=='amiga'else setup.PORT_STORES,c)
 if platform=='st':
  assert events==[(setup.SEL,1,7),(setup.DATA,1,0x28)]
  assert [get(view,a,2)for a in (setup.TYPE,setup.OVOL,setup.OPER)]==[0,0,0]
  assert [get(view,a,2)for a in (setup.PVOL,setup.PPER,setup.ENV,setup.STARVOL,setup.EVENTVOL)]==before_state
  assert list(c.d)==before[0]
 else:
  expected=[]
  for port,pointer,length,volume,period in [(0xdff0a0,0x59f34,0x2168,24,358),(0xdff0b0,0x5e220,0x1da,0,1500),(0xdff0c0,0x5e5f0,0x1212,0,658),(0xdff0d0,0x4d0ca,20,0,5124)]:
   expected.extend(((port,4,address(pointer)),(port+4,2,length),(port+8,2,volume),(port+6,2,period)))
  assert events==expected+[(address(setup.TYPE),2,0),(0xdff096,2,0x820f)]
 assert c.a[7]==STACK+4 and list(c.a)[1:7]==before[1][1:7]


def test_phase_six_reloads_all_71_physical_descriptors_and_retains_old_request():
 m,view=machine('amiga')
 for kind in range(71):
  transition.prepare(view,kind,phase=7);put(view,transition.VOL,30,2)
  sample=get(view,transition.DESC+16*kind);length=get(view,transition.DESC+16*kind+4,2)
  _,events=trace('amiga',m,0x4c62c,0x4c78e,transition.STORES)
  assert events[:4]==[(transition.OUT,2,30>>5),(transition.PTR,4,sample+6),(transition.LENGTH,2,length),(transition.DMA,2,0x8208)]
  assert get(view,transition.PREVIOUS)==0x11223344 and get(view,transition.REQUESTED)==sample+6


@pytest.mark.parametrize('phase,restart',[(0,0),(8,0),(7,0),(65535,0),(65535,65535)])
def test_sample_transition_keeps_boundary_phase_and_restart_rules(phase,restart):
 m,view=machine('amiga');transition.prepare(view,1,phase,restart);put(view,transition.VOL,30,2)
 _,events=trace('amiga',m,0x4c62c,0x4c78e,transition.STORES)
 skip=phase&32768 and not restart&32768;p=phase if skip else(phase-1)&65535
 assert get(view,transition.TRANS,2)==(p if skip or not p&32768 else 65535)
 if not skip and p==7:assert events[-1]==(transition.DMA,2,8)
 if phase==65535 and not restart&32768:assert events==[]

@pytest.mark.parametrize('route',('gray','fade','random','inside','surface'))
def test_amiga_interrupt_palette_continuation_reuses_existing_priority_oracle(route):
 from tests import test_starglider2_palette_priority as palette
 m,view=machine('amiga');palette.prepare(view);put(view,palette.OVERRIDE,1,2)
 if route=='gray':put(view,palette.GRAY,1,2);expected=0xfff
 elif route=='fade':view[palette.FADE]=64;expected=7
 elif route=='random':put(view,palette.SPIN,0,2);expected=palette.rng(0x12345678,0xabcdef01)[1]&4095
 elif route=='inside':view[APP+0x77c]=1;expected=0x66a
 else:expected=0xffa
 trace('amiga',m,0x4c78e,0x4cac0)
 assert [get(view,a,2)for a in palette.COLOURS]==[expected]*3


@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='external vasm is the source build dependency')
def test_compiled_sound_symbols_bind_qualified_code_and_descriptor_fields(tmp_path):
 import struct,subprocess
 from pathlib import Path
 from test_starglider2_retail_model_headers import image
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered'
 symbols={'update_amiga_frame_effects':0x4d5ac,'advance_paula_sample_transition_continuation':0x4dfd8,'update_alternate_sound_and_display_effects':0x4eeec,'initialize_paula_sample_channels':0x4f888,'call_amiga_interrupt_sound_bridge':0xe154,'call_st_interrupt_sound_bridge':0x3f37c,'paula_object_sound_descriptors':0x4e5a0,'psg_object_type_base_volumes_or_negative':0x4f7ea,'SG2SoundDescriptor_sample_base':0,'SG2SoundDescriptor_sample_length_words':4,'SG2SoundDescriptor_object_effect_dispatch_gate':14,'SG2SoundWorkspace_pending_bomb_bounce_sound':0xae1}
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 result=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert result.returncode==0,result.stdout+result.stderr
 raw=out.read_bytes();size=4*len(symbols)
 assert raw[:-size]==image('st')and struct.unpack('>'+str(len(symbols))+'I',raw[-size:])==tuple(symbols.values())

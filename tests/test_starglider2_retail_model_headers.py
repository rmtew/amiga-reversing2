"""Reuse qualified headers; test the original shared loader and its real guards."""
import json,os,struct
from functools import cache
from pathlib import Path
import pytest
from amiga_reversing.disasm.game_catalog import load_family,materialize
from amiga_reversing.disasm.mapped_execution import MappedExecution
from amiga_reversing.tools.compare_starglider2 import model_streams
ROOT=Path(__file__).resolve().parents[1];APP,ACTOR,STACK,RETURN=0x70000,0x60000,0xf0000,0xff000
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='private catalogue-bound retail payloads')

@cache
def image(platform):
 f=load_family(ROOT,'starglider2');target='starglider2_retail_amiga' if platform=='amiga' else 'starglider2_retail'
 return materialize(ROOT,'starglider2',f['targets'][target]['artifact']).read_bytes()

@cache
def models(platform):
 return model_streams(image(platform),0x19234)

def base(platform,*,whole=True):
 c=MappedExecution(0x100000,register_seed=0xdeadbeef);raw=image(platform)
 if whole:c.seed(0x1000,raw)
 else:c.seed(0x4a40,raw[0x3a40:0x3ab0])
 c.seed(APP,bytes(0x800));c.cpu.a[6]=APP;c.cpu.a[7]=STACK;c.seed(STACK,RETURN.to_bytes(4,'big'))
 c.allow_write(STACK-64,64);c.seed(0x49c0,bytes(2))
 actor=bytearray(68);actor[3]=0;actor[0x1d]=0xfd;actor[8:12]=bytes.fromhex('abcdef01');c.seed(ACTOR,actor);c.cpu.a[4]=ACTOR
 for at,size in [(0x174,2),(0x178,4),(0x10,4),(8,4),(0x14,4),(0x24,4),(0x190,2),(0x1aa,2),(0x1e4,2),(0x1e2,2),(0x70,4)]:c.allow_write(APP+at,size)
 return c

@pytest.mark.parametrize('platform',['amiga','st'])
def test_original_header_prefix_for_every_qualified_model_and_first_variant(platform):
 raw=image(platform);by_ordinal={n:m for m in models(platform) for n in m['ordinals']}
 assert len(by_ordinal)==104 and len(models(platform))==103
 for ordinal in range(104):
  model=by_ordinal[ordinal];header=model['header'];data=raw[header:header+28]
  for selector in (0,1):
   c=base(platform);c.cpu.d[0]=ordinal;c.seed(ACTOR+3,bytes([selector]));c.seed(APP+0x70,(0x1a3d4).to_bytes(4,'big'));c.seed(APP+0x24,(0x1a3d4).to_bytes(4,'big'))
   c.run(0x4a42,0x4ab0,80)
   expected={0x174:data[:2],0x178:data[2:6],0x10:data[6:10],8:data[10:14],0x14:data[14:18],0x190:ordinal.to_bytes(2,'big'),0x1aa:b'\0\x0d',0x1e4:data[22:24]}
   table=int.from_bytes(data[18:22],'big');expected[0x24]=raw[table-4096:table-4096+4] if selector and table else bytes(4)
   for at,value in expected.items():assert c.read(APP+at,len(value))==value,(ordinal,selector,hex(at))
   if int.from_bytes(data[22:24],'big'):
    assert c.read(APP+0x70,4)==data[24:28] and c.read(APP+0x1e2,2)==bytes.fromhex('ef01')
    assert c.cpu.a[0]==header+4096+28
   else:
    assert c.read(APP+0x70,4)==(0x1a3d4).to_bytes(4,'big') and c.read(APP+0x1e2,2)==bytes(2)
    assert c.cpu.a[0]==header+4096+24
   assert c.read(ACTOR+3,1)==bytes([selector]) and c.cpu.a[7]==STACK

@pytest.mark.parametrize('platform',['amiga','st'])
def test_original_104_header_extent_initializer_reuses_qualified_coordinate_pools(platform):
 raw=image(platform);c=base(platform);c.allow_write(0x5930,208)
 c.run(0x49f8,RETURN,150000)
 ptrs=struct.unpack('>104I',raw[0x19234:0x193d4]);expected=[]
 for pointer in ptrs:
  header=pointer-4096;count=int.from_bytes(raw[header+4:header+6],'big');pool=int.from_bytes(raw[header+14:header+18],'big')-4096
  assert count>0 and 0<=pool<=len(raw)-2*count
  expected.append(max(struct.unpack('>'+str(count)+'h',raw[pool:pool+2*count])))
 assert c.read(0x5930,208)==struct.pack('>104h',*expected)
 assert c.cpu.a[3]==0x1a3d4 and c.cpu.a[2]==0x5930+208 and c.cpu.a[7]==STACK+4

@pytest.mark.parametrize('platform',['amiga','st'])
def test_loader_guard_is_signed_packet_count_not_model_id_bound(platform):
 c=base(platform,whole=False);c.seed(0x49c0,(146).to_bytes(2,'big'));c.cpu.d[0]=0xdeadffff
 before=c.read(APP,0x800);c.run(0x4a42,RETURN,10);assert c.read(APP,0x800)==before
 # The loader itself does not reject index104. Only the qualified pointer
 # table is mapped, so its next lookup must fail instead of blessing a model.
 c=base(platform,whole=False);c.seed(0x1a234,image(platform)[0x19234:0x193d4]);c.cpu.d[0]=104
 with pytest.raises(ValueError,match='unknown read/fetch'):c.run(0x4a42,0x4ab0,30)

def test_shared_header_consumers_have_symbolic_context_without_blanket_gameplay_header_type():
 value=os.getenv('SGII_RETAIL_RENDERED_SOURCE')
 if not value:pytest.skip('set SGII_RETAIL_RENDERED_SOURCE to a fresh native export')
 text=Path(value).read_text()
 assert 'SG2ModelDrawContextPrefix_active_model_coordinate_pool(a6)' in text
 assert 'admit_next_model_face_command:' in text and 'project_ground_plane_faces_loop:' in text
 assert 'load_qualified_model_header_for_extent_scan:' in text

@pytest.mark.parametrize('platform',['amiga','st'])
def test_visible_actor_gate_distinguishes_special_low_bytes_but_not_full_model_bounds(platform):
 for kind,replacement in [(0,0),(1,0),(30,0),(30,50),(30,103),(30,104),(30,128),(50,0),(103,0),(104,0),(127,0),(128,0),(145,0),(0x8001,0)]:
  for active in (0,255):
   c=base(platform);c.seed(ACTOR,kind.to_bytes(2,'big'));c.seed(ACTOR+0x1e,bytes([active]));c.seed(APP+0x192,replacement.to_bytes(2,'big'))
   c.cpu.a[5]=0xd0000;c.seed(0xd0000,ACTOR.to_bytes(4,'big'));c.allow_write(0xe144,2);c.allow_write(APP+0x132,6);c.allow_write(APP+0x118,6)
   selected=replacement if kind==30 else kind
   stop=0x3fea if kind==0 else 0x3f96 if selected&128 else 0x3fde if active else 0x40ae
   c.run(0x3f70,stop,45)
   assert c.cpu.d[0]==selected and c.cpu.a[4]==ACTOR
 # In particular, IDs104..127 reach the model-call setup when active. The
 # gate is not a proof that these otherwise-unqualified headers are valid.

@pytest.mark.parametrize('platform',['amiga','rgb','mono'])
def test_original_emulator_header_slice_matches_current_cpu_contract(platform):
 value=os.getenv('SGII_MODEL_HEADER_DIRECTORY')
 if not value:pytest.skip('set SGII_MODEL_HEADER_DIRECTORY to private original captures')
 p=Path(value)/platform;r=json.loads((p/'receipt.private.json').read_text());assert not r['host_guest_memory_write']
 before=(p/'before-ram.private.bin').read_bytes();after=(p/'after-ram.private.bin').read_bytes()
 if platform=='amiga':regs=r['registers'];app=0x69668
 else:
  import re
  text=(p/'emulator.log').read_text().split('> savebin '+str(p/'before-ram.private.bin'))[0]
  regs={k.lower():int(v,16) for k,v in re.findall(r'\b([DA][0-7]) ([0-9A-F]{8})',text)};app=0x61668
 assert int.from_bytes(before[regs['a7']:regs['a7']+4],'big')==0x3fe6
 assert regs['d0']==50  # Actual original gameplay path, not the model viewer.
 c=MappedExecution(0x100000);c.seed(0,before)
 for k,v in regs.items():
  if len(k)==2 and k[0] in 'da' and k[1].isdigit():(c.cpu.d if k[0]=='d' else c.cpu.a)[int(k[1])]=v
 for offset,size in [(0x174,2),(0x178,4),(0x10,4),(8,4),(0x14,4),(0x24,4),(0x190,2),(0x1aa,2),(0x1e4,2),(0x1e2,2),(0x70,4)]:c.allow_write(app+offset,size)
 c.run(0x4a42,0x4ab0,80)
 for offset,size in [(0x174,2),(0x178,4),(0x10,4),(8,4),(0x14,4),(0x24,4),(0x190,2),(0x1aa,2),(0x1e4,2),(0x1e2,2),(0x70,4)]:
  assert c.read(app+offset,size)==after[app+offset:app+offset+size]

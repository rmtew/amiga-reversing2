"""Original panel instructions, independent pixel oracle and optional real ST runs."""
import json,os,re,struct
from functools import cache
from pathlib import Path
import pytest
from amiga_reversing.disasm.mapped_execution import MappedExecution
from amiga_reversing.disasm.game_catalog import load_family,materialize
ROOT=Path(__file__).resolve().parents[1]
APP,STACK,END,SCREEN=0x61668,0xf0000,0xff000,0x80000
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='private hash-bound retail input')

@cache
def image(platform):
 f=load_family(ROOT,'starglider2');name='starglider2_retail_amiga' if platform=='amiga' else 'starglider2_retail'
 return materialize(ROOT,'starglider2',f['targets'][name]['artifact']).read_bytes()


def context(platform,records,terminator=0):
 c=MappedExecution(0x100000,register_seed=0xdeadbeef);c.seed(0x1000,image(platform));c.seed(APP,bytes(0x1000));c.cpu.a[6]=APP;c.cpu.a[7]=STACK
 c.seed(STACK,END.to_bytes(4,'big'));c.allow_write(STACK-256,256)
 c.seed(APP,SCREEN.to_bytes(4,'big'));c.seed(APP+0x1f2,b'\xff' if platform=='mono' else b'\0');c.seed(APP+0x762,len(records).to_bytes(2,'big'))
 c.seed(APP+0x6d0,(0xd0000).to_bytes(4,'big'));pointers=[]
 for i,(kind,flags,x,z) in enumerate(records):
  at=0xd1000+64*i;pointers.append(at);r=bytearray(64);struct.pack_into('>H',r,0,kind);r[2]=flags;struct.pack_into('>hhh',r,0x16,x,1234,z);c.seed(at,r)
 c.seed(0xd0000,struct.pack('>'+str(len(pointers)+1)+'I',*pointers,terminator))
 # These explicitly initialized lookup fixtures express each mode's actual
 # consumer contract, rather than claim that stored zeroes are runtime tables.
 c.seed(0x43064,struct.pack('>200H',*(y*(40 if platform=='amiga' else 160) for y in range(200))))
 c.seed(0x18008,struct.pack('>320H',*((x//16)*2 if platform=='amiga' else (x//16)*8 for x in range(320))))
 c.seed(0x18288,struct.pack('>320H',*(0x8000>>(x%16) for x in range(320))))
 base=0x70000 if platform=='amiga' else SCREEN;c.seed(base,b'\xa5'*32768);c.allow_write(base,32768)
 return c,base


def oracle(platform,raw,records):
 out=bytearray(b'\xa5'*32768)
 def word(at,value):out[at:at+2]=(int.from_bytes(out[at:at+2],'big')|value).to_bytes(2,'big')
 if platform=='amiga':
  for plane in range(4):
   for y in range(144,179):out[plane*8192+y*40+16:plane*8192+y*40+20]=bytes(4)
   out[plane*8192+161*40+16:plane*8192+161*40+20]=(0x8000).to_bytes(4,'big')
 elif platform=='rgb':
  for y in range(144,178):out[y*160+64:y*160+80]=bytes(16)
  out[159*160+72:159*160+80]=bytes.fromhex('8000800080008000')
 else:
  for y in range(288,356):out[y*80+32:y*80+40]=bytes(8)
  for y in (319,320):out[y*80+32:y*80+40]=bytes.fromhex('0000000180000000')
 for kind,flags,x,z in records:
  if flags&0x10 or not(-8192<x<8192 and -8192<z<8192):continue
  sx=144+(x>>9);sy=160+((-z)>>9)
  if platform=='mono':
   # Preserve the actual mask selector (sx & 14), including its
   # quantisation. Do not replace it with a hypothetical sx%8 mapping.
   mask=0xc000>>(sx&14);at=sy*160+(sx//8)*2;word(at,mask);word(at+80,mask)
  else:
   colour=raw[0x4900-4096+kind];mask=0x8000>>(sx%16)
   for plane in range(4):
    if colour&(1<<plane):word(plane*8192+sy*40+(sx//16)*2 if platform=='amiga' else sy*160+(sx//16)*8+plane*2,mask)
 return bytes(out)

CASES=[[],[(1,0,0,0)],[(0,0,0,0)],[(9,0,511,-511)],[(6,0,-513,513)],[(1,0x10,0,0)],[(1,0,-8192,0)],[(1,0,8192,0)],[(1,0,0,-8192)],[(1,0,0,8192)],[(1,0,-8191,8191)],[(1,0,8191,-8191)],[(1,0,0,0),(6,0,512,-512),(9,0,-512,512)]]

@pytest.mark.parametrize('platform',['amiga','rgb','mono'])
@pytest.mark.parametrize('records',CASES)
def test_original_panel_full_buffer_matches_pixel_oracle_and_preserves_inputs(platform,records):
 c,base=context(platform,records);before=c.read(0xd0000,4*(len(records)+1));state=c.read(APP,0x1000)
 start,stop=(0x459c,END) if platform=='amiga' else (0x3c34e,0x3c53c)
 c.run(start,stop,7000)
 assert c.read(base,32768)==oracle(platform,image(platform),records)
 assert c.read(APP,0x1000)==state and c.read(0xd0000,len(before))==before
 if platform=='amiga':assert c.cpu.a[7]==STACK+4
 else:assert c.cpu.a[7]==STACK

@pytest.mark.parametrize('platform',['amiga','rgb','mono'])
@pytest.mark.parametrize('sentinel',[0,1])
def test_null_or_odd_contact_pointer_stops_before_dereferencing(platform,sentinel):
 c,base=context(platform,[(1,0,0,0)]);c.seed(0xd0000,sentinel.to_bytes(4,'big'))
 c.run(0x459c if platform=='amiga' else 0x3c34e,END if platform=='amiga' else 0x3c53c,7000)
 assert c.read(base,32768)==oracle(platform,image(platform),[])

@pytest.mark.parametrize('mode',['rgb','mono'])
def test_cpu_panel_slice_matches_original_hatari_ram_and_full_buffer(mode):
 value=os.getenv('SGII_PANEL_DIRECTORY')
 if not value:pytest.skip('set SGII_PANEL_DIRECTORY to private original runtime captures')
 p=Path(value)/mode;receipt=json.loads((p/'receipt.private.json').read_text());assert not receipt['host_guest_memory_write']
 before=(p/'before-ram.private.bin').read_bytes();after=(p/'after-ram.private.bin').read_bytes();assert len(before)==len(after)==1048576
 text=(p/'emulator.log').read_text().split('> savebin '+str(p/'before-ram.private.bin'))[0]
 registers={reg:int(value,16) for reg,value in re.findall(r'\b([DA][0-7]) ([0-9A-F]{8})',text)};assert len(registers)==16
 c=MappedExecution(0x100000);c.seed(0,before)
 for k,v in registers.items():(c.cpu.d if k[0]=='D' else c.cpu.a)[int(k[1])]=v
 base=receipt['screen'];c.allow_write(base,32768);c.allow_write(c.cpu.a[7]-256,256)
 c.run(0x3c34e,0x3c53c,12000)
 assert c.read(base,32768)==after[base:base+32768]


def test_original_amiga_cpu_panel_matches_copperline_full_buffer():
 value=os.getenv('SGII_PANEL_DIRECTORY')
 if not value:pytest.skip('set SGII_PANEL_DIRECTORY to private original runtime captures')
 p=Path(value)/'amiga';receipt=json.loads((p/'receipt.private.json').read_text());assert not receipt['host_guest_memory_write']
 before=(p/'before-ram.private.bin').read_bytes();after=(p/'after-ram.private.bin').read_bytes()
 assert len(before)==len(after)==524288
 c=MappedExecution(0x100000);c.seed(0,before)
 for k,v in receipt['registers'].items():
  if re.fullmatch('[da][0-7]',k):(c.cpu.d if k[0]=='d' else c.cpu.a)[int(k[1])]=v
 c.cpu.sr=receipt['registers']['sr'];c.allow_write(0x70000,32768);c.allow_write(c.cpu.a[7]-256,256)
 c.run(0x459c,0x48b0,12000)
 assert c.read(0x70000,32768)==after[0x70000:0x78000]

@pytest.mark.parametrize('platform',['amiga','rgb','mono'])
@pytest.mark.parametrize('empty_kind',['count','pointer'])
def test_empty_contact_sources_are_not_dereferenced(platform,empty_kind):
 c,base=context(platform,[(1,0,0,0)])
 if empty_kind=='count':
  c.seed(APP+0x762,b'\0\0');c.seed(APP+0x6d0,(0xdead0000).to_bytes(4,'big'))
 else:c.seed(APP+0x6d0,bytes(4))
 c.run(0x459c if platform=='amiga' else 0x3c34e,END if platform=='amiga' else 0x3c53c,7000)
 assert c.read(base,32768)==oracle(platform,image(platform),[])


def test_connected_panel_routines_and_bounded_mask_table_are_rendered():
 value=os.getenv('SGII_RETAIL_RENDERED_SOURCE')
 if not value:pytest.skip('set SGII_RETAIL_RENDERED_SOURCE to a fresh export')
 text=Path(value).read_text()
 for name in ['st_monochrome_contact_dot_masks','draw_platform_contact_panel','amiga_draw_fixed_cockpit_contact_panel','st_colour_read_contact_actor_fields','st_monochrome_read_contact_actor_fields']:
  assert name in text,name


def test_verified_actor_contracts_resolve_only_the_three_read_windows():
 value=os.getenv('SGII_RETAIL_RENDERED_SOURCE')
 if not value:pytest.skip('set SGII_RETAIL_RENDERED_SOURCE to a fresh export')
 text=Path(value).read_text()
 for field in ['contact_flags','contact_x','contact_y','contact_z']:
  assert text.count('SG2ContactActorPrefix_'+field+'(a4)')==3
 assert text.count('SG2ContactActorPrefix_kind_colour_index.w(a4)')==3
 evidence=os.getenv('SGII_RETAIL_ANALYSIS')
 if evidence:
  s=json.loads(Path(evidence).read_text())['sections'][0]
  rows=[r for r in s['recovered_platform_typed_accesses'] if r.get('root_struct_name')=='SG2ContactActorPrefix']
  assert len(rows)==15

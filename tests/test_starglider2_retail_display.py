"""Stored and late-ST display phases remain distinct, using original code.

These CPU windows start after the actual shifter-mode read/colour-mode write.
They do not invent interrupt delivery or certify the omitted hardware prefix.
"""
import os
import struct
from functools import cache
from pathlib import Path
import pytest
from amiga_reversing.disasm.mapped_execution import MappedExecution
from amiga_reversing.disasm.game_catalog import load_family,materialize
from amiga_reversing.disasm.c_backend import assemble_platform_source_text_with_c_backend

ROOT=Path(__file__).resolve().parents[1]
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='private hash-bound retail input')
APP,STACK,RETURN=0x61668,0xf0000,0xff000
BRIDGE=0x34b0
SLOTS=(0,6,12,18,24,30,42,48)
TARGETS={'colour':(0x3c29c,0x3c30c,0x3c0ac,0x3c0a2,0x3c23c,0x3c34e,0x4ed0c,0x4f93a),
         'monochrome':(0x3be8c,0x3be8c,0x3c176,0x3c16c,0x3c23c,0x3c34e,0x4ed0c,0x4f93a)}

@cache
def image():
 family=load_family(ROOT,'starglider2');return materialize(ROOT,'starglider2',family['targets']['starglider2_retail']['artifact']).read_bytes()


def setup(mode,seed=0xdeadbeef):
 cpu=MappedExecution(0x100000,register_seed=seed);cpu.seed(0x1000,image());cpu.seed(APP,bytes(0x800))
 cpu.cpu.a[6]=APP;cpu.cpu.a[7]=STACK;cpu.seed(STACK,RETURN.to_bytes(4,'big'));cpu.allow_write(STACK-256,256)
 cpu.cpu.d[0]=2 if mode=='monochrome' else 0
 cpu.allow_write(APP+0x1f2,1);cpu.allow_write(0x7938,8);cpu.allow_write(0x18008,640)
 for offset in SLOTS:cpu.allow_write(BRIDGE+offset+2,4)
 if mode=='monochrome':cpu.allow_write(0x18288,640)
 else:
  cpu.allow_write(0x54dc8,32);cpu.allow_write(0x57f00,32)
 stop=0x3bd9c if mode=='monochrome' else 0x3bd4e
 trace=cpu.run(0x3bc44,stop,5000)
 return cpu,trace


@pytest.mark.parametrize('mode',TARGETS)
@pytest.mark.parametrize('seed',[0,0xdeadbeef])
def test_late_st_setup_selects_complete_display_jumps_without_rewriting_stored_image(mode,seed):
 cpu,trace=setup(mode,seed);expected=TARGETS[mode]
 encoded,_=assemble_platform_source_text_with_c_backend('atari-st-raw','section code,code\n'+''.join(f'jmp ${target:x}.l\n' for target in expected),target_cpu='68000')
 actual=b''.join(cpu.read(BRIDGE+slot,6) for slot in SLOTS);assert actual==encoded
 raw=image();assert cpu.read(BRIDGE+36,6)==raw[BRIDGE+36-4096:BRIDGE+42-4096]  # untouched seventh slot
 assert cpu.read(APP+0x1f2,1)==(b'\xff' if mode=='monochrome' else b'\0')
 assert trace['stop_pc']==(0x3bd9c if mode=='monochrome' else 0x3bd4e)


@pytest.mark.parametrize('mode',TARGETS)
def test_st_pixel_lookup_tables_and_panel_pointers_have_exact_bounded_extents(mode):
 cpu,_=setup(mode);raw=image()
 expected=[(x//8)*2 if mode=='monochrome' else (x//16)*8 for x in range(320)]
 assert cpu.read(0x18008,640)==struct.pack('>320H',*expected)
 assert cpu.read(0x7938,8)==struct.pack('>II',*( (0x6efec,0x6efe8) if mode=='monochrome' else (0x6ef58,0x6ef50)))
 if mode=='monochrome':assert cpu.read(0x18288,640)==struct.pack('>320H',*(0x8000>>(2*(x%8)) for x in range(320)))
 else:assert cpu.read(0x18288,640)==raw[0x18288-4096:0x18508-4096]
 assert cpu.read(0x18006,2)==raw[0x18006-4096:0x18008-4096]
 assert cpu.read(0x18508,2)==raw[0x18508-4096:0x1850a-4096]


def test_st_colour_converts_both_palettes_then_marks_cockpit_for_predecode_callback():
 cpu,_=setup('colour');raw=image()
 for address in (0x54dc8,0x57f00):
  old=struct.unpack('>16H',raw[address-4096:address-4096+32]);expected=[(x>>1)&0x777 for x in old]
  if address==0x54dc8:expected[0]=1
  assert cpu.read(address,32)==struct.pack('>16H',*expected)
  assert cpu.read(address+32,4)==raw[address-4096+32:address-4096+36]


def test_st_monochrome_setup_does_not_claim_or_perform_colour_palette_conversion():
 cpu,_=setup('monochrome');raw=image()
 for address in (0x54dc8,0x57f00):assert cpu.read(address,32)==raw[address-4096:address-4096+32]


def test_marked_picture_routes_through_callback_then_rejoins_decode_setup():
 # The marker requests a preparation callback; it does not skip decoding.
 # Stop before the callback and test its suffix conditional on a normal return.
 cpu=MappedExecution(0x100000,register_seed=0xdeadbeef);cpu.seed(0x1000,image())
 cpu.cpu.a[0]=0xd0000;cpu.seed(0xd0000,b'\0\1');cpu.cpu.a[7]=STACK
 cpu.seed(STACK,RETURN.to_bytes(4,'big'));cpu.allow_write(STACK-4,4)
 cpu.run(0x3a5c,0x365a,10)
 assert cpu.cpu.a[7]==STACK-4 and cpu.read(STACK-4,4)==(0xd0000).to_bytes(4,'big')
 # $365A calls the separate preparation callback. Its implementation is not
 # executed or stubbed by this local window.
 cpu.allow_write(0xd0000,2);cpu.run(0x365e,0x3a64,10)
 assert cpu.cpu.a[0]==0xd0000 and cpu.read(0xd0000,2)==b'\0\0'
 assert cpu.cpu.a[7]==STACK-4


@cache
def amiga_image():
 family=load_family(ROOT,'starglider2');return materialize(ROOT,'starglider2',family['targets']['starglider2_retail_amiga']['artifact']).read_bytes()


def amiga_context():
 # Model the custom-register aperture as writable storage only. This proves
 # CPU values/widths, not chipset side effects or bus/DMA timing.
 cpu=MappedExecution(0xe00000,register_seed=0xdeadbeef);cpu.seed(0x1000,amiga_image())
 cpu.seed(0x69668,bytes(0x800));cpu.cpu.a[6]=0x69668;cpu.cpu.a[7]=STACK
 cpu.seed(STACK,RETURN.to_bytes(4,'big'));cpu.allow_write(STACK-256,256)
 return cpu


@pytest.mark.parametrize('direction',['in','out'])
def test_amiga_fade_steps_each_rgb4_channel_and_writes_sixteen_words_per_stage(direction):
 cpu=amiga_context();work,hardware,source=0x39c8,0xdff180,0xd0000
 colours=[0,0xfff,0x123,0xf00,0x0f0,0x00f,0xabc,0x789,0x555,0x246,0x135,0xfed,0x810,0x108,0x080,0x001]
 cpu.seed(source,struct.pack('>16H',*colours));cpu.cpu.a[1]=source
 cpu.seed(hardware,b'\xa5'*32);cpu.allow_write(hardware,32);cpu.allow_write(work,32);cpu.allow_write(0x69668+0x60,8)
 if direction=='out':cpu.seed(work,struct.pack('>16H',*colours))
 start,end=(0x3952,0x39be) if direction=='in' else (0x3a14,0x3a56)
 for stage in range(1,17):
  cpu.run(start,0x38c2,2000)
  # Explicit modeled external tick after the wait routine sampled the old
  # counter. The real RNG/wait instructions still run; no IRQ is claimed.
  tick=((cpu.cpu.d[0]&65535)+1)&65535;cpu.seed(0x69668+0x17c,tick.to_bytes(2,'big'))
  cpu.run(0x38c2,end,7000)
  expected=[]
  for colour in colours:
   parts=[(colour>>shift)&15 for shift in (8,4,0)]
   if direction=='in':parts=[min(channel,stage) for channel in parts]
   else:parts=[max(0,channel-stage) for channel in parts]
   expected.append((parts[0]<<8)|(parts[1]<<4)|parts[2])
  expected=struct.pack('>16H',*expected)
  assert cpu.read(work,32)==expected and cpu.read(hardware,32)==expected
  assert cpu.read(source,32)==struct.pack('>16H',*colours)
  start=end
 cpu.run(start,RETURN,12);assert cpu.cpu.a[7]==STACK+4


@pytest.mark.parametrize('index',[0,4,8])
def test_amiga_buffer_cycle_uses_three_pointer_tables_and_separate_draw_display_roles(index):
 cpu=amiga_context();app=0x69668;cpu.seed(app+0x207,bytes([index]));cpu.allow_write(app+0x207,1)
 cpu.allow_write(app,8);cpu.seed(0xdff080,bytes(4));cpu.allow_write(0xdff080,4)
 raw=amiga_image();tables=[raw[address-4096+index:address-4096+index+4] for address in (0x392e,0x393a,0x3946)]
 cpu.run(0x38fa,RETURN,40)
 assert cpu.read(0xdff080,4)==tables[0] and cpu.read(app+4,4)==tables[1] and cpu.read(app,4)==tables[2]
 assert cpu.read(app+0x207,1)==bytes([(index+4)%12])
 # The CPU store to COP1LC does not establish when Copper execution switches.


def test_amiga_frame_service_counts_and_rotates_without_claiming_a_vblank_wait():
 cpu=amiga_context();app=0x69668;cpu.seed(app+0x207,b'\0');cpu.seed(app+0x756,b'\xff\xff');cpu.seed(app+0x162,b'\x7f\xff')
 for at,n in ((app,8),(app+0x207,1),(app+0x756,2),(app+0x162,2),(0xdff080,4)):cpu.allow_write(at,n)
 cpu.run(0x34e8,RETURN,70)
 assert cpu.read(app+0x756,2)==b'\0\0' and cpu.read(app+0x162,2)==b'\x80\0'
 assert cpu.read(app+0x207,1)==b'\x04'


def test_reviewed_display_contract_names_are_present_in_native_rendering():
 source=Path(os.environ['SGII_RETAIL_RENDERED_SOURCE']).read_text()
 for name in ('st_install_display_mode','st_colour_fade_in_palette',
              'st_monochrome_palette_noop','st_reset_psg_mixer_and_sound_state',
              'amiga_rotate_display_buffers','amiga_fade_work_palette_rgb4',
              'screen_x_byte_offsets','st_shifter_base_register_cycle',
              'prepare_marked_picture_then_decode'):
  assert name+':' in source,name

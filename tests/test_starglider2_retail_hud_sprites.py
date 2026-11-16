"""Retail HUD source ownership and ST conversion, using original instructions.

The mutable source directory, converted monochrome packets and fixed overlay
readers are distinct contracts. CPU/RAM evidence does not prove sprite DMA,
physical scanout or exclusion of later sound-buffer reuse.
"""
import os,struct
import pytest
from amiga_reversing.disasm.mapped_execution import MappedExecution
from test_starglider2_retail_input import program
from tests.test_starglider2_text_editor import original_image,state,run,put,get,APP as OLD_APP,FB
from test_starglider2_retail_scene_raster import machine
from tests.test_starglider2_overlay import draw_reference,SPRITES
from tests.test_starglider2_heading_strip import BEGIN,END as DRAW_END
from tests.test_starglider2_alternate_meters import interleave
from test_starglider2_retail_display import setup,STACK,RETURN
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail input')
DIR,MODES,SCANS,FIRST,LAST,END=0x2f790,0x2f838,0x2f860,0x2f87c,0x3029c,0x30524
OUTPUT,ENTRY,ROW,EXIT=0x5b8d8,0x3bdee,0x3be12,0x3be8c

def source():
 raw=program('st')[0]
 def read(p,n):return raw[p-4096:p-4096+n]
 pointers=struct.unpack('>41I',read(DIR,164));modes=read(MODES,40)
 assert pointers[0]==FIRST and pointers[-1]==LAST
 assert read(DIR+164,4)==b'\xff'*4
 assert all(b>a and (b-a)%4==0 for a,b in zip(pointers,pointers[1:]))
 assert sum((b-a)//4 for a,b in zip(pointers,pointers[1:]))==648
 return raw,read,pointers,modes

def converted_reference():
 raw,read,pointers,modes=source();out=bytearray();directory=[]
 for start,end,mode in zip(pointers,pointers[1:],modes):
  directory.append(OUTPUT+len(out))
  # DBF includes one row after the apparent payload, in the next header.
  for at in range(start+4,end+4,4):
   first,other=struct.unpack('>HH',read(at,4));keep=~(first|other)&65535
   words=(first&other,0,first&~other,0)if mode&128 else(first,other,0,0)if mode else(first&~other,0,0,first)
   out.extend(struct.pack('>III',interleave(keep,keep),interleave(*words[:2]),interleave(*words[2:])))
 directory.append(OUTPUT+len(out));assert len(out)==7776
 return bytes(out),struct.pack('>41I',*directory)

def conversion(source_short=0,output_short=0):
 raw,read,pointers,modes=source();cpu=MappedExecution(0x100000,register_seed=0xdeadbeef)
 cpu.seed(ENTRY,read(ENTRY,EXIT+4-ENTRY));cpu.seed(DIR,read(DIR,168));cpu.allow_write(DIR,164);cpu.seed(MODES,modes)
 cpu.seed(FIRST+4,read(FIRST+4,LAST-FIRST-source_short))
 cpu.seed(OUTPUT-4,b'\xa5'*7784);cpu.allow_write(OUTPUT,7776-output_short)
 cpu.seed(STACK-64,bytes(68));cpu.allow_write(STACK-64,64);cpu.seed(STACK,RETURN.to_bytes(4,'big'));cpu.cpu.a[7]=STACK
 return cpu

def test_complete_original_converter_rewrites_41_pointers_and_exactly_648_twelve_byte_rows():
 expected,directory=converted_reference();cpu=conversion();cpu.run(ENTRY,RETURN,500000)
 assert cpu.read(OUTPUT,7776)==expected and cpu.read(DIR,168)==directory+b'\xff'*4
 assert cpu.read(OUTPUT-4,4)==cpu.read(OUTPUT+7776,4)==b'\xa5'*4
 assert cpu.cpu.a[1]==OUTPUT+7776 and cpu.cpu.a[7]==STACK+4
 with pytest.raises(ValueError,match='unknown bytes'):cpu.read(FIRST,4)

@pytest.mark.parametrize('source_short,output_short,message',[(1,0,'unknown read/fetch'),(0,1,'forbidden write')])
def test_converter_boundaries_are_required_not_guessed_image_heights(source_short,output_short,message):
 cpu=conversion(source_short,output_short)
 with pytest.raises(ValueError,match=message):cpu.run(ENTRY,RETURN,500000)

def test_a_second_conversion_is_not_idempotent_or_covered_by_the_one_pass_output_bound():
 cpu=conversion();cpu.run(ENTRY,RETURN,500000);cpu.cpu.a[7]=STACK
 with pytest.raises(ValueError,match='forbidden write'):cpu.run(ENTRY,RETURN,1000000)

@pytest.mark.parametrize('mode',('colour','monochrome'))
def test_actual_late_st_setup_converts_directory_only_in_monochrome(mode):
 cpu,trace=setup(mode);raw,read,pointers,modes=source()
 if mode=='monochrome':
  cpu.allow_write(0x50426,18848);cpu.allow_write(DIR,164);cpu.allow_write(OUTPUT,7776)
 cpu.run(trace['stop_pc'],RETURN,2000000)
 expected,directory=converted_reference()
 assert cpu.read(DIR,168)==(directory+b'\xff'*4 if mode=='monochrome'else read(DIR,168))
 assert cpu.read(FIRST,END-FIRST)==read(FIRST,END-FIRST)
 if mode=='monochrome':assert cpu.read(OUTPUT,7776)==expected
 else:assert cpu.read(OUTPUT,7776)==read(OUTPUT,7776)


def test_source_directories_and_bank_reuse_only_byte_qualified_earlier_asset_analysis(original_image):
 raw,read,pointers,modes=source();old=original_image[0]
 def previous(p,n):return old[p-4096:p-4096+n]
 assert pointers==tuple(p+0x18c0 for p in struct.unpack('>41I',previous(0x2ded0,164)))
 assert modes==previous(0x2df78,40)
 scans=struct.unpack('>7I',read(SCANS,28));assert scans==tuple(p+0x18c0 for p in struct.unpack('>7I',previous(0x2dfa0,28)))
 assert read(FIRST,END-FIRST)==previous(0x2dfbc,3240)
 assert sorted((*scans,LAST,0x304dc))==list(range(LAST,END,72))
 # Slot 9 is a software icon with zero prefix words, not a DMA sprite bound.
 assert pointers[10]-pointers[9]==60 and read(pointers[9],4)==bytes(4)

@pytest.mark.parametrize('mode',(0,255))
@pytest.mark.parametrize('name',sorted(SPRITES))
def test_nine_original_overlay_sources_keep_the_fixed_sixteen_row_software_contract(mode,name):
 platform,m,v=machine('mono'if mode else'colour');put(m,OLD_APP,FB);m[OLD_APP+0x1f2]=mode
 m[BEGIN:DRAW_END]=b'\xa5'*(DRAW_END-BEGIN);source=SPRITES[name]+0x18c0+4
 c=state(m,0x3be8e);c.a[0]=source;c.d[1]=167;c.d[2]=81
 expected=draw_reference(m,m[BEGIN:DRAW_END],source,167,81,mode);before=bytes(m[source-4:source+68])
 run(program(platform),m,c,{0xffffff00})
 assert bytes(m[BEGIN:DRAW_END])==expected and c.a[0]==source+64
 assert bytes(m[source-4:source+68])==before

@pytest.mark.parametrize('reserve',(0,2048,6144,8192,10240,32768))
def test_amiga_power_meter_selects_directory_or_updates_real_sprite_control_prefix(reserve):
 raw=program('amiga')[0];cpu=MappedExecution(0x1000000);start,stop=0xd47a,0xd4cc
 cpu.seed(start,raw[start-4096:stop+2-4096]);cpu.seed(DIR,raw[DIR-4096:MODES-4096]);cpu.seed(FIRST,raw[FIRST-4096:END-4096])
 app=0x90000;cpu.cpu.a[6]=app;cpu.seed(app+0x774,reserve.to_bytes(2,'big'))
 for at in(FIRST,0x2f938):cpu.allow_write(at,2)
 cpu.allow_write(0xdff134,4);cpu.run(start,stop,100)
 level=(reserve>>11)+((reserve>>11)>>1)
 if level<=5:expected=int.from_bytes(raw[0x2f7b8-4096+4*level:0x2f7b8-4096+4*level+4],'big')
 else:
  expected=0x2f938 if level&1 else FIRST
  assert cpu.read(expected,2)==((((220-level)<<8)|0x70)&65535).to_bytes(2,'big')
  assert cpu.read(expected+2,2)==raw[expected+2-4096:expected+4-4096]
 assert cpu.read(0xdff134,4)==expected.to_bytes(4,'big')

@pytest.mark.parametrize('mode',(0,128))
def test_five_original_meter_backgrounds_capture_56_rows_with_profile_specific_column_spacing(mode):
 raw=program('st')[0];cpu=MappedExecution(0x100000);cpu.seed(4096,raw);cpu.seed(0x68000,bytes((i*37+19)&255 for i in range(0xa000)))
 cpu.seed(0x90000+0x1f2,bytes([mode]));cpu.cpu.a[6]=0x90000;cpu.seed(STACK,RETURN.to_bytes(4,'big'));cpu.cpu.a[7]=STACK
 background=0x3d840;cpu.allow_write(background,2240)
 cleared=(0x3cae4,0x3cae6,0x3cae8,0x3caea,0x3c8ee,0x3c7b0,0x3c826,0x3c89a,0x3c990,0x3caee)
 for old in(*cleared,0x3caec,0x3caf0):cpu.allow_write(old+0x19ac,2)
 pointers=struct.unpack('>5I',cpu.read(0x3d7f0,20));assert pointers==tuple(background+448*i for i in range(5))
 positions=struct.unpack('>5I',cpu.read((0x3be6c if mode else 0x3be58)+0x19ac,20));expected=bytearray()
 for offset in positions:
  for row in range(56):
   for column in(0,80 if mode else 4):expected.extend(cpu.read(0x68000+offset+row*160+column,4))
 before=(cpu.read(background-4,4),cpu.read(background+2240,4));cpu.run(0x3d75e,RETURN,10000)
 assert cpu.read(background,2240)==expected
 assert(cpu.read(background-4,4),cpu.read(background+2240,4))==before
 assert all(cpu.read(old+0x19ac,2)==bytes(2)for old in cleared)
 assert cpu.read(0x3e498,2)==b'\0\x0a' and cpu.read(0x3e49c,2)==b'\0\x14'


def test_committed_hud_entries_render_as_code_and_phase_types_are_used():
 from pathlib import Path
 path=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered/retail-shared.s';text=path.read_text()
 for name,first in(('update_amiga_hud_sprites','lea.l'),('update_amiga_power_meter','move.w'),('capture_alternate_meter_backgrounds','clr.w'),('convert_st_monochrome_hud_source_directory','lea.l')):
  block=text.split(name+':\n',1)[1];assert block.lstrip().startswith(first),(name,block[:100])
 # Exact reassembly alone would also accept incorrectly retained data bytes.
 for name in('SG2HUDHardwareControlWords_vertical_start_and_horizontal','SG2STMonoHUDRow_destination_keep_bits','SG2STHUDSavedRow_first_column_longs'):
  assert text.count(name)>1,name

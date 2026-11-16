"""Retail coordinate lookup and shared glyph consumers with bounded CPU states.

Independent pixel expectations cover each layout. These are not boot, live
cursor/font ownership, physical scanout or arbitrary-character safety claims.
"""
import ctypes,os
import pytest
from tests.test_starglider2_text_editor import state,run,put,get,APP,FB,INPUT,STACK,RETURN
from test_starglider2_retail_input import program
from tests.test_starglider2_interleaved_color_kernels import kernels as earlier_image
from tests.test_starglider2_alternate_text import expanded
from amiga_reversing.disasm.mapped_execution import MappedExecution
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
LOOKUP,FONT,NUMERIC=0x18508,0x18620,0x186a0
COL,ROW,DEST,INVERSE,COLOUR,STEP=0xdec3,0xdec4,0xdeca,0xdeba,0xdfcc,0xdff4


def memory(platform):
 raw=program(platform)[0];m=(ctypes.c_uint8*0xa1000)();ctypes.memmove(ctypes.addressof(m)+4096,raw,len(raw));return m


def test_coordinate_lookup_is_packed_bcd_with_original_terminal_zeros(earlier_image):
 old=earlier_image[0];raw=program('st')[0];table=raw[LOOKUP-4096:LOOKUP-4096+256]
 assert table==old[0x16c60-4096:0x16d60-4096]
 assert all(v>>4<=9 and v&15<=9 for v in table)
 decoded=[10*(v>>4)+(v&15)for v in table]
 assert decoded[:254]==sorted(decoded[:254])
 assert all(abs(v-min(99,2*i//5))<=1 for i,v in enumerate(decoded[:254]))
 assert [decoded[i]for i in(0,3,25,128,249,253,254,255)]==[0,1,10,51,99,99,0,0]


@pytest.mark.parametrize('platform',('amiga','st'))
@pytest.mark.parametrize('x,z',((0,0),(3,25),(128,249),(253,254),(254,255)))
def test_actual_hud_lookup_packs_two_bytes_without_replacing_terminal_values(platform,x,z):
 m=memory(platform);put(m,APP+0x704,x<<16);put(m,APP+0x70c,z<<16)
 c=state(m,0x4560);c.d[3]=16;run(program(platform),m,c,{0x4584})
 assert c.d[0]&65535==m[LOOKUP+x]<<8|m[LOOKUP+z]


@pytest.mark.parametrize('profile,char,inverse,mask',[(p,c,i,k)for p in('amiga','colour','mono')for c,i,k in((32,False,5),(65,False,15),(126,True,5))])
def test_glyph_pixels_cursor_and_font_restoration(profile,char,inverse,mask):
 platform='amiga'if profile=='amiga'else'st';m=memory(platform)
 put(m,0x27be,APP);put(m,APP,FB+0x8000);put(m,APP+4,FB);put(m,4,FB+0x4000)
 put(m,0xcc52,27406,2);put(m,0xcc4c,12345,2);put(m,DEST,FB);m[COL]=m[ROW]=m[INVERSE]=0;m[COLOUR]=6
 m[FB:FB+0x8000]=b'\xa5'*0x8000;before=bytes(m[FB:FB+0x8000]);font=bytes(m[FONT:FONT+768])
 text=bytes([0x80|mask,1 if inverse else 2,char,0]);m[INPUT:INPUT+len(text)]=text
 entry={'amiga':0xdca0,'colour':0x3d374,'mono':0x3d164}[profile]
 c=state(m,entry);c.a[1]=INPUT;run(program(platform),m,c,{RETURN})
 expected=bytearray(before);glyph=font[8*(char-32):8*(char-31)]
 for row,value in enumerate(glyph):
  if inverse:value^=255
  if profile=='mono':
   for extra in(0,80):expected[160*row+extra:160*row+extra+2]=expanded(value)
  else:
   for plane in range(4):expected[(40*row+0x2000*plane)if profile=='amiga'else(160*row+2*plane)]=value if mask>>plane&1 else 0
 assert bytes(m[FB:FB+0x8000])==expected and bytes(m[FONT:FONT+768])==font
 assert m[COL]==1 and m[ROW]==0 and get(m,DEST)==FB+(2 if profile=='mono'else 1)
 assert m[INVERSE]==(255 if inverse else 0)and m[COLOUR]==(6 if profile=='mono'else mask)
 assert c.a[7]==STACK+4


@pytest.mark.parametrize('profile,word',[(p,w)for p in('amiga','colour','mono')for w in(0,0x1234,0x9999,0xabcd)])
def test_coordinate_nibble_alias_uses_original_glyphs_and_profile_geometry(profile,word):
 platform='amiga'if profile=='amiga'else'st';m=memory(platform);m[FB-0x8000:FB+0x10000]=b'\xa5'*0x18000
 before=bytearray(m);entry={'amiga':0xd706,'colour':0x3e8ce,'mono':0x3ef28}[profile]
 anchors={'amiga':(0x7007e,),'colour':(0x68298,0x70298,0x78298),'mono':(0x681ec,0x701ec,0x781ec)}[profile]
 for digit,shift in enumerate((12,8,4,0)):
  glyph=m[NUMERIC+8*((word>>shift)&15):NUMERIC+8*(((word>>shift)&15)+1)]
  for anchor in anchors:
   for row,value in enumerate(glyph):
    if profile=='amiga':
     for plane in((2,3)if digit<2 else(3,)):before[anchor+0x2000*plane+40*row+digit]=value
    elif profile=='colour':
     for plane in((4,6)if digit<2 else(6,)):before[anchor+160*row+(digit if digit<2 else digit+6)+plane]=value
    else:
     for extra in(0,80):before[anchor+160*row+extra+2*digit:anchor+160*row+extra+2*digit+2]=expanded(value)
 c=state(m,entry);c.d[0]=0xbeef0000|word;run(program(platform),m,c,{RETURN})
 assert bytes(m[FB-0x8000:FB+0x10000])==before[FB-0x8000:FB+0x10000]
 assert c.d[0]==0xbeef0000|word and c.a[7]==STACK+4


def test_complete_font_is_one_stored_owner_and_nibble_view_is_an_alias(earlier_image):
 old=earlier_image[0];raw=program('st')[0]
 assert raw[FONT-4096:FONT-4096+760]==old[0x16d60-4096:0x17058-4096]
 assert NUMERIC==FONT+8*(ord('0')-32)
 assert raw[NUMERIC-4096+8*10:NUMERIC-4096+8*16]==raw[FONT-4096+8*(ord(':')-32):FONT-4096+8*(ord('@')-32)]


@pytest.mark.parametrize('mismatch', (None,1,21))
def test_st_buffer_probe_compares_only_twenty_two_bytes_after_a1_run(mismatch):
 raw=program('st')[0];pattern=raw[0x18608-4096:0x18608-4096+22]
 candidate=bytearray(pattern)
 if mismatch is not None:candidate[mismatch]^=1
 c=MappedExecution(0x100000);c.seed(0x3ca12,raw[0x3ca12-4096:0x3ca36-4096]);c.seed(0x18608,pattern)
 c.seed(0x78000,b'\0\x99\xa1\xa1'+candidate);c.seed(STACK,(0xff000).to_bytes(4,'big'));c.cpu.a[7]=STACK
 c.run(0x3ca12,0xff000,200)
 compared=22 if mismatch is None else mismatch+1
 assert c.cpu.a[1]==0x18608+compared and c.cpu.a[0]==0x78004+compared
 assert bool(c.cpu.sr&4)==(mismatch is None)

@pytest.mark.parametrize('platform,signature',[(p,s)for p in('amiga','st')for s in(0,27406)])
def test_retail_positioned_text_guard_retains_its_cursor_fallback(platform,signature):
 m=memory(platform);put(m,0xcc52,signature,2);c=state(m,0xdbe4)
 run(program(platform),m,c,{0xdbf0,0xdca0})
 assert c.pc==(0xdbf0 if signature==27406 else 0xdca0)and c.a[7]==STACK


@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_font_owner_alias_and_consumer_symbols(tmp_path):
 import struct,subprocess
 from pathlib import Path
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered';source=(directory/'retail-shared.s').read_text()
 symbols={'coordinate_byte_to_bcd_digits':LOOKUP,'font_printable_ascii_rows':FONT,'font_numeric_nibble_glyph_view':NUMERIC,'text_cursor_framebuffer_pointer':DEST,'text_colour_mask':COLOUR,'draw_amiga_coordinate_digits':0xd706,'print_planar_text_at_cursor':0xdca0,'print_alternate_cursor_text_mode0':0x3d374,'print_alternate_cursor_text_mode1':0x3d164,'st_compare_buffer_prefix_after_a1_run':0x3ca12,'st_buffer_probe_comparison_bytes':0x18608}
 assert 'lea.l font_printable_ascii_rows.l,a2'in source and 'lea.l font_numeric_nibble_glyph_view.l,a2'in source
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert r.returncode==0,r.stdout+r.stderr
 raw=out.read_bytes();size=4*len(symbols)
 assert raw[:-size]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-size:])==tuple(symbols.values())

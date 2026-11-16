"""Amiga cockpit Copper storage and original CPU patch/install windows.

Registers are mapped storage, not custom-chip behavior. These tests establish
list contents and CPU changes, not beam timing, DMA or complete scanout.
"""
import os,struct
from pathlib import Path
import pytest
from test_starglider2_retail_display import amiga_context,amiga_image,STACK,RETURN
from tests.test_starglider2_text_editor import get
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
LISTS=((0xcef8,0xcf20,0xcfd4),(0xcfd4,0xcffc,0xd0b0),(0xd0b0,0xd0d8,0xd14c))
EFFECTS=(0xcf58,0xd034,0xd0f0)

@pytest.mark.parametrize('start,gate,end',LISTS)
def test_complete_lists_keep_early_gate_lower_cockpit_block_and_final_end(start,gate,end):
 raw=amiga_image();at=lambda pc:pc-4096
 pairs=list(struct.iter_unpack('>HH',raw[at(start):at(end)]))
 assert pairs[:2]==[(0x8e,0x2c81),(0x90,0xf4c1)]
 assert pairs[(gate-start)//4]==(0xffff,0xfffe) and pairs[-1]==(0xffff,0xfffe)
 # Every other command is a legal even custom register MOVE, except the
 # explicit lower-block WAIT. No zero padding is silently called a command.
 assert all(reg&1==0 and reg<=0x1fe or(reg,value)in((0xffff,0xfffe),(0xae01,0xff00))for reg,value in pairs)
 assert pairs.count((0xae01,0xff00))==1
 assert pairs.count((0x19e,0))==1 and pairs.count((0x19e,0xfff))==1
 if start!=0xd0b0:
  def pointer(off):return (get(raw,at(off)+2,2)<<16)|get(raw,at(off)+6,2)
  assert [pointer(start+8+8*i)for i in range(4)]==[0x70000+0x2000*i for i in range(4)]
  base=0x78000 if start==0xcef8 else 0x79000
  assert [pointer(gate+4+8*i)for i in range(4)]==[base+0x2000*i for i in range(4)]
  lower=next(i for i,pair in enumerate(pairs)if pair==(0xae01,0xff00))+1
  assert pairs[lower:lower+8]==[(reg,value)for i in range(4)for reg,value in ((0xe0+4*i,7),(0xe2+4*i,0x1450+0x2000*i))]
 else:
  assert not any(0xe0<=reg<=0xee for reg,value in pairs[(gate-start)//4+1:])


def test_real_enable_rotation_disable_rotation_keeps_all_other_list_bytes():
 c=amiga_context();app=0x69668;raw=amiga_image();before=c.read(0xcef8,0xd14c-0xcef8)
 for start,gate,end in LISTS:c.allow_write(gate,4)
 for at,n in ((app,8),(app+0x207,1),(0xdff080,4)):c.allow_write(at,n)
 c.seed(0xdff080,bytes(4));c.seed(app+0x207,b'\0')
 c.run(0x21b6,0x21d4,3)
 expected=bytearray(before)
 for start,gate,end in LISTS:expected[gate-0xcef8:gate-0xcef8+4]=bytes.fromhex('4a01ff00')
 assert c.read(0xcef8,len(before))==expected
 c.run(0x38fa,RETURN,40);assert get(c.memory,0xdff080)==0xd0b0 and c.memory[app+0x207]==4
 c.cpu.a[7]=STACK;c.seed(STACK,RETURN.to_bytes(4,'big'));c.run(0x26fa,0x2718,3)
 assert c.read(0xcef8,len(before))==before
 c.run(0x38fa,RETURN,40);assert get(c.memory,0xdff080)==0xcef8 and c.memory[app+0x207]==8
 assert c.read(0xcef8,len(before))==before

@pytest.mark.parametrize('start,stop,target,writes',((0xcce2,0xccfc,0xcef8,3),(0xcd98,0xcdb2,0xd0b0,3)))
def test_boot_install_writes_pointer_strobes_copjmp_read_and_sets_dma_window(start,stop,target,writes):
 c=amiga_context();app=0x69668;c.cpu.a[5]=0xdff000
 c.seed(0xdff080,b'\xa5'*4);c.seed(0xdff088,b'\x12\x34');c.seed(0xdff096,b'\xa5'*2)
 c.allow_write(0xdff080,4);c.allow_write(0xdff096,2);c.allow_write(app+0x207,1)
 trace=c.run(start,stop,12)
 assert c.read(0xdff080,4)==target.to_bytes(4,'big') and c.read(0xdff088,2)==b'\x12\x34'
 assert c.read(0xdff096,2)==(b'\0\x40'if start==0xcce2 else b'\x81\xe0') and trace['writes']==writes
 if start==0xcd98:assert c.memory[app+0x207]==4


def test_palette_service_changes_only_the_three_colour15_value_slots():
 from test_starglider2_retail_sound import machine,trace
 from tests import test_starglider2_palette_priority as palette
 m,view=machine('amiga');palette.prepare(view);view[palette.FADE]=64
 before=bytes(m[0xcef8:0xd14c]);trace('amiga',m,0x4c78e,0x4cac0)
 expected=bytearray(before)
 for at in EFFECTS:
  assert get(m,at+12,2)==0x19e
  expected[at+14-0xcef8:at+16-0xcef8]=(7).to_bytes(2,'big')
 assert bytes(m[0xcef8:0xd14c])==expected

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_copper_owners_and_symbolic_cycle(tmp_path):
 import subprocess
 from test_starglider2_retail_input import program
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered';source=(directory/'retail-shared.s').read_text()
 symbols={**{f'amiga_rotating_copper_list_{letter}':start for letter,(start,gate,end)in zip('abc',LISTS)},**{f'amiga_copper_list_{letter}_mode_gate':gate for letter,(start,gate,end)in zip('abc',LISTS)},**{f'amiga_copper_list_{letter}_colour15_value':at+14 for letter,at in zip('abc',EFFECTS)},'disable_midframe_copper_blocks_continuation':0x26fa,'install_boot_amiga_copper_list_a':0xcce2,'install_boot_amiga_copper_list_c':0xcd98}
 block=source.split('amiga_copper_pointer_cycle:',1)[1].split('amiga_display_pointer_cycle:',1)[0]
 assert block.count('dc.l amiga_rotating_copper_list_')==3 and '$0000'not in block,block
 block=source.split('amiga_rotating_copper_list_a:',1)[1].split('amiga_rotating_copper_list_b:',1)[0]
 assert 'dc.w'in block and 'dc.b'not in block
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert r.returncode==0,r.stdout+r.stderr
 data=out.read_bytes();n=4*len(symbols);assert data[:-n]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',data[-n:])==tuple(symbols.values())

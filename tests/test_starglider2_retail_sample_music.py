"""Original ST sample interrupt and shared music-ring CPU/RAM contracts.

Strict mapped slices qualify read bounds. Existing sparse logical RAM supports
full high-address port writes and self-modified instruction fetch. Neither is
hardware timing, automatic interrupt delivery, analogue sound, disk I/O or proof
that other workspace users cannot overlap music playback.
"""
import os,struct
import pytest
from amiga_reversing.disasm.mapped_execution import MappedExecution
from test_starglider2_retail_input import program,memory,state
from tests.test_starglider2_text_editor import original_image,put,get
from tests.test_starglider2_hud_coordinates import run_ram
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail input')
INIT,RING,READ,BLOCKS=0x102f8,0x10544,0x10608,0x1060c
INSTALL,ISR,OPERAND,TABLE,LEFT,NEXT=0x11854,0x118dc,0x118e4,0x11926,0x12126,0x1212a
BLOCK_BYTES,SAMPLE,STACK,RETURN=0x12620,0x80000,0xf0000,0xff000
PSG,MFP,PALETTE=0xffff8800,0xfffffa00,0xffff8240

def long(c,p,n):c.seed(p,(n&0xffffffff).to_bytes(4,'big'))
def word(c,p,n):c.seed(p,(n&65535).to_bytes(2,'big'))
def integer(c,p,n=4):return int.from_bytes(c.read(p,n),'big')

def bounded():
 raw=program('st')[0];c=MappedExecution(0x100000,register_seed=0x12345678)
 for lo,hi in((INIT,0x10310),(ISR,TABLE),(NEXT,0x12178)):c.seed(lo,raw[lo-4096:hi-4096])
 # Six read bytes per eight-byte row; the two tail bytes stay unknown.
 for row in range(256):c.seed(TABLE+8*row,raw[TABLE-4096+8*row:TABLE-4096+8*row+6])
 c.seed(RING,raw[RING-4096:RING-4096+28]);c.allow_write(RING,28)
 for p,n in((READ,2),(BLOCKS,2),(OPERAND,4),(LEFT,4),(BLOCK_BYTES,4)):c.allow_write(p,n)
 word(c,READ,0);word(c,BLOCKS,2);long(c,LEFT,2);long(c,BLOCK_BYTES,5632);long(c,OPERAND,SAMPLE);c.seed(SAMPLE,b'\0')
 c.seed(STACK-32,bytes(38));c.allow_write(STACK-32,32);c.cpu.a[7]=STACK;long(c,STACK,RETURN);c.run(INIT,0x1030e,100)
 assert c.read(RING,28)==struct.pack('>7I',*(0x431f4+5632*i for i in range(7)))
 return c

def sparse():
 m=memory('st');c=state(m,INIT);run_ram(program('st'),m,c,{0x1030e})
 assert[get(m,RING+4*i)for i in range(7)]==[0x431f4+5632*i for i in range(7)]
 put(m,OPERAND,SAMPLE);put(m,LEFT,2);put(m,BLOCK_BYTES,5632);put(m,READ,0,2);put(m,BLOCKS,2,2)
 m[MFP+25]=0x55;put(m,PALETTE,0xa55a,2);return m

def interrupt(m,observe=None):
 c=state(m,ISR);put(m,STACK,0x2304,2);put(m,STACK+2,RETURN);d,a=list(c.d),list(c.a)
 run_ram(program('st'),m,c,{RETURN},observe=observe,limit=100)
 assert list(c.d)==d and list(c.a[:7])==a[:7] and c.a[7]==STACK+6 and c.sr==0x2304
 return c


def test_all_256_bytes_select_only_six_bytes_from_each_eight_byte_packet():
 c=bounded();raw=program('st')[0];rows=[raw[TABLE-4096+8*i:TABLE-4096+8*i+8]for i in range(256)]
 assert all(row[::2]==bytes([8,9,10,0])and max(row[1:6:2])<=15 and row[6:]==bytes(2)for row in rows)
 for sample in range(256):
  long(c,OPERAND,SAMPLE);c.seed(SAMPLE,bytes([sample]));c.cpu.d[0]=0xa5a50000|sample;c.cpu.a[7]=STACK
  row=rows[(sample+128)&255];c.run(ISR,0x11902,40)
  assert c.cpu.d[0]==int.from_bytes(row[:4],'big')and c.cpu.d[1]&65535==int.from_bytes(row[4:6],'big')
  assert c.cpu.a[0]==PSG and integer(c,OPERAND)==SAMPLE+1
 with pytest.raises(ValueError,match='unknown bytes'):c.read(TABLE+6,2)


def test_next_interrupt_requires_the_next_sample_byte_to_be_readable():
 c=bounded();c.cpu.a[7]=STACK;c.run(ISR,0x11902,40);c.cpu.a[7]=STACK
 with pytest.raises(ValueError,match='unknown read/fetch'):c.run(ISR,0x11902,40)


def test_full_self_modified_interrupt_emits_all_sample_packets_and_restores_exception_frames():
 m=sparse();raw=program('st')[0]
 for sample in range(256):
  put(m,OPERAND,SAMPLE);put(m,LEFT,2);m[SAMPLE]=sample;seen=[]
  def observe(pc):
   if pc==0x11906:seen.append(bytes(m[p]for p in(PSG,PSG+2,PSG+4,PSG+6)))
   if pc==0x1190a:seen.append(bytes(m[p]for p in(PSG,PSG+2)))
  interrupt(m,observe);row=raw[TABLE-4096+8*((sample+128)&255):TABLE-4096+8*((sample+128)&255)+6]
  assert seen==[row[:4],row[4:]]
  assert get(m,OPERAND)==SAMPLE+1 and get(m,LEFT)==1
  assert m[MFP+15]==0xdf and get(m,PALETTE,2)==0 and m[MFP+25]==0x55


@pytest.mark.parametrize('remaining,offset,continues',[(2,0,True),(2,24,True),(1,24,False),(0,0,False),(32768,24,True),(32769,0,False),(65535,0,False)])
def test_last_byte_keeps_signed_stop_and_exact_seven_slot_wrap(remaining,offset,continues):
 m=sparse();put(m,LEFT,1);put(m,BLOCKS,remaining,2);put(m,READ,offset,2);interrupt(m)
 assert get(m,BLOCKS,2)==(remaining-1)&65535
 if continues:
  following=0 if offset+4==28 else offset+4
  assert get(m,READ,2)==following and get(m,OPERAND)==0x431f4+5632*(following//4)
  assert get(m,LEFT)==5632 and m[MFP+25]==0x55 and get(m,PALETTE,2)==0
 else:
  assert get(m,READ,2)==offset and get(m,OPERAND)==SAMPLE+1 and get(m,LEFT)==0
  assert m[MFP+25]==0 and get(m,PALETTE,2)==0xa55a  # Stop omits the regular black-palette store.


def test_ring_wrap_is_equality_only_not_a_guard_for_an_invalid_cursor():
 c=bounded();word(c,READ,28);word(c,BLOCKS,2)
 with pytest.raises(ValueError,match='unknown read/fetch'):c.run(NEXT,0x12170,100)


@pytest.mark.parametrize('slot',(0,3,6))
def test_buffer_setup_patches_operand_vector_and_all_timer_ports(slot):
 m=sparse();put(m,READ,slot*4,2);m[MFP+7]=0x81;m[MFP+19]=0x02;c=state(m,0x1182e)
 run_ram(program('st'),m,c,{RETURN})
 assert get(m,OPERAND)==0x431f4+slot*5632 and get(m,LEFT)==5632 and get(m,BLOCK_BYTES)==5632
 assert get(m,0x134)==ISR and m[MFP+7]==0xa1 and m[MFP+19]==0x22
 assert m[MFP+25]==4 and m[MFP+31]==5 and m[PSG]==5 and m[PSG+2]==0 and c.a[7]==STACK+4


def test_stored_packets_match_only_the_qualified_earlier_table(original_image):
 raw=program('st')[0];old=original_image[0]
 assert raw[TABLE-4096:LEFT-4096]==old[0x116c6-4096:0x11ec6-4096]
 assert raw[OPERAND-4096:OPERAND-4096+4]==bytes.fromhex('00012345')


def test_zero_sample_count_wraps_without_advancing_the_ring():
 m=sparse();put(m,LEFT,0);put(m,BLOCKS,1,2);put(m,READ,24,2);interrupt(m)
 assert get(m,LEFT)==0xffffffff and get(m,BLOCKS,2)==1 and get(m,READ,2)==24
 assert m[MFP+25]==0x55 and get(m,PALETTE,2)==0


def test_committed_interrupt_is_code_and_packet_fields_are_used():
 from pathlib import Path
 text=(Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered/retail-shared.s').read_text()
 assert text.split('st_buffered_sample_interrupt:\n',1)[1].lstrip().startswith('movem.l')
 assert text.split('read_next_st_buffered_sample_byte:\n',1)[1].lstrip().startswith('move.b')
 # The renderer uses the containing instruction plus two for an interior alias.
 assert text.count('read_next_st_buffered_sample_byte+2.l')>=3
 for field in('SG2STSampleRegisterPacket_channel_ab_register_value_pairs','SG2STSampleRegisterPacket_channel_c_register_value_pair'):assert text.count(field)>1

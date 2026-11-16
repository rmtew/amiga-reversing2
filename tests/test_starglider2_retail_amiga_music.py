"""Original Amiga music preparation, cached copy and Paula refill contracts.

Custom registers are readable/writable RAM apertures. Supplied request bits and
exception frames do not deliver hardware interrupts, model set/clear registers,
prove sample audibility/timing or exclude other shared-workspace users.
"""
import os,struct
import pytest
from amiga_reversing.disasm.mapped_execution import MappedExecution
from test_starglider2_retail_input import program
from tests.test_starglider2_music_ring import advance
from tests.test_memory_frame_arithmetic import ConcreteState
from tests.test_starglider2_hud_coordinates import run_ram
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail input')
RING,READ,PRODUCER,BLOCKS,ADVANCED=0x10544,0x10608,0x1060a,0x1060c,0x10610
PROBE,CACHED,STAGED,TRANSFER=0x10612,0x10613,0x12624,0x12628
SHARED,CACHE,CUSTOM,IRQ=0x431f4,0xc00000,0xdff000,0x10560
STACK,RETURN=0xf0000,0xff000

def word(c,p,n):c.seed(p,(n&65535).to_bytes(2,'big'))
def long(c,p,n):c.seed(p,(n&0xffffffff).to_bytes(4,'big'))
def integer(c,p,n=4):return int.from_bytes(c.read(p,n),'big')

def machine():
 c=MappedExecution(0xe00000,register_seed=0x12345678);c.seed(4096,program('amiga')[0]);c.seed(STACK-128,bytes(134));c.allow_write(STACK-128,128)
 c.cpu.a[7]=STACK;long(c,STACK,RETURN)
 for p,n in((RING,28),(READ,2),(PRODUCER,2),(BLOCKS,2),(ADVANCED,1),(STAGED,4),(TRANSFER,4)):c.allow_write(p,n)
 for off,n in((0x96,2),(0x9a,2),(0x9c,2),(0x9e,2),(0xa0,4),(0xa4,2),(0xa6,2),(0xa8,2),(0xc0,4),(0xc4,2),(0xc6,2),(0xc8,2)):
  c.seed(CUSTOM+off,b'\xa5'*n);c.allow_write(CUSTOM+off,n)
 word(c,CUSTOM+0x180,0xa55a)  # No write permission: retail omits the older palette store.
 c.run(0x102f8,0x1030e,100);assert c.read(RING,28)==struct.pack('>7I',*(SHARED+5632*i for i in range(7)))
 return c


def test_original_vector_store_connects_level_four_to_the_music_consumer():
 c=machine();c.allow_write(0x70,4);c.run(0xce62,0xce6a,1)
 assert integer(c,0x70)==IRQ


@pytest.mark.parametrize('cached,probe,stop',[(1,0,0x103b8),(0x80,0x80,0x103b8),(0,1,0x103b8),(0,0,0x10388)])
def test_retail_cache_guards_read_the_actual_loaded_and_probe_flags(cached,probe,stop):
 c=machine();c.seed(CACHED,bytes([cached]));c.seed(PROBE,bytes([probe]));before=integer(c,TRANSFER)
 c.run(0x1034c,stop,30);assert integer(c,STAGED)==CACHE
 assert integer(c,TRANSFER)==(before if cached else CACHE)
 assert integer(c,CUSTOM+0x9e,2)==(0xa5a5 if cached else 0x9500)
 if not cached and not probe:assert c.cpu.d[1]==79


def test_prepared_music_sets_both_paula_channels_and_raw_dma_irq_commands():
 c=machine();c.seed(ADVANCED,b'\xff');word(c,READ,24);c.run(0x10424,0x1049a,40)
 assert integer(c,ADVANCED,1)==0 and integer(c,BLOCKS,2)==80 and integer(c,READ,2)==0 and c.cpu.d[1]==75
 for channel in(0xa0,0xc0):
  assert integer(c,CUSTOM+channel)==SHARED
  assert[integer(c,CUSTOM+channel+off,2)for off in(4,6,8)]==[2816,358,64]
 assert integer(c,CUSTOM+0x96,2)==0x8205 and integer(c,CUSTOM+0x9a,2)==0xc200


def test_cached_refill_copies_exactly_5632_bytes_twice_and_advances_only_the_source_cursor():
 c=machine();data=bytes((i*29+7+(i//5632)*53)&255 for i in range(11264));c.seed(CACHE,data);long(c,STAGED,CACHE)
 for index,slot in enumerate((0,6)):
  dest=SHARED+slot*5632;c.seed(dest-4,b'\xa5'*5640);c.allow_write(dest,5632);long(c,TRANSFER,dest)
  c.cpu.a[7]=STACK;long(c,STACK,RETURN);d,a=list(c.cpu.d),list(c.cpu.a);c.run(0x10618,RETURN,4000)
  assert c.read(dest,5632)==data[index*5632:(index+1)*5632] and integer(c,STAGED)==CACHE+(index+1)*5632
  assert c.read(dest-4,4)==c.read(dest+5632,4)==b'\xa5'*4
  assert list(c.cpu.d)==d and list(c.cpu.a[:7])==a[:7] and c.cpu.a[7]==STACK+4
 assert c.read(CACHE,11264)==data


@pytest.mark.parametrize('offset',(0,20,24))
def test_prefill_selects_the_real_next_ring_destination(offset):
 c=machine();word(c,PRODUCER,offset);c.run(0x103ca,0x103f4,30);following=advance(offset)
 assert integer(c,PRODUCER,2)==following and integer(c,TRANSFER)==SHARED+5632*(following//4)


@pytest.mark.parametrize('offset',(20,24))
def test_producer_wait_reloads_consumer_and_keeps_two_slot_lookahead(offset):
 c=machine();word(c,PRODUCER,offset);c.run(0x1049c,0x104cc,30);following=advance(offset);lookahead=advance(advance(following))
 assert integer(c,PRODUCER,2)==following and c.cpu.d[0]&65535==lookahead
 word(c,READ,lookahead);c.run(0x104cc,RETURN,2,expected_stop='limit');assert c.cpu.pc==0x104cc
 word(c,READ,lookahead^4);c.run(0x104cc,0x104d4,2);assert c.cpu.d[0]&65535==lookahead


@pytest.mark.parametrize('pending,remaining,offset',[(False,1,24),(True,2,0),(True,2,24),(True,1,24),(True,0,0),(True,32769,0)])
def test_real_paula_consumer_preserves_frame_and_uses_zero_only_block_stop(pending,remaining,offset):
 c=machine();word(c,CUSTOM+0x1e,0x200 if pending else 0x80);word(c,READ,offset);word(c,BLOCKS,remaining);c.seed(ADVANCED,b'\x55')
 c.cpu.a[7]=STACK;c.cpu.sr=0x2700;c.seed(STACK,struct.pack('>HI',0x2315,RETURN));d,a=list(c.cpu.d),list(c.cpu.a)
 trace=c.run(IRQ,0x105ce,70000);left=(remaining-1)&65535
 # Observed execution deliberately refuses exception returns. Check the known
 # frame, then execute that original RTE with the existing RAM-fetch helper.
 assert c.read(STACK,6)==struct.pack('>HI',0x2315,RETURN)
 run_ram(program('amiga'),c.memory,ConcreteState.from_buffer(c.cpu),{RETURN},limit=2)
 assert list(c.cpu.d)==d and list(c.cpu.a[:7])==a[:7] and c.cpu.a[7]==STACK+6 and c.cpu.sr==0x2315
 assert integer(c,CUSTOM+0x9c,2)==0x380 and integer(c,CUSTOM+0x180,2)==0xa55a
 if not pending:
  assert integer(c,BLOCKS,2)==remaining and integer(c,READ,2)==offset and integer(c,ADVANCED,1)==0x55
  assert integer(c,CUSTOM+0xa4,2)==0xa5a5 and trace['steps']<30
 elif left==0:
  assert integer(c,BLOCKS,2)==0 and integer(c,READ,2)==offset and integer(c,ADVANCED,1)==0x55
  assert[integer(c,CUSTOM+off,2)for off in(0xa4,0xa6,0xc4,0xc6)]==[1]*4
  assert integer(c,CUSTOM+0x9a,2)==0x380 and integer(c,CUSTOM+0x96,2)==5 and integer(c,CUSTOM+0xc8,2)==0
  assert trace['steps']<40
 else:
  following=advance(offset);assert integer(c,BLOCKS,2)==left and integer(c,READ,2)==following and integer(c,ADVANCED,1)==255
  assert integer(c,CUSTOM+0xa0)==integer(c,CUSTOM+0xc0)==SHARED+5632*(following//4)
  assert integer(c,CUSTOM+0xa4,2)==integer(c,CUSTOM+0xc4,2)==2816
  assert integer(c,CUSTOM+0xa6,2)==integer(c,CUSTOM+0xc6,2)==0xa5a5 and 65536<trace['steps']<66000


def test_committed_amiga_consumer_has_instructions_and_used_hardware_fields():
 from pathlib import Path
 text=(Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered/retail-shared.s').read_text()
 assert text.split('service_amiga_music_audio_interrupt:\n',1)[1].lstrip().startswith('movem.l')
 vector=text.split('install_amiga_music_level4_vector:\n',1)[1].splitlines()[0]
 assert '#service_amiga_music_audio_interrupt' in vector
 for field in('interrupt_requests','interrupt_acknowledge','audio0_location','audio2_location','audio2_length_words','audio2_volume'):
  assert text.count('SG2AmigaMusicCustomRegisters_'+field)>1,field

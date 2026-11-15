"""Shared decimal formatting: real instruction bodies and actual retail callers.

The caller supplies writable output storage and the A6 context. No text display
or hardware helper is stubbed or claimed: the rating wrapper stops at its real
print tail, after executing the formatter and jump bridge.
"""
import os
import struct
from pathlib import Path
import pytest
from tests.test_starglider2_retail_inheritance import context,data,APP,STACK,RETURN

pytestmark=pytest.mark.skipif(not os.getenv('SGII_RETAIL_DIRECTORY'),reason='private pinned SGII images')
DEST=0xd0000
ENTRY={'old':dict(word=0x2558,long=0x2574,four=0x25d4,wrapper=0xb40c,print=0xc4e4,table=0x2530),
       'amiga':dict(word=0x256c,long=0x2588,four=0x25e8,wrapper=0xb418,print=0xc4f0,table=0x2544),
       'st':dict(word=0x256c,long=0x2588,four=0x25e8,wrapper=0xb418,print=0xc4f0,table=0x2544)}


def expected(mode,value):
 """Digit extraction by division, independent of the repeated-subtract code."""
 bits=value&(65535 if mode!='long' else 0xffffffff)
 signed=bits-(65536 if mode!='long' else 2**32) if bits&(32768 if mode!='long' else 0x80000000) else bits
 magnitude=abs(signed)
 if mode=='word':return (('- ' if signed<0 else '')+str(magnitude)).encode()+b'\0'
 count=4 if mode=='four' else 9;out=bytearray()
 for power in reversed(range(count)):
  q,magnitude=divmod(magnitude,10**power);out.append((48+q)&255)
 if mode=='long':out=out.lstrip(b'0') or bytearray(b'0')
 return (b'-' if signed<0 and mode=='four' else b'- ' if signed<0 else b'')+out+b'\0'


@pytest.mark.parametrize('mode,values',[
 ('word',(0,1,9,10,9999,10000,32767,32768,65535,0xa5a50009)),
 ('long',(0,1,10,99999999,100000000,999999999,1000000000,0x7fffffff,0x80000000,0xffffffff)),
 ('four',(0,1,10,999,1000,9999,10000,32767,32768,65535,0x12340009)),
])
def test_all_numeric_entries_preserve_original_width_sign_and_non_digit_overflow(mode,values):
 for value in values:
  wanted=expected(mode,value)
  for platform,entries in ENTRY.items():
   cpu=context(platform);cpu.seed(DEST-4,b'\xa5'*64);cpu.allow_write(DEST,len(wanted));cpu.allow_write(APP+0x58,4)
   cpu.cpu.d[0]=value;cpu.cpu.a[1]=DEST
   d,a=list(cpu.cpu.d),list(cpu.cpu.a);table=cpu.read(entries['table'],40)
   cpu.run(entries[mode],RETURN,1000)
   assert cpu.read(DEST,len(wanted))==wanted,(platform,mode,hex(value))
   assert cpu.read(DEST-4,4)==b'\xa5'*4 and cpu.read(DEST+len(wanted),4)==b'\xa5'*4
   assert int.from_bytes(cpu.read(APP+0x58,4),'big')==DEST+len(wanted)
   assert list(cpu.cpu.d)==d and list(cpu.cpu.a)[:7]==a[:7] and cpu.cpu.a[7]==STACK+4
   assert cpu.read(entries['table'],40)==table==struct.pack('>10I',*(10**i for i in range(10)))


@pytest.mark.parametrize('platform',ENTRY)
def test_rating_wrapper_runs_real_nine_place_bridge_and_restores_label_pointer(platform):
 entries=ENTRY[platform];cpu=context(platform);cpu.seed(DEST,b'\xa5'*64);cpu.allow_write(DEST+34,10);cpu.allow_write(APP+0x58,4)
 cpu.cpu.a[1]=DEST;cpu.cpu.d[0]=123456789;before=list(cpu.cpu.d)
 cpu.run(entries['wrapper'],entries['print'],1000)
 assert cpu.read(DEST,34)==b'\xa5'*34 and cpu.read(DEST+34,10)==b'123456789\0'
 assert cpu.cpu.a[1]==DEST and cpu.cpu.a[7]==STACK and list(cpu.cpu.d)==before
 assert int.from_bytes(cpu.read(APP+0x58,4),'big')==DEST+44


@pytest.mark.parametrize('platform',ENTRY)
def test_decimal_contract_refuses_an_undersized_caller_buffer(platform):
 cpu=context(platform);cpu.seed(DEST,b'\xa5'*8);cpu.allow_write(DEST,1);cpu.allow_write(APP+0x58,4)
 cpu.cpu.a[1]=DEST;cpu.cpu.d[0]=42
 with pytest.raises(ValueError,match='forbidden write'):cpu.run(ENTRY[platform]['word'],RETURN,1000)


@pytest.mark.parametrize('field',range(4))
@pytest.mark.parametrize('value',[0,123456789,0x80000000])
def test_actual_rating_field_rows_have_room_for_formatter_and_preserve_neighbours(field,value):
 # Four real consumer LEAs, not inferred tables or invented caller storage.
 for platform,entries in ENTRY.items():
  base=(0xb208,0xb236,0xb264,0xb296)[field]+(0 if platform=='old' else 12)
  cpu=context(platform);before=cpu.read(base-2,50);text=expected('long',value)
  cpu.cpu.a[1]=base;cpu.cpu.d[0]=value;cpu.allow_write(base+34,len(text));cpu.allow_write(APP+0x58,4)
  cpu.run(entries['wrapper'],entries['print'],1000)
  assert cpu.read(base-2,36)==before[:36]
  assert cpu.read(base+34,len(text))==text
  assert cpu.read(base+46,2)==before[48:50]
  assert cpu.cpu.a[1]==base and int.from_bytes(cpu.read(APP+0x58,4),'big')==base+34+len(text)


def test_native_source_names_connected_decimal_entries_and_actual_rating_labels():
 source=(Path(os.environ['SGII_RETAIL_RENDERED_SOURCE'])).read_text()
 for name in ('format_signed_word_decimal_text','format_signed_long_nine_decimal_places','format_signed_word_four_decimal_positions','format_and_print_rating_label','decimal_place_value_longs_word_cursor','pilot_rating_shots_fired_label','pilot_rating_hit_accuracy_label'):
  assert name+':' in source

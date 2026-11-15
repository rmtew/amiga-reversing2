"""Shared stored pictures: bounded four-stream RLE, not a screen renderer.

The independent decoder and unaltered CPU routine agree for old and both retail
images. Underfilled last bytes, column-major writes and plane padding remain
untouched. Pixel scanout is covered separately by the paired emulator captures.
"""
import os
import pytest
from tests.test_starglider2_retail_inheritance import context,data,RETURN

pytestmark=pytest.mark.skipif(not os.getenv('SGII_RETAIL_DIRECTORY'),reason='private pinned SGII images')
DEST,STREAM=0x80000,0xd0000
ENTRIES={'old':(0x3a7e,0x3af8),'amiga':(0x3a8a,0x3b04),'st':(0x3a8a,0x3b04)}
ASSETS=[('cockpit',0x5241c,0x53dc8,12566,(7999,8000,7999,7999)),('argonaut_splash',0x55554,0x56f00,14773,(7999,7999,7999,7999))]


def decode(raw,start):
 out=bytearray(b'\xa5'*32768);at=start;counts=[]
 for plane in range(4):
  count=0
  while True:
   command=raw[at];at+=1
   if not command:break
   n=((256-command)&127) if command&128 else command
   if not n:raise ValueError('zero literal count has DBF wrap behavior in original code')
   if command&128:values=raw[at:at+n];assert len(values)==n;at+=n
   else:values=bytes([raw[at]])*n;at+=1
   for value in values:
    if count>=8000:raise ValueError('picture exceeds 200 rows by 40 columns')
    out[plane*8192+(count%200)*40+count//200]=value;count+=1
  counts.append(count)
 return bytes(out),at,tuple(counts)


def execute(platform,source,palette,raw=None):
 cpu=context(platform)
 if raw is not None:cpu.seed(source,raw)
 cpu.seed(DEST-4,b'\xa5'*(32768+8));cpu.allow_write(DEST,32768)
 cpu.cpu.a[0]=source;cpu.cpu.a[1]=DEST;cpu.cpu.a[4]=DEST;cpu.cpu.d[0]=palette;cpu.cpu.d[4]=0
 entry,pop=ENTRIES[platform];cpu.run(entry,pop,400000)
 end=cpu.cpu.a[0];assert cpu.cpu.d[4]&65535==4
 cpu.run(pop,RETURN,3);assert cpu.cpu.a[0]==palette
 assert cpu.read(DEST-4,4)==b'\xa5'*4 and cpu.read(DEST+32768,4)==b'\xa5'*4
 return cpu.read(DEST,32768),end


@pytest.mark.parametrize('platform',ENTRIES)
def test_repeat_and_literal_packets_cross_column_boundaries(platform):
 stream=b''.join(bytes([127,10+p,74,20+p,253,30+p,40+p,50+p,0]) for p in range(4))
 wanted,end,counts=decode(stream,0);assert counts==(204,)*4
 actual,stopped=execute(platform,STREAM,0x12345678,stream)
 assert actual==wanted and stopped==STREAM+end==STREAM+len(stream)


@pytest.mark.parametrize('asset',ASSETS,ids=[x[0] for x in ASSETS])
def test_complete_stored_assets_retain_original_read_extent_and_underfill(asset):
 name,old,retail,length,counts=asset;oldbytes=data('old')[old:old+32+length]
 assert len(oldbytes)==32+length
 for platform in ENTRIES:
  base=old if platform=='old' else retail;raw=data(platform)
  assert raw[base:base+32+length]==oldbytes
  wanted,end,actual_counts=decode(raw,base+32)
  assert end==base+32+length and actual_counts==counts
  actual,stopped=execute(platform,4096+base+32,4096+base)
  assert actual==wanted and stopped==4096+end


@pytest.mark.parametrize('platform',ENTRIES)
def test_reserved_literal_control_does_not_get_silently_repaired(platform):
 # $80 becomes zero before SUBQ/DBF, so the original attempts a huge literal
 # run. The bounded witness must refuse the unknown next byte, not clamp it.
 with pytest.raises(ValueError,match='unknown read/fetch'):
  execute(platform,STREAM,0,b'\x80\x7f')


def st_colour(planar):
 out=bytearray(32000)
 for row in range(200):
  for group in range(20):
   for plane in range(4):
    src=plane*8192+row*40+group*2;dst=row*160+group*8+plane*2
    out[dst:dst+2]=planar[src:src+2]
 return bytes(out)


def st_mono(planar):
 out=bytearray()
 for row in range(200):
  for a,b in ((0,1),(2,3)):
   for group in range(20):
    offset=row*40+group*2;left=int.from_bytes(planar[a*8192+offset:a*8192+offset+2],'big');right=int.from_bytes(planar[b*8192+offset:b*8192+offset+2],'big')
    value=0
    for bit in reversed(range(16)):value=(value<<2)|(((left>>bit)&1)<<1)|((right>>bit)&1)
    out+=value.to_bytes(4,'big')
 return bytes(out)


@pytest.mark.parametrize('platform',['amiga','st'])
@pytest.mark.parametrize('asset',ASSETS,ids=[x[0] for x in ASSETS])
def test_retail_st_colour_stream_adapter_uses_word_interleaved_rows(platform,asset):
 _,_,base,_,_=asset;raw=data(platform);planar,end,_=decode(raw,base+32)
 cpu=context(platform);cpu.seed(DEST-4,b'\xa5'*(32000+8));cpu.allow_write(DEST,32000)
 cpu.seed(0xefffc,(4096+base).to_bytes(4,'big'));cpu.cpu.a[7]=0xefffc
 cpu.cpu.a[0]=4096+base+32;cpu.cpu.a[1]=DEST;cpu.cpu.a[4]=DEST;cpu.cpu.d[4]=0
 cpu.run(0x3b8c,0x3c0a,400000)
 assert cpu.cpu.a[0]==end+4096 and cpu.read(DEST,32000)==st_colour(planar)
 cpu.run(0x3c0a,RETURN,3);assert cpu.cpu.a[0]==4096+base
 assert cpu.read(DEST-4,4)==b'\xa5'*4 and cpu.read(DEST+32000,4)==b'\xa5'*4


@pytest.mark.parametrize('platform',['amiga','st'])
@pytest.mark.parametrize('asset',ASSETS,ids=[x[0] for x in ASSETS])
def test_retail_st_monochrome_adapter_converts_two_row_pairs_and_stops_before_hardware(platform,asset):
 from tests.test_starglider2_retail_inheritance import APP
 _,_,base,_,_=asset;planar,_,_=decode(data(platform),base+32)
 cpu=context(platform);cpu.seed(0x70000-4,b'\xa5'*(32000+8));cpu.allow_write(0x70000,32000)
 cpu.seed(0x78000-4,b'\xa5'*(32768+8));cpu.allow_write(0x78000,32768)
 cpu.seed(APP+0x1f2,b'\x02');cpu.seed(0xefffc,(4096+base).to_bytes(4,'big'));cpu.cpu.a[7]=0xefffc
 cpu.cpu.a[0]=4096+base+32;cpu.cpu.a[1]=0x70000;cpu.cpu.a[4]=0x70000;cpu.cpu.d[4]=0
 # 8,000 output WORD pairs require 896,000 bit-loop instructions alone.
 # Include loads/stores and the preceding bounded RLE decode in this budget.
 cpu.run(0x3b08,0x3b82,1500000)
 assert cpu.read(0x78000,32768)==planar and cpu.read(0x70000,32000)==st_mono(planar)
 for address,length in ((0x70000,32000),(0x78000,32768)):
  assert cpu.read(address-4,4)==b'\xa5'*4 and cpu.read(address+length,4)==b'\xa5'*4
 # $3B82 writes ST palette hardware. This CPU test deliberately stops there;
 # real monochrome scanout remains a separate emulator proof.
 assert cpu.cpu.pc==0x3b82


def test_native_source_uses_shared_asset_names_and_scoped_st_path_names():
 from pathlib import Path
 source=(Path(os.environ['SGII_RETAIL_RENDERED_SOURCE'])).read_text()
 for name in ('decode_four_planar_picture_streams','decode_st_colour_picture_streams','decode_st_monochrome_picture','cockpit_picture_palette','cockpit_picture_rle_data','argonaut_splash_picture_palette','argonaut_splash_picture_rle_data'):
  assert name+':' in source

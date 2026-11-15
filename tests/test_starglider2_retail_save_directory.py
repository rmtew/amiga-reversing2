"""Original ADLS lookup, slot layout and driver binding over supplied RAM.

UI/driver calls are boundaries. Port values in sparse RAM are CPU stimuli,
not a WD1772, Paula, disk codec or persistent-media implementation.
"""
import os
import pytest
from test_starglider2_retail_inventory import base,APP,STACK,RETURN
from test_starglider2_retail_workspace import put,get
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
DIRECTORY,INPUT=0x7e400,0x128ba
AMIGA_TARGETS=(0x10836,0x10856,0x10876,0x10cc0,0x10cec,0x10c90,0x10b00,0x1088e,0x10c70)
ST_TARGETS=(0x111ba,0x111da,0x111ec,0x11236,0x11280,0x111f6,0x112ca,0x113b4,0x1162e)


def directory(c,names,count=None,magic=0x47414d45):
 data=bytearray(520);put(data,0,magic);put(data,4,len(names)if count is None else count)
 for n,name in enumerate(names):data[8+32*n:8+32*n+len(name)+1]=name+b'\0'
 c.seed(DIRECTORY,bytes(data))


@pytest.mark.parametrize('magic,count',[(0,1),(0x47414d45,0)])
def test_empty_or_wrong_directory_is_rejected_before_ui(magic,count):
 c=base();directory(c,[b'A'],count,magic);before=c.read(APP,0x6598)
 c.run(0x11050,RETURN,20)
 assert c.cpu.d[0]==0xffffffff and c.cpu.d[2]==0 and c.read(APP,0x6598)==before


@pytest.mark.parametrize('names,query,index',[
 ([b'ALPHA',b'BETA'],b'ALPHA',0),([b'ALPHA',b'BETA'],b'BETA',1),
 ([b'ALPHA',b'ALP'],b'AL',0),([b'ALPHA'],b'alpha',None),
 ([b'ALPHA'],b'ALPHAX',None),([b'ONE',b'TWO',b'THREE'],b'THR',2),
 ([b'FIRST',b''],b'ZZ',None)])
def test_lookup_preserves_prefix_match_case_and_first_empty_record(names,query,index):
 c=base();directory(c,names);c.seed(INPUT,query+b'\0')
 before=c.read(DIRECTORY,520);c.run(0x110a8,RETURN,400)
 assert c.read(DIRECTORY,520)==before
 assert c.cpu.d[0]==(0 if index is not None else 0xffffffff)
 if index is not None:assert c.cpu.d[2]==index and c.cpu.a[2]==DIRECTORY+8+32*index
 else:assert c.cpu.d[2]==(1 if names[-1]==b'' else len(names))


def test_empty_query_cancels_without_scanning_directory():
 c=base();directory(c,[b'A']);c.seed(INPUT,b'\0');c.run(0x110a8,RETURN,10)
 assert c.cpu.d[0]==0xfffffffe


def test_lookup_count_loop_uses_low_word_even_when_the_long_count_is_nonzero_high():
 c=base();directory(c,[b'A',b'B'],0x12340001);c.seed(INPUT,b'B\0')
 c.run(0x110a8,RETURN,80)
 assert c.cpu.d[0]==0xffffffff and c.cpu.d[2]==1


@pytest.mark.parametrize('index', (0,1,14,15))
def test_appending_name_writes_full_32_bytes_before_fifteenth_slot_limit(index):
 c=base();directory(c,[b'OLD']*index);c.allow_write(DIRECTORY,520);c.allow_write(0x431f4,512)
 data=b'NEW\0'+bytes(range(28));c.seed(INPUT,data);c.cpu.a[2]=DIRECTORY+8+32*index;c.cpu.d[2]=index
 before=c.read(DIRECTORY,520);c.run(0x100b2,0x101d4 if index>=15 else 0x100ec,600)
 assert c.read(DIRECTORY+8+32*index,32)==data
 if index<15:
  assert get(c.memory,DIRECTORY)==0x47414d45 and get(c.memory,DIRECTORY+4)==index+1
  assert c.read(0x431f4,512)==c.read(DIRECTORY,512) and c.cpu.d[2]==index
 else:assert c.read(DIRECTORY,8)==before[:8]


@pytest.mark.parametrize('slot',(0,1,14))
def test_slot_seek_requests_five_steps_per_index_before_five_payload_cylinders(slot):
 c=base();c.cpu.d[2]=slot;pc=0x10d16;calls=0
 while True:
  stop=RETURN if slot==0 else 0xfdfe
  c.run(pc,stop,30)
  if slot==0:break
  # Each step is a hardware boundary. Return the unchanged caller state.
  calls+=1;pc=get(c.memory,c.cpu.a[7]);c.cpu.a[7]+=4
  if calls==slot*5:
   c.run(pc,RETURN,30);break
 assert calls==5*slot and c.cpu.a[7]==STACK+4
 # The existing saved-read-loop witness proves the following five steps.


@pytest.mark.parametrize('platform',('st','amiga'))
def test_original_st_initializer_rebinds_only_nine_jump_operands(platform):
 c=base(platform);put(c.memory,0x27be,APP);c.allow_write(0xfdec,54)
 before=c.read(0xfdec,54);c.run(0x3cdc0,0x3ce36,100)
 after=c.read(0xfdec,54)
 assert [after[n*6:n*6+2]for n in range(9)]==[b'\x4e\xf9']*9
 assert tuple(int.from_bytes(after[n*6+2:n*6+6],'big')for n in range(9))==ST_TARGETS
 assert tuple(int.from_bytes(before[n*6+2:n*6+6],'big')for n in range(9))==AMIGA_TARGETS
 # Calling ST setup explicitly rebinds either payload; entry dispatch selects it.


def test_crc_table_builder_matches_all_ccitt_entries_and_split_byte_storage():
 c=base();c.allow_write(0x123f6,512);c.run(0x10f3a,RETURN,20000)
 for byte in range(256):
  crc=byte<<8
  for _ in range(8):crc=((crc<<1)^ (0x1021 if crc&0x8000 else 0))&65535
  assert c.memory[0x123f6+byte]==crc>>8 and c.memory[0x124f6+byte]==crc&255


def test_original_st_write_sector_command_sequence_uses_ten_512_byte_transfers():
 from test_starglider2_retail_input import memory,state,run
 m=memory('st');c=state(m,0x113b4);calls=[]
 def ports(pc):
  if pc==0x115b8:calls.append((get(m,0xffff8606,2),c.d[7]&65535,get(m,0x1262c)))
  if pc==0x1160a:put(m,0xffff8604,0x80,2)
 run('st',m,c,RETURN,ports,limit=40000)
 commands=[(mode,value,addr)for mode,value,addr in calls if mode==0x180]
 sectors=[value for mode,value,addr in calls if mode==0x184]
 assert sectors==list(range(1,11))
 assert commands==[(0x180,0xa0,0x7e000+512*n)for n in range(10)]
 assert c.d[0]==0 and get(m,0x1262c)==0x7f400


def test_original_st_format_emits_write_track_and_ten_physical_sector_ids():
 from test_starglider2_retail_input import memory,state,run
 m=memory('st');c=state(m,0x11476);put(m,0x12602,7,2);commands=[]
 source=bytes((n*29)&255 for n in range(5120));m[0x7e000:0x7f400]=source
 def ports(pc):
  if pc==0x115b8:commands.append((get(m,0xffff8606,2),c.d[7]&65535))
  if pc==0x1160a:put(m,0xffff8604,0x80,2)
 run('st',m,c,RETURN,ports,limit=50000)
 assert commands[-2:]==[(0x190,14),(0x180,0xf0)] and c.d[0]==0
 # Ten 594-byte records after 60 gap bytes: IDAM, synthesized CRC token,
 # data mark/payload, CRC token and gap. These are WD1772 input bytes.
 ids=[]
 for n in range(10):
  start=0x78000+60+594*n;ids.append(m[start+18])
  assert m[start+16]==7 and m[start+19]==2
  sector=ids[-1];assert bytes(m[start+59:start+59+512])==source[(sector-1)*512:sector*512]
 assert sorted(ids)==list(range(1,11))


def test_original_amiga_encoder_builds_ibm_sectors_and_requests_raw_track_dma():
 import binascii
 from test_starglider2_retail_input import memory,state,run
 m=memory('amiga');c=state(m,0x10f3a);run('amiga',m,c,RETURN,limit=20000)
 put(m,0x12602,7,2);put(m,0x12608,10,2);put(m,0x12614,1,2);put(m,0x12628,0x7e000)
 m[0xbfe001]=8;m[0xbfdd00]=16
 source=bytes((n*29)&255 for n in range(5120));m[0x7e000:0x7f400]=source;writes=[]
 def ports(pc):
  if pc in (0x10a84,0x10a8a):writes.append(get(m,0xdff024,2))
  if pc==0x10a8c:put(m,0x12610,1,2)  # Supplied disk interrupt, no DMA device.
 c=state(m,0x1088e);run('amiga',m,c,0xfe10,ports,limit=300000)
 assert writes==[0xd800,0xd800] and get(m,0xdff020)==0x78000
 def decode(data):
  words=[int.from_bytes(data[n:n+2],'big')for n in range(0,len(data),2)]
  return bytes(sum(((word>>(2*bit))&1)<<bit for bit in range(8))for word in words)
 raw=bytes(m[0x78000:0x7b000]);sync=b'\x44\x89'*3;at=0;headers=[];payloads=[];header_positions=[];data_positions=[]
 while (at:=raw.find(sync,at))>=0:
  mark=decode(raw[at+6:at+8])[0]
  if mark==0xfe:
   record=decode(raw[at+6:at+20]);headers.append(record);header_positions.append(0x78000+at)
   assert record[:3]==bytes([0xfe,7,0]) and record[4]==2
   assert binascii.crc_hqx(b'\xa1'*3+record,0xffff)==0
  elif mark==0xfb:
   record=decode(raw[at+6:at+6+1030]);payloads.append(record);data_positions.append(0x78000+at)
   assert binascii.crc_hqx(b'\xa1'*3+record,0xffff)==0
  else:pytest.fail('Unexpected encoded address mark')
  at+=6
 assert len(headers)==len(payloads)==10
 assert sorted(h[3]for h in headers)==list(range(1,11))
 for header,payload in zip(headers,payloads):
  sector=header[3];assert payload[1:513]==source[(sector-1)*512:sector*512]
 # Close the logical codec loop with the original reader, separately from
 # independent decoding. No emulated disk/DMA delivers these RAM bytes.
 put(m,0x12628,0x90000);m[0x90000:0x91400]=b'\xa5'*5120
 for header,hp,dp in zip(headers,header_positions,data_positions):
  c=state(m,0x10f64);c.a[0]=hp;c.a[4]=0x7d000;c.d[1]=9
  run('amiga',m,c,RETURN,limit=1000)
  assert c.d[7]&255==0 and bytes(m[0x7d000:0x7d008])==b'\xa1'*3+header[:5]
  put(m,0x12606,header[3]-1,2)
  c=state(m,0x10f7a);c.a[0]=dp;c.a[4]=0x7d008
  run('amiga',m,c,RETURN,limit=15000);assert c.d[7]&255==0
 assert bytes(m[0x90000:0x91400])==source
 # A changed encoded data bit must fail CRC; decoding can still dirty staging.
 dp=data_positions[0];m[dp+6+84]^=1;put(m,0x12606,headers[0][3]-1,2)
 c=state(m,0x10f7a);c.a[0]=dp;c.a[4]=0x7d008
 run('amiga',m,c,RETURN,limit=15000);assert c.d[7]&255!=0

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='external vasm is the source build dependency')
def test_compiled_save_format_symbols_bind_only_the_qualified_spans(tmp_path):
 import struct,subprocess
 from pathlib import Path
 from test_starglider2_retail_model_headers import image
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered'
 symbols={'find_saved_game_directory_entry':0x11050,'amiga_write_ibm_sector_track':0x1088e,'st_write_ten_sector_track':0x113b4,'st_format_ten_sector_track':0x11476,'byte_to_mfm_word_table':0x12176,'mfm_nibble_decode_table':0x12376,'crc16_ccitt_split_table':0x123f6,'disk_io_state':0x125fe,'sector_write_interleave_order':0x12630,'disk_sector_track_template':0x1263c,'SG2SaveDirectoryHeader_entry_count':4,'SG2TrackTemplate_sector_payload':58,'SG2DiskIOState_read_buffer':42}
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 result=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert result.returncode==0,result.stdout+result.stderr
 raw=out.read_bytes();size=4*len(symbols)
 assert raw[:-size]==image('st')and struct.unpack('>'+str(len(symbols))+'I',raw[-size:])==tuple(symbols.values())

@pytest.mark.parametrize('valid',(False,True))
def test_adls_volume_prefix_check_compares_all_86_bytes_before_acceptance(valid):
 c=base();header=c.read(0x128de,86);c.seed(0x7e000,header if valid else header[:-1]+bytes([header[-1]^1]))
 put(c.memory,0x12628,0x7e000);c.allow_write(0x125fe,1);c.seed(0x125fe,b'\0')
 c.run(0x10e58,RETURN if valid else 0x10e74,300)
 if valid:assert c.cpu.d[0]==0

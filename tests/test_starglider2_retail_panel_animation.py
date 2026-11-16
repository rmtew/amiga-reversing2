"""Panel record ownership and three original CPU output layouts.

Supplied RAM checks prove these bounded states,not normal animation cadence,
converted-asset lifetime,interrupt exclusion or physical display output.
"""
import ctypes,os,struct
import pytest
from tests.test_starglider2_text_editor import state,run,put,get,APP,INPUT,STACK,RETURN
from test_starglider2_retail_input import program
from tests.test_starglider2_interleaved_color_kernels import kernels as earlier_image
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
STATE,COUNT,RECORDS,DIRECTORY,ASSETS=0x50260,0x50264,0x50266,0x50326,0x50426


def memory(profile='colour'):
 image=program('amiga'if profile=='amiga'else'st');m=(ctypes.c_uint8*0xa1000)();ctypes.memmove(ctypes.addressof(m)+4096,image[0],len(image[0]));m[APP+0x1f2]=2 if profile=='mono'else 0
 m[APP+0x7ea]=2;put(m,STATE,3,2);return image,m


def invoke(image,m):
 c=state(m,0x3392);d=list(c.d);a=list(c.a);run(image,m,c,{RETURN},limit=15000)
 assert list(c.d)==d and list(c.a[:7])==a[:7]and c.a[7]==STACK+4
 return c


@pytest.mark.parametrize('ticks,fast',((0,0),(4,1),(5,0),(0x80,0),(0x105,255)))
def test_original_tick_gate_is_signed_low_byte_and_reload_request_precedes_gate(ticks,fast):
 image,m=memory();put(m,APP+0x7c2,ticks,2);m[APP+0x209]=fast;put(m,COUNT,0,2);put(m,STACK,RETURN)
 before=bytearray(m);before[0xe144]=0x70;before[0xe145]=0
 for at in(RECORDS+3*24+16,RECORDS+4*24+16):put(before,at,0 if fast else 100,2)
 before[APP+0x209]=0
 if 5<=(ticks&255)<128:put(before,APP+0x7c2,0,2)
 invoke(image,m);before[STACK-60:STACK+4]=bytes(m[STACK-60:STACK+4]);assert bytes(m)==before


@pytest.mark.parametrize('weapon,family,directory,n',((8,2,0x503f6,4),(0,0,0x503ae,8),(4,1,0x503ce,4),(12,4,0x503de,6),(2,3,0x50406,4)))
def test_weapon_family_replaces_slot6_directory_count_and_current_only_on_change(weapon,family,directory,n):
 image,m=memory();m[APP+0x7ea]=weapon;put(m,STATE,0xffff,2);put(m,APP+0x7c2,5,2)
 for i in range(8):put(m,RECORDS+24*i+14,10,2)
 invoke(image,m);slot=RECORDS+6*24
 assert get(m,STATE,2)==family and get(m,slot+6)==directory and get(m,slot+22,2)==n and get(m,slot+18,2)==1
 assert [get(m,RECORDS+24*i+14,2)for i in range(8)]==[9]*8
 put(m,slot+18,3,2);put(m,APP+0x7c2,5,2);invoke(image,m)
 assert get(m,slot+18,2)==3 and get(m,slot+6)==directory


@pytest.mark.parametrize('profile,current',(('amiga',1),('colour',1),('mono',1),('mono',2)))
def test_full_service_copies_selected_frame_using_each_profile_offsets_and_wrap(profile,current):
 image,m=memory(profile);put(m,COUNT,1,2);put(m,APP+0x7c2,5,2)
 record=struct.pack('>3HI7H',10,24,36,INPUT,2,2,0,3,current,0x5aa5,2);m[RECORDS:RECORDS+24]=record
 frames=(INPUT+0x40,INPUT+0x80)
 for i,p in enumerate(frames):
  put(m,INPUT+4*i,p)
  for j in range(16):put(m,p+2*j,((i+1)*0x1234+j*0x111)&65535,2)
 m[0x68000:0x80000]=b'\xa5'*0x18000;put(m,STACK,RETURN);before=bytearray(m)
 before[0xe144]=0x70;before[0xe145]=2;put(before,APP+0x7c2,0,2)
 for at in(RECORDS+3*24+16,RECORDS+4*24+16):put(before,at,100,2)
 put(before,RECORDS+14,3,2);put(before,RECORDS+18,2 if current==1 else 1,2)
 source=frames[current-1]
 for row in range(2):
  for group in range(2):
   words=bytes(m[source+row*16+group*8:source+row*16+group*8+8])
   if profile=='amiga':
    for plane in range(4):
     at=0x70000+10+40*row+2*group+0x2000*plane;before[at:at+2]=words[2*plane:2*plane+2]
   else:
    for base in(0x68000,0x70000,0x78000):
     at=base+(24 if profile=='colour'else 36)+160*row+(8 if profile=='colour'else 4)*group
     if profile=='colour':before[at:at+8]=words
     else:before[at:at+4]=words[:4];before[at+80:at+84]=words[4:]
 invoke(image,m);before[STACK-60:STACK+4]=bytes(m[STACK-60:STACK+4]);assert bytes(m)==before
 assert get(m,RECORDS+20,2)==0x5aa5 # Unread WORD,not an invented state field.


def test_fixed_record_bounds_and_all_directory_slots_have_original_consumers(earlier_image):
 old=earlier_image[0];raw=program('st')[0];assert get(raw,COUNT-4096,2)==8;claimed=set()
 for i in range(8):
  new=raw[RECORDS-4096+24*i:RECORDS-4096+24*(i+1)];before=bytearray(old[0x4e8ba-4096+24*i:0x4e8ba-4096+24*(i+1)])
  put(before,6,get(before,6)+0x19ac);assert new==before
  pointer=get(new,6);n=get(new,22,2);claimed.update(range(pointer,pointer+4*n))
 for at,n in ((0x503ae,8),(0x503ce,4),(0x503de,6),(0x503f6,4),(0x50406,4)):claimed.update(range(at,at+4*n))
 assert claimed==set(range(DIRECTORY,ASSETS))
 refs=struct.unpack('>64I',raw[DIRECTORY-4096:ASSETS-4096]);previous=struct.unpack('>64I',old[0x4e97a-4096:0x4ea7a-4096])
 assert refs==tuple(p+0x19ac for p in previous)and len(set(refs))==54
 assert raw[ASSETS-4096:0x54dc6-4096]==old[0x4ea7a-4096:0x5341a-4096]
 # This proves stored identity;ST mono conversion is an existing separate check.


@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_records_and_shared_frame_directory_preserve_gap_and_field_roles(tmp_path):
 import json,subprocess
 from pathlib import Path
 target=Path(__file__).resolve().parents[1]/'targets/starglider2_retail';directory=target/'rendered';meta=json.loads((target/'target_metadata.json').read_text());source=(directory/'retail-shared.s').read_text()
 symbols=dict(update_panel_animations=0x4ff78,update_panel_animations_bridge=0x3392,panel_slot6_frame_family=STATE,panel_animation_count=COUNT,panel_animation_records=RECORDS,panel_frame_references=DIRECTORY,SG2PanelAnimationRecord_amiga_destination_byte_offset=0,SG2PanelAnimationRecord_st_colour_destination_byte_offset=2,SG2PanelAnimationRecord_st_mono_destination_byte_offset=4,SG2PanelAnimationRecord_frame_directory=6,SG2PanelAnimationRecord_reload_countdown=16,SG2PanelAnimationRecord_current_frame=18,SG2PanelAnimationRecord_frame_count=22)
 assert not any(e['type']=='data'and e['addr']<=STATE-4096+2<(e.get('end')or e['addr'])for e in meta['seeded_entities'])
 assert 'SG2PanelAnimationRecord_unread'not in source
 assert 'SG2PanelAnimationRecord_reload_countdown(a5)'in source
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 result=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True);assert result.returncode==0,result.stdout+result.stderr
 raw=out.read_bytes();n=4*len(symbols);assert raw[:-n]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-n:])==tuple(symbols.values())

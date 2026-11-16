"""Retail body-cache and surface/space transitions on original instructions.

Supplied nearby lists and RAM prove finite paths. These are constructed CPU
checks, not a natural planetfall, universal tag bounds or pointer lifetimes.
"""
import ctypes,os
import pytest
from tests import test_starglider2_body_cache_exit as oracle
from tests.test_starglider2_text_editor import state,run,put,get,APP,INPUT
from test_starglider2_retail_input import program
from test_starglider2_retail_encounters import word
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')

@pytest.fixture(params=('amiga','st'))
def machine(request,monkeypatch):
 image=program(request.param);m=(ctypes.c_uint8*0xa1000)();ctypes.memmove(ctypes.addressof(m)+4096,image[0],len(image[0]))
 def retail_run(image,m,c,stops,*args,**kw):
  delta=0x195e if c.pc<0x33b3a else 0x195c
  c.pc+=delta;run(image,m,c,{p+delta for p in stops},*args,**kw);c.pc-=delta
 monkeypatch.setattr(oracle,'run',retail_run)
 for k,v in dict(REFY=0x18f02,RADII=0x18eb2,YTHRESH=0x3af18).items():monkeypatch.setattr(oracle,k,v)
 return image,m

@pytest.mark.parametrize('records',(
 [],[(147,[1,2,3],4)],
 [(128,[1,2,3],-1),(129,[4,5,6],32767),(128,[7,8,9],-32768)],
 [(128,[1,2,3],1),(0x8080,[4,5,6],-1),(145,[7,8,9],-32768)],
 [(127,[1,2,3],4),(0xff80,[4,5,6],1)],
))
def test_capture_preserves_word_index_aliases_sign_extension_and_last_writer(machine,records):
 oracle.capture(*machine,records)

@pytest.mark.parametrize('tag,metadata,index',((128,0,0),(129,0xa5a58000,1),(144,65535,16),(145,0x7fffffff,1),(147,65535,19),(0x8080,0x80000000,0x8000),(0xff80,0xfedcba98,0xff00)))
def test_restore_walk_is_21_records_and_only_selected_xyz_reaches_player(machine,tag,metadata,index):
 oracle.restore(*machine,tag,metadata,index)

@pytest.mark.parametrize('index,position,yaw,delta,speed',((0,1,0,0,460),(15,1,2048,0,460),(1,2,0,0,460),(1,1,0,-1,460),(1,1,0,0,459),(1,1,4095,1,460),(1,6,32768,0,32768),(1,7,65535,0,65535)))
def test_exit_gate_retains_original_n_only_predicates(machine,index,position,yaw,delta,speed):
 oracle.test_surface_exit_height_angle_and_speed_use_original_n_predicates(*machine,index,position,yaw,delta,speed)

@pytest.mark.parametrize('index,y,radius',((0,0,1),(1,-1,-1),(15,0x7fffffff,0x80000000)))
def test_restored_height_uses_saved_selector_and_arithmetic_half(machine,index,y,radius):
 image,m=machine;put(m,APP+0x708,y&0xffffffff);word(m,APP+0x830,index^7);put(m,0x18eb2+4*index,radius&0xffffffff)
 expected=(y+2*get(m,0x18f02+4*index)-(oracle.signed(radius,32)>>1)-200)&0xffffffff
 c=state(m,0x358c2);c.d[7]=0xbeef0000|index;before=bytearray(m);put(before,APP+0x708,expected);before[0xe145]=0x89
 run(image,m,c,{0x358f6});assert bytes(m)==before


def initialized_transition(machine,body=1):
 image,m=machine
 put(m,APP+0x44,0x15808);put(m,APP+0x48,0x16008)
 put(m,APP+0x60,0x12345678);put(m,APP+0x64,0xabcdef01)
 word(m,APP+0x830,body);word(m,APP+0x798,body)
 word(m,APP+0x7ae,0);word(m,APP+0x7b4,1);put(m,0xe0c2,0)
 return image,m


@pytest.mark.parametrize('ordinary',(False,True))
def test_actual_planetfall_reaches_cache_then_pool_rebuild_without_mock_calls(machine,ordinary):
 image,m=initialized_transition(machine);record=INPUT+0x400;player=INPUT+0x700;refs=INPUT+0x200
 word(m,APP+0x75e,1);put(m,APP+0x6c8,refs);put(m,refs,record);word(m,record,129)
 for off,value in ((4,10),(8,20),(12,30)):put(m,record+off,value)
 word(m,record+32,0x8001);word(m,record+38,0);word(m,record+40,0);word(m,record+42,400)
 m[0x6c53]=0;m[APP+0x77d]=255;put(m,APP+0x700,player)
 if ordinary:
  extra=INPUT+0x500;word(m,APP+0x75e,2);put(m,refs+4,extra);word(m,extra,1)
  for off,value in ((4,111),(8,222),(12,333)):put(m,extra+off,value)
 c=state(m,0x3524c);seen=[]
 run(image,m,c,{0x35a06},lambda pc:seen.append(pc) if pc in (0x35464,0x35498,0x19650,0x38b32,0x3553e)else None,limit=180000)
 assert all(pc in seen for pc in (0x35464,0x35498,0x19650,0x38b32,0x3553e))
 assert m[APP+0x77d]==0 and m[APP+0xaa5]==255 and get(m,APP+0x798,2)==1
 assert [get(m,APP+0x88c+off)for off in(0,4,8,12)]==[10,20,30,0xffff8001]
 assert get(m,APP+0x700)==APP+0x2330 and get(m,APP+0x2330,2)==30
 assert get(m,APP+0x9b0)==0 and bytes(m[APP+0xa02:APP+0xa2a])==bytes(40)
 if ordinary:
  assert [get(m,0x3b4d0+off,2)for off in(0,2,4,6,8)]==[1,111,222,333,65535]
  recreated=APP+0x2330+249*68
  assert get(m,recreated,2)==1
  # The original recreator stores all three coordinates into X. Preserve that
  # behavior: the last Z store wins; freshly cleared Y/Z remain zero.
  assert [get(m,recreated+off)for off in(4,8,12)]==[(get(m,APP+0x70c)+333)&0xffffffff,0,0]



def test_actual_exit_rebuild_restores_selected_body_and_rejoins_readiness(machine):
 image,m=initialized_transition(machine);m[APP+0x77d]=0;m[APP+0xaa5]=0
 word(m,APP+0x744,239);word(m,APP+0x748,0);word(m,APP+0x75a,460)
 ref=get(m,0x18f06);put(m,APP+0x708,ref);cache=APP+0x88c
 coords=(123456,654321,234567)
 for off,value in zip((0,4,8,12),(*coords,0xffff8001)):put(m,cache+off,value)
 c=state(m,0x3572c);seen=[]
 run(image,m,c,{0x35a06},lambda pc:seen.append(pc)if pc in(0x38ad2,0x19650,0x3d712,0x35874,0x38b32,0x39146)else None,limit=180000)
 assert all(pc in seen for pc in(0x38ad2,0x19650,0x3d712,0x35874,0x38b32,0x39146))
 assert m[APP+0x77d]==255 and get(m,APP+0x798,2)==0 and m[APP+0xa7d]==255
 pool=APP+0x2330;actors=[pool+68*i for i in range(1,22)];selected=[p for p in actors if get(m,p,2)==129];assert len(selected)==1
 assert [get(m,selected[0]+off)for off in(4,8,12)]==list(coords) and get(m,selected[0]+32,2)==0x8001
 height=(coords[1]+2*ref-(oracle.signed(get(m,0x18eb6),32)>>1)-200)&0xffffffff
 assert [get(m,APP+off)for off in(0x704,0x708,0x70c)]==[coords[0],height,coords[2]]
 assert [get(m,cache+off)for off in(0,4,8,12)]==[*coords,0xffff8001]
 assert get(m,APP+0x9b0)==0 and bytes(m[APP+0xa02:APP+0xa2a])==bytes(40)

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_cache_symbols_and_table_boundaries(tmp_path):
 import struct,subprocess
 from pathlib import Path
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered';source=(directory/'retail-shared.s').read_text()
 symbols={'capture_next_nearby_body_cache_record':0x35464,'rebuild_surface_pool_then_restore_nearby_objects':0x35498,'update_point_field_flag_from_world_y':0x3572c,'restore_next_cached_body_record':0x35874,'derive_post_restore_player_height':0x358c2,'restore_nearby_objects_after_body_cache':0x358f6,'nonmodel_object_base_radii':0x18eb2,'flight_point_field_y_thresholds':0x3af18,'world_departure_moon_flags':0x3a18a,'SG2BodyCacheActor_cached_state_word20':32}
 assert source.count('SG2BodyCacheActor_cached_state_word20(a1)')==2
 assert source.count('bsr.w initialize_world_object_pool_bridge')>=2
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert r.returncode==0,r.stdout+r.stderr
 raw=out.read_bytes();n=4*len(symbols);assert raw[:-n]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-n:])==tuple(symbols.values())

@pytest.mark.parametrize('space',(0,255))
def test_unchanged_space_snapshot_skips_all_rebuild_calls(machine,space):
 image,m=machine;m[APP+0x77d]=m[APP+0xaa5]=space
 c=state(m,0x357ae)
 # Set the stack before taking the expected image; no call runs on this path.
 before=bytearray(m);before[0xe145]=0x83
 run(image,m,c,{0x35952},limit=10);assert bytes(m)==before

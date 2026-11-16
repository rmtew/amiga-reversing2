"""Body selection, surface entry and environment consumers on original CPUs.

Constructed lists and state prove these finite paths, not a natural planetfall,
valid selector domains, full rebuilding, hardware scanout or pointer lifetimes.
"""
import ctypes,os
import pytest
from tests.test_starglider2_text_editor import state,run,put,get,APP,INPUT
from tests import test_starglider2_world_selection as selection
from tests import test_starglider2_world_service_phases as service
from test_starglider2_retail_input import program
from test_starglider2_retail_encounters import word
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
DELTA=0x195e;MATERIAL=0x30dee

@pytest.fixture(params=('amiga','st'))
def machine(request,monkeypatch):
 image=program(request.param);m=(ctypes.c_uint8*0xa1000)();ctypes.memmove(ctypes.addressof(m)+4096,image[0],len(image[0]))
 def retail_run(image,m,c,stops,*args,**kw):
  c.pc+=DELTA;run(image,m,c,{p+DELTA for p in stops},*args,**kw);c.pc-=DELTA
 monkeypatch.setattr(selection,'run',retail_run);monkeypatch.setattr(selection,'FLAGS',0x6c52)
 monkeypatch.setattr(service,'run',retail_run)
 return image,m

@pytest.mark.parametrize('space,y,body',((0,-1999,0),(0,-2000,16),(1,-3999,2),(0,-4000,5),(0,-7999,16),(0,-8000,1),(128,-1,1),(0,120,1),(0,0x80000000,1),(0,-2000,17),(0,-4000,65535)))
def test_material_selection_reuses_independent_n_only_and_alias_oracle(machine,space,y,body):
 image,m=machine;symbols={k:APP+v for k,v in [('space_environment_flag',0x77d),('player_world_y',0x708),('selected_celestial_body_index',0x830)]}
 symbols.update(special_mesh_material_index=MATERIAL,world_low_altitude_mesh_material_indices=0x3b216,world_middle_altitude_mesh_material_indices=0x3b238,world_high_altitude_mesh_material_indices=0x3b25a)
 service.test_altitude_material_profile_retains_n_only_limits_and_unchecked_body_aliases(image,m,symbols,space,y,body)

@pytest.mark.parametrize('records,world',(([],(0,0,0)),([(1,(0,0,0)),(145,(0,0,0))],(0,0,0)),([(129,(10,0,0)),(130,(0,-10,0))],(0,0,0)),([(129,(-0x80000000,0,0)),(130,(1,0,0))],(0,0,0))))
def test_candidate_order_and_stale_selection_reuse_existing_oracle(machine,records,world):
 image,m=machine;selection.test_selection_preserves_stale_state_last_ties_and_long_overflow(image,m,records,world)

@pytest.mark.parametrize('tag,flag,depth,x,y,index',((129,0,305,0,0,1),(129,0,305,144,0,1),(129,0,305,0,49,1),(129,0,304,0,0,1),(129,128,400,0,0,1),(132,0,400,0,0,1),(144,0,400,0,0,1),(129,0,400,0,0,0),(129,0,305,-32768,0,1),(129,0,32768,0,0,1)))
def test_projected_entry_windows_and_zero_index_response_reuse_original_oracle(machine,tag,flag,depth,x,y,index):
 image,m=machine;selection.surface(image,m,tag,flag,depth,x,y,index)

@pytest.mark.parametrize('body',(1,8,15))
def test_accepted_candidate_reaches_real_capture_and_world_entry_pose(machine,body):
 image,m=machine;record=INPUT+0x400;player=INPUT+0x700;refs=INPUT+0x200
 word(m,APP+0x75e,1);put(m,APP+0x6c8,refs);put(m,refs,record);word(m,record,128+body)
 for off,value in ((4,10),(8,20),(12,30)):put(m,record+off,value)
 word(m,record+38,0);word(m,record+40,0);word(m,record+42,400);m[0x6c52+body]=0
 m[APP+0x77d]=255;put(m,APP+0x700,player);word(m,APP+0x9ae,0)
 # The actual nearby-capture helper skips this celestial record; no state
 # injection or mocked game calls occur between selection and entry pose.
 c=state(m,0x3524c);run(image,m,c,{0x35398},limit=3000)
 assert m[APP+0x77d]==0 and m[APP+0xaa5]==255 and get(m,APP+0x830,2)==body
 run(image,m,c,{0x35454},limit=3000)
 mask=get(m,0x18f62+4*body);height=(get(m,0x18f02+4*body)+200)&0xffffffff
 assert [get(m,APP+off)for off in(0x704,0x708,0x70c)]==[mask>>1,height,mask>>1]
 assert [get(m,player+off)for off in(4,8,12)]==[mask>>1,height,mask>>1]
 assert [get(m,APP+off,2)for off in(0x744,0x746,0x748)]==[0xf0a,0,0]
 assert [get(m,player+off,2)for off in(16,18,20)]==[0xf0a,0,0]
 assert m[APP+0xbb9]==1 and get(m,MATERIAL,2)==get(m,0x3b25a+2*body,2)
 assert get(m,APP+0x7b0,2)==get(m,0x6bfa+2*body,2) and get(m,APP+0x798,2)==body
 assert get(m,APP+0x9ae,2)==get(m,APP+0xa74,2)==0 and m[APP+0xa7e]==0

@pytest.mark.parametrize('body,flag',((1,0),(2,127),(8,128),(15,255)))
def test_planetfall_notice_and_atmosphere_sign_select_the_actual_message_path(machine,body,flag):
 image,m=machine;word(m,APP+0x830,body);m[0x394aa+body]=flag;word(m,APP+0x7ae,0);word(m,APP+0x7b4,33)
 put(m,0xe0c2,0);put(m,0xe0c6,0xdeadbeef)
 c=state(m,0x3553e);run(image,m,c,{0x35a06},limit=5000)
 detected=bool(flag&128);assert m[APP+0xbb7]==(255 if detected else 0)
 # Actual queue insertion adds its spacer for the empty first item, and the
 # fourth explicit item is the standard blank-event pointer.
 expected=[get(m,0x39e56+4*body),0xe0fa,get(m,0x394ba+4*(11 if detected else 10)),get(m,0x394ba+4),get(m,0x394ba+4*35)]
 assert get(m,APP+0x7ae,2)==len(expected) and get(m,APP+0x7b4,2)==0
 assert [get(m,0xe0c6+4*i)for i in range(len(expected))]==expected

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_environment_symbols_and_finite_data_owners(tmp_path):
 import struct,subprocess
 from pathlib import Path
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered';source=(directory/'retail-shared.s').read_text()
 symbols={'test_selected_body_surface_entry':0x352ca,'clear_space_state_for_surface_entry':0x3533e,'world_low_altitude_mesh_material_indices':0x3b216,'world_middle_altitude_mesh_material_indices':0x3b238,'world_high_altitude_mesh_material_indices':0x3b25a,'world_atmosphere_base_rgb_words':0x3b29c,'world_atmosphere_altitude_shifts':0x3b2bc,'world_atmosphere_presence_flags':0x394aa,'planetfall_message_pointers':0x39e56,'SG2BodyEntryWorkspace_world_transition_space_snapshot':0xaa5}
 assert 'SG2BodyEntryWorkspace_world_transition_space_snapshot(a6)'in source
 block=source.split('planetfall_message_pointers:',1)[1].split('taymar_offer_dialogue_pointers:',1)[0]
 assert block.count('dc.l ')==16 and '$0003'not in block,block
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert r.returncode==0,r.stdout+r.stderr
 raw=out.read_bytes();n=4*len(symbols);assert raw[:-n]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-n:])==tuple(symbols.values())

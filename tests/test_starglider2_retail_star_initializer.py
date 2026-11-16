"""Actual retail star initialization and constructed placement/colour paths.

The older arithmetic oracle is reused with actual retail lookup words. Static
and supplied-record dispatch are not evidence of ordinary gameplay reachability.
"""
import ctypes,json,os,struct
from pathlib import Path
import pytest
from tests import test_starglider2_radial_initializers as oracle
from tests.test_starglider2_motion_integration import expected_vector
from tests.test_starglider2_palette_priority import rng
from tests.test_starglider2_text_editor import state,run,put,get,APP,INPUT,RETURN
from tests.test_starglider2_retail_world_placement import catalogue
from test_starglider2_retail_input import program
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
ENTRY,CHOICES=0x1a0d4,0x1a200
FIELDS=dict(initialize_star_radius_position_and_colour=ENTRY,nonmodel_object_base_radii=0x18eb2,SG2RadialObject_base_radius=34,SG2RadialObject_radius_work_value=54,SG2StarObject_primary_colour_index=16,SG2ObjectCore_durability_or_negative=28)


@pytest.fixture(params=('amiga','st'))
def retail(request):
 image=program(request.param);m=(ctypes.c_uint8*0xa1000)();ctypes.memmove(ctypes.addressof(m)+4096,image[0],len(image[0]))
 put(m,APP+0x44,0x15808);put(m,APP+0x48,0x16008);return image,m


@pytest.mark.parametrize('incoming,seed',((0,(0,0)),(4095,(0xffffffff,0x80000000)),(0x12345678,(0x12345678,0x90abcdef))))
def test_older_oracle_matches_both_retail_images_and_existing_star_colour_consumer(retail,monkeypatch,incoming,seed):
 image,m=retail;seen=[]
 monkeypatch.setattr(oracle,'expected_vector',lambda m,a,s:expected_vector(m,a,s,tables=(0x15808,0x16008)))
 def observed(image,m,c,stops):
  def trace(pc):
   if pc in(0x1a228,0x1a22e):seen.append((pc,c.d[3]&65535))
  run(image,m,c,stops,trace)
 monkeypatch.setattr(oracle,'run',observed)
 oracle.test_star_uses_inherited_magnitude_and_four_prng_advances(image,m,FIELDS,incoming,seed)
 assert [pc for pc,_ in seen].count(0x1a228)==4
 assert [value for pc,value in seen if pc==0x1a22e]==[(incoming&4095)+20480]
 assert bytes(m[CHOICES:CHOICES+8])==bytes((0,3,0,3,0,1,0,1))
 # Connect the initialized WORD to the already qualified real renderer read.
 packet=INPUT+0x800;m[packet:packet+16]=b'\xcc'*16;c=state(m,0x68cc);c.a[4]=INPUT;c.a[1]=packet
 colour=get(m,INPUT+16,2);run(image,m,c,{0x68fa},limit=3)
 assert bytes(m[packet:packet+16])==b'\xcc'*4+colour.to_bytes(2,'big')+b'\xcc'*10


def test_only_verified_static_initializer_slot_and_media_domain_are_claimed():
 raw=program('st')[0];pointers=struct.unpack_from('>148I',raw,0x197aa-4096)
 assert [i for i,p in enumerate(pointers)if p==ENTRY]==[147]
 assert 147 not in catalogue()['type_domain']['special_draw_reader_words']
 # Known original static maps do not supply147;no dynamic/boot exclusion is
 # inferred merely from that catalogue or absence of a direct BSR/JMP.


def test_supplied_type147_placement_reaches_real_dispatch_and_initializer(retail):
 image,m=retail;actor=INPUT+0x1000;m[actor:actor+68]=b'\xcc'*68
 m[INPUT:INPUT+10]=struct.pack('>HII',147,1234,5678);put(m,APP+0x60,0x12345678);put(m,APP+0x64,0x90abcdef)
 c=state(m,0x19712);c.a[0]=actor;c.a[1]=INPUT;c.a[3]=0x195cc;c.a[4]=0x18b8e;c.d[4]=0xffffffff;c.d[3]=0x12345678;events=[]
 run(image,m,c,{0x1974c},lambda pc:events.append(pc)if pc in(0x1974a,ENTRY,0x1a228,0x1a22e)else None)
 assert events.count(0x1974a)==events.count(ENTRY)==events.count(0x1a22e)==1 and events.count(0x1a228)==4
 assert get(m,actor,2)==147 and c.a[0]==actor and c.a[1]==INPUT+10 and c.d[3]==0x12345678
 a,b=0x12345678,0x90abcdef
 for _ in range(4):a,b=rng(a,b)
 assert(get(m,APP+0x60),get(m,APP+0x64))==(a,b)
 assert get(m,actor+16,2)==m[CHOICES+(b&7)]and get(m,actor+34)==get(m,actor+54)==get(m,0x18efe)
 assert m[actor+3]==0 and m[actor+28]==(m[0x195cc+147]|128)and m[actor+29]==m[0x18b8e+147]and m[actor+30]==255
 assert bytes(m[actor+18:actor+28])==b'\xcc'*10 # Untouched orientation/relative fields.


@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_initializer_uses_star_view_and_only_eight_colour_choice_bytes(tmp_path):
 import subprocess
 target=Path(__file__).resolve().parents[1]/'targets/starglider2_retail';directory=target/'rendered';meta=json.loads((target/'target_metadata.json').read_text());source=(directory/'retail-shared.s').read_text()
 symbols=dict(initialize_star_radius_position_and_colour=ENTRY,choose_star_initial_pitch=0x1a0f8,star_initial_primary_colour_choices=CHOICES,advance_world_initializer_random_state_bridge=0x1a228,build_world_initializer_motion_vector_bridge=0x1a22e,SG2StarDiscActor_primary_colour_index=16)
 assert not any(e['type']=='data'and e['addr']<=CHOICES+8-4096<(e.get('end')or e['addr'])for e in meta['seeded_entities'])
 block=source.split('initialize_star_radius_position_and_colour:',1)[1].split('initialize_radial_body_radii_and_hide_contact:',1)[0]
 assert 'SG2StarDiscActor_primary_colour_index(a0)'in block and 'SG2RadialProjectionActor_source_radius(a0)'in block
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True);assert r.returncode==0,r.stdout+r.stderr
 raw=out.read_bytes();n=4*len(symbols);assert raw[:-n]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-n:])==tuple(symbols.values())

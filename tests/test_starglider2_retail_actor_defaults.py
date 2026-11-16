"""Model default prefixes and phase-specific original actor construction.

Reuse original jettison/encounter/placement witnesses. These bounded views do
not turn the original unchecked indices into a universal actor type guarantee.
"""
import json,os,struct
from pathlib import Path
import pytest
from tests import test_starglider2_retail_inventory as inventory
from tests import test_starglider2_retail_encounters as encounters
from tests.test_starglider2_retail_variant_cycles import machine,shared_bytes,ACTOR
from tests.test_starglider2_retail_world_placement import catalogue
from tests.test_starglider2_retail_model_headers import models
from test_starglider2_retail_input import program
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
MOTION,MODE,N=0x194f0,0x195cc,104
CHOICES=(0x3b336,0x3b356,0x3b376,0x3b396,0x3b3b6,0x3b3d6,0x3b436,0x3b456,0x3b476)


def bounded(c):
 c.known[MOTION+2*N:MODE]=bytes(MODE-MOTION-2*N)
 c.known[MODE+N:0x1963a]=bytes(0x1963a-MODE-N)
 return c


def test_established_producer_catalogues_fit_the_model_prefix_not_all_actor_tags():
 raw=shared_bytes();domain=catalogue()['type_domain'];placed={v&255 for v in domain['model_path_reader_words']}
 choices={struct.unpack_from('>H',raw,p-4096+2*i)[0]for p in CHOICES for i in range(16)}
 headers={i for model in models('st')for i in model['ordinals']}
 assert headers==set(range(N))and max(placed)==102 and max(choices)==91
 assert placed|choices<=headers and domain['special_draw_reader_words']==list(range(128,146))
 # Execute the actual builder:103 is offered,while adjacent104 is not.
 c=inventory.base();c.seed(inventory.COUNTS+103,b'\1\1');c.run(0x1dce,inventory.RETURN,2000)
 assert c.read(inventory.TAGS,1)==b'\x67'and c.read(inventory.QTY,2)==b'\1\xff'
 assert c.read(inventory.POINTERS+4,4)==b'\xff'*4


@pytest.mark.parametrize('kind',(17,89,103))
def test_original_jettison_oracle_reads_raw_signed_scale_through_last_model(monkeypatch,kind):
 original=inventory.drop_fixture
 monkeypatch.setattr(inventory,'drop_fixture',lambda *a,**kw:bounded(original(*a,**kw)))
 inventory.test_real_constructor_and_motion_helper_publish_jettisoned_record(kind,0,0,(0,0,0))


@pytest.mark.parametrize('kind',(17,89))
def test_real_encounter_choice_halves_negative_odd_scale_and_preserves_partial_record(kind):
 raw=shared_bytes();at,index=next((p,i)for p in CHOICES for i in range(16)if struct.unpack_from('>H',raw,p-4096+2*i)[0]==kind)
 c=bounded(inventory.base());before=b'\xa5'*68;c.seed(inventory.ACTOR,before);c.allow_write(inventory.ACTOR,68)
 c.cpu.a[0]=at;c.cpu.a[4]=inventory.ACTOR;c.cpu.d[0]=2*index
 c.run(0x3518e,0x351f4,100);wanted=encounters.constructor(c.memory,kind,before)
 assert c.read(inventory.ACTOR,68)==wanted
 stored=struct.unpack_from('>h',raw,MOTION-4096+2*kind)[0];result=struct.unpack('>h',c.read(inventory.ACTOR+32,2))[0]
 assert stored in(-175,-45)and result==stored//2 # Arithmetic shift rounds negative odds down.


@pytest.mark.parametrize('kind',(130,145))
def test_radial_placement_reads_adjacent_code_then_sets_high_bit_without_model_semantics(kind):
 raw=shared_bytes();c=bounded(machine(kind));before=bytearray(b'\xa5'*68);before[:2]=kind.to_bytes(2,'big');c.seed(ACTOR,before);saved_a2=c.cpu.a[2]
 source=MODE+kind;value=raw[source-4096]
 assert source>=0x1963a # A code BYTE,not an extension of the model-mode table.
 c.run(0x19728,0x1972e,1);assert c.read(ACTOR+28,1)==bytes([value])
 c.run(0x1972e,0x1974c,100)
 before[28]=value|128;before[29]=raw[0x18b8e-4096+kind];before[30]=255;before[3]=0
 radius=raw[0x18eb2-4096+4*(kind-128):0x18eb2-4096+4*(kind-128)+4];before[34:38]=before[54:58]=radius
 before[8:12]=(-20000000 if kind==130 else -100000).to_bytes(4,'big',signed=True)
 if kind==145:before[2]|=16
 assert c.read(ACTOR,68)==before and c.cpu.a[2]==saved_a2
 # No durability meaning is assigned to these inherited low bits or to the
 # radial radius/cache overlay at the model motion/relative-coordinate slots.


def test_supplied_index104_is_outside_the_published_model_default_view():
 c=bounded(inventory.drop_fixture(104))
 with pytest.raises(ValueError,match='unknown read/fetch')as failure:c.run(0x1c64,0x1bd2,2000)
 assert f'0, {MODE+104}, 1'in str(failure.value)


@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_model_prefixes_leave_tails_and_radial_code_ownership_intact(tmp_path):
 import subprocess
 target=Path(__file__).resolve().parents[1]/'targets/starglider2_retail';directory=target/'rendered';meta=json.loads((target/'target_metadata.json').read_text());source=(directory/'retail-shared.s').read_text()
 symbols=dict(actor_default_motion_words=MOTION,actor_initial_behavior_modes=MODE,actor_type_004_initial_behavior_mode=MODE+4,actor_type_019_initial_behavior_mode=MODE+19,initialize_celestial_body_radius_and_y=0x1a0a6,initialize_radial_body_radii_and_hide_contact=0x1a176)
 for pc in(MOTION+2*N,MODE+N,MODE+130):assert not any(e['type']=='data'and e['addr']<=pc-4096<(e.get('end')or e['addr'])for e in meta['seeded_entities'])
 assert 'move.w $0(a0,d0.w),SG2SoundActor_motion_vector_scale(a2)'in source
 for name in('initialize_celestial_body_radius_and_y','initialize_radial_body_radii_and_hide_contact'):
  body=source.split(name+':',1)[1].split('\trts',1)[0];assert 'SG2RadialProjectionActor_scaled_radius(a0)'in body and 'SG2RadialProjectionActor_source_radius(a0)'in body
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 result=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True);assert result.returncode==0,result.stdout+result.stderr
 raw=out.read_bytes();n=4*len(symbols);assert raw[:-n]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-n:])==tuple(symbols.values())

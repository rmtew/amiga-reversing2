"""Three original height-limit consumers with shared existing boundary oracle.

Thresholds compare world Y,not velocity. CPU states are supplied;these are not
ordinary-play reachability or unrestricted actor-index guarantees.
"""
import os,struct
from pathlib import Path
import pytest
from tests import test_starglider2_actor_dispatch as oracle
from tests.test_starglider2_retail_variant_cycles import shared_bytes
from tests.test_starglider2_retail_inheritance import context,APP
from test_starglider2_retail_input import program
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
POS,NEG,ACTOR=0x1934c,0x1941e,0xd0000
IDS=(7,13,16,18,21,27,28,29,31,32,33,35,41,45)


def test_existing_independent_height_oracle_retains_equal_and_four_inverted_pairs():
 oracle.test_type_indexed_vertical_thresholds_preserve_order_and_inverted_pairs()


def test_original_second_phase_directory_bounds_the_qualified_threshold_domain():
 raw=shared_bytes();table=0x8230;entries=struct.unpack_from('>148h',raw,table-4096)
 assert tuple(i for i,off in enumerate(entries)if table+off==0xa6a0)==IDS
 assert max(IDS)==45 and 2*(max(IDS)+1)==92
 for kind in IDS:oracle.dispatch(raw,kind,expected=0xa6a0)


def fixture(root,kind,height,velocity=0,state=6,override=0,*,negative_known=True):
 c=context('st');raw=shared_bytes();actor=bytearray(68);struct.pack_into('>H',actor,0,kind);actor[28]=state
 struct.pack_into('>I',actor,8,(height-velocity)&0xffffffff);struct.pack_into('>h',actor,46,velocity);struct.pack_into('>H',actor,38,override)
 c.seed(ACTOR,actor);c.allow_write(ACTOR,68);c.cpu.a[0]=ACTOR;c.allow_write(0xe145,1)
 c.seed(APP+0x6fc,b'\xff'*4);c.seed(APP+0x700,bytes(4))
 # Supply only the selected threshold cells. Lower and skipped gates must
 # not depend on neighbouring values or speculative full-table storage.
 c.known[POS:NEG+210]=bytes(NEG+210-POS)
 c.seed(POS+2*kind,raw[POS-4096+2*kind:POS-4096+2*kind+2])
 if negative_known:c.seed(NEG+2*kind,raw[NEG-4096+2*kind:NEG-4096+2*kind+2])
 return c


@pytest.mark.parametrize('root,state,active',((0x8c1e,2,False),(0x8c1e,255,True),(0x901c,2,False),(0x901c,130,True),(0x901c,131,False)))
def test_steering_state_gates_preserve_unsigned_vs_n_only_byte_predicates(root,state,active):
 kind=7 if root==0x8c1e else 13;c=fixture(root,kind,-30000,state=state,negative_known=False)
 if not active:c.known[POS+2*kind:POS+2*kind+2]=bytes(2)
 stop=(0x8ca8 if root==0x8c1e else 0x90be)if active else(0x8d5c if root==0x8c1e else 0x918e)
 c.run(root,stop,100);assert struct.unpack('>h',c.read(ACTOR+46,2))[0]==int(active)


@pytest.mark.parametrize('root,kind,height,velocity,answer',((0x8c1e,7,-500,9,10),(0x8c1e,7,-499,-10,-10),(0x8c1e,27,-1750,10,10),(0x901c,13,-1700,9,10),(0x901c,13,-500,-10,-10)))
def test_steering_thresholds_adjust_one_step_and_keep_signed_ten_caps(root,kind,height,velocity,answer):
 c=fixture(root,kind,height,velocity);c.run(root,0x8ca8 if root==0x8c1e else 0x90be,100)
 assert struct.unpack('>h',c.read(ACTOR+46,2))[0]==answer and int.from_bytes(c.read(ACTOR+8,4),'big',signed=True)==height


@pytest.mark.parametrize('height,answer',((-1700,1),(-1000,-1)))
def test_second_steering_override_follows_positive_height_test_but_bypasses_negative_table(height,answer):
 c=fixture(0x901c,13,height,override=1,negative_known=False);c.run(0x901c,0x90be,100)
 assert struct.unpack('>h',c.read(ACTOR+46,2))[0]==answer


@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_height_views_keep_tails_raw_and_world_y_distinct_from_velocity(tmp_path):
 import json,subprocess
 target=Path(__file__).resolve().parents[1]/'targets/starglider2_retail';directory=target/'rendered';meta=json.loads((target/'target_metadata.json').read_text());source=(directory/'retail-shared.s').read_text()
 symbols=dict(actor_positive_y_velocity_thresholds=POS,actor_negative_y_velocity_thresholds=NEG,move_and_steer_actor_with_y_override=0x901c,set_actor_y_velocity_positive_five=0xa724,set_actor_y_velocity_negative_five=0xa71a)
 for pc in(POS+92,NEG+92):assert not any(e['type']=='data'and e['addr']<=pc-4096<(e.get('end')or e['addr'])for e in meta['seeded_entities'])
 block=source.split('update_actor_vertical_velocity_thresholds:',1)[1].split('integrate_actor_motion_and_turn_timer:',1)[0]
 assert 'SG2ActorModelPrefix_world_y(a0)'in block and 'SG2ActorModelPrefix_velocity_y(a0)'in source.split('set_actor_y_velocity_positive_five:',1)[1].split('\n',3)[1]
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True);assert r.returncode==0,r.stdout+r.stderr
 raw=out.read_bytes();n=4*len(symbols);assert raw[:-n]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-n:])==tuple(symbols.values())

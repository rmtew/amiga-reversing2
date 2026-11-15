"""Recheck transferred matrix/view contracts on old and both retail images.

Synthetic call contexts establish local access/width/lifetime contracts. They
are separate from the already recorded real retail boot/gameplay witnesses.
"""
import hashlib
from functools import cache
import math
import os
from pathlib import Path
import struct
import pytest
from amiga_reversing.disasm.mapped_execution import MappedExecution

pytestmark=pytest.mark.skipif(not os.getenv('SGII_RETAIL_DIRECTORY'),reason='private retail and older reference fixtures')
ROOT=Path(__file__).resolve().parents[1]
APP,SIN,COS,POSE,STACK,RETURN=0xe0000,0xc0000,0xc2000,0xd0000,0xf0000,0xff000
ENTRIES={'old':dict(build=0x184c,transpose=0x1b1e,transform=0x1ba8,matrix=0x1bfc,viewoffset=0x2c74,cockpit=0x2c96),
         'amiga':dict(build=0x1862,transpose=0x1b34,transform=0x1bbe,matrix=0x1c12,viewoffset=0x2c80,cockpit=0x2ca2),
         'st':dict(build=0x1862,transpose=0x1b34,transform=0x1bbe,matrix=0x1c12,viewoffset=0x2c80,cockpit=0x2ca2)}


@cache
def data(platform):
 from amiga_reversing.disasm.game_catalog import load_family,materialize
 if platform=='old':
  family=load_family(ROOT,'starglider2');return materialize(ROOT,'starglider2',family['targets']['amiga_raw_starglider2_game']['artifact']).read_bytes()
 p=Path(os.environ['SGII_RETAIL_DIRECTORY'])
 name='amiga-retail-handoff.private.bin' if platform=='amiga' else 'main_at_st_handoff.bin.private.bin'
 b=(p/name).read_bytes();expected='334f83ec3bdb30e36b2e5c741b7788e4a3489ee15811d11e1e52ef83bd28a938' if platform=='amiga' else '20c19400180d7e846b78aa615b68446293f8ca54015c4f4a42a77f03b24e8260'
 assert hashlib.sha256(b).hexdigest()==expected
 return b


def context(platform):
 cpu=MappedExecution(0x100000,register_seed=0xdeadbeef);cpu.seed(0x1000,data(platform))
 cpu.seed(APP,bytes(0x800));cpu.cpu.a[6]=APP;cpu.cpu.a[7]=STACK
 cpu.seed(STACK,RETURN.to_bytes(4,'big'));cpu.allow_write(STACK-256,256)
 return cpu


def lookup_context(cpu):
 sine=[round(math.sin(i*2*math.pi/4096)*16384) for i in range(4096)]
 cosine=[sine[(i+1024)&4095] for i in range(4096)]
 cpu.seed(SIN,struct.pack('>4096h',*sine));cpu.seed(COS,struct.pack('>4096h',*cosine))
 cpu.seed(APP+0x44,struct.pack('>II',SIN,COS))


def matrix(platform,entry,angles):
 cpu=context(platform);lookup_context(cpu);base=0x1000+ENTRIES[platform]['matrix']
 before=cpu.read(base-2,22);cpu.allow_write(base,18)
 for i,value in enumerate(angles,1):cpu.cpu.d[i]=value&0xffffffff
 cpu.run(0x1000+ENTRIES[platform][entry],RETURN,1500)
 assert cpu.read(base-2,2)==before[:2] and cpu.read(base+18,2)==before[-2:]
 return struct.unpack('>9h',cpu.read(base,18))


@pytest.mark.parametrize('angles',[(0,0,0),(1024,0,0),(0,1024,0),(17,-85,4097),(2047,2048,-4096)])
def test_matrix_build_and_literal_transpose_keep_nine_word_layout(angles):
 outputs=[]
 for platform in ENTRIES:
  built=matrix(platform,'build',angles);transposed=matrix(platform,'transpose',angles)
  assert transposed==tuple(built[row+3*column] for row in range(3) for column in range(3))
  outputs.append(built)
 assert outputs[0]==outputs[1]==outputs[2]
 if angles==(0,0,0):assert outputs[0]==(16384,0,0,0,-16384,0,0,0,-16384)


@pytest.mark.parametrize('coefficients,vector',[
 ((16384,0,0,0,16384,0,0,0,16384),(120,-999,32767)),
 ((32767,32767,32767,-32768,5,-2,700,-900,1000),(32767,32767,-32768)),
 ((0,-16384,0,16384,0,0,0,0,16384),(-12345,789,1)),
])
def test_matrix_consumer_preserves_fixed_point_wrap_and_row_order(coefficients,vector):
 expected=[(sum(coefficients[3*r+i]*vector[i] for i in range(3))&0xffffffff)>>14&65535 for r in range(3)]
 for platform in ENTRIES:
  cpu=context(platform);base=0x1000+ENTRIES[platform]['matrix'];cpu.seed(base,struct.pack('>9h',*coefficients))
  for i,value in enumerate(vector,1):cpu.cpu.d[i]=0xa5a50000|(value&65535)
  saved=(cpu.cpu.d[4],cpu.cpu.d[5],cpu.cpu.a[5]);cpu.run(0x1000+ENTRIES[platform]['transform'],RETURN,100)
  assert [cpu.cpu.d[i]&65535 for i in range(1,4)]==expected
  assert (cpu.cpu.d[4],cpu.cpu.d[5],cpu.cpu.a[5])==saved


@pytest.mark.parametrize('platform',ENTRIES)
def test_lookup_pointer_contract_refuses_unknown_lifetime(platform):
 cpu=context(platform);cpu.seed(APP+0x44,struct.pack('>II',SIN,COS));cpu.allow_write(0x1000+ENTRIES[platform]['matrix'],18)
 # Pointer values alone do not make their pointees valid/readable.
 with pytest.raises(ValueError,match='unknown read/fetch'):
  cpu.run(0x1000+ENTRIES[platform]['build'],RETURN,100)


@pytest.mark.parametrize('platform',ENTRIES)
def test_mapped_player_view_offset_accesses_keep_word_width_and_mask(platform):
 cpu=context(platform);cpu.cpu.a[0]=POSE;pose=bytearray(22);struct.pack_into('>HHH',pose,16,0xff0,0x730,0x910)
 cpu.seed(POSE,pose);cpu.seed(APP+0x7bc,struct.pack('>HH',0x180,0x900));cpu.allow_write(APP+0x7b6,4)
 cpu.run(0x1000+ENTRIES[platform]['viewoffset'],RETURN,30)
 assert cpu.read(APP+0x7b6,4)==struct.pack('>HH',(0xff0+0x180)&4095,(0x730+0x900)&4095)
 assert cpu.read(POSE,22)==pose


@pytest.mark.parametrize('y,space',[(300,0),(-400,0),(300,255)])
def test_mapped_cockpit_initializer_retains_conditional_y_clamp(y,space):
 for platform in ENTRIES:
  cpu=context(platform);cpu.cpu.a[0]=POSE;pose=bytearray(22);pose[2]=0xbd
  struct.pack_into('>iii',pose,4,1234,y,-987);struct.pack_into('>HHH',pose,16,17,23,29)
  cpu.seed(POSE,pose);cpu.seed(APP+0x77d,bytes([space]));cpu.allow_write(POSE+2,1)
  for off,n in [(0x20a,1),(0x710,12),(0x7b6,6)]:cpu.allow_write(APP+off,n)
  cpu.run(0x1000+ENTRIES[platform]['cockpit'],RETURN,60)
  expected_y=y if space or y<-120 else -120
  assert cpu.read(APP+0x710,12)==struct.pack('>iii',1234,expected_y,-987)
  assert cpu.read(POSE+2,1)==b'\xbf'


def signed_word(value):
 value &= 65535
 return value-65536 if value&32768 else value


def test_retail_pilot_accuracy_signed_low_words_and_overflow_mask():
 for platform in ('amiga','st'):
  for hits in (0,1,100,32767,32768,65535,0x12340009):
   for shots in (0,1,100,32767,32768,65535,65536,65537,0xffff0000):
    cpu=context(platform);cpu.cpu.d[0]=hits;cpu.cpu.d[1]=shots
    cpu.seed(APP+0x79c,b'\xbe\xef');cpu.allow_write(APP+0x79c,2)
    divisor=signed_word(shots);stop=0xb11e if not divisor else 0xb136
    cpu.run(0xb116,stop,10)
    if not divisor:assert cpu.read(APP+0x79c,2)==b'\xbe\xef';continue
    dividend=signed_word(hits)*100;q=abs(dividend)//abs(divisor)
    if (dividend<0)!=(divisor<0):q=-q
    expected=(q if -32768<=q<=32767 else dividend)&255
    assert cpu.cpu.d[0]==expected and cpu.read(APP+0x79c,2)==expected.to_bytes(2,'big')


def test_retail_pilot_rank_thresholds_and_physical_pointer_extent():
 for platform in ('amiga','st'):
  raw=data(platform);table=0xb3d8;ptrs=struct.unpack('>16I',raw[table-4096:table-4096+64])
  assert len(set(ptrs))==11 and len(set(ptrs[10:]))==1
  for accuracy in (0,9,10,59,60,69,70,79,100,255):
   for bonus in (0,1,2,6,7,16,17,0x80000000,0xffffffff):
    for damage in (0,599,600,1399,1400,2399,2400,0x80000000,0xffffffff):
     cpu=context(platform);cpu.cpu.d[0]=0
     cpu.seed(APP+0x79c,accuracy.to_bytes(2,'big'))
     cpu.seed(APP+0x6ec,bonus.to_bytes(4,'big'));cpu.seed(APP+0x6f0,damage.to_bytes(4,'big'))
     cpu.run(0xb146,0xb1d6,60)
     base=accuracy//10 if accuracy<70 else 8
     extra=4 if bonus==0x80000000 else 0 if bonus==0xffffffff else sum(bonus>=t for t in (1,2,7,17))
     penalty=3 if damage==0x80000000 else 0 if damage==0xffffffff else sum(damage>=t for t in (600,1400,2400))
     rank=max(0,min(10,base+extra-penalty))
     assert cpu.cpu.d[0]&65535==rank*4 and cpu.cpu.a[0]==table and cpu.cpu.a[1]==ptrs[rank]


@pytest.mark.parametrize('energy,add,bonus,expected',[(65535,1,4,(65535,4)),(65534,1,4,(65535,4)),(65534,2,4,(65535,5)),(1,2,0,(3,0))])
def test_bonus_producer_counts_carry_but_not_already_saturated_energy(energy,add,bonus,expected):
 for platform in ('amiga','st'):
  cpu=context(platform);cpu.cpu.d[1]=add;cpu.seed(APP+0x794,energy.to_bytes(2,'big'));cpu.seed(APP+0x6ec,bonus.to_bytes(4,'big'))
  cpu.allow_write(APP+0x794,2);cpu.allow_write(APP+0x6ec,4)
  cpu.run(0xc40a,0xb9ce,30)
  assert (int.from_bytes(cpu.read(APP+0x794,2),'big'),int.from_bytes(cpu.read(APP+0x6ec,4),'big'))==expected


def test_amiga_row_offset_prefix_writes_exactly_two_hundred_words():
 for platform,entry,base,stop in [('old',0x3e96e,0x416b8,0x3e98e),('amiga',0x4031a,0x43064,0x4033a)]:
  cpu=context(platform);cpu.seed(0x1002,b'\x80\x01');cpu.allow_write(base,400)
  before=cpu.read(base-2,404);cpu.run(entry,stop,1000)
  assert cpu.read(base,400)==struct.pack('>200H',*(i*40 for i in range(200)))
  assert cpu.read(base-2,2)==before[:2] and cpu.read(base+400,2)==before[-2:]


def test_shared_native_export_keeps_semantics_and_symbolic_verdicts():
 source=(Path(os.environ['SGII_RETAIL_RENDERED_SOURCE'])).read_text()
 for name in ('build_three_angle_rotation_matrix','transform_vector_by_built_matrix','set_cockpit_view_from_player','apply_pilot_energy_overflow_rank_bonuses'):
  assert name+':' in source
 assert '\tdc.l pilot_rating_dead_so_soon' in source
 assert source.count('\tdc.l pilot_rating_smug_but_still_dead')==6
 assert '\tdc.b "DEAD SO SOON?",$00' in source
 assert 'SG2RotationMatrixWords_m22 RS.W 1' in source
 assert 'SG2MatrixLookupContext' not in source

"""Original coordinate snapshot, Q14 view transform and connected consumers.

These CPU slices preserve the real nested producer calls. They do not measure
interrupt/display timing or assert that a reused record has a global lifetime.
"""
import os,struct
import pytest
from test_starglider2_retail_frame_lists import setup,partition,pointers,APP,POOL,STACK,RETURN,put,get,shared_bytes
from test_starglider2_retail_sound import address
from tests.test_starglider2_homing_updates import heading
from tests.test_starglider2_object_sound import metric
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
IDENTITY=(16384,0,0,0,16384,0,0,0,16384)
TURN45=(11585,0,11585,0,16384,0,-11585,0,11585)

def signed16(v):return(v+32768)%65536-32768

def transformed(matrix,vector):
 return tuple((((sum(signed16(a)*signed16(v)for a,v in zip(matrix[i:i+3],vector))&0xffffffff)<<2)&0xffffffff)>>16 for i in(0,3,6))

def scene(matrix,origin=(0,0,0)):
 ox,oy,oz=origin;c=setup([(30,origin),(1,(ox+1000,oy,oz+1000)),(1,(ox,oy,oz+1500)),(0,(0,0,0))],origin)
 put(c.memory,APP+0x700,POOL);c.seed(POOL+2,b'\2');c.seed(APP+0x77c,b'\1')
 c.seed(APP+0x106,struct.pack('>9h',*matrix));c.seed(0x5932,b'\0\1');c.allow_write(0x49c2,1)
 return c

def original_producer_calls(c):
 c.cpu.a[6]=APP;c.cpu.a[7]=STACK
 c.run(0x3f12,0x4158,30);assert get(c.memory,c.cpu.a[7])==0x3f2c
 c.run(0x4158,0x4338,2000);assert get(c.memory,c.cpu.a[7])==0x3f3e
 c.run(0x4338,0x3f3e,3000)

def vector(c,record,offset=22):return tuple(get(c.memory,record+offset+2*i,2)for i in range(3))

def bearing(c,record):
 c.cpu.a[0]=record;c.cpu.a[6]=APP;c.cpu.a[7]=STACK;c.cpu.d[0]=c.cpu.d[1]=0
 put(c.memory,STACK,RETURN);c.run(0xaf9c,RETURN,300)
 expected=heading(c.memory,get(c.memory,record+50,2),get(c.memory,record+54,2),get(c.memory,POOL+50,2),get(c.memory,POOL+54,2),table_base=0x15604)
 assert c.cpu.d[1]&65535==expected;return expected

def selected(c,platform):
 c.allow_write(0x4ea00,0x76);c.allow_write(0x4ec02,2);c.allow_write(0x4f740,0xaa);c.allow_write(address(0x39ce0),2)
 c.cpu.a[6]=APP;c.cpu.a[7]=STACK
 if platform=='amiga':
  c.run(address(0x4be58),address(0x4bf46),1000);record=get(c.memory,address(0x4d088))
  assert c.cpu.d[2]&65535==metric(vector(c,record),2)
  return record
 c.run(address(0x4d452),address(0x4d53a),1000);return get(c.memory,address(0x4dda8))

def render_pose(c,record):
 assert record in pointers(c,0x6cc,0x760)
 c.cpu.a[4]=record;c.cpu.a[6]=APP;c.cpu.a[7]=STACK;c.cpu.d[0]=1
 c.run(0x3fac,0x4a42,50)
 assert tuple(get(c.memory,APP+0x132+2*i,2)for i in range(3))==vector(c,record)
 assert tuple(get(c.memory,APP+0x118+2*i,2)for i in range(3))==tuple(get(c.memory,record+16+2*i,2)for i in range(3))

@pytest.mark.parametrize('matrix,winner',((IDENTITY,2),(TURN45,1)))
def test_real_producers_feed_rendering_and_sound_but_preserve_steering_basis(matrix,winner):
 c=scene(matrix,(4096,100,8192));original_producer_calls(c)
 for index,relative in((1,(1000,0,1000)),(2,(0,0,1500))):
  record=POOL+68*index
  assert vector(c,record,50)==relative
  assert vector(c,record)==transformed(matrix,relative)
  render_pose(c,record)
 assert bearing(c,POOL+68)==heading(c.memory,1000,1000,0,0,table_base=0x15604)
 for platform in('amiga','st'):assert selected(c,platform)==POOL+68*winner


def test_world_writes_do_not_refresh_cached_consumers_until_next_scene_snapshot():
 c=scene(TURN45);original_producer_calls(c);record=POOL+68
 before=vector(c,record),vector(c,record,50),bearing(c,record)
 put(c.memory,record+4,4000)
 assert (vector(c,record),vector(c,record,50),bearing(c,record))==before
 assert selected(c,'amiga')==record
 original_producer_calls(c)
 assert vector(c,record,50)==(4000,0,1000)and vector(c,record)==transformed(TURN45,(4000,0,1000))
 assert bearing(c,record)!=before[2]
 for platform in('amiga','st'):assert selected(c,platform)==POOL+136

@pytest.mark.parametrize('matrix,xyz',[(IDENTITY,(32767,-32768,1)),((32767,32767,32767)*3,(32767,32767,32767)),(TURN45,(-30000,12345,30000))])
def test_view_rotation_is_wrapped_word_input_q14_not_float_or_saturating_math(matrix,xyz):
 c=scene(matrix);record=POOL+68;c.cpu.a[4]=record;c.cpu.a[6]=APP;c.cpu.d[0]=1
 for off,value in zip((22,24,26),xyz):put(c.memory,record+off,value,2)
 c.cpu.d[1:4]=[v&65535 for v in xyz]
 c.cpu.a[7]=STACK;c.run(0x43b4,0x440a,100)
 assert vector(c,record)==transformed(matrix,xyz)


def test_main_loop_consumes_scene_cache_before_flight_and_actor_updates():
 raw=shared_bytes()
 def target(pc):
  at=pc-4096;assert raw[at:at+2]==b'\x61\0'
  return pc+2+int.from_bytes(raw[at+2:at+4],'big',signed=True)
 assert [(pc,target(pc))for pc in(0x12b4,0x12c6,0x12fc,0x1314)]==[(0x12b4,0x3df4),(0x12c6,0x34da),(0x12fc,0x340a),(0x1314,0x7fdc)]

@pytest.mark.parametrize('kind,xyz,radius',((128,(100000,0,300000),1<<20),(145,(0,1000,524288),1<<20)))
def test_radial_records_scale_long_deltas_and_reuse_the_model_cache_overlay(kind,xyz,radius):
 from tests.test_starglider2_contact_plot import radial_reference
 c=setup([(kind,xyz),(0,(0,0,0))]);c.seed(APP+0x77c,b'\1');c.seed(APP+0x106,struct.pack('>9h',*IDENTITY))
 c.seed(POOL+50,b'\xa5'*8);put(c.memory,POOL+54,radius);put(c.memory,APP+0x864,1<<18)
 before=c.read(POOL+50,8);partition(c);assert c.read(POOL+50,8)==before
 c.cpu.a[7]=STACK;c.run(0x4338,RETURN,2000)
 shift=radial_reference(xyz);scaled=tuple(v>>shift for v in xyz)
 assert get(c.memory,POOL+44,2)==shift and vector(c,POOL)==transformed(IDENTITY,scaled)
 assert get(c.memory,POOL+34)==((1<<18 if kind==145 else radius)>>shift)
 assert c.read(POOL+50,8)==before

@pytest.mark.parametrize('xyz',((0,0,0),(1024,0,0),(-2147483648,0,1)))
def test_radial_normalizer_keeps_original_wrapped_sign_and_register_contract(xyz):
 from tests.test_starglider2_contact_plot import radial_reference
 c=scene(IDENTITY);c.cpu.a[7]=STACK;put(c.memory,STACK,RETURN)
 c.cpu.d[1:4]=[v&0xffffffff for v in xyz];upper=c.cpu.d[6]&0xffff0000
 c.run(0x48b2,RETURN,100)
 assert tuple(c.cpu.d[1:4])==tuple(v&0xffffffff for v in xyz)
 assert c.cpu.d[6]==upper|radial_reference(xyz)

@pytest.mark.parametrize('y,space,expected',((300,0,-120),(-1000,0,-1000),(300,128,300)))
def test_actual_cockpit_origin_copies_world_units_with_surface_y_clamp(y,space,expected):
 c=scene(IDENTITY,(4096,y,8192));c.seed(APP+0x77d,bytes([space]));c.seed(APP+0x7eb,b'\0')
 for off in(0x7bc,0x7be):put(c.memory,APP+off,0,2)
 c.cpu.a[6]=APP;c.cpu.a[7]=STACK;put(c.memory,STACK,RETURN);c.run(0x3c4c,RETURN,300)
 assert tuple(get(c.memory,APP+off)for off in(0x710,0x714,0x718))==(4096,expected&0xffffffff,8192)

@pytest.mark.parametrize('depth,stop',((128,0x4528),(129,0x44c2),(11999,0x44c2),(12000,0x44b4),(65535,0x4528)))
def test_scene_projection_guard_routes_depth_before_lookup_or_division(depth,stop):
 from amiga_reversing.disasm.mapped_execution import MappedExecution
 raw=shared_bytes();c=MappedExecution(0x100000);c.seed(0x44a8,raw[0x34a8:0x34c2]);c.cpu.d[3]=depth
 c.run(0x44a8,stop,20)

@pytest.mark.parametrize('depth,x,y',((130,32767,-32768),(1001,500,-300),(11999,-32768,32767)))
def test_projection_lookup_uses_even_depth_byte_offset_and_q15_word_products(depth,x,y):
 from amiga_reversing.disasm.mapped_execution import MappedExecution
 raw=shared_bytes();c=MappedExecution(0x100000);c.seed(0x44c2,raw[0x34c2:0x34dc])
 base=0x2c6b8;c.seed(base+130,raw[base-4096+130:base-4096+12000])
 c.cpu.d[1]=x&65535;c.cpu.d[2]=y&65535;c.cpu.d[3]=depth
 c.run(0x44c2,0x44dc,40);factor=signed16(int.from_bytes(raw[base-4096+(depth&65534):base-4096+(depth&65534)+2],'big'))
 assert tuple(c.cpu.d[i]&65535 for i in(1,2))==tuple(((value*factor*2)&0xffffffff)>>16 for value in(x,y))

@pytest.mark.parametrize('depth',(128,12000))
def test_forced_lookup_does_not_turn_the_caller_bound_into_a_global_table_guard(depth):
 from amiga_reversing.disasm.mapped_execution import MappedExecution
 raw=shared_bytes();c=MappedExecution(0x100000);c.seed(0x44c2,raw[0x34c2:0x34dc]);c.seed(0x2c6b8+130,raw[0x2b6b8+130:0x2b6b8+12000]);c.cpu.d[3]=depth
 with pytest.raises(ValueError,match='unknown read/fetch'):c.run(0x44c2,0x44dc,40)

@pytest.mark.parametrize('mode',(0,7,8,255))
def test_view_mode_guard_uses_only_eight_of_thirteen_stored_offsets(mode):
 raw=shared_bytes();c=scene(IDENTITY);c.seed(APP+0x7eb,bytes([mode]));index=mode if mode<8 else 0
 expected=0x3c66+int.from_bytes(raw[0x2c66+2*index:0x2c68+2*index],'big',signed=True)
 c.cpu.a[6]=APP;c.run(0x3c4c,expected,30)

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='external vasm is the source build dependency')
def test_compiled_coordinate_symbols_preserve_phase_specific_layouts(tmp_path):
 import subprocess
 from pathlib import Path
 from test_starglider2_retail_model_headers import image
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered'
 source=(directory/'retail-shared.s').read_text()
 radial=source.split('prepare_radial_object_projection_scale:',1)[1].split('rotate_actor_relative_coordinates_into_view:',1)[0]
 assert 'SG2RadialProjectionActor_source_radius(a4)'in radial and 'SG2RadialProjectionActor_projection_right_shift(a4)'in radial
 assert 'SG2ModelCoordinateActor_origin_relative_'not in radial and 'SG2ActorModelPrefix_velocity_x(a4)'not in radial
 symbols={'cache_model_origin_relative_coordinates':0x41dc,'choose_radial_projection_right_shift':0x48b2,'projection_scale_lookup_prefix':0x2c6b8,'view_mode_dispatch_offsets':0x3c66,'SG2CoordinateFrameWorkspace_view_rotation_matrix':0x106,'SG2CoordinateFrameWorkspace_model_origin_delta_x':0x132,'SG2ModelCoordinateActor_origin_relative_z':54,'SG2RadialProjectionActor_source_radius':54,'SG2RadialProjectionActor_projection_right_shift':44}
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 result=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert result.returncode==0,result.stdout+result.stderr
 raw=out.read_bytes();size=4*len(symbols)
 assert raw[:-size]==image('st')and struct.unpack('>'+str(len(symbols))+'I',raw[-size:])==tuple(symbols.values())

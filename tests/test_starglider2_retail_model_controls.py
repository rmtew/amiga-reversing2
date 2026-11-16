"""Retail model-control storage and connected retirement packet contracts.

Reuse existing geometry oracles and the existing complete extent initializer
check. Supplied state is not a natural-playthrough or model-domain guarantee.
"""
import ctypes,os
import pytest
from tests.test_starglider2_text_editor import state,run,put,get,APP,INPUT,STACK,RETURN
from test_starglider2_retail_input import program
from test_starglider2_retail_model_pipeline import EarlierRenderAddresses
from tests import test_starglider2_retirement_faces as retirement
from tests.test_starglider2_control_normalization import signed
from amiga_reversing.disasm.mapped_execution import MappedExecution
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')

@pytest.fixture(params=('amiga','st'))
def machine(request):
 image=program(request.param);raw=image[0];m=(ctypes.c_uint8*0xa1000)();ctypes.memmove(ctypes.addressof(m)+4096,raw,len(raw));return image,m,EarlierRenderAddresses(m)

FIELDS=dict(model_view_vertex_scratch_prefix=0x21e,active_model_retirement_phase_word=0x778,retirement_face_displacement_x=0x18,retirement_face_displacement_y=0x1c,retirement_face_displacement_z=0x20,space_environment_flag=0x77d,model_origin_delta_y=0x134,model_face_vertex_count_scratch=0x1b8,drawing_fill_style_word=0x1a0,saved_model_face_loop_index=0x77a,projection_screen_origin_x=0x194,projection_screen_origin_y=0x196,view_clip_min_x=0xe4,view_clip_max_x=0xe6,view_clip_min_y=0xe8,view_clip_max_y=0xea,active_model_header_counts=0x178,model_last_vertex_index=0x174,model_view_matrix=0xf4,active_model_vertex_reference_records=8,active_model_coordinate_pool=0x14,active_model_vertex_variant_data=0x24,active_model_face_commands=0x10)

@pytest.mark.parametrize('points,phase',[(retirement.GEOMETRY[i],p)for i,p in((0,0),(0,15),(1,1),(12,32768),(12,65535))])
def test_retirement_cross_products_reuse_original_truncation_oracle(machine,points,phase):
 image,m,v=machine;c=retirement.prepare(v,FIELDS,points,phase);c.pc+=24
 run(image,m,c,{0x55a2})
 for axis,value in zip('xyz',retirement.displacements(points,phase)):
  p=APP+FIELDS['retirement_face_displacement_'+axis]
  assert signed(get(m,p,2))==value and get(m,p+2,2)==0xb6b6


def test_retirement_packet_reuses_last_depth_and_pixel_coordinate_oracle(machine):
 image,m,v=machine;points=[(0,0,1000),(80,0,1001),(0,60,1003)];c=retirement.prepare(v,FIELDS,points);c.pc+=24
 run(image,m,c,{RETURN})
 projected=[]
 for x,y,z in points:
  depth=z&65534;coefficient=get(m,0x2c6b8+depth,2)
  xy=[signed(((signed(coefficient)*a*2)&0xffffffff)>>16)for a in(x,y)];projected.append((*xy,depth))
 expected=[projected[-1][2],retirement.classified_style(3,[p[0]for p in projected]),*[n for x,y,z in projected for n in(x,y)],65535]
 assert[get(m,retirement.OUTPUT+2*i,2)for i in range(len(expected))]==expected
 assert get(m,0x49c0,2)==1 and get(m,retirement.REFS)==retirement.OUTPUT


@pytest.mark.parametrize('kind,selector',((0,0),(1,1),(47,0),(103,1)))
def test_retiring_model_loader_copies_flag_header_and_variant_without_invented_bounds(machine,kind,selector):
 image,m,v=machine;actor=INPUT+0x400;m[actor:actor+68]=bytes(68);m[actor+3]=selector;m[actor+0x1d]=0xfd
 c=state(m,0x5350);c.a[4]=actor;c.d[0]=kind;put(m,APP+0x24,0xa5a5a5a5);run(image,m,c,{0x53b2})
 header=get(m,0x1a234+4*kind);table=get(m,header+18)
 assert m[0x58c6]==m[0x58c7+kind]and get(m,APP+0x1aa,2)==13
 for dest,source,size in((0x174,0,2),(0x178,2,4),(0x10,6,4),(8,10,4),(0x14,14,4)):
  assert bytes(m[APP+dest:APP+dest+size])==bytes(m[header+source:header+source+size])
 assert get(m,APP+0x24)==(get(m,table)if selector and table else 0)


@pytest.mark.parametrize('phase,flag',((2,0),(3,0),(15,1),(15,0),(128,0),(131,0)))
def test_retirement_fallback_gate_keeps_byte_subtraction_sign_and_flag(machine,phase,flag):
 image,m,v=machine;m[APP+0x779]=phase;m[0x58c6]=flag;put(m,APP+0x1aa,15,2)
 c=state(m,0x53c6);run(image,m,c,{0x4fc2,0x5400})
 emits=not((phase-3)&128)and not flag
 assert c.pc==(0x5400 if emits else 0x4fc2)
 if emits:
  header=get(m,0x1a234+4*47)
  assert get(m,APP+0x1aa,2)==16 and get(m,APP+0x24)==0
  assert get(m,APP+0x10)==get(m,header+6)
 else:assert get(m,APP+0x1aa,2)==15


@pytest.mark.parametrize('right',range(0,16,2))
def test_real_model47_face_producer_selects_only_eight_word_styles(machine,right):
 image,m,v=machine;left=0x12345678;put(m,APP+0x60,left);put(m,APP+0x64,right);put(m,APP+0x190,47,2)
 put(m,INPUT+0x400,0x8303,2);c=state(m,0x4b6c);c.a[4]=INPUT+0x400;c.a[0]=INPUT
 run(image,m,c,{0x4b98});rot=((left<<3)|(left>>29))&0xffffffff;value=(rot&0xffff0000)|(((rot-7)^right)&65535)
 styles=(1,3,4,5,6,3,1,4)
 assert get(m,APP+0x60)==right and get(m,APP+0x64)==value
 assert get(m,APP+0x1a0,2)==styles[(value&14)//2]
 assert c.a[0]==INPUT and c.a[7]==STACK-4


@pytest.mark.parametrize('index',(0,103,104))
def test_declared_suppression_prefix_is_not_a_runtime_index_guard(index):
 raw=program('st')[0];c=MappedExecution(0x100000);c.seed(0x5358,raw[0x4358:0x4366]);c.seed(0x58c7,raw[0x48c7:0x492f]);c.seed(0x58c6,b'\xa5');c.allow_write(0x58c6,1);c.cpu.d[0]=index
 if index==104:
  with pytest.raises(ValueError,match='unknown read/fetch'):c.run(0x5358,0x5366,10)
 else:
  c.run(0x5358,0x5366,10);assert c.read(0x58c6,1)==raw[0x48c7+index:0x48c8+index]


def test_encoded_reference_scratch_keeps_signs_separate_from_cached_values(machine):
 image,m,v=machine;pool=INPUT+0x1000;put(m,APP+0x14,pool)
 for i,value in enumerate((100,200,300)):put(m,pool+2*i,value,2)
 matrix=(16384,0,0,0,16384,0,0,0,16384)
 for i,value in enumerate(matrix):put(m,APP+0xf4+2*i,value,2)
 m[0x4920e:0x4920e+14400]=bytes(14400)
 for refs,answer in(((0,0x8002,4),(100,-200,300)),((0x8000,2,0x8004),(-100,200,-300))):
  c=state(m,0x56d4);c.d[1:4]=refs;run(image,m,c,{RETURN})
  assert tuple(get(m,0x58be+2*i,2)for i in range(3))==refs
  assert tuple(signed(v)for v in c.d[1:4])==answer
  # Cache invalidation is the caller's job;new source values alone do not refresh it.
  for i,value in enumerate((1000,2000,3000)):put(m,pool+2*i,value,2)


@pytest.mark.parametrize('phase',(1,15,62))
def test_surface_retirement_bias_uses_even_byte_offsets_and_low_word_add(machine,phase):
 image,m,v=machine;points=[(31000,-30000,29000),(-20000,17000,13000),(15000,27000,-31000)]
 c=retirement.prepare(v,FIELDS,points,phase,space=False);c.pc+=24;run(image,m,c,{0x5520})
 bias=signed(get(m,0x5694+(phase&65534),2));expected=retirement.displacements(points,phase,bias)[1]
 run(image,m,c,{0x5526});assert signed(get(m,APP+0x1c,2))==expected

@pytest.mark.parametrize('kind',(0,3,30,47,49,84,91,103,65535))
def test_original_backface_policy_clears_previous_flag_and_selects_six_ids(machine,kind):
 image,m,v=machine;put(m,APP+0x190,kind,2);put(m,0x58bc,0x1234,2);c=state(m,0x4af2)
 run(image,m,c,{0x4b50});assert get(m,0x58bc,2)==(65535 if kind in(3,30,47,49,84,91)else 0)


@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_model_control_owners_and_workspace_fields(tmp_path):
 import struct,subprocess
 from pathlib import Path
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered';source=(directory/'retail-shared.s').read_text()
 symbols={'model47_random_face_styles':0x58ac,'force_model_backface_refresh':0x58bc,'encoded_vertex_x_reference_scratch':0x58be,'encoded_vertex_y_reference_scratch':0x58c0,'encoded_vertex_z_reference_scratch':0x58c2,'retirement_model_skip_fallback_flag':0x58c6,'model_retirement_fallback_suppression_prefix':0x58c7,'model_maximum_signed_coordinates':0x5930,'retirement_face_y_bias_prefix':0x5694,'prepare_retirement_model_faces':0x5350,'select_model_backface_refresh_policy':0x4af2,'SG2RetiringModelWorkspace_retirement_face_displacement_y':0x1c,'SG2RetiringModelWorkspace_active_model_retirement_phase_word':0x778}
 assert 'SG2RetiringModelWorkspace_retirement_face_displacement_y(a6)'in source
 first=source.split('model_maximum_signed_coordinates:',1)[1].strip().splitlines()[0];assert first.strip().startswith('dcb.w $68,'),first
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert r.returncode==0,r.stdout+r.stderr
 raw=out.read_bytes();size=4*len(symbols)
 assert raw[:-size]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-size:])==tuple(symbols.values())

"""Retail model/face producers and clipped packets through original code.

Reuse earlier independent geometry and packet oracles. Stored-model bounds
are a finite-data contract, not a guard on arbitrary runtime header changes.
"""
import os
import pytest
from amiga_reversing.disasm.mapped_execution import MappedExecution
from amiga_reversing.tools.compare_starglider2 import model_streams
from test_starglider2_retail_variant_cycles import shared_bytes
from test_starglider2_retail_sound import machine,program,state,run,put,get,APP,STACK,RETURN
from tests.test_starglider2_face_admission import slots,check_admission_pipeline,TRIANGLE,ACCEPT
from tests.test_starglider2_polygon_clipping import reference as clip_reference,SCRATCH_A,SCRATCH_B
from tests.test_starglider2_control_normalization import signed
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')

def render_address(at):
 if 0x47862<=at<0x4bc00:return at+0x19ac
 if 0x3c2c<=at<0x3c34:return at+12
 if 0x49a8<=at<0x49ac or 0x52ba<=at<0x6100:return at+24
 return at

class EarlierRenderAddresses:
 """Translate earlier fixture addresses only; never change pointer values."""
 def __init__(self,m):self.m=m
 def key(self,k):
  if not isinstance(k,slice):return render_address(k)
  start=render_address(k.start);assert render_address(k.stop-1)==start+k.stop-k.start-1
  return slice(start,start+k.stop-k.start,k.step)
 def __getitem__(self,k):return self.m[self.key(k)]
 def __setitem__(self,k,v):self.m[self.key(k)]=v

@pytest.mark.parametrize('points',(TRIANGLE,ACCEPT,ACCEPT+[(100,100,1000)]))
def test_admission_transform_projection_and_packet_reuse_the_existing_oracle(slots,points):
 m,_=machine('st');view=EarlierRenderAddresses(m)
 # Header pointers are actual RAM addresses, not translated fixture handles.
 check_admission_pipeline(program('st'),m,slots,points,entry=0x4b6c,view=view,admitted_buffer=0x4ca4e)

@pytest.mark.parametrize('points,mask',[
 ([(0,0,1024),(100,100,1024)],0),
 ([(-2000,0,1024),(100,0,1024)],1),
 ([(0,-1000,1024),(0,100,1024)],4),
 ([(10,20,256),(100,40,128)],128),
 ([(-2000,-1000,128),(2000,-1000,1024),(2000,1000,1024),(-2000,1000,1024)],143)])
def test_five_plane_clipping_reuses_word_rounding_order_and_duplicate_oracle(points,mask):
 m,_=machine('st');source=0x88000
 for i,xyz in enumerate(points):
  for j,value in enumerate(xyz):put(m,source+6*i+2*j,value&65535,2)
 c=state(m,0x5b0a);c.a[2]=source;c.a[3]=0;c.d[7]=len(points);c.d[4]=mask
 expected,old_address=clip_reference(points,mask);run(program('st'),m,c,{RETURN})
 assert c.a[2]==render_address(old_address)and c.d[7]&65535==len(expected)
 actual=[tuple(signed(get(m,c.a[2]+6*i+2*j,2))for j in range(3))for i in range(len(expected))]
 assert actual==expected


def stored_models():return model_streams(shared_bytes(),0x19234)

def test_all_stored_headers_fit_the_qualified_working_prefixes():
 raw=shared_bytes();models=stored_models();coordinate_max=vertex_max=face_bytes=0;lines=0
 for model in models:
  header=model['header'];count=int.from_bytes(raw[header+4:header+6],'big');vertices=int.from_bytes(raw[header:header+2],'big')+1
  refs=int.from_bytes(raw[header+10:header+14],'big')-4096
  for vertex in range(vertices):
   for axis in range(3):
    value=int.from_bytes(raw[refs+8*vertex+2*axis:refs+8*vertex+2*axis+2],'big')&32767
    assert not value&1 and value//2<count
  coordinate_max=max(coordinate_max,count);vertex_max=max(vertex_max,vertices)
  stream=model['main'];face_bytes=max(face_bytes,stream['end']-stream['start']+2*stream['count'])
  for record in stream['records']:
   if len(record['vertices'])==2:lines+=1;assert record['header']&32768
 assert (len(models),coordinate_max,vertex_max,face_bytes,lines)==(103,287,48,624,76)
 assert coordinate_max+1<=300 and face_bytes<=700


def admission(stream,*,truncate=False,header=None,force=0):
 raw=shared_bytes();c=MappedExecution(0x100000,register_seed=0xdeadbeef)
 c.seed(0x4b6c,raw[0x3b6c:0x3ca2]);start,end=stream['start'],stream['end'];data=raw[start:end-(2 if truncate else 0)]
 if header is not None:data=header.to_bytes(2,'big')+data[2:]
 c.seed(start+4096,data);c.seed(APP,bytes(4096));c.allow_write(APP,4096)
 c.seed(APP+0x756,b'\0\1');c.seed(APP+0x1f0,b'\0');c.seed(0x58bc,force.to_bytes(2,'big'))
 c.seed(0x52d6,b'\0\0');c.allow_write(0x52d6,2);c.allow_write(0xe145,1)
 c.seed(0x4ca4e,b'\xcc'*700);c.allow_write(0x4ca4e,700)
 c.seed(0x4cd0a,b'\xa5'*384);c.seed(STACK-512,bytes(516));c.allow_write(STACK-512,516)
 c.cpu.a[0]=APP+0x21e;c.cpu.a[4]=start+4096;c.cpu.a[5]=0x4ca4e;c.cpu.a[6]=APP;c.cpu.a[7]=STACK;c.cpu.d[0]=stream['count']-1
 return c


def test_largest_actual_face_stream_stages_without_touching_projected_cache():
 model=next(m for m in stored_models()if 99 in m['ordinals']);stream=model['main'];c=admission(stream)
 c.seed(APP+0x1f0,b'\1');c.run(0x4b6c,0x4ca2,10000)
 expected=b''
 for record in stream['records']:
  colour=record['header']&255;colour=colour if colour<128 else colour+65280
  expected+=colour.to_bytes(2,'big')+b''.join(x.to_bytes(2,'big')for x in record['vertices'])+b'\xff\xff'
 assert len(expected)==624 and c.read(0x4ca4e,624)==expected
 assert c.read(0x4ca4e+624,76)==b'\xcc'*76 and c.read(0x4cd0a,384)==b'\xa5'*384
 with pytest.raises(ValueError,match='unknown read/fetch'):
  c=admission(stream,truncate=True);c.seed(APP+0x1f0,b'\1');c.run(0x4b6c,0x4ca2,10000)


def test_two_vertex_header_flag_is_what_prevents_the_third_offset_read():
 model=next(m for m in stored_models()if any(len(r['vertices'])==2 for r in m['main']['records']))
 record=next(r for r in model['main']['records']if len(r['vertices'])==2)
 # Locate this exact six-byte record inside its proven counted stream.
 encoded=record['header'].to_bytes(2,'big')+b''.join(x.to_bytes(2,'big')for x in record['vertices'])
 raw=shared_bytes();start=raw.index(encoded,model['main']['start'],model['main']['end']);stream=dict(start=start,end=start+6,count=1)
 c=admission(stream,force=65535);c.run(0x4b6c,0x4ca2,200)
 assert c.cpu.a[4]==start+4096+6 and c.cpu.a[5]==0x4ca4e+8
 # An explicitly malformed fixture removes the bypass. No game bytes change.
 c=admission(stream,header=record['header']&32767,force=65535);c.seed(APP+0x756,b'\0\0')
 with pytest.raises(ValueError,match='unknown read/fetch'):c.run(0x4b6c,0x4ca2,200)

@pytest.mark.parametrize('points,flags',[
 ([(-2000,-1000,1024),(2000,-1000,1024),(0,1000,1024)],(5,6,8)),
 ([(-100,-50,64),(100,-50,1024),(0,100,1024)],(128,0,0)),
 ([(2000,0,1024),(2200,100,1024),(2400,-100,1024)],(2,2,2))])
def test_admitted_vertices_run_through_real_outcodes_clipping_and_packet_publication(slots,points,flags):
 from tests import test_starglider2_face_admission as admission_oracle
 from tests.test_starglider2_face_packet_emission import projected,classified_style
 m,_=machine('st');view=EarlierRenderAddresses(m)
 cpu,cache,_=admission_oracle.prepare(view,slots,points,header=0x8303,flag=0)
 admission_oracle.encoded_fixture(view,slots,points)
 def word(at,v):put(view,at,v&65535,2)
 word(APP+slots['model_last_vertex_index'],2)
 for off,value in((0x194,159),(0x196,79),(0xe4,16),(0xe6,303),(0xe8,30),(0xea,128)):word(APP+off,value)
 output,refs=admission_oracle.OUTPUT,admission_oracle.REFS
 put(view,0x3c30,output);put(view,0x3c2c,refs);word(0x49a8,0)
 view[output:output+256]=b'\xcc'*256;view[refs:refs+32]=b'\xa5'*32
 cpu.pc=0x4b6c;cpu.a[5]=0x4ca4e;run(program('st'),m,cpu,{RETURN})
 assert tuple(view[cache+8*i+7]for i in range(3))==flags
 assert [tuple(signed(get(view,cache+8*i+2*j,2))for j in range(3))for i in range(3)]==points
 common=15
 for flag in flags:common&=flag
 if common:
  assert get(view,0x49a8,2)==0 and get(view,0x3c30)==output and get(view,0x3c2c)==refs
  return
 mask=0
 for flag in flags:mask|=flag
 clipped,_=clip_reference(points,mask)
 if clipped and clipped[-1]==clipped[0]:clipped=clipped[:-1]
 values=[projected(p)for p in clipped];assert values and all(p is not None for p in values)
 expected=[sum(z for x,y,z in values)//len(values),classified_style(3,[x for x,y,z in values]),*[v for x,y,z in values for v in(x,y)],65535]
 assert [get(view,output+2*i,2)for i in range(len(expected))]==expected
 assert get(view,0x49a8,2)==1 and get(view,refs)==output and get(view,0x3c2c)==refs+4

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='external vasm is the source build dependency')
def test_compiled_pipeline_symbols_keep_buffer_boundaries_and_draw_context(tmp_path):
 import struct,subprocess
 from pathlib import Path
 from test_starglider2_retail_model_headers import image
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered'
 source=(directory/'retail-shared.s').read_text()
 assert 'SG2ModelPipelineWorkspace_frame_handoff_counter(a6)'in source
 assert 'SG2ModelPipelineWorkspace_drawing_fill_style(a6)'in source
 symbols={'transform_encoded_vertex_coordinates':0x56d4,'resolve_cached_model_vertex':0x5854,'clip_polygon_in_view_volume':0x5b0a,'admitted_model_face_command_buffer':0x4ca4e,'projected_model_vertex_prefix':0x4cd0a,'clip_xyz_scratch_a_prefix':0x5f04,'clip_xyz_scratch_b_prefix':0x5fc6,'model_scene_packet_start':0x52d2,'admitted_model_face_count':0x52d6,'force_model_backface_refresh':0x58bc,'SG2ModelPipelineWorkspace_frame_handoff_counter':0x756,'SG2ModelDrawContextPrefix_active_model_vertex_reference_records':8}
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 result=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert result.returncode==0,result.stdout+result.stderr
 raw=out.read_bytes();size=4*len(symbols)
 assert raw[:-size]==image('st')and struct.unpack('>'+str(len(symbols))+'I',raw[-size:])==tuple(symbols.values())

"""Original retail screen-line clipping and tilted horizon/data consumers.

Finite CPU/RAM witnesses preserve original arithmetic. They do not certify
physical scanout or universal ownership/lifetime of shared buffers.
"""
import os,struct
import pytest
from tests.test_starglider2_text_editor import state,run,put,get,APP,FB,STACK,RETURN
from test_starglider2_retail_input import program
from test_starglider2_retail_terrain import machine,address,execute,word
from tests.test_starglider2_radial_callers import offsets
from tests.test_starglider2_scene_packets import fields
from amiga_reversing.disasm.mapped_execution import MappedExecution
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
BOUNDS=(16,303,30,128);CLIP=0x60ae;SINE,COSINE=0x15808,0x16008

def signed(v):return(v+32768)%65536-32768

def quotient(n,d):return(-1 if(n<0)!=(d<0)else 1)*(abs(n)//abs(d))

def code(x,y,b):
 left,right,top,bottom=b;return(8 if x>right else 0)|(4 if y>bottom else 0)|(2 if x<left else 0)|(1 if y<top else 0)

def line_reference(points,bounds):
 points=[list(map(signed,p))for p in points];left,right,top,bottom=bounds
 for _ in range(32):
  a,b=points;ca,cb=code(*a,bounds),code(*b,bounds)
  if not ca|cb:return 0,points
  if ca&cb:return -1,points
  if any(not(-16383<v<16383)for p in points for v in p):return -1,points
  if a[0]==b[0]:
   for p in points:p[1]=max(top,min(bottom,p[1]))
   continue
  if a[1]==b[1]:
   for p in points:p[0]=max(left,min(right,p[0]))
   continue
  index=0 if ca else 1;p=points[index];other=points[1-index];mask=ca or cb
  axis,bound=next((axis,bound)for bit,axis,bound in((1,1,top),(2,0,left),(4,1,bottom),(8,0,right))if mask&bit)
  second=1-axis;p[second]=signed(p[second]+quotient(signed(bound-p[axis])*signed(other[second]-p[second]),signed(other[axis]-p[axis])));p[axis]=bound
 raise AssertionError('reference line did not converge')

@pytest.mark.parametrize('points,bounds',[
 ([(16,30),(303,128)],BOUNDS),([(20,40),(20,40)],BOUNDS),
 ([(-100,79),(400,79)],BOUNDS),([(160,-100),(160,300)],BOUNDS),
 ([(-100,-100),(400,200)],BOUNDS),([(400,200),(-100,-100)],BOUNDS),
 ([(10,60),(250,100)],BOUNDS),([(50,0),(260,100)],BOUNDS),
 ([(50,60),(400,100)],BOUNDS),([(50,60),(160,200)],BOUNDS),
 ([(50,60),(-100,100)],BOUNDS),([(50,60),(160,0)],BOUNDS),
 ([(-100,0),(-50,150)],BOUNDS),([(0,0),(500,10)],BOUNDS),
 ([(-16382,79),(16382,79)],BOUNDS),([(-16383,79),(160,79)],BOUNDS),
 ([(160,79),(16383,79)],BOUNDS),([(-17000,0),(17000,0)],(-20000,20000,-20000,20000))])
def test_original_screen_clipper_matches_word_integer_reference_and_saved_frame(points,bounds):
 platform,m,v=machine();
 for off,val in zip((0xe4,0xe6,0xe8,0xea),bounds):word(m,APP+off,val)
 c=state(m,CLIP)
 for reg,value in zip(range(4,8),[x for p in points for x in p]):c.d[reg]=(c.d[reg]&0xffff0000)|(value&65535)
 d,a=list(c.d),list(c.a);status,expected=line_reference(points,bounds);run(program(platform),m,c,{RETURN})
 assert c.d[0]==status&0xffffffff and list(c.d[1:4])==d[1:4]
 assert[(c.d[i]>>16)for i in range(4,8)]==[(d[i]>>16)for i in range(4,8)]
 assert[[signed(c.d[4]),signed(c.d[5])],[signed(c.d[6]),signed(c.d[7])]]==expected
 assert list(c.a[:7])==a[:7]and c.a[7]==STACK+4


def test_original_installer_and_all_masked_heading_indices_bound_the_5120_word_trig_view():
 raw=program('st')[0];c=MappedExecution(0x100000,register_seed=0x12340000);ret=0xff000
 c.seed(0x1f32,raw[0xf32:0xf4e]);c.seed(0x30f10,raw[0x2ff10:0x2ff5a]);c.seed(SINE,raw[SINE-4096:0x18008-4096]);c.seed(STACK-64,bytes(68));c.allow_write(STACK-64,68)
 c.cpu.a[6]=APP;c.cpu.a[7]=STACK;c.allow_write(APP+0x44,8);c.seed(STACK,ret.to_bytes(4,'big'));c.run(0x1f32,ret,20)
 assert c.read(APP+0x44,8)==struct.pack('>II',SINE,COSINE)
 values=struct.unpack('>5120h',raw[SINE-4096:0x18008-4096]);assert (values[4],values[4100])==(101,100)  # Preserve the stored quantization difference; this is not a repeated quarter.
 for angle in range(4096):
  c.seed(APP+0x7b8,angle.to_bytes(2,'big'));c.cpu.a[6]=APP;c.cpu.a[7]=STACK;c.cpu.d[1]=16384;c.cpu.d[3]=0
  c.run(0x30f10,ret,100);index=(-angle)&4095
  assert signed(c.cpu.d[1])==values[1024+index]and signed(c.cpu.d[3])==signed(-values[index])
 # The next WORD is deliberately not mapped; it is not part of this owner.
 with pytest.raises(ValueError,match='unknown bytes'):c.read(0x18008,2)


def configure_horizon(profile,offsets,pitch,roll):
 platform,m,v=machine(profile);o=offsets;c=state(m,0x1f32);run(program(platform),m,c,{RETURN})
 for name,val in(('view_rotation_0',pitch),('view_rotation_1',0),('view_rotation_2',roll),('view_clip_min_x',16),('view_clip_max_x',303),('view_clip_min_y',30),('view_clip_max_y',128),('projection_screen_origin_x',159),('projection_screen_origin_y',79)):word(m,APP+o[name],val)
 m[APP+0x7f6]=1;word(m,APP+0x7b0,9);m[APP+o['inside_structure_flag']]=m[APP+0x77d]=0;put(m,APP+o['view_origin_y'],(-1000)&0xffffffff)
 put(v,0x3c30,0x84000);put(v,0x3c2c,0x83000);word(v,0x49a8,0)
 return platform,m,v


def close_ground_polygon(a,b,bounds=BOUNDS):
 left,right,top,bottom=bounds;w,h=right-left,bottom-top;perimeter=2*(w+h)
 def distance(p):
  x,y=p
  if y==top:return x-left
  if x==right:return w+y-top
  if y==bottom:return w+h+right-x
  assert x==left,p;return 2*w+h+bottom-y
 corners=[(left,top),(right,top),(right,bottom),(left,bottom)];start=distance(b);extent=(distance(a)-start)%perimeter
 between=sorted(((distance(p)-start)%perimeter,p)for p in corners if 0<(distance(p)-start)%perimeter<extent)
 return[a,b]+[p for d,p in between]

@pytest.mark.parametrize('pitch,roll',[(0,64),(0,128),(0,256),(0,512),(0,768),(0,3584),(0,3968),(128,256),(-128,512)])
def test_tilted_horizon_calls_original_line_clipper_then_closes_the_viewport_boundary(offsets,pitch,roll):
 platform,m,v=configure_horizon('colour',offsets,pitch,roll);verify_horizon_polygon(platform,m,v)

def verify_horizon_polygon(platform,m,v):
 c=state(m,0x30524);run(program(platform),m,c,{CLIP})
 before=[[signed(c.d[4]),signed(c.d[5])],[signed(c.d[6]),signed(c.d[7])]];status,points=line_reference(before,BOUNDS);assert status==0
 caller=get(m,c.a[7]);run(program(platform),m,c,{caller});assert c.d[0]==0
 assert[[signed(c.d[4]),signed(c.d[5])],[signed(c.d[6]),signed(c.d[7])]]==points
 run(program(platform),m,c,{RETURN});assert get(v,0x49a8,2)==1 and get(v,0x3c2c)==0x83004 and get(m,0x83000)==0x308b4
 polygon=[];p=0x308b8
 while get(m,p,2)<32768:polygon.append((get(m,p,2),get(m,p+2,2)));p+=4
 split=signed(get(v,0x2f010,2));cap=BOUNDS if split<0 else(*BOUNDS[:3],split)
 if split>=0:assert split==max(p[1]for p in points)
 assert polygon==close_ground_polygon(*map(tuple,points),bounds=cap),(points,polygon,split)
 assert get(m,p)==0xffffffff and get(m,0x308b4,2)==65535
 return polygon

@pytest.mark.parametrize('profile,roll',[(p,r)for p in('colour','mono')for r in(64,512)])
def test_tilted_horizon_band_and_clipped_polygon_reach_both_st_pixel_writers(offsets,fields,profile,roll):
 from tests import test_starglider2_scene_packets as scene
 from tests import test_starglider2_span_interpolation as edges
 from tests import test_starglider2_interleaved_reader_context as colour
 from tests import test_starglider2_alternate_pattern_reader as patterns
 platform,m,v=configure_horizon(profile,offsets,0,roll);polygon=verify_horizon_polygon(platform,m,v)
 m[FB-16:FB+0x8010]=b'\xa5'*0x8020;put(m,fields['draw_buffer_base'],FB);m[fields['alternate_graphics_mode']]=2 if profile=='mono'else 0
 split=signed(get(v,0x2f010,2));records=[]
 if split<0:records=[(0 if profile=='mono'else 15,30,[(16,303)]*99)]
 else:
  if split>30:records.append((0 if profile=='mono'else 15,30,[(16,303)]*(split-30)))
  records.append((9,split,[(16,303)]*(129-split)))
 painter=patterns.expected if profile=='mono'else colour.expected_memory;expected=painter(v,records)
 if profile=='mono':
  for row in range(4):
   for col in(0,4):
    at=FB+0x700c+row*80+col;expected[at:at+4]=bytes(m[at:at+4])
 for lower in(0,1):
  entry=0x3a82a if profile=='mono'else 0x3a760;c=state(m,address(entry));c.d[0]=lower;execute(platform,m,c,entry)
 assert bytes(m[FB-16:FB+0x8010])==bytes(expected[FB-16:FB+0x8010])
 put(m,0x82ffc,scene.GUARD);word(m,scene.GUARD,65535);word(m,fields['player_rotation_2'],0)
 c=state(m,address(scene.PREPARE));c.a[2]=0x82ffc;c.d[0]=1;run(program(platform),m,c,{address(0x3dad4)})
 assert get(m,0x83000)==0x308b4;hud=get(m,0x83004);assert hud==address(0x3a0d2)and get(m,0x83008)==0xffffffff
 points=[];p=hud+4
 while get(m,p,2)<32768:points.append((get(m,p,2),get(m,p+2,2)));p+=4
 records=[];fraction=65535
 for header,vertices in((0x308b4,polygon),(hud,points)):
  if len(vertices)>2:pairs,fraction=edges.polygon_pairs(v,vertices,fraction)
  else:pairs=edges.line_pairs(v,vertices[0][0],vertices[1][0],vertices[1][1]-vertices[0][1])
  records.append((get(m,header+2,2),min(y for x,y in vertices),pairs))
 expected=painter(v,records);run(program(platform),m,c,{RETURN})
 assert bytes(m[FB-16:FB+0x8010])==bytes(expected[FB-16:FB+0x8010])and c.a[7]==STACK+4

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='external vasm is the source build dependency')
def test_compiled_shared_clipper_and_overlapping_trig_view_symbols(tmp_path):
 import subprocess
 from pathlib import Path
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered';source=(directory/'retail-shared.s').read_text()
 symbols={'clip_line_to_view_bounds':0x60ae,'clip_line_to_view_bounds_continuation':0x60b2,'accept_clipped_view_line':0x609e,'reject_clipped_view_line':0x60a6,'intersect_first_endpoint_with_top_edge':0x615e,'intersect_second_endpoint_with_right_edge':0x6254,'sine_cosine_lookup_words':SINE,'cosine_lookup_view':COSINE,'SG2ModelPipelineWorkspace_clip_left':0xe4}
 assert 'SG2ModelPipelineWorkspace_clip_left(a6)'in source.split('clip_line_to_view_bounds:',1)[1].split('sort_and_draw_disc_queue:',1)[0]
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 result=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert result.returncode==0,result.stdout+result.stderr
 raw=out.read_bytes();size=4*len(symbols);assert raw[:-size]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-size:])==tuple(symbols.values())

"""Retail ground geometry, packet phases and finite Atari ST pixel witnesses.

Original CPU execution and supplied bounded geometry do not certify physical
scanout, general arena capacity or disk/music lifetime exclusion.
"""
import os,struct
import pytest
from tests.test_starglider2_text_editor import state,run,put,get,APP,FB,INPUT,STACK,RETURN
from test_starglider2_retail_input import program
from test_starglider2_retail_scene_raster import machine as raster_machine,EarlierAddresses as RasterAddresses,address as raster_address
from tests import test_starglider2_ground_face_packets as ground
from tests import test_starglider2_special_ground_grid as grid
from tests import test_starglider2_span_interpolation as edges
from tests import test_starglider2_scene_packets as scene
from tests.test_starglider2_scene_packets import fields
from tests import test_starglider2_interleaved_reader_context as colour
from tests import test_starglider2_alternate_pattern_reader as patterns
from tests.test_starglider2_ground_face_packets import slots
from tests.test_starglider2_radial_callers import offsets
from test_starglider2_retail_model_headers import models
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
FIXED={0x18b8:0x18d4,0x5918:0x5930,0x2bfc:0x2c12,0x3c2c:0x3c38,0x3c30:0x3c3c,0x2adf8:0x2c6b8,0x13c02:0x15330}

def address(old):
 for base,size in((0x18b8,2),(0x5918,2),(0x2bfc,18),(0x3c2c,8),(0x2adf8,12000),(0x13c02,2)):
  if base<=old<base+size:return FIXED[base]+old-base
 if old in FIXED:return FIXED[old]
 if 0x49a8<=old<0x6100:return old+24
 if 0x2ec64<=old<0x2f018:return old+0x18c0
 if 0x2f018<=old<0x2f700:return old+0x18cc
 if 0x3a752<=old<0x3a8f0:return old+0x194c
 return raster_address(old)

class EarlierAddresses(RasterAddresses):
 def key(self,k):
  if not isinstance(k,slice):return address(k)
  start=address(k.start);assert address(k.stop-1)==start+k.stop-k.start-1
  return slice(start,start+k.stop-k.start,k.step)

def machine(profile='colour'):
 platform,m,_=raster_machine(profile);return platform,m,EarlierAddresses(m)

def execute(platform,m,c,old,stops=(RETURN,),limit=30000):
 c.pc=address(old);run(program(platform),m,c,{address(p)for p in stops},limit=limit);return c

def word(m,p,v):put(m,p,v&65535,2)

@pytest.mark.parametrize('count,expected',[(0,3),(143,146),(144,146),(145,145),(32768,32771)])
def test_ground_face_count_gate_and_cached_packet_format(slots,count,expected):
 platform,m,v=machine();c,cache,_=ground.prepare(v,slots,faces=3);word(v,0x49a8,count)
 execute(platform,m,c,0x4fac);made=expected-count
 assert get(v,0x49a8,2)==expected and get(v,0x3c30)==ground.OUTPUT+14*made and get(v,0x3c2c)==ground.REFS+4*made
 for i in range(made):assert[get(v,ground.OUTPUT+14*i+2*j,2)for j in range(7)]==[0x7fe0,0,40,50,60,60,65535]

@pytest.mark.parametrize('depth',(128,129,11999,12000,32768))
def test_ground_view_ready_and_projected_phase_markers_keep_existing_projection_oracle(slots,depth):
 platform,m,v=machine();c,cache,_=ground.prepare(v,slots)
 for j,value in enumerate((1000,-1000,depth,0x01a5)):word(v,cache+2*j,value)
 expected=ground.project((1000,-1000,ground.signed(depth)));execute(platform,m,c,0x4fac)
 if expected is None:assert get(v,0x49a8,2)==0 and get(v,0x3c30)==ground.OUTPUT and get(v,cache+6,2)==0x01a5
 else:assert[get(v,cache+2*j,2)for j in range(4)]==[*expected,0xfedc]and get(v,0x49a8,2)==1

@pytest.mark.parametrize('picture_word,flags,admitted',[(0x6600,0,False),(0x6600,2,True),(0x4e71,0,True)])
def test_retail_grid_entry_has_a_distinct_picture_opcode_condition(picture_word,flags,admitted):
 platform,m,v=machine();m[APP+0x7f6]=flags;put(m,APP+0x714,0);word(m,0x3a60,picture_word)
 # Only the fixture RAM changes; original code/data files are untouched.
 c=state(m,0x308d8);run(program(platform),m,c,{0x308ec,0x308ee})
 assert c.pc==(0x308ee if admitted else 0x308ec)

@pytest.mark.parametrize('height',(-8001,-8000,0,0x7fffffff))
def test_grid_height_gate_keeps_the_original_n_only_long_comparison(height):
 platform,m,v=machine();m[APP+0x7f6]=2;put(m,APP+0x714,height&0xffffffff);c=state(m,0x308d8)
 run(program(platform),m,c,{0x308ec,0x308fa});assert c.pc==(0x308fa if((height+8000)&0xffffffff)<0x80000000 else 0x308ec)


def initialise_directory(platform,m,v):
 c=state(m,address(0x2f4f8));run(program(platform),m,c,{RETURN})
 actual=[get(v,grid.DIRECTORY+2*i,2)for i in range(100)]
 expected=[8*n for row in range(5)for col in range(5)for n in(6*row+col,6*row+col+1,6*(row+1)+col+1,6*(row+1)+col)]
 assert actual==expected and max(actual)==280

@pytest.mark.parametrize('origin,xstep,zstep,xedge,zedge',[
 ((-300,-200,1000),(120,0,0),(0,80,0),(0,0,0),(0,0,0)),
 ((32767,-32768,100),(32767,-32768,-1),(-32768,32767,2),(10,-20,30),(-40,50,-60))])
def test_grid_builder_writes_exactly_36_xyz_prefixes_and_preserves_record_tails(slots,origin,xstep,zstep,xedge,zedge):
 platform,m,v=machine();source=APP+slots['model_view_vertex_scratch_prefix'];m[source-2:source+290]=b'\xa5'*292
 for at,values in((grid.ORIGIN,origin),(grid.XSTEP,xstep),(grid.ZSTEP,zstep),(grid.XEDGE,xedge),(grid.ZEDGE,zedge)):grid.triples(v,at,values)
 expected=bytearray(m[source-2:source+290])
 for row in range(6):
  for col in range(6):
   for j in range(3):
    value=origin[j]+row*zstep[j]+col*xstep[j]+(zedge[j]if row==0 else zedge[j]-zstep[j]if row==5 else 0)+(xedge[j]if col==0 else xedge[j]-xstep[j]if col==5 else 0)
    at=2+8*(6*row+col)+2*j;expected[at:at+2]=(value&65535).to_bytes(2,'big')
 c=state(m,address(0x2f164));execute(platform,m,c,0x2f164,(0x2f23e,));assert bytes(m[source-2:source+290])==expected and c.a[0]==source+288


def build_finite_grid(platform,m,v,slots,phase=0):
 initialise_directory(platform,m,v);source=APP+slots['model_view_vertex_scratch_prefix']
 for at,values in((grid.ORIGIN,(-300,-200,1000)),(grid.XSTEP,(120,0,0)),(grid.ZSTEP,(0,80,0)),(grid.XEDGE,(60,0,0)),(grid.ZEDGE,(0,40,0))):grid.triples(v,at,values)
 m[source:source+288]=bytes(288);m[address(grid.PROJECTED):address(grid.PROJECTED)+288]=bytes(288)
 c=state(m,address(0x2f164));execute(platform,m,c,0x2f164,(0x2f23e,))
 for off,val in((0x194,159),(0x196,79),(0xe4,16),(0xe6,303),(0xe8,30),(0xea,128)):word(m,APP+off,val)
 execute(platform,m,c,0x2f23e,(0x2f2d8,))
 for i in range(36):
  col,row=i%6,i//6;point=(-300+120*col+(60 if col==0 else -60 if col==5 else 0),-200+80*row+(40 if row==0 else -40 if row==5 else 0),1000);expected=ground.project(point)
  assert[get(v,grid.PROJECTED+8*i+2*j,2)for j in range(3)]==list(expected)
  assert get(v,grid.PROJECTED+8*i+6,2)==0
 m[grid.PACKETS-4:grid.PACKETS+600]=b'\xcc'*604;m[grid.REFS-4:grid.REFS+120]=b'\xa5'*124
 put(v,grid.PACKET_CURSOR,grid.PACKETS);put(v,grid.REFS_CURSOR,grid.REFS);word(v,grid.PHASE,phase);word(v,grid.MATERIAL,9);word(v,grid.CANDIDATES,25);word(v,grid.COUNT,0)
 execute(platform,m,c,0x2f2d8)
 expected=[];cursor=grid.PACKETS
 for cell in range(25):
  phase=(~phase)&65535
  if not phase:continue
  corners=[get(v,grid.DIRECTORY+8*cell+2*j,2)for j in range(4)];xy=[(get(v,grid.PROJECTED+n,2),get(v,grid.PROJECTED+n+2,2))for n in corners]
  words=[0x7ff0,9,*[x for p in xy for x in p],65535];assert[get(m,cursor+2*j,2)for j in range(11)]==words;expected.append((cursor,xy));cursor+=22
 assert get(v,grid.COUNT,2)==len(expected)and get(v,grid.PACKET_CURSOR)==cursor and get(v,grid.REFS_CURSOR)==grid.REFS+4*len(expected)
 assert[get(m,grid.REFS+4*i)for i in range(len(expected))]==[p for p,xy in expected]
 return expected,cursor

@pytest.mark.parametrize('phase',(0,65535))
def test_grid_producers_feed_the_25_cell_checkerboard_in_directory_order(slots,phase):
 platform,m,v=machine();packets,end=build_finite_grid(platform,m,v,slots,phase)
 assert len(packets)==(13 if not phase else 12)and end==grid.PACKETS+22*len(packets)
 assert bytes(m[grid.PACKETS-4:grid.PACKETS])==b'\xcc'*4 and bytes(m[grid.REFS-4:grid.REFS])==b'\xa5'*4


def test_st_colour_ground_producers_sort_and_draw_through_the_real_scene_service(slots,fields):
 platform,m,v=machine();packets,cursor=build_finite_grid(platform,m,v,slots)
 # Append one actual model ground face into the grid's live packet/reference tail.
 c,cache,_=ground.prepare(v,slots);word(v,grid.COUNT,len(packets));put(v,grid.PACKET_CURSOR,cursor);put(v,grid.REFS_CURSOR,grid.REFS+4*len(packets))
 execute(platform,m,c,0x4fac);assert get(v,grid.COUNT,2)==14;shadow=(cursor,[(40,50),(60,60)])
 put(m,grid.REFS-4,scene.GUARD);word(m,scene.GUARD,65535);put(m,fields['draw_buffer_base'],FB);m[fields['alternate_graphics_mode']]=0;word(m,fields['player_rotation_2'],0)
 m[FB-16:FB+0x8010]=b'\xa5'*0x8020;c=state(m,address(scene.PREPARE));c.a[2]=grid.REFS-4;c.d[0]=14
 run(program(platform),m,c,{address(0x3dad4)})
 order=[get(m,grid.REFS+4*i)for i in range(15)];assert set(order[:-1])=={p for p,xy in packets}|{shadow[0]}
 assert[get(m,p,2)for p in order[:-1]]==[0x7ff0]*13+[0x7fe0]
 assert order[-1]==address(0x3a0d2)and get(m,grid.REFS+60)==0xffffffff
 known=dict(packets+[shadow]);hud=order[-1];xy=[];p=hud+4
 while get(m,p,2)<32768:xy.append((get(m,p,2),get(m,p+2,2)));p+=4
 known[hud]=xy;records=[];fraction=65535
 for p in order:
  pairs,fraction=edges.polygon_pairs(v,known[p],fraction)if len(known[p])>2 else(edges.line_pairs(v,known[p][0][0],known[p][1][0],known[p][1][1]-known[p][0][1]),fraction)
  records.append((get(m,p+2,2),min(y for x,y in known[p]),pairs))
 expected=colour.expected_memory(v,records);run(program(platform),m,c,{RETURN})
 assert bytes(m[FB-16:FB+0x8010])==bytes(expected[FB-16:FB+0x8010])and c.a[7]==STACK+4


def test_stored_ground_streams_have_positive_bounded_vertex_references():
 raw=program('st')[0];count=records=max_vertices=0
 for model in models('st'):
  stream=model.get('extra')
  if not stream or not stream['count']:continue
  count+=1;vertices=int.from_bytes(raw[model['header']:model['header']+2],'big')+1
  for face in stream['records']:
   records+=1;max_vertices=max(max_vertices,len(face['vertices']));assert face['vertices'] and all(not n&7 and n//8<vertices for n in face['vertices'])
 assert (count,records,max_vertices)==(45,82,8)

@pytest.mark.parametrize('profile',('colour','mono'))
def test_real_level_horizon_producer_feeds_both_st_background_writers(profile,offsets,fields):
 platform,m,v=machine(profile);o=offsets;c=state(m,0x1f32);run(program(platform),m,c,{RETURN})
 for name,val in(('view_rotation_0',0),('view_rotation_1',0),('view_rotation_2',0),('view_clip_min_x',16),('view_clip_max_x',303),('view_clip_min_y',30),('view_clip_max_y',128),('projection_screen_origin_x',159),('projection_screen_origin_y',79)):word(m,APP+o[name],val)
 m[APP+0x7f6]=1;word(m,APP+0x7b0,9);m[APP+o['inside_structure_flag']]=m[APP+0x77d]=0;put(m,APP+o['view_origin_y'],(-1000)&0xffffffff)
 put(v,grid.PACKET_CURSOR,grid.PACKETS);put(v,grid.REFS_CURSOR,grid.REFS);word(v,grid.COUNT,0)
 c=state(m,address(0x2ec64));execute(platform,m,c,0x2ec64)
 split=get(v,0x2f010,2);assert split==79 and get(v,grid.COUNT,2)==0 and get(v,grid.REFS_CURSOR)==grid.REFS
 assert get(v,0x2f014,2)==15 and get(v,0x2f016,2)==9
 m[FB-16:FB+0x8010]=b'\xa5'*0x8020;put(m,fields['draw_buffer_base'],FB)
 records=[(0 if profile=='mono'else 15,30,[(16,303)]*(split-30)),(9,split,[(16,303)]*(129-split))]
 expected=(patterns.expected if profile=='mono'else colour.expected_memory)(v,records)
 if profile=='mono':
  for row in range(4):
   for column in(0,4):
    at=FB+0x700c+80*row+column;expected[at:at+4]=bytes(m[at:at+4])
 for lower in(0,1):
  c=state(m,address(0x3a82a if profile=='mono'else 0x3a760));c.d[0]=lower;execute(platform,m,c,0x3a82a if profile=='mono'else 0x3a760)
 assert bytes(m[FB-16:FB+0x8010])==bytes(expected[FB-16:FB+0x8010])


def test_zero_ground_vertex_nibble_is_not_an_empty_face_guard(slots):
 platform,m,v=machine();c,cache,_=ground.prepare(v,slots);word(v,ground.COMMANDS,0xf0ff)
 execute(platform,m,c,0x4fac,(0x50f6,))
 assert c.d[0]&65535==65535 and get(v,grid.COUNT,2)==1 and get(m,ground.REFS)==ground.OUTPUT


def test_selected_main_frame_path_queues_landscape_before_models_and_depth_sort():
 raw=program('st')[0]
 def target(pc):
  at=pc-4096;assert raw[at:at+2]==b'\x61\0';return pc+2+int.from_bytes(raw[at+2:at+4],'big',signed=True)
 assert[(pc,target(pc))for pc in(0x3eb0,0x3fe2,0x4072)]==[(0x3eb0,0x49ec),(0x3fe2,0x4a42),(0x4072,0x49e0)]
 assert raw[0x3e82-4096:0x3e88-4096]==bytes.fromhex('4279000049c0')
 for bridge,destination in((0x49ec,0x30524),(0x49e0,address(scene.PREPARE))):assert raw[bridge-4096:bridge-4096+6]==b'\x4e\xf9'+destination.to_bytes(4,'big')

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='external vasm is the source build dependency')
def test_compiled_terrain_symbols_keep_retail_entry_and_record_overlays_distinct(tmp_path):
 import subprocess
 from pathlib import Path
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered';source=(directory/'retail-shared.s').read_text()
 symbols={'build_landscape_horizon_and_grid':0x30524,'build_ground_grid_if_enabled':0x308d8,'test_grid_option_after_picture_opcode_check':0x308e4,'append_model_ground_plane_faces':0x4fc4,'ground_grid_quad_vertex_offsets':0x30e48,'horizon_ground_split_row':0x308d0,'SG2TerrainWorkspace_ground_drop_view_x':0x4c,'SG2TerrainWorkspace_saved_ground_face_loop_index':0x77a,'SG2GridViewVertex_view_z':4,'SG2GridProjectedVertex_clip_outcode':6,'SG2GridViewVertex_SIZEOF':8,'SG2GridProjectedVertex_SIZEOF':8}
 assert 'SG2TerrainWorkspace_saved_ground_face_loop_index(a6)'in source
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 result=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert result.returncode==0,result.stdout+result.stderr
 raw=out.read_bytes();size=4*len(symbols);assert raw[:-size]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-size:])==tuple(symbols.values())


def test_original_grid_root_derives_geometry_from_view_state_before_packet_publication(offsets):
 platform,m,v=machine();o=offsets
 for entry in(0x1f32,0x284c):
  if entry==0x284c:
   for name,val in(('view_rotation_0',128),('view_rotation_1',0),('view_rotation_2',0)):word(m,APP+o[name],val)
  c=state(m,entry);run(program(platform),m,c,{RETURN})
 for name,val in(('view_clip_min_x',16),('view_clip_max_x',303),('view_clip_min_y',30),('view_clip_max_y',128),('projection_screen_origin_x',159),('projection_screen_origin_y',79)):word(m,APP+o[name],val)
 for name,val in(('view_origin_x',8192),('view_origin_y',-1000),('view_origin_z',16384)):put(m,APP+o[name],val&0xffffffff)
 m[APP+0x7f6]=2;initialise_directory(platform,m,v);put(v,grid.PACKET_CURSOR,grid.PACKETS);put(v,grid.REFS_CURSOR,grid.REFS);word(v,grid.COUNT,0);word(v,grid.MATERIAL,9)
 c=state(m,0x308d8);run(program(platform),m,c,{RETURN})
 for first,column in((grid.XSTEP,0),(grid.ZSTEP,2)):
  expected=[ground.signed((ground.signed(get(m,APP+0x106+2*(3*row+column),2))*16384)>>16)for row in range(3)]
  assert[ground.signed(get(v,first+2*j,2))for j in range(3)]==expected
 assert get(v,grid.CANDIDATES,2)==0 and 1<=get(v,grid.COUNT,2)<=13
 for p in(0x2f566,0x2f56a):assert get(v,p)&4095==0
 cursor=grid.PACKETS
 for i in range(get(v,grid.COUNT,2)):
  assert get(m,grid.REFS+4*i)==cursor and get(m,cursor,2)==0x7ff0;cursor+=4;vertices=0
  while get(m,cursor,2)<32768:
   x,y=get(m,cursor,2),get(m,cursor+2,2);assert 16<=x<=303 and 30<=y<=128;cursor+=4;vertices+=1
  assert 3<=vertices<=32;cursor+=2
 assert cursor==get(v,grid.PACKET_CURSOR)and get(v,grid.REFS_CURSOR)==grid.REFS+4*get(v,grid.COUNT,2)

@pytest.mark.parametrize('corner,fallback',[(0,True),(1,True),(2,False),(3,False)])
def test_grid_fast_path_reads_padding_only_for_its_first_two_corners(slots,corner,fallback):
 platform,m,v=machine();build_finite_grid(platform,m,v,slots)
 vertex=get(v,grid.DIRECTORY+2*corner,2);v[grid.PROJECTED+vertex+7]=1
 put(v,grid.PACKET_CURSOR,grid.PACKETS);put(v,grid.REFS_CURSOR,grid.REFS);word(v,grid.COUNT,0);word(v,grid.CANDIDATES,25);word(v,grid.PHASE,0)
 c=state(m,address(0x2f2d8));execute(platform,m,c,0x2f2d8,(0x2f370,0x2f4d4))
 assert c.pc==address(0x2f370 if fallback else 0x2f4d4)and get(v,grid.COUNT,2)==(0 if fallback else 1)

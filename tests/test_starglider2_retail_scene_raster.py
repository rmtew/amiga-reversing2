"""Retail packet phases and framebuffer writes using existing independent oracles.

Finite supplied queues and CPU RAM writes do not establish global capacities,
normal-game reachability, palette RGB, interrupt ownership or physical scanout.
"""
import ctypes,os
from functools import cache
import pytest
from tests.test_starglider2_text_editor import state,run,put,get,APP,FB,INPUT,STACK,RETURN,original_image
from test_starglider2_retail_input import program
from tests import test_starglider2_scene_packets as scene
from tests.test_starglider2_scene_packets import fields
from tests.test_starglider2_face_admission import slots
from tests import test_starglider2_planar_span_reader as planar
from tests import test_starglider2_interleaved_reader_context as colour
from tests import test_starglider2_alternate_pattern_reader as pattern
from amiga_reversing.disasm.mapped_execution import MappedExecution
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
DELTA=0x19ac

def address(old):
 if 0x3a0d2<=old<0x3a0d8:return old+0x194c
 if old==0x3af30:return 0x3c87c
 if 0x3a000<=old<0x4bc00:return old+DELTA
 if old in (0xe102,0xe103):return old+0x42
 return old

class EarlierAddresses:
 """Translate fixture addresses only; leave stored pointer values unchanged."""
 def __init__(self,m):self.m=m
 def __iter__(self):return iter(self.m)
 def key(self,k):
  if not isinstance(k,slice):return address(k)
  start=address(k.start);assert address(k.stop-1)==start+k.stop-k.start-1
  return slice(start,start+k.stop-k.start,k.step)
 def __getitem__(self,k):return self.m[self.key(k)]
 def __setitem__(self,k,v):self.m[self.key(k)]=v

@cache
def initialized(profile):
 platform='amiga'if profile=='amiga'else'st';raw=program(platform)[0];m=(ctypes.c_uint8*0xa1000)();ctypes.memmove(ctypes.addressof(m)+4096,raw,len(raw))
 put(m,APP+4,FB);view=EarlierAddresses(m)
 c=state(m,address(0x3e96e));run(program(platform),m,c,{RETURN},limit=50000)
 # Original init generates Amiga masks/rows; ST retains the stored row table.
 stride=40 if profile=='amiga'else 160
 assert all(get(view,0x416b8+2*y,2)==stride*y for y in range(200))
 view[0x416a5]=2 if profile=='mono'else 0
 return bytes(m)

def machine(profile):
 m=(ctypes.c_uint8*0xa1000).from_buffer_copy(initialized(profile))
 return 'amiga'if profile=='amiga'else'st',m,EarlierAddresses(m)

@pytest.mark.parametrize('keys',[(0,65535,32768,1),(3,1,3,0,65535,1),(7,7,7),(0,),(65535,)])
def test_unsigned_depth_sort_reuses_reference_and_payload_contract(keys):
 platform,m,v=machine('amiga');rows=scene.references(v,keys);payload=bytes(m[scene.HEADERS:scene.HEADERS+8*len(keys)])
 c=state(m,address(scene.SORT));c.a[0]=INPUT+4;c.a[1]=INPUT+4*len(keys);run(program(platform),m,c,{RETURN})
 actual=[get(m,INPUT+4+4*i)for i in range(len(keys))]
 assert sorted(actual)==sorted(rows)and[get(m,p,2)for p in actual]==sorted(keys,reverse=True)
 assert bytes(m[scene.HEADERS:scene.HEADERS+8*len(keys)])==payload and get(m,INPUT)==scene.GUARD


def test_sorter_does_not_supply_its_own_high_guard():
 raw=program('st')[0];start=address(scene.SORT);end=address(0x41690);c=MappedExecution(0x100000)
 c.seed(start,raw[start-4096:end-4096]);c.seed(INPUT+4,(INPUT+128).to_bytes(4,'big'));c.allow_write(INPUT+4,4);c.seed(INPUT+128,b'\0\x2a');c.seed(STACK-64,bytes(68));c.allow_write(STACK-64,68);put(c.memory,STACK,0xff000)
 c.cpu.a[0]=c.cpu.a[1]=INPUT+4;c.cpu.a[7]=STACK
 with pytest.raises(ValueError,match='unknown read/fetch'):c.run(start,0xff000,100)

@pytest.mark.parametrize('profile',('amiga','colour','mono'))
@pytest.mark.parametrize('style',range(16))
def test_original_profile_readers_and_all_regular_callbacks_match_existing_pixel_oracles(profile,style):
 platform,m,v=machine(profile);records=[(style,17,[(0,319),(15,16),(127,63)])]
 module=planar if profile=='amiga'else colour
 c=module.prepare(v,None,records);c.pc=address(planar.ENTRY);expected=(pattern.expected if profile=='mono'else module.expected_memory)(v,records)
 # prepare(mode0) deliberately clears the mode snapshot; select mono after it.
 v[0x416a5]=2 if profile=='mono'else 0;expected[address(0x416a5)]=v[0x416a5]
 if profile=='amiga':expected[0xe103]=m[0xe103];expected[address(0xe103)]=5
 run(program(platform),m,c,{RETURN})
 assert bytes(m)==expected and c.a[2]==INPUT+8 and c.a[7]==STACK+4

@pytest.mark.parametrize('profile,style',[('amiga',-1),('amiga',-17),('amiga',-32768),('colour',-1),('colour',-17),('mono',-1),('mono',-17)])
def test_negative_style_families_preserve_each_profile_contract(profile,style):
 platform,m,v=machine(profile);records=[(style,197,[(35,37),(70,71),(110,108)])];module=planar if profile=='amiga'else colour
 c=module.prepare(v,None,records);c.pc=address(planar.ENTRY);v[0x416a5]=2 if profile=='mono'else 0
 expected=(pattern.expected if profile=='mono'else module.expected_memory)(v,records)
 if profile=='amiga':expected[0xe103]=m[0xe103];expected[address(0xe103)]=5
 run(program(platform),m,c,{RETURN});assert bytes(m)==expected

@pytest.mark.parametrize('points',[[(10,5),(20,8)],[(10,8),(20,5)],[(10,5),(20,5),(30,8),(40,5)]])
def test_cycle_keeps_last_equal_minimum_y_and_replaces_reference(points):
 platform,m,v=machine('st');scene.polygon(v,scene.HEADERS,points);put(m,INPUT,scene.HEADERS);put(m,INPUT+4,0xffffffff)
 c=state(m,address(scene.CYCLE));c.a[1]=scene.OUTPUT;c.a[2]=c.a[6]=INPUT;run(program(platform),m,c,{address(scene.HANDOFF)})
 index=max(i for i,xy in enumerate(points)if xy[1]==min(y for x,y in points));expected=points[index:]+points[:index];end=scene.OUTPUT+6+4*len(points)
 assert get(m,scene.OUTPUT)==end and get(m,scene.OUTPUT+4,2)==7
 assert[(get(m,scene.OUTPUT+6+4*i,2),get(m,scene.OUTPUT+8+4*i,2))for i in range(len(points))]==expected
 assert get(m,end)==0 and get(m,INPUT)==scene.OUTPUT and get(m,INPUT+4)==0xffffffff

@pytest.mark.parametrize('profile',('amiga','colour','mono'))
def test_real_packet_cycle_interpolation_and_profile_reader_paint_the_same_horizontal_segment(profile):
 platform,m,v=machine(profile);points=[(20,40),(60,40)];scene.polygon(v,scene.HEADERS,points,style=7);put(m,INPUT,scene.HEADERS);put(m,INPUT+4,0xffffffff);put(v,0x416a8,FB)
 c=state(m,address(scene.CYCLE));c.a[1]=scene.OUTPUT;c.a[2]=c.a[6]=INPUT;m[FB-16:FB+0x8010]=b'\xa5'*0x8020
 records=[(7,40,[(20,60)])];expected=(planar.expected_memory if profile=='amiga'else pattern.expected if profile=='mono'else colour.expected_memory)(v,records)
 expected_fb=bytes(expected[FB-16:FB+0x8010]);run(program(platform),m,c,{RETURN})
 assert bytes(m[FB-16:FB+0x8010])==expected_fb
 span=address(0x41848);assert get(m,INPUT)==span and[get(m,span+2*i,2)for i in range(5)]==[7,40,20,60,65535]
 assert get(m,INPUT+4)==0xffffffff and c.a[7]==STACK+4

@pytest.mark.parametrize('count',(32,33))
def test_clipper_copy_requires_caller_to_respect_the_named_32_xyz_prefix(count):
 raw=program('st')[0];c=MappedExecution(0x100000);start,end=0x5b0a,0x5f04
 c.seed(start,raw[start-4096:end-4096]);source=INPUT;c.seed(source,b'\0\0\0\0\x04\0'*count)
 c.seed(APP,bytes(4096));c.allow_write(APP,4096);c.cpu.a[6]=APP;c.seed(0x5f04,b'\xa5'*194);c.allow_write(0x5f04,192);c.seed(STACK,(0xff000).to_bytes(4,'big'));c.cpu.a[7]=STACK;c.cpu.a[2]=source;c.cpu.a[3]=0;c.cpu.d[7]=count;c.cpu.d[4]=0
 if count==33:
  with pytest.raises(ValueError,match='write'):c.run(start,0xff000,1000)
 else:
  c.run(start,0xff000,1000)
  assert c.cpu.d[7]&65535==32 and c.read(0x5f04,192)==b'\0\0\0\0\x02\0'*32
  assert c.read(0x5f04+192,2)==b'\xa5'*2

@pytest.mark.parametrize('profile,count',[(p,n)for p in('amiga','colour','mono')for n in(0,3)])
def test_actual_preparation_sorts_before_profile_hud_and_refreshes_snapshots(fields,profile,count):
 platform,m,v=machine(profile);keys=[123,65535,0][:count];scene.references(v,keys)
 put(m,fields['draw_buffer_base'],FB);m[fields['alternate_graphics_mode']]=2 if profile=='mono'else 0;put(m,fields['player_rotation_2'],0xf341,2)
 put(m,INPUT+4+4*count,0x3c36);c=state(m,address(scene.PREPARE));c.a[2]=INPUT;c.d[0]=count;run(program(platform),m,c,{address(0x3dad4),RETURN})
 assert get(v,0x416a8)==FB and get(v,0x416a6,2)==0x341 and v[0x416a5]==(2 if profile=='mono'else 0)
 if not count and profile=='amiga':assert c.pc==RETURN and get(m,INPUT+4)==0x3c36;return
 first=INPUT+(4 if count else 0);assert[get(m,get(m,first+4*i),2)for i in range(count)]==sorted(keys,reverse=True)
 tail=first+4*count
 if profile=='amiga':assert c.a[4]==tail
 else:
  assert get(m,tail)==address(0x3a0d2)and c.a[4]==tail+4
  assert get(v,0x3a0d4,2)==(7 if profile=='mono'else 2)
 assert get(m,c.a[4])==0xffffffff


def test_source_tables_reuse_the_hash_checked_earlier_export(original_image):
 old=original_image[0];new=program('st')[0]
 # Five callback tables plus masks, patterns, row offsets and reciprocal data.
 for at,size in[(0x3dd8e,32),(0x3ea92,32),(0x3edc4,32),(0x3f112,32),(0x3ff42,32),(0x3f132,128),(0x3ddae,320),(0x3ffba,4608),(0x4146e,64),(0x415be,128),(0x416b8,400),(0x4b99e,600)]:
  mapped=address(at);assert old[at-4096:at-4096+size]==new[mapped-4096:mapped-4096+size]

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='external vasm is the source build dependency')
def test_compiled_scene_phase_types_and_all_relative_callback_tables(tmp_path):
 import struct,subprocess
 from pathlib import Path
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered';source=(directory/'retail-shared.s').read_text()
 symbols={'sort_and_draw_scene_packets':address(scene.PREPARE),'sort_scene_references_by_depth_key':address(scene.SORT),'draw_scene_packet_spans':address(scene.HANDOFF),'draw_planar_4plane_span_records':address(planar.ENTRY),'draw_interleaved_4plane_span_records':address(colour.ENTRY),'enter_alternate_interleaved_span_reader':address(0x41394),'SG2ScenePolygonHeader_depth_sort_key':0,'SG2SceneCycledHeader_vertices_end':0,'SG2SceneCycledHeader_fill_style':4,'SG2SceneSpanHeader_first_scanline':2,'interleaved_span_right_masks':address(0x3f132),'interleaved_span_left_masks':address(0x3f172)}
 for name in('drawing_dispatch_offsets','planar_cell32_dispatch_offsets','planar_cell16_dispatch_offsets','drawing_dispatch_interleaved_color_offsets','drawing_dispatch_interleaved_cell_color_offsets'):
  block=source.split(name+':',1)[1].split('\n\n',1)[0]
  assert block.count('-'+name)==16,(name,block)
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 result=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert result.returncode==0,result.stdout+result.stderr
 raw=out.read_bytes();size=4*len(symbols);assert raw[:-size]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-size:])==tuple(symbols.values())

@pytest.mark.parametrize('points,sentinel',[
 ([(10,2),(30,8),(0,8)],65535),
 ([(10,2),(30,2),(30,8),(10,8)],32768),
 ([(10,2),(30,5),(40,10),(0,10),(5,6)],65535)])
def test_multi_edge_interpolation_reuses_existing_fraction_and_lane_oracle(points,sentinel):
 from tests import test_starglider2_span_interpolation as edges
 platform,m,v=machine('st');c=edges.prepare(v,[points],sentinel);c.pc=address(scene.CYCLE)
 pairs,fraction=edges.polygon_pairs(v,points,sentinel);run(program(platform),m,c,{address(edges.HANDOFF)})
 span=address(edges.SPANS);expected=[7,min(y for x,y in points),*[v for pair in pairs for v in pair],65535]
 assert[get(m,span+2*i,2)for i in range(len(expected))]==expected
 assert get(m,INPUT)==span and c.a[3]==span+2*len(expected)and c.d[2]&65535==fraction


def test_original_model_admission_reaches_the_amiga_pixel_writer(slots):
 from tests import test_starglider2_face_admission as face
 from tests import test_starglider2_span_interpolation as edges
 from tests.test_starglider2_ground_face_packets import project
 from test_starglider2_retail_model_pipeline import EarlierRenderAddresses
 platform,m,v=machine('amiga');face.check_admission_pipeline(program(platform),m,slots,face.ACCEPT,entry=0x4b6c,view=EarlierRenderAddresses(m),admitted_buffer=0x4ca4e)
 points=[project(p)[:2]for p in face.ACCEPT];pairs,_=edges.polygon_pairs(v,points,65535)
 records=[(3,min(y for x,y in points),pairs)];m[FB-16:FB+0x8010]=b'\xa5'*0x8020;put(v,0x416a8,FB)
 put(m,face.REFS+4,0xffffffff);c=state(m,address(scene.CYCLE));c.a[1]=scene.OUTPUT;c.a[2]=c.a[6]=face.REFS
 expected=planar.expected_memory(v,records);run(program(platform),m,c,{RETURN})
 assert bytes(m[FB-16:FB+0x8010])==bytes(expected[FB-16:FB+0x8010])
 assert get(m,face.REFS)==address(edges.SPANS)and c.a[7]==STACK+4

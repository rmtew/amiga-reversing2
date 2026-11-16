"""Bounded capture/HUD views and ST glyph table on original retail instructions.

Constructed CPU states reuse the independently checked earlier HUD oracle.
These are not natural gameplay, scanout or workspace-lifetime guarantees.
"""
import ctypes,os
import pytest
from tests import test_starglider2_hud_attitude as oracle
from tests.test_starglider2_text_editor import state,run,put,get,APP,INPUT,STACK,RETURN
from test_starglider2_retail_input import program
from tests.test_starglider2_alternate_text import expanded
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')


def memory(platform):
 image=program(platform);m=(ctypes.c_uint8*0xa1000)();ctypes.memmove(ctypes.addressof(m)+4096,image[0],len(image[0]));return image,m


@pytest.fixture
def hud(monkeypatch):
 def address(pc):
  if 0x39d70<=pc<0x3a0b8:return pc+0x194c
  if 0x4b99e<=pc<0x4bd9e:return pc+0x19ac
  return {0x3a2c8:0x3bc14,0x3a2ca:0x3bc16}.get(pc,pc)
 def retail_run(image,m,c,stops,*args,**kw):
  c.pc=0x49ce if c.pc==0x39d70 else address(c.pc)
  run(image,m,c,{address(pc)for pc in stops},*args,**kw)
 monkeypatch.setattr(oracle,'run',retail_run)
 monkeypatch.setattr(oracle,'put',lambda m,a,v,width=4:put(m,address(a),v,width))
 monkeypatch.setattr(oracle,'get',lambda m,a,width=4:get(m,address(a),width))
 for k,v in dict(SINE=0x15808,COS=0x16008,VECTORS=0x3ba04,CORNERS=0x3ba22,CYCLE=0x3ba80,WORK=0x431f4,LEFT=0x3bb98,RIGHT=0x3bb18,MODE=0x3bc1a,ROLL=0x3bc1c).items():monkeypatch.setattr(oracle,k,v)


@pytest.mark.parametrize('platform',('amiga','st'))
@pytest.mark.parametrize('pitch,roll',((0,0),(511,128),(1024,2048),(65535,3968)))
def test_bridge_projection_uses_original_view_angles_and_platform_offset(hud,platform,pitch,roll):
 oracle.test_four_original_vectors_use_view_angles_and_platform_translation(*memory(platform),pitch,roll,platform=='amiga')


@pytest.mark.parametrize('roll,mode',((0,1),(833,0),(2880,2)))
def test_amiga_bridge_runs_projection_spans_plane_writes_and_restores_registers(hud,roll,mode):
 oracle.test_original_entry_connects_projection_spans_plane_and_saved_return(*memory('amiga'),roll,mode)


@pytest.mark.parametrize('roll,mode,first,spans',((832,0,0,[(0,31)]),(2881,2,1,[(31,32)]),(833,1,33,[(1,15),(15,30)])))
def test_amiga_masks_include_left_index31_live_edge_alias(hud,roll,mode,first,spans):
 image,m=memory('amiga');put(m,0x3bc14,0x13572468)
 assert 0x3bb98+31*4==0x3bc14 and get(m,0x3bb98+31*4)==0x13572468
 oracle.test_plane_switch_clear_span_masks_and_unclipped_leading_rows(image,m,roll,mode,first,spans)


@pytest.mark.parametrize('shift,left,right,top,bottom',((0,0,31,0,1),(3,15,16,31,32)))
def test_corner_cycle_reads_complete_sentinel_and_retains_low_word(hud,shift,left,right,top,bottom):
 oracle.test_rectangle_cycle_retains_first_minimum_and_inclusive_span_rows(*memory('amiga'),shift,left,right,top,bottom)


def test_st_bridge_returns_after_projecting_without_raster_plane_writes(hud):
 image,m=memory('st');put(m,APP+0x44,oracle.SINE);put(m,APP+0x48,oracle.COS);put(m,APP+0x748,833,2)
 points,scratch=oracle.projected(m,0,0,False);m[0x70000:0x78000]=b'\xa5'*0x8000
 c=state(m,0x49ce);d=list(c.d);a=list(c.a);before=bytearray(m)
 for i,(x,y)in enumerate(points):put(before,oracle.CORNERS+4*i,x,2);put(before,oracle.CORNERS+4*i+2,y,2)
 put(before,oracle.CORNERS+16,65535,2);put(before,oracle.ROLL,833,2)
 for off,value in zip((0x164,0x166,0x16c,0x16e),scratch):put(before,APP+off,value,2)
 run(image,m,c,{RETURN});before[STACK-96:STACK+4]=bytes(m[STACK-96:STACK+4])
 assert bytes(m)==before and list(c.d)==d and list(c.a[:7])==a[:7]and c.a[7]==STACK+4


@pytest.mark.parametrize('platform',('amiga','st'))
@pytest.mark.parametrize('count',(0,23))
def test_capture_twenty_record_cap_terminator_and_unwritten_tail(platform,count):
 image,m=memory(platform);refs=INPUT;records=INPUT+0x100;player=(0x12345678,0x87654321,0x7fffffff)
 put(m,APP+0x75e,count,2);put(m,APP+0x6c8,refs)
 for off,v in zip((0x704,0x708,0x70c),player):put(m,APP+off,v)
 expected=[]
 for i in range(count):
  at=records+68*i;put(m,refs+4*i,at);tag=(30 if i==0 else 128 if i==1 else i+1);put(m,at,tag,2)
  coords=(i*100000,0xffffffff-i,0x80000000+i)
  for off,v in zip((4,8,12),coords):put(m,at+off,v)
  if tag!=30 and not(tag&128):expected.append((tag,*[(v-p)&65535 for v,p in zip(coords,player)]))
 expected=expected[:20];m[0x3b4d0:0x3b612]=b'\xcc'*322;c=state(m,0x38ad2);run(image,m,c,{RETURN})
 content=b''.join(v.to_bytes(2,'big')for record in expected for v in record)+b'\xff\xff'
 assert bytes(m[0x3b4d0:0x3b612])==content+b'\xcc'*(322-len(content))
 assert get(m,0x3b4ce,2)==(19-len(expected))&65535


def test_st_glyph_table_is_exactly_256_doubled_byte_patterns():
 raw=program('st')[0];table=raw[0x3f16e-4096:0x3f36e-4096]
 assert table==b''.join(expanded(v)for v in range(256))
 # Both existing glyph CPU consumers zero-extend a BYTE then double it;
 # all resulting WORD reads fit,including the final value255 at offset510.
 assert 2*255+2==len(table)==512
 # Preserve the original left-mask omission of $00000FFF at index20.
 for base,size in ((0x3bb18,32),(0x3bb98,31)):
  values=[int.from_bytes(raw[base-4096+4*i:base-4096+4*i+4],'big')for i in range(size)]
  assert values==[((0xffffffff<<(31-i))&0xffffffff)if base==0x3bb18 else 0xffffffff>>(i+(i>=20))for i in range(size)]


@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_bounded_views_and_live_alias_not_adjacent_allocations(tmp_path):
 import json,struct,subprocess
 from pathlib import Path
 target=Path(__file__).resolve().parents[1]/'targets/starglider2_retail';directory=target/'rendered';meta=json.loads((target/'target_metadata.json').read_text())
 symbols=dict(draw_hud_attitude_polygon_bridge=0x49ce,draw_hud_attitude_polygon=0x3b6bc,saved_nearby_object_prefix=0x3b4d0,maximum_saved_nearby_terminator_slot=0x3b570,hud_attitude_rectangle_vectors=0x3ba04,hud_attitude_projected_corners=0x3ba22,hud_attitude_corner_cycle=0x3ba80,hud_attitude_right_pixel_masks=0x3bb18,hud_attitude_left_pixel_mask_prefix=0x3bb98,hud_attitude_forward_edge_x=0x3bc14,hud_attitude_reverse_edge_x=0x3bc16,st_glyph_byte_to_doubled_pixels=0x3f16e,draw_st_mode1_double_width_glyph_rows=0x3d5ba,draw_st_double_width_coordinate_glyph_rows=0x3efd2,SG2NearbyCaptureRecord_relative_z=6,SG2AttitudeVector_z=4)
 # No ownership of the unused capture tail,corner storage tails or table suffix.
 for pc in(0x3b572,0x3ba1c,0x3ba1e,0x3ba36,0x3ba94,0x3bc18,0x3bc1e,0x3f36e):
  assert not any(e['addr']<=pc-4096<(e.get('end')or e['addr'])for e in meta['seeded_entities']if e['type']=='data')
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 result=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True);assert result.returncode==0,result.stdout+result.stderr
 raw=out.read_bytes();n=4*len(symbols);assert raw[:-n]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-n:])==tuple(symbols.values())


@pytest.mark.parametrize('entry,end,coordinate',((0x3d5ba,0x3d656,False),(0x3efd2,0x3f0f6,True)))
@pytest.mark.parametrize('complete',(True,False))
def test_both_glyph_readers_need_last_table_byte_but_not_suffix(entry,end,coordinate,complete):
 from amiga_reversing.disasm.mapped_execution import MappedExecution
 raw=program('st')[0];c=MappedExecution(0x100000,register_seed=0x12340000);stop=0xff000;stack=0xf0000
 c.seed(entry,raw[entry-4096:end-4096]);c.seed(0x3f16e,raw[0x3f16e-4096:0x3f16e-4096+(512 if complete else 511)])
 c.seed(0x80000,b'\xff'*8);c.seed(stack,stop.to_bytes(4,'big'));c.seed(stack-16,bytes(16));c.allow_write(stack-16,16)
 for at in(0x70000,0x72000,0x74000):c.seed(at,bytes(0x500));c.allow_write(at,0x500)
 c.cpu.a[0]=0x70000;c.cpu.a[2]=0x80000;c.cpu.a[3]=0x72000;c.cpu.a[4]=0x74000;c.cpu.a[7]=stack;c.cpu.d[0]=0
 if not complete:
  with pytest.raises(ValueError,match='unknown read/fetch')as failure:c.run(entry,stop,200)
  assert f'0, {0x3f36c}, 2' in str(failure.value)
  return
 c.run(entry,stop,200)
 for at in((0x70000,0x72000,0x74000)if coordinate else(0x70000,)):
  for row in range(16):assert c.read(at+80*row,2)==b'\xff\xff'
 assert c.cpu.a[2]==0x80000 and c.cpu.a[7]==stack+4

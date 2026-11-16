"""Bounded HUD scaling/cache and viewer decimal scratch on original CPUs.

Existing glyph/contact pixel and decimal oracles are reused. Coordinate phases
stop at their real draw/heading call sites;no game call is replaced or stubbed.
"""
import os,struct
import pytest
from test_starglider2_retail_input import program
from tests.test_starglider2_retail_inheritance import context,APP,RETURN
from tests.test_starglider2_retail_numeric_text import expected
from tests import test_starglider2_retail_panel as panel
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
SHIFTS,COLOURS,CACHE,TEXT=0x48f0,0x4900,0x49b6,0x49b8


@pytest.mark.parametrize('platform,body,space,x,z',(('amiga',0,0,0x12345678,0x87654321),('st',15,0,0xffffffff,0x7fffffff),('st',65535,255,0x12345678,0xfedcba98)))
def test_real_quantizer_selects_body_or_space_shift_then_draws_only_changed_pair(platform,body,space,x,z):
 c=context(platform);c.seed(APP+0x830,body.to_bytes(2,'big'));c.seed(APP+0x77d,bytes([space]));c.seed(APP+0x704,x.to_bytes(4,'big'));c.seed(APP+0x70c,z.to_bytes(4,'big'))
 raw=program(platform)[0];table=raw[0x18508-4096:0x18608-4096];shift=16 if space else raw[SHIFTS-4096+body]
 wanted=table[(x>>shift)&255]<<8|table[(z>>shift)&255]
 c.seed(CACHE,b'\xde\xad');c.allow_write(CACHE,2)
 if space:c.known[SHIFTS:COLOURS]=bytes(16) # Space bypasses the body table entirely.
 c.run(0x4548,0x4584,30);assert c.cpu.d[0]&65535==wanted
 c.run(0x4584,0x4592,4);assert c.read(CACHE,2)==wanted.to_bytes(2,'big')
 # Stop before the real glyph call;the independent glyph tests execute it.
 c.run(0x4548,0x4596,40);assert c.read(CACHE,2)==wanted.to_bytes(2,'big')


def test_reset_to_zero_does_not_force_a_redraw_of_zero_coordinates():
 c=context('amiga');c.seed(CACHE,b'\xab\xcd');c.allow_write(CACHE,2);c.seed(APP+0x77d,b'\xff')
 c.run(0x21e2,0x21e8,1);assert c.read(CACHE,2)==bytes(2)
 c.run(0x4548,0x4596,40);assert c.cpu.d[0]&65535==0 and c.read(CACHE,2)==bytes(2)


@pytest.mark.parametrize('profile',('amiga','rgb','mono'))
def test_contact_last_supported_type_uses_colour_prefix_only_in_colour_modes(profile):
 records=[(147,0,512,-512)];c,base=panel.context(profile,records);raw=panel.image(profile)
 c.known[COLOURS:CACHE]=bytes(CACHE-COLOURS)
 if profile!='mono':c.seed(COLOURS,raw[COLOURS-4096:COLOURS-4096+148])
 c.run(0x459c if profile=='amiga'else 0x3c34e,panel.END if profile=='amiga'else 0x3c53c,7000)
 assert c.read(base,32768)==panel.oracle(profile,raw,records)
 # Mono still loads the base into A1,but never reads the colour bytes.


@pytest.mark.parametrize('profile',('amiga','rgb'))
def test_colour_prefix_does_not_claim_unproven_higher_type_slots(profile):
 c,_=panel.context(profile,[(148,0,0,0)]);raw=panel.image(profile);c.known[COLOURS:CACHE]=bytes(CACHE-COLOURS);c.seed(COLOURS,raw[COLOURS-4096:COLOURS-4096+148])
 with pytest.raises(ValueError,match='unknown read/fetch')as failure:
  c.run(0x459c if profile=='amiga'else 0x3c34e,panel.END if profile=='amiga'else 0x3c53c,7000)
 assert f'0, {COLOURS+148}, 1'in str(failure.value)
 # This is a published-view limit,not an added guard or proof that type148
 # can never be supplied. The original caller's indexed access is unchecked.


@pytest.mark.parametrize('value',(0,4095,65535,32768))
def test_actual_viewer_buffer_supports_four_positions_plus_optional_sign_and_nul(value):
 for platform in('amiga','st'):
  c=context(platform);c.seed(TEXT-2,b'\xcc'*12);c.allow_write(TEXT,6);c.allow_write(APP+0x58,4)
  c.cpu.a[1]=TEXT;c.cpu.d[0]=value;wanted=expected('four',value)
  c.run(0xfdda,RETURN,1000)
  assert c.read(TEXT,len(wanted))==wanted
  assert c.read(TEXT-2,2)==b'\xcc'*2 and c.read(TEXT+len(wanted),8-len(wanted))==b'\xcc'*(8-len(wanted))
  assert int.from_bytes(c.read(APP+0x58,4),'big')==TEXT+len(wanted)


@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_hud_views_stop_at_supported_prefix_and_buffer_bounds(tmp_path):
 import json,subprocess
 from pathlib import Path
 target=Path(__file__).resolve().parents[1]/'targets/starglider2_retail';directory=target/'rendered';meta=json.loads((target/'target_metadata.json').read_text())
 symbols=dict(body_hud_coordinate_right_shifts=SHIFTS,contact_type_plane_masks=COLOURS,hud_coordinate_bcd_pair_cache=CACHE,viewer_decimal_text_scratch=TEXT,select_body_hud_coordinate_shift=0x4552,quantize_world_xz_for_hud_digits=0x4560,cache_and_draw_changed_hud_coordinates=0x458c,update_heading_after_coordinate_cache_check=0x4596)
 for pc in(COLOURS+148,TEXT+6):assert not any(e['type']=='data'and e['addr']<=pc-4096<(e.get('end')or e['addr'])for e in meta['seeded_entities'])
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True);assert r.returncode==0,r.stdout+r.stderr
 raw=out.read_bytes();n=4*len(symbols);assert raw[:-n]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-n:])==tuple(symbols.values())

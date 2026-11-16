"""Retail heat/pressure and shared countdown consumers on original CPUs.

RAM, metrics and nearby lists are explicit inputs, not a natural flight replay
or proof that arbitrary selectors and out-of-range table aliases occur in play.
"""
import ctypes,os
import pytest
from tests import test_starglider2_space_hazards as oracle
from tests.test_starglider2_text_editor import state,run,put,get,APP,STACK
from test_starglider2_retail_input import program
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
SYMBOLS={
 'space_environment_flag':APP+0x77d,'system_center_proximity_metric':APP+0x9b4,
 'millway_proximity_metric':APP+0x9bc,'player_world_y':APP+0x708,
 'icarus_shield_strength':APP+0x776,'icarus_power_reserve':APP+0x774,
 'type128_disc_outer_layer_index':APP+0x9cc,'nearby_object_count':APP+0x75e,
 'nearby_objects_cursor':APP+0x6c8,'space_effect_base_rgb_word':0x3afa2,
 'space_effect_override_rgb_word':0x3afa4,'system_center_space_colour_bytes':0x3afa6,
 'millway_space_colour_bytes':0x3afbe,'type128_disc_layers_by_proximity':0x3afd6,
 'fatal_overheat_latched_flag':0x3b61e,'event_message_pointers':0x394ba,
 'energy_spheroid_primary_colour_sequence':0x3af64,'energy_spheroid_secondary_colour_sequence':0x3af82,
 'SG2_SPACE_EFFECT_DEFAULT_OVERRIDE_RGB':39,'SG2_SPACE_EFFECT_OVERRIDE_RGB_BITS':76,
}

@pytest.fixture(params=('amiga','st'))
def machine(request,monkeypatch):
 image=program(request.param);m=(ctypes.c_uint8*0xa1000)();ctypes.memmove(ctypes.addressof(m)+4096,image[0],len(image[0]))
 def retail_run(image,m,c,stops,*args,**kw):
  delta=0x195a if c.pc>=0x362f4 else 0x195e
  c.pc+=delta;run(image,m,c,{p+delta for p in stops},*args,**kw);c.pc-=delta
 monkeypatch.setattr(oracle,'run',retail_run)
 for k,v in dict(NOTICE=0x3afa0,QUEUE=0xe0c6,BLANK=0xe0fa).items():monkeypatch.setattr(oracle,k,v)
 return image,m,SYMBOLS

@pytest.mark.parametrize('metric,shield,notice,power',(
 (0,'borrow',7,0),(0,'exact',1,0),(0,'survive',0,65530),
 (0x40000,'maximum',32768,65530),(5999999,'exact',0,0),
 (0xffffffff,'survive',1,0),
))
def test_heat_damage_borrow_recharge_carry_and_warning_reload(machine,metric,shield,notice,power):
 oracle.test_star_heat_uses_word_damage_borrow_and_power_carry_with_metric_warning_reload(*machine,metric,shield,notice,power)

@pytest.mark.parametrize('metric,shield,notice',((0,'borrow',7),(0,'exact',0),(899999,'survive',1),(900000,'exact',0),(1199999,'maximum',32768),(0xffffffff,'borrow',0)))
def test_pressure_has_two_losses_without_heat_recharge_or_actor_retirement(machine,metric,shield,notice):
 oracle.test_millway_pressure_uses_two_losses_and_fixed_warning_reload_without_power_or_retirement(*machine,metric,shield,notice)

@pytest.mark.parametrize('latch',(0,127,128,255))
def test_fatal_heat_warning_and_one_time_nonplayer_phase_clear(machine,latch):
 oracle.test_fatal_heat_always_requests_warning_but_only_nonnegative_latch_clears_nonplayer_phases(*machine,latch)

@pytest.mark.parametrize('space,star,pressure,y,route,index',(
 (0,0,0,-20000000,'skip',None),(1,0,0,-20000000,'skip',None),
 (128,0,0,-20000000,'star',0),(255,5999999,0,-18000001,'star',22),
 (255,6000000,0,-20000000,'pressure',0),(255,6000000,1199999,-19600001,'pressure',18),
 (255,6000000,1200000,-20000000,'default',None),
 (255,0,1200000,-18000000,'default',None),(255,0,1200000,-22000000,'default',None),
 (255,6000000,0,-19600000,'default',None),(255,6000000,0,-20400000,'default',None),
 (255,0x80000000,0,-20000000,'pressure',0),(255,0x80600000,0,-20000000,'star',8216),
 (255,0xffffffff,0,-20000000,'star',16383),(255,6000000,0xffffffff,-20000000,'pressure',65535),
 (255,0,0,-2147483648,'default',None),(255,0,1200000,-21999999,'star',0),
))
def test_exposure_priority_height_edges_and_n_only_aliases(machine,space,star,pressure,y,route,index):
 oracle.test_proximity_and_height_routes_preserve_priority_n_only_aliases_and_default_distinction(*machine,space,star,pressure,y,route,index)

@pytest.mark.parametrize('producer,index',(('star_reset',30),('star_reset',31),('pressure_reset',30),('pressure_reset',31),('word_overflow',30),('word_overflow',31)))
def test_warning_producer_reaches_actual_shared_spheroid_colour_consumer(machine,producer,index):
 oracle.test_warning_reload_is_read_as_mutable_tail_bytes_by_original_spheroid_phase(*machine,producer,index)

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_hazard_symbols_and_finite_lookup_extents(tmp_path):
 import struct,subprocess,json
 from pathlib import Path
 target=Path(__file__).resolve().parents[1]/'targets/starglider2_retail';directory=target/'rendered';source=(directory/'retail-shared.s').read_text()
 symbols={'gate_space_proximity_damage_or_surface_service':0x34c6e,'gate_millway_pressure_service':0x34d9e,'handle_fatal_star_heat_borrow':0x34cf0,'clear_next_nonplayer_phase_after_fatal_heat':0x34d2e,'age_millway_pressure_warning_countdown':0x34e38,'system_center_space_colour_bytes':0x3afa6,'millway_space_colour_bytes':0x3afbe,'type128_disc_layers_by_proximity':0x3afd6,'space_hazard_notice_countdown':0x3afa0,'energy_spheroid_secondary_colour_sequence':0x3af82}
 assert 'bclr.b #2,SG2ActorModelPrefix_flags(a2)'in source
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert r.returncode==0,r.stdout+r.stderr
 raw=out.read_bytes();n=4*len(symbols);assert raw[:-n]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-n:])==tuple(symbols.values())
 md=json.loads((target/'target_metadata.json').read_text())
 for name,size,unit in (('system_center_space_colour_bytes',24,'byte'),('millway_space_colour_bytes',24,'byte'),('type128_disc_layers_by_proximity',62,'word')):
  owner=next(e for e in md['seeded_entities']if e.get('name')==name and e.get('end')is not None)
  assert owner['end']-owner['addr']==size and owner['unit']==unit
 # Do not enlarge the existing numeric prefix just to absorb the writable WORD.
 owner=next(e for e in md['seeded_entities']if e.get('name')=='energy_spheroid_secondary_colour_sequence')
 timer=next(e for e in md['seeded_entities']if e.get('name')=='space_hazard_notice_countdown')
 assert owner['end']-owner['addr']==30 and timer['addr']==owner['end']and timer['end']-timer['addr']==2

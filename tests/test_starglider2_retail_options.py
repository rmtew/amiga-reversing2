"""Retail options-state windows using existing independent text/state oracles.

Sparse RAM represents the ST IKBD data port; this does not execute disk I/O,
deliver real input, establish live timing or impose boolean saved settings.
"""
import os
import pytest
from tests import test_starglider2_options_controls as old
from test_starglider2_retail_input import memory,program
from tests.test_starglider2_text_editor import state,run,put,get,APP,STACK,RETURN
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
FIELDS=dict(crosshair_autocentre_mode=0x7f0,fixed_sight_mode_flag=0x7e6,one_hand_control_flag=0x7f1,joystick_control_enabled_flag=0x7ef,pilot_rating_saved_control_settings=0x1310e,options_joystick_status_text=0xe7cf,options_one_hand_status_text=0xe7f4,options_fixed_sight_status_text=0xe819,options_autocentre_status_text=0xe83e)


def address(pc):return pc+(0x48 if pc<0xe440 else 0x4c)if 0xe12c<=pc<0xe6fa else pc

@pytest.fixture(params=('amiga','st'))
def machine(request,monkeypatch):
 platform=request.param;m=memory(platform)
 def retail_run(image,m,c,stops,*args,**kwargs):
  c.pc=address(c.pc);return run(image,m,c,{address(p)for p in stops},*args,**kwargs)
 monkeypatch.setattr(old,'run',retail_run)
 return platform,program(platform),m


@pytest.mark.parametrize('mode,enabled',((0,False),(1,True),(2,False),(3,True),(4,True),(128,False),(255,True)))
def test_loaded_statuses_reuse_original_nonzero_and_autocentre_oracle(machine,mode,enabled):
 platform,image,m=machine;old.test_loaded_settings_render_nonzero_flags_and_all_autocentre_bytes(image,m,FIELDS,mode,enabled)

@pytest.mark.parametrize('mode',(0,1,2,3,128,255))
def test_autocentre_cycle_retains_partial_text_updates(machine,mode):
 platform,image,m=machine;old.test_autocentre_cycle_preserves_the_original_partial_text_updates(image,m,FIELDS,mode)

@pytest.mark.parametrize('value,entry,flag,status,true_value',[(v,*p)for v in(0,2,255)for p in((0xe55e,'one_hand_control_flag','options_one_hand_status_text',1),(0xe5ba,'fixed_sight_mode_flag','options_fixed_sight_status_text',255))])
def test_toggle_encodings_and_partial_status_writes(machine,value,entry,flag,status,true_value):
 platform,image,m=machine;old.test_menu_toggles_use_nonzero_tests_and_distinct_true_encodings(image,m,FIELDS,value,entry,flag,status,true_value)

@pytest.mark.parametrize('value,one_hand',((0,255),(2,255),(255,0)))
def test_joystick_off_dependency_and_st_port_command(machine,value,one_hand):
 platform,image,m=machine;m[0xfffffc02]=0xa5
 old.test_joystick_off_also_disables_one_hand_without_normalizing_unrelated_flags(image,m,FIELDS,value,one_hand)
 assert m[0xfffffc02]==((0x14 if value==0 else 8)if platform=='st'else 0xa5)

@pytest.mark.parametrize('values',((0,0,0,0),(3,128,255,2)))
def test_four_saved_option_bytes_preserve_the_opaque_tail(machine,values):
 platform,image,m=machine;old.test_four_saved_bytes_roundtrip_without_touching_the_opaque_tail(image,m,FIELDS,values)

@pytest.mark.parametrize('first', (0,ord('/'),ord('0'),ord('7'),ord('8'),255))
def test_mouse_scale_accepts_only_single_ascii_digit_zero_through_seven(machine,first):
 platform,image,m=machine;m[0xe9d3]=first;put(m,APP+0x740,0x1234,2)
 c=state(m,0xe3ee);run(image,m,c,{0xe29e})
 assert get(m,APP+0x740,2)==(first-48 if 48<=first<=55 else 0x1234)


def test_mouse_editor_call_declares_one_character_limit(machine):
 platform,image,m=machine;c=state(m,0xe3d6);run(image,m,c,{0xd804})
 assert c.a[0]==0xe9d3 and get(m,0xd930,2)==1 and get(m,c.a[7])==0xe3e6


@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_options_state_streams_and_interior_names(tmp_path):
 import struct,subprocess
 from pathlib import Path
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered';source=(directory/'retail-shared.s').read_text()
 symbols={'options_menu_heading':0xe78f,'options_joystick_status_text':0xe7cf,'options_one_hand_status_text':0xe7f4,'options_fixed_sight_status_text':0xe819,'options_autocentre_status_text':0xe83e,'mouse_scaling_prompt_prefix':0xe915,'mouse_scaling_decimal_text':0xe940,'mouse_scaling_input_prompt':0xe946,'mouse_scale_input_prefix':0xe9d3,'options_menu_palette':0xe9de,'saved_options_control_bytes':0x1310e,'SG2OptionsWorkspace_joystick_control_enabled_flag':0x7ef,'SG2OptionsWorkspace_one_hand_control_flag':0x7f1}
 assert 'SG2OptionsWorkspace_joystick_control_enabled_flag(a6)'in source
 assert source.count('options_menu_heading:')==1 and source.count('mouse_scaling_decimal_text:')==1
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert r.returncode==0,r.stdout+r.stderr
 raw=out.read_bytes();size=4*len(symbols)
 assert raw[:-size]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-size:])==tuple(symbols.values())

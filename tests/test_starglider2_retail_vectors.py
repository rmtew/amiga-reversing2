"""Installed Amiga vectors and original handlers under supplied CPU frames.

Custom/CIA apertures are RAM,not chip emulation. Tests establish installation,
finite CPU effects and short-frame RTE behavior,not hardware interrupt delivery,
68000 bus-error recovery,priority ownership or physical acknowledgement timing.
"""
import os,struct
import pytest
from amiga_reversing.disasm.mapped_execution import MappedExecution
from test_starglider2_retail_input import program
from tests.test_starglider2_hud_coordinates import run_ram
from tests.test_memory_frame_arithmetic import ConcreteState
from tests import test_starglider2_interrupt_motion_gates as motion
from tests.test_starglider2_text_editor import state,run,put,get,APP as DENSE_APP
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
CUSTOM,APP,STACK,RETURN=0xdff000,0x90000,0xf0000,0xff000


def context():
 c=MappedExecution(0xe00000,register_seed=0x12345678);c.seed(4096,program('amiga')[0]);c.seed(STACK-256,bytes(262));c.allow_write(STACK-256,256)
 c.seed(APP,bytes(0x6598));c.allow_write(APP,0x6598);c.seed(0x27be,APP.to_bytes(4,'big'));c.seed(CUSTOM,bytes(0x200));c.allow_write(CUSTOM,0x200)
 c.cpu.a[5]=CUSTOM;c.cpu.a[6]=APP;c.cpu.a[7]=STACK;return c


def exception(c,sr=0x2315):
 frame=struct.pack('>HI',sr,RETURN);c.seed(STACK,frame);c.cpu.a[7]=STACK;c.cpu.sr=0x2700
 c.cpu.a[5]=0xdead00;c.cpu.a[6]=0xbeef00 # Arbitrary interrupted values,not installer bases.
 return frame,list(c.cpu.d),list(c.cpu.a[:7])


def finish_rte(c,at,frame,registers):
 assert c.cpu.pc==at and c.cpu.a[7]==STACK and c.read(STACK,6)==frame
 run_ram(program('amiga'),c.memory,ConcreteState.from_buffer(c.cpu),{RETURN},limit=2)
 assert c.cpu.a[7]==STACK+6 and c.cpu.sr==int.from_bytes(frame[:2],'big')
 assert list(c.cpu.d)==registers[0]and list(c.cpu.a[:7])==registers[1]


def test_bulk_defaults_temporary_probe_and_final_vector_ownership_are_distinct():
 c=context();c.seed(STACK,RETURN.to_bytes(4,'big'));c.allow_write(8,124)
 c.run(0xce0a,0xce1c,100);assert c.read(8,124)==struct.pack('>31I',*([0xcef4]*31))
 c.allow_write(0x10612,1);c.run(0xce1c,0xce32,8)
 assert c.read(8,8)==struct.pack('>II',0xceec,0xceec)
 expected={0x64:0xcbec,0x68:0xc8d0,0x6c:0xc6fa,0x70:0x10560,0x74:0xcbd0,0x78:0xc896,0x7c:0xc8b2,0x60:0xc8b2,8:0xc628,12:0xc666,16:0xc6a4,20:0xc6f0}
 c.run(0xce4a,0xceaa,12)
 for vector,target in expected.items():assert int.from_bytes(c.read(vector,4),'big')==target
 assert c.read(0x80,4)==(0xcef4).to_bytes(4,'big') # Default trap0 slot survives.

@pytest.mark.parametrize('entry,rte,pending_bits',((0xcbd0,0xcbea,0xffff),(0xc896,0xc8b0,0x8000),(0xc8b2,0xc8cc,0x4123),(0xcbd0,0xcbea,0)))
def test_level5_level6_and_shared_level7_spurious_ack_preserve_saved_registers(entry,rte,pending_bits):
 c=context();c.seed(CUSTOM+0x1e,pending_bits.to_bytes(2,'big'));c.seed(CUSTOM+0x9c,b'\xa5\x5a');frame,d,a=exception(c)
 c.run(entry,rte,30);assert c.read(CUSTOM+0x9c,2)==(pending_bits&0x7fff).to_bytes(2,'big');finish_rte(c,rte,frame,(d,a))
 # They acknowledge all returned low15 request bits,not a level-specific mask.


def test_disk_block_level1_sets_completion_and_returns_without_general_register_clobber():
 c=context();c.allow_write(0x12610,2);c.seed(0x12610,b'\x12\x34');frame,d,a=exception(c)
 c.run(0xcbec,0xcbfc,4);assert c.read(CUSTOM+0x9c,2)==b'\0\2'and c.read(0x12610,2)==b'\xff\xff';finish_rte(c,0xcbfc,frame,(d,a))


def test_divide_by_zero_colour_marker_preserves_short_frame_and_registers():
 c=context();frame,d,a=exception(c);c.run(0xc6f0,0xc6f8,2);assert c.read(CUSTOM+0x180,2)==b'\x0f\x0f';finish_rte(c,0xc6f8,frame,(d,a))


def test_temporary_upper_ram_probe_sets_flag_then_uses_default_rte_tail():
 c=context();c.allow_write(0x10612,1);c.seed(0x10612,b'\0');frame,d,a=exception(c)
 c.run(0xceec,0xcef4,1);assert c.read(0x10612,1)==b'\xff';finish_rte(c,0xcef4,frame,(d,a))
 # This supplied short frame is not a seven-WORD 68000 bus/address-error frame.

@pytest.mark.parametrize('cooldown,ticks,window',((0,0,0),(1,49,7),(32768,65535,65535)))
def test_full_level3_disabled_game_services_runs_input_hud_then_restores_exception(cooldown,ticks,window):
 c=context();c.seed(0xbfe000,bytes(0x1000));c.allow_write(0xbfe000,0x1000)
 c.seed(APP+0x7c4,cooldown.to_bytes(2,'big'));c.seed(APP+0x160,ticks.to_bytes(2,'big'));c.seed(APP+0x162,window.to_bytes(2,'big'))
 c.seed(CUSTOM+0x1e,b'\xff\xff');frame,d,a=exception(c);c.run(0xc6fa,0xc894,500)
 next_ticks=(ticks+1)&65535;sample=next_ticks>=int.from_bytes(c.read(0xc4ec,2),'big')
 assert int.from_bytes(c.read(APP+0x160,2),'big')==(0 if sample else next_ticks)
 assert int.from_bytes(c.read(APP+0x17c,2),'big')==1
 assert int.from_bytes(c.read(APP+0x15e,2),'big')==(window if sample else 0)
 assert int.from_bytes(c.read(APP+0x162,2),'big')==(0 if sample else window)
 assert int.from_bytes(c.read(APP+0x754,2),'big')==(65535 if sample else 0)
 left=(cooldown-1)&65535;assert int.from_bytes(c.read(APP+0x7c4,2),'big')==(0 if left&32768 else left)
 assert c.read(CUSTOM+0x9c,2)==b'\0\x20'and c.read(CUSTOM+0x120,32)==struct.pack('>8I',*([0xd644]*8))
 finish_rte(c,0xc894,frame,(d,a))

@pytest.mark.parametrize('modal,partition,count',((0,0,0),(0,0,2),(1,0,2),(0,1,2)))
def test_retail_level3_motion_tail_reuses_checked_signed_velocity_oracle(monkeypatch,modal,partition,count):
 import ctypes
 image=program('amiga');m=(ctypes.c_uint8*0xa1000)();ctypes.memmove(ctypes.addressof(m)+4096,image[0],len(image[0]))
 def retail_run(image,m,c,stops,*args,**kwargs):c.pc+=12;run(image,m,c,{p+12 for p in stops},*args,**kwargs);c.pc-=12
 monkeypatch.setattr(motion,'run',retail_run);monkeypatch.setattr(motion,'PARTITION',0x49c2)
 fields={n:DENSE_APP+off for n,off in(('modal_command_input_flag',0x6da),('integrating_object_count',0x788),('integrating_objects_cursor',0x6bc),('horizontal_world_wrap_mask',0x6fc))}
 motion.test_any_nonzero_gate_skips_object_motion_and_zero_allows_signed_velocity_then_xz_wrap(image,m,fields,0xc82c,0xc876,modal,partition,count)

@pytest.mark.parametrize('inhibit,count',((0,0),(0,1),(0,32768),(128,0)))
def test_raster_reload_tail_uses_nonzero_inhibit_and_sign_after_word_decrement(inhibit,count):
 import ctypes
 image=program('amiga');m=(ctypes.c_uint8*0xa1000)();ctypes.memmove(ctypes.addressof(m)+4096,image[0],len(image[0]));m[0xc4ee]=inhibit;put(m,0xc4ea,count,2)
 c=state(m,0xc820);run(image,m,c,{0xc838});assert get(m,0xc4ea,2)==(count if inhibit else 5 if(count-1)&32768 else(count-1)&65535)

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_vector_entries_are_derived_and_register_views_start_after_loads(tmp_path):
 from pathlib import Path
 import subprocess,json
 target=Path(__file__).resolve().parents[1]/'targets/starglider2_retail';directory=target/'rendered';text=(directory/'retail-shared.s').read_text();metadata=json.loads((target/'target_metadata.json').read_text())
 symbols=dict(mark_amiga_divide_by_zero_colour=0xc6f0,amiga_vertical_blank_game_service=0xc6fa,acknowledge_amiga_pending_requests_level6=0xc896,acknowledge_amiga_pending_requests_level7_or_spurious=0xc8b2,acknowledge_amiga_pending_requests_level5=0xcbd0,signal_amiga_disk_block_completion_interrupt=0xcbec,mark_failed_amiga_upper_ram_probe=0xceec,amiga_default_exception_rte=0xcef4,SG2AmigaFrameWorkspace_weapon_action_cooldown=0x7c4,SG2AmigaFrameWorkspace_frame_service_ticks_in_window=0x160,SG2AmigaMusicCustomRegisters_interrupt_acknowledge=0x9c)
 for name in list(symbols)[:8]:assert not text.split(name+':',1)[1].split('\n',2)[1].startswith('\tdc.'),name
 roots={pc-4096 for pc in list(symbols.values())[:8]};assert not roots&{e['addr']for e in metadata['seeded_code_entrypoints']}
 for seed in metadata['entry_register_seeds']:
  if seed.get('context_name')in('workspace_loaded_inside_amiga_level3_handler','custom_base_loaded_inside_interrupt_handler'):assert seed['entry_offset']not in roots
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 result=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True);assert result.returncode==0,result.stdout+result.stderr
 raw=out.read_bytes();n=4*len(symbols);assert raw[:-n]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-n:])==tuple(symbols.values())

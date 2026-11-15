"""Original new-game, resume and saved-state boundaries over supplied RAM.

Disk/UI calls are explicit stop points, not emulated successful operations.
Checksum/copy/rebase run unmodified. No complete disk or valid-save claim.
"""
import os
import pytest
from test_starglider2_retail_inventory import base,APP,STACK,RETURN
from test_starglider2_retail_workspace import put,get,expected as rebase_expected
from test_starglider2_retail_mission_state import prepare_reset
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')

DEFAULTS={0x754:(2,50),0x742:(2,0),0x7c6:(2,65535),0x1aa:(2,4),0x798:(2,3),0x79a:(2,50),0x71c:(4,0),0x7f2:(1,64),0x5c:(2,0),0x1fe:(1,0),0x7aa:(2,0x9999),0x7ac:(2,1),0x17c:(2,0),0x7c4:(2,0),0x6dc:(4,0),0x6e4:(4,0),0x6e0:(4,0),0x6e8:(4,0),0x6f8:(4,0),0x6f4:(4,0),0x6f0:(4,0),0x6ec:(4,0),0x792:(2,0),0x76a:(2,0),0x76c:(2,0),0x7a2:(2,0),0x7a4:(2,0),0x7a6:(2,0),0x7a8:(2,0xff74),0x776:(2,0),0x774:(2,0),0x794:(2,0),0x758:(2,0),0x752:(2,16),0x796:(2,0),0x78e:(2,0),0x744:(2,0),0x746:(2,0),0x748:(2,0),0x7b6:(2,0),0x7b8:(2,0),0x7ba:(2,0),0x7bc:(2,0),0x7be:(2,0),0x7c0:(2,0),0x704:(4,50100),0x70c:(4,24400),0x708:(4,-1000),0x710:(4,50100),0x714:(4,-1000),0x718:(4,24400),0x11e:(2,65535),0x122:(2,65535),0x78a:(2,0),0x78c:(2,0),0x7ea:(1,0),0x7eb:(1,0),0x7ec:(1,0),0x7e9:(1,255),0x1f6:(1,0),0x77c:(1,0),0x7e4:(1,0),0x77d:(1,0),0x7ce:(1,0),0x7cf:(1,0),0xbba:(1,0),0x830:(2,3),0x7f6:(1,3),0xbb9:(1,255),0x6fc:(4,0x1ffff),0x192:(2,30)}

@pytest.mark.parametrize('platform,fill,centre',[('st',0xa5,(160,79)),('amiga',0x55,(319,199))])
def test_fresh_defaults_full_footprint_preserves_mission_pool_and_device_preferences(platform,fill,centre):
 c=base(platform);c.seed(APP,bytes([fill])*0x6598)
 put(c.memory,APP+0x19c,centre[0],2);put(c.memory,APP+0x19e,centre[1],2)
 expected=bytearray(c.read(APP,0x6598));source=c.read(0x1000,419308)
 for off,(width,value)in DEFAULTS.items():put(expected,off,value,width)
 put(expected,0x766,centre[0],2);put(expected,0x768,centre[1],2)
 c.run(0x2028,RETURN,300)
 assert c.read(APP,0x6598)==expected and c.read(0x1000,419308)==source
 assert c.cpu.a[7]==STACK+4

@pytest.mark.parametrize('guard',(0,0x66e3))
def test_defaults_guard_redirects_to_splash_before_any_workspace_write(guard):
 c=base();c.seed(0xcc5c,guard.to_bytes(2,'big'));before=c.read(APP,0x6598)
 c.run(0x2028,0x2292,10);assert c.read(APP,0x6598)==before and c.cpu.a[7]==STACK

@pytest.mark.parametrize('platform',('st','amiga'))
def test_new_game_original_call_chain_resets_flight_then_mission_before_cockpit(platform):
 c=base(platform);c.allow_write(0xe144,2);prepare_reset(c)
 for off in (0xa7f,0xa80,0xa81,0xa82,0xa83,0xa84):c.memory[APP+off]=255
 c.seed(APP+0x2330,b'\xcc'*17000);put(c.memory,APP+0x71c,0x12345678)
 put(c.memory,APP+0x19c,160,2);put(c.memory,APP+0x19e,79,2)
 c.run(0x121a,0x21aa,3000)
 assert [get(c.memory,APP+o)for o in (0x704,0x708,0x70c)]==[50100,0xfffffc18,24400]
 assert get(c.memory,APP+0x71c)==0 and c.read(APP+0xa7f,6)==bytes(6)
 assert c.read(APP+0x2330,17000)==b'\xcc'*17000
 assert get(c.memory,c.cpu.a[7])==0x1240 and c.memory[APP+0x204]==0

@pytest.mark.parametrize('available',(0,1,128,255))
def test_interrupted_resume_gate_requires_nonzero_saved_state_flag(available):
 c=base();c.memory[APP+0xbbb]=available;c.seed(STACK,(0x1234).to_bytes(4,'big')+RETURN.to_bytes(4,'big'))
 before=c.read(APP,0x6598);c.run(0xe42e,0xe43a if not available else 0x11f8,30)
 assert c.read(APP,0x6598)==before
 assert c.cpu.a[7]==STACK+(4 if available else 0)

@pytest.mark.parametrize('platform',('st','amiga'))
def test_resume_bridge_goes_to_cockpit_without_new_game_or_mission_reset(platform):
 c=base(platform);c.seed(APP,b'\xa5'*0x6598);before=c.read(APP,0x6598)
 c.run(0x131d4,0x21aa,10)
 assert c.read(APP,0x6598)==before and get(c.memory,c.cpu.a[7])==0x11fc

@pytest.mark.parametrize('values',[(0,0,0,0),(3,255,1,128)])
def test_options_start_persists_only_four_preferences_then_returns(values):
 c=base();c.allow_write(0xe8f9,1);c.allow_write(0x1310e,4)
 for off,value in zip((0x7f0,0x7e6,0x7f1,0x7ef),values):c.memory[APP+off]=value
 before=c.read(APP,0x6598);c.run(0xe702,0xe72e,10)
 assert get(c.memory,c.cpu.a[7])==0xe70e
 c.cpu.a[7]+=4  # Heading UI is outside this original persistence continuation.
 c.run(0xe70e,RETURN,30)
 assert c.read(0x1310e,4)==bytes(values) and c.read(APP,0x6598)==before

@pytest.mark.parametrize('platform',('st','amiga'))
def test_load_entry_invalidates_resume_before_first_disk_ui_boundary(platform):
 c=base(platform);c.memory[APP+0xbbb]=255
 for at,size in ((0x12608,2),(0x12614,2),(0x12628,4),(0x1261c,4)):c.allow_write(at,size)
 before=bytearray(c.read(APP,0x6598));before[0xbbb]=0
 c.run(0xff6a,0x10e26,20)
 assert c.read(APP,0x6598)==before
 assert [get(c.memory,p,w)for p,w in ((0x12608,2),(0x12614,2),(0x12628,4),(0x1261c,4))]==[10,1,0x7e000,0x129c2]

@pytest.mark.parametrize('platform,valid,word',[('st',True,0),('amiga',True,0xffffffff),('st',False,0xffffffff),('amiga',False,0x80000000)])
def test_checksum_acceptance_copies_exact_saved_suffix_and_restores_actual_pointer_encoding(platform,valid,word):
 c=base(platform);prefix,size,source=0x6b4,0x5ee4,0x431f4
 saved=bytearray(size)
 for n in range(0,size,4):put(saved,n,(word+n*0x1020304)&0xffffffff)
 # Known pointer encodings and two guarded actor-link examples, not a valid save.
 put(saved,0x700-prefix,0x2330);put(saved,0x85a-prefix,0);put(saved,0x9b0-prefix,0)
 for n in range(250):
  at=0x2330-prefix+68*n;put(saved,at,0x80,2)
 c.seed(source,bytes(saved));checksum=sum(int.from_bytes(saved[n:n+4],'big')for n in range(0,size,4))&0xffffffff
 c.seed(source+size,((checksum+(not valid))&0xffffffff).to_bytes(4,'big'))
 c.seed(APP,b'\x5a'*0x6598);c.memory[APP+0xbbb]=0;before=c.read(APP,0x6598)
 c.run(0xffd2,0xfdf8 if valid else 0x1000a,30000)
 assert c.read(source,size)==saved
 if not valid:assert c.read(APP,0x6598)==before
 else:
  expected=bytearray(c.memory);expected[APP:APP+0x6598]=before
  expected[APP+prefix:APP+0x6598]=saved
  expected=rebase_expected(expected,APP,True)
  assert c.read(APP,0x6598)==expected[APP:APP+0x6598]
  assert c.read(APP,prefix)==before[:prefix] and get(c.memory,APP+0x700)==APP+0x2330

@pytest.mark.parametrize('platform',('st','amiga'))
def test_loaded_resume_keeps_restored_mission_state_until_cockpit_entry(platform):
 c=base(platform);prepare_reset(c);c.allow_write(0xe144,2)
 c.run(0x121a,0x21aa,3000)
 # Disk restore overwrites reset values; resume must not apply reset again.
 for off in (0xa7f,0xa81,0xa83):c.memory[APP+off]=255
 put(c.memory,APP+0x704,123456);put(c.memory,APP+0x71c,0x98765432)
 before=c.read(APP,0x6598);c.cpu.a[7]=STACK
 c.run(0x131d4,0x21aa,10)
 assert c.read(APP,0x6598)==before and get(c.memory,APP+0x71c)==0x98765432

@pytest.mark.parametrize('platform',('st','amiga'))
def test_new_world_call_chain_reseeds_target_tags_and_pool_before_shared_effects(platform):
 c=base(platform);prepare_reset(c);c.allow_write(0xe144,2)
 for at,size in ((0x1a1f8,4),(0x1a1fc,4),(0x1a224,1),(0x1a210,4)):c.allow_write(at,size)
 put(c.memory,APP+0x44,0x15808);put(c.memory,APP+0x48,0x16008)
 c.run(0x121a,0x21aa,3000);c.cpu.a[7]=STACK
 c.seed(APP+0xda6,b'\xa5'*104);c.run(0x1256,0x34e0,150000)
 assert c.read(APP+0xda6,103)==c.read(0x192e2,103) and c.memory[APP+0xe0d]==0xa5
 assert get(c.memory,APP+0x700)==APP+0x2330 and get(c.memory,APP+0x2330,2)==30
 assert c.cpu.a[7]==STACK-4 and get(c.memory,c.cpu.a[7])==0x127e

@pytest.mark.parametrize('platform,construction,bomb_count,found',[
 ('st',-32768,0,-1),('amiga',-1,0,-1),('st',0,1,0),('amiga',52,1,249),('st',53,1,-1)])
def test_post_display_reentry_rebuilds_header_but_preserves_mission_and_carried_bomb(platform,construction,bomb_count,found):
 c=base(platform);prepare_reset(c);header=get(c.memory,0x1a234+4*99)
 c.allow_write(0xcf20,4);c.allow_write(0xcffc,4);c.allow_write(0xd0d8,4);c.allow_write(0x49b6,2)
 put(c.memory,APP+0x868,construction,2);put(c.memory,APP+0xa76,0x81234)
 for off in (0x838,0x83c,0x85a,0x9b0,0x86a,0x86e):put(c.memory,APP+off,0xdeadbeef)
 for off in (0xa7f,0xa81,0xa83):c.memory[APP+off]=255
 c.memory[APP+0xae5+98]=bomb_count
 if found>=0:put(c.memory,APP+0x2330+found*68,98,2)
 put(c.memory,APP+0x71c,0x12345678);before=c.read(APP,0x6598)
 c.run(0x21b6,0x21e8,20)
 assert all(get(c.memory,p)==0x4a01ff00 for p in (0xcf20,0xcffc,0xd0d8))
 c.run(0x21ec,RETURN,3000)  # Display handoff and sine-pointer installation remain outside this slice.
 assert get(c.memory,header+2,2)==(52-max(0,construction))&65535
 assert all(get(c.memory,APP+off)==0 for off in (0x838,0x83c,0x85a,0x9b0,0x86a,0x86e))
 assert c.read(APP+0xa7f,6)==before[0xa7f:0xa85]
 assert get(c.memory,APP+0xa76)==0x81234 and get(c.memory,APP+0x71c)==0x12345678
 assert c.memory[APP+0xae3]==c.memory[APP+0xae4]==0
 assert c.read(APP+0x78a,4)==bytes(4)

@pytest.mark.parametrize('platform',('st','amiga'))
def test_options_load_calls_real_defaults_tag_pool_and_mission_resets_before_disk_entry(platform):
 c=base(platform);prepare_reset(c)
 for at,size in ((0x1a1f8,4),(0x1a1fc,4),(0x1a224,1),(0x1a210,4)):c.allow_write(at,size)
 put(c.memory,APP+0x44,0x15808);put(c.memory,APP+0x48,0x16008)
 c.seed(APP+0xda6,b'\xa5'*104);c.seed(APP+0x2330,b'\xcc'*17000)
 for off in (0xa7f,0xa80,0xa81,0xa82,0xa83,0xa84):c.memory[APP+off]=255
 c.run(0xe4ba,0xff6a,150000)
 assert c.read(APP+0xa7f,6)==bytes(6) and get(c.memory,APP+0x71c)==0
 assert get(c.memory,APP+0x700)==APP+0x2330 and get(c.memory,APP+0x2330,2)==30
 assert c.read(APP+0xda6,103)==c.read(0x192e2,103)and c.memory[APP+0xe0d]==0xa5
 assert c.cpu.a[7]==STACK-4 and get(c.memory,c.cpu.a[7])==0xe4ce


def test_saved_read_loop_requests_five_cylinders_with_fixed_destination_stride():
 c=base();c.allow_write(0x12628,4);put(c.memory,0x12628,0x431f4)
 c.cpu.d[1]=4;pc=0xffb4;destinations=[]
 for n in range(5):
  c.run(pc,0xfdfe,20)  # Advance-cylinder driver is an explicit external boundary.
  assert get(c.memory,c.cpu.a[7])==0xffba
  c.cpu.a[7]+=4;c.run(0xffba,0x10ac8,10)
  assert get(c.memory,c.cpu.a[7])==0xffbe
  destinations.append(get(c.memory,0x12628))
  c.cpu.a[7]+=4;c.cpu.sr|=4  # Supply successful read status, not disk contents.
  stop=0xffb4 if n<4 else 0xffd2
  c.run(0xffbe,stop,20);pc=stop
 assert destinations==[0x431f4+5120*n for n in range(5)]
 assert get(c.memory,0x12628)==0x431f4+25600 and c.cpu.a[7]==STACK

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='external vasm is the source build dependency')
def test_compiled_lifecycle_symbols_keep_entry_and_state_boundaries(tmp_path):
 import struct,subprocess
 from pathlib import Path
 from test_starglider2_retail_model_headers import image
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered'
 symbols={'start_new_game_after_title':0x121a,'resume_saved_or_interrupted_game':0x11f8,'reset_gameplay_state_and_input_defaults':0x2028,'restore_cockpit_and_weapon_hud_state':0x21aa,'reset_model_target_selection_tags':0x1963a,'initial_model_type_target_selection_tags':0x192e2,'validate_saved_workspace_checksum':0xffd2,'resume_saved_game_bridge':0x131d4,'SG2GameLifecycleWorkspace_player_score_bcd':0x71c,'SG2GameLifecycleWorkspace_fire_key_scancode':0x7f2,'SG2GameLifecycleWorkspace_model_target_selection_tags':0xda6}
 asm=tmp_path/'fields.s';out=tmp_path/'fields.bin'
 asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 result=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert result.returncode==0,result.stdout+result.stderr
 raw=out.read_bytes();size=4*len(symbols)
 assert raw[:-size]==image('st') and struct.unpack('>'+str(len(symbols))+'I',raw[-size:])==tuple(symbols.values())

@pytest.mark.parametrize('entry,status,files,prompt',[(0x1003c,0xfffe,0,None),(0x1003c,1,0,0x12b2b),(0x1001a,0xfffe,3,None),(0x1001a,1,0,0x12d1c),(0x1001a,1,1,0x12cb4),(0x1001a,1,0x10000,0x12d1c)])
def test_loader_cancel_and_lookup_failure_choose_the_actual_bounded_prompt(entry,status,files,prompt):
 c=base();c.cpu.d[0]=status;c.cpu.d[2]=files;before=c.read(APP,0x6598)
 c.run(entry,0xfdf8 if prompt is None else 0x10e8a,30)
 assert c.read(APP,0x6598)==before
 if prompt is not None:assert c.cpu.a[1]==prompt

@pytest.mark.parametrize('retry',(False,True))
def test_retry_response_returns_to_load_entry_or_disk_exit_without_copy(retry):
 c=base();c.cpu.sr=(c.cpu.sr|4)if retry else(c.cpu.sr&~4)
 before=c.read(APP,0x6598);c.run(0x1002e,0xff6a if retry else 0xfdf8,10)
 assert c.read(APP,0x6598)==before

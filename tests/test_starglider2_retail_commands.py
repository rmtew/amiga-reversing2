"""Retail key dispatch, view state and real point/message consumers.

These original CPU witnesses use supplied RAM state. Separate original-media
runs qualify live S/P/W/5/1 keyboard paths on Amiga and ST; they do not establish
all command reachability or live joystick/mouse coverage.
"""
import pytest
from test_starglider2_retail_input import memory,state,program,APP,STACK,RETURN,KEYS
from tests.test_starglider2_text_editor import run as original_run
from test_starglider2_retail_workspace import put,get
from tests.test_starglider2_control_normalization import signed
from tests.test_starglider2_view_input import (prepare as old_prepare,check_reinitialized_points,
 check_message as old_message,message_pointer,PRESETS,sector)
pytestmark=pytest.mark.skipif(__import__('os').getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
MODE_CACHE,DIRECTION_CACHE,QUEUE,BLANK=0x2f80,0x2f82,0xe0c6,0xe0fa
DIRECTION_TABLE,MODE_TABLE,ENTRY=0x2e0a,0x2eca,0x2c36
OFFSETS={
  "pending_key_scancode": 515,
  "view_mode": 2027,
  "view_offset_distance": 1984,
  "view_rotation_offset_0": 1980,
  "view_rotation_offset_1": 1982,
  "inside_structure_flag": 1916,
  "pending_message_count": 1966,
  "message_display_countdown": 1972,
  "shared_random_state_a": 96,
  "shared_random_state_b": 100,
  "point_field_world_positions": 3014,
  "point_field_previous_view_positions": 3134,
  "player_world_x": 1796,
  "player_world_y": 1800,
  "player_world_z": 1804,
  "player_object_reference": 1792,
  "world_object_pool": 9008,
  "world_object_slot_count": 370,
  "horizontal_world_wrap_mask": 1788,
  "view_rotation_0": 1974,
  "view_rotation_1": 1976,
  "view_rotation_2": 1978,
  "sine_lookup_pointer": 68,
  "cosine_lookup_pointer": 72,
  "weapon_selection_and_status": 2026,
  "neutron_bomb_spawn_request": 2787,
  "neutron_bomb_retract_request": 2788,
  "model_type_population_counts": 2789,
  "carried_neutron_bomb_reference": 2678,
  "debug_features_enabled_flag": 502,
  "landscape_background_draw_flags": 2038,
  "current_structure_service_id": 1730,
  "tractor_input_override_flag": 2722,
  "tractor_command_toggle_word": 2102,
  "scan_target_reference": 1712,
  "scan_target_type": 2112,
  "tractor_target_reference": 2104,
  "previous_tractor_target_reference": 2108
}
FIELDS={k:APP+v for k,v in OFFSETS.items()}

def prepare(m,**kwargs):
 old_prepare(m,FIELDS,keys=KEYS,mode_cache=MODE_CACHE,direction_cache=DIRECTION_CACHE,queue=QUEUE,**kwargs)

def message(m,platform,table,index):
 old_message(m,FIELDS,message_pointer(program(platform),table,index),queue=QUEUE,blank=BLANK)

def execute(m,pc=ENTRY,platform='st',stops=None,limit=5000):
 c=state(m,pc);original_run(program(platform),m,c,{RETURN}if stops is None else stops,limit=limit);return c

def word(m,off,value):put(m,APP+off,value&65535,2)

@pytest.mark.parametrize('platform',('amiga','st'))
@pytest.mark.parametrize('raw_key',range(128))
def test_dispatch_uses_real_translation_then_reaches_specific_gameplay_consumer(platform,raw_key):
 m=memory(platform);m[APP+0x203]=raw_key;put(m,0x3b4c8,199,2)
 token=m[0xdf4e+raw_key]if raw_key else 0
 routes={8:0x1856,27:0x24e0,160:0x33fe,161:0x1a92,87:0x1a92,70:0x1e88,73:0x7554,68:0x33a4,84:0x339e,65:0x33ec,82:0x338c}
 expected=routes.get(token,0x19d0);c=execute(m,0x1824,platform,set(routes.values())|{0x19d0})
 assert c.pc==expected and m[APP+0x203]==0
 if 48<=token<=56:assert get(m,APP+0x1aa,2)==token-48
 if token==83:assert get(m,0x18d4,2)==0
 if token==80:assert m[APP+0x7f6]==2

@pytest.mark.parametrize('platform',('amiga','st'))
@pytest.mark.parametrize('key',range(1,9))
@pytest.mark.parametrize('old_mode',(0,5))
def test_number_keys_use_original_point_reset_and_message_queue(platform,key,old_mode):
 m=memory(platform);prepare(m,key=key,mode=old_mode,distance=100,pitch=0x1234,yaw=0x5678)
 for code in (0x0f,0x5e,0x4a,0x4f,0x4e,0x4c,0x4d):m[KEYS+code]=255
 c=execute(m,platform=platform)
 assert m[APP+0x7eb]==key-1 and get(m,APP+0x7c0,2)==800
 assert get(m,APP+0x7bc,2)==0x1234 and get(m,APP+0x7be,2)==0x5678
 check_reinitialized_points(m,FIELDS,key-1!=old_mode);message(m,platform,MODE_TABLE,key-1)
 assert c.a[6]==APP and c.a[7]==STACK+4

@pytest.mark.parametrize('distance',(-32768,-1,0,736,799,800,801,863,9936,9999,10000,10001,32767))
@pytest.mark.parametrize('decrease,increase',((False,False),(True,False),(False,True),(True,True)))
def test_held_view_distance_preserves_ordered_soft_limits(distance,decrease,increase):
 m=memory('st');prepare(m,distance=distance);m[KEYS+0x0f]=decrease;m[KEYS+0x4a]=increase
 expected=distance
 if decrease and expected>800:expected=signed(expected-64)
 if increase and expected<=10000:expected=signed(expected+64)
 execute(m);assert signed(get(m,APP+0x7c0,2))==expected
 assert get(m,APP+0x7ae,2)==3 and get(m,APP+0x7b4,2)==9;check_reinitialized_points(m,FIELDS,False)

@pytest.mark.parametrize('key,yaw',list(PRESETS.items()))
@pytest.mark.parametrize('pitch,previous',((0,0),(1,0),(0,2048),(65535,65535)))
def test_direction_presets_change_and_rebuild_before_real_message(key,yaw,pitch,previous):
 m=memory('st');prepare(m,key=key,pitch=pitch,yaw=previous);execute(m)
 changed=pitch!=0 or previous!=yaw
 assert get(m,APP+0x7bc,2)==0 and get(m,APP+0x7be,2)==yaw
 check_reinitialized_points(m,FIELDS,changed)
 if changed and sector(yaw)!=yaw:message(m,'st',DIRECTION_TABLE,sector(yaw))
 else:assert get(m,APP+0x7ae,2)==3

@pytest.mark.parametrize('yaw',(0,1,255,256,511,512,2048,4095,65535))
@pytest.mark.parametrize('left,right',((False,False),(True,False),(False,True),(True,True)))
def test_held_yaw_uses_word_wrap_and_can_announce_with_zero_net_change(yaw,left,right):
 m=memory('st');prepare(m,yaw=yaw);m[KEYS+0x4f]=left;m[KEYS+0x4e]=right;expected=yaw;last=None
 for pressed,change in ((left,-32),(right,32)):
  if pressed:
   expected=(expected+change)&65535
   if sector(expected)!=expected:last=sector(expected)
 execute(m);assert get(m,APP+0x7be,2)==expected
 if last is None:assert get(m,APP+0x7ae,2)==3 and get(m,DIRECTION_CACHE,2)==0x5a5a
 else:message(m,'st',DIRECTION_TABLE,last);assert get(m,DIRECTION_CACHE,2)==last
 check_reinitialized_points(m,FIELDS,False)

@pytest.mark.parametrize('yaw',(0,1,255,256,511,512,2048,4095,65535))
@pytest.mark.parametrize('inside',(0,1,128,255))
@pytest.mark.parametrize('mode',(0,4,7,128,255))
def test_direction_notice_uses_signed_interior_and_mode_tests(yaw,inside,mode):
 m=memory('st');prepare(m,mode=mode,yaw=yaw,inside=inside);execute(m,0x2dba)
 index=sector(yaw);changed=index!=yaw;allowed=inside<128 or signed(mode,8)<4 or index in(0,4)
 assert get(m,DIRECTION_CACHE,2)==(index if changed else 0x5a5a)
 if changed and allowed:message(m,'st',DIRECTION_TABLE,index)
 else:assert get(m,APP+0x7ae,2)==3 and get(m,APP+0x7b4,2)==9

@pytest.mark.parametrize('mode',(0,4,255))
@pytest.mark.parametrize('distance',(-32768,0,799,800,801,10000))
def test_cockpit_toggle_does_not_rebuild_points(mode,distance):
 m=memory('st');prepare(m,key=0x43,mode=mode,distance=distance);execute(m)
 selected=4 if mode==0 else 0
 assert m[APP+0x7eb]==selected and get(m,APP+0x7c0,2)==max(800,distance)
 message(m,'st',MODE_TABLE,selected);check_reinitialized_points(m,FIELDS,False)

@pytest.mark.parametrize('pitch',(0,0xfc00))
@pytest.mark.parametrize('yaw',(0,2048))
@pytest.mark.parametrize('inside,mode',((0,0),(0,4),(128,4)))
def test_below_preset_uses_stored_ninth_message_and_pitch_early_return(pitch,yaw,inside,mode):
 m=memory('st');prepare(m,key=0x2e,mode=mode,pitch=pitch,yaw=yaw,inside=inside);execute(m)
 changed=pitch!=0xfc00
 assert get(m,APP+0x7bc,2)==0xfc00 and get(m,APP+0x7be,2)==(0 if changed else yaw)
 check_reinitialized_points(m,FIELDS,changed);assert get(m,DIRECTION_CACHE,2)==0x5a5a
 if changed and not(inside>=128 and mode>=4):message(m,'st',DIRECTION_TABLE,8)
 else:assert get(m,APP+0x7ae,2)==3

@pytest.mark.parametrize('mode',range(8))
@pytest.mark.parametrize('distance',(-1,799,800,801))
@pytest.mark.parametrize('same',(False,True))
def test_mode_message_cache_precedes_distance_and_queue_work(mode,distance,same):
 m=memory('st');prepare(m,distance=distance);put(m,MODE_CACHE,mode if same else 65535,2)
 c=state(m,0x2e92);c.d[0]=mode;original_run(program('st'),m,c,{RETURN})
 assert signed(get(m,APP+0x7c0,2))==(distance if same else max(distance,800))
 if same:assert get(m,APP+0x7ae,2)==3 and get(m,APP+0x7b4,2)==9
 else:message(m,'st',MODE_TABLE,mode)

@pytest.mark.parametrize('pitch',(0,1,32767,65535))
@pytest.mark.parametrize('decrease,increase',((False,False),(True,False),(False,True),(True,True)))
def test_held_pitch_changes_without_point_reset_or_message(pitch,decrease,increase):
 m=memory('st');prepare(m,pitch=pitch);m[KEYS+0x4c]=decrease;m[KEYS+0x4d]=increase;execute(m)
 assert get(m,APP+0x7bc,2)==(pitch-32*decrease+32*increase)&65535
 assert get(m,APP+0x7ae,2)==3 and get(m,APP+0x7b4,2)==9;check_reinitialized_points(m,FIELDS,False)

@pytest.mark.parametrize('selected',range(256))
@pytest.mark.parametrize('available',(0,1))
@pytest.mark.parametrize('carried',(0,0x80000))
def test_weapon_cycle_preserves_mask_and_bomb_request_rules(selected,available,carried):
 m=memory('st');m[APP+0x7ea]=selected;m[APP+0xae5+0x62]=available;put(m,APP+0xa76,carried)
 m[APP+0xae3]=m[APP+0xae4]=0x55;execute(m,0x1a92)
 value=(selected&31)+4;value=0 if value==20 else value
 assert m[APP+0x7ea]==value
 assert m[APP+0xae3]==(255 if not carried else 0x55)if value==16 and available else m[APP+0xae3]==0
 assert m[APP+0xae4]==(0 if value==16 and available else 255)

@pytest.mark.parametrize('platform',('amiga','st'))
@pytest.mark.parametrize('toggle',(0,1,65535,32768))
def test_t_command_reaches_real_toggle_and_release_preserving_old_reference(platform,toggle):
 m=memory(platform);m[APP+0x203]=0x14;word(m,0x836,toggle);put(m,APP+0x838,0x80000);put(m,APP+0x83c,0x12345678)
 word(m,0x840,1);word(m,0x84c,99);m[APP+0xaa2]=255;put(m,0x3b4c8,199,2)
 # The override path belongs to a later service; stop at the actual T handler.
 c=execute(m,0x1824,platform,{0x370e2});assert m[APP+0x203]==0
 original_run(program(platform),m,c,{0x19ae},limit=5000)
 assert c.a[6]==APP and c.a[7]==STACK and c.d[0]&65535==0x54
 expected=(-toggle)&65535;assert get(m,APP+0x836,2)==expected
 if expected&32768:
  assert get(m,APP+0x838)==0 and get(m,APP+0x840,2)==0 and get(m,APP+0x84c,2)==0
  assert m[APP+0xaa2]==0 and get(m,APP+0x83c)==0x12345678
 else:assert get(m,APP+0x838)==0x80000 and m[APP+0xaa2]==255


@pytest.mark.parametrize('value',range(256))
def test_audio_key_preserves_negated_sign_flag_including_zero_and_128(value):
 m=memory('st');m[APP+0x203]=0x50;m[0x3b623]=value;put(m,0x3b4c8,199,2)
 execute(m,0x1824,stops={0x19d0})
 assert m[0x3b623]==(-value)&255

@pytest.mark.parametrize('flag',(0,1,2,3,128,255))
def test_p_key_changes_only_landscape_control_bit_one(flag):
 m=memory('st');m[APP+0x203]=0x19;m[APP+0x7f6]=flag;put(m,0x3b4c8,199,2)
 execute(m,0x1824,stops={0x19d0});assert m[APP+0x7f6]==flag^2

@pytest.mark.parametrize('value',range(256))
@pytest.mark.parametrize('inhibit',(0,128))
def test_audio_command_sign_is_consumed_by_original_amiga_volume_gate(value,inhibit):
 m=memory('amiga');m[APP+0x203]=0x50;m[0x3b623]=value;put(m,0x3b4c8,199,2)
 execute(m,0x1824,'amiga',{0x19d0});m[APP+0x6da]=inhibit;put(m,0x4ea16,37,2)
 execute(m,0x4d5fc,'amiga',{0x4d61e})
 assert get(m,0xdff0a8,2)==(37 if ((-value)&128)and not inhibit else 0)

@pytest.mark.parametrize('value',(0,1,32768,65535))
def test_s_command_projection_flag_reaches_ground_face_gate(value):
 m=memory('st');m[APP+0x203]=0x21;put(m,0x18d4,value,2);put(m,0x3b4c8,199,2)
 execute(m,0x1824,stops={0x19d0});c=execute(m,0x4fd8,stops={0x4fe2,0x52c4})
 assert c.pc==(0x52c4 if value==65535 else 0x4fe2)

@pytest.mark.parametrize('value',range(256))
def test_f_command_reaches_fixed_sight_toggle_and_returns(value):
 m=memory('st');m[APP+0x203]=0x23;m[APP+0x7e6]=value;put(m,0x3b4c8,199,2)
 c=execute(m,0x1824)
 assert m[APP+0x7e6]==value^255 and c.a[7]==STACK+4

@pytest.mark.parametrize('platform',('amiga','st'))
@pytest.mark.parametrize('countdown',(0,199,200,32767,32768,65535))
def test_frame_dispatch_gates_view_poll_then_translates_same_number_key(platform,countdown):
 m=memory(platform);prepare(m,key=5,distance=100);put(m,0x3b4c8,countdown,2)
 execute(m,0x1824,platform)
 assert m[APP+0x7eb]==(4 if signed(countdown)>199 else 0) and m[APP+0x203]==0
 assert get(m,APP+0x1aa,2)==5
 check_reinitialized_points(m,FIELDS,signed(countdown)>199)

@pytest.mark.parametrize('ejecting',(0,128))
def test_space_ends_ejection_countdown_and_t_is_ignored_during_ejection(ejecting):
 m=memory('st');m[0x3b4c6]=ejecting;put(m,0x3b4c8,199,2);m[APP+0x203]=0x40
 execute(m,0x1824,stops={0x19d0});assert get(m,0x3b4c8,2)==(0 if ejecting else 199)
 m[APP+0x203]=0x14;c=execute(m,0x1824,stops={0x339e,0x19d0})
 assert c.pc==(0x19d0 if ejecting else 0x339e)

@pytest.mark.parametrize('service',(0,1,2,3,65535))
def test_backspace_qualifies_inventory_setup_gate_without_claiming_modal_loop(service):
 m=memory('st');m[APP+0x203]=0x41;word(m,0x6c2,service);put(m,0x3b4c8,199,2)
 c=execute(m,0x1824,stops={0x1856,0x1b30})
 assert c.pc==(0x1856 if service in(0,1,2)else 0x1b30)

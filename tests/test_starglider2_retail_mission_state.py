"""Original retail reset footprints and status consumers over supplied RAM.

Reuse older independent reset expectations with explicit retail addresses.
These are bounded function witnesses, not new-game boot or valid-save proof.
"""
import os
import pytest
from test_starglider2_retail_inventory import base,APP,STACK
from test_starglider2_retail_model_headers import image
from test_starglider2_retail_workspace import put,get
from test_starglider2_retail_taymar import ready
from tests.test_starglider2_mission_reset import ARRAYS,SCALARS
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
RESET,STATUS,RETURN=0x38d64,0x37ccc,0xff000
QUEUE,BLANK,EVENTS=0xe0c6,0xe0fa,0x394ba
OFFSETS={
 'released_object_tracking_references':0xa02,
 'model_type_population_counts':0xae5,
 'taymar_delivered_model_counts_prefix':0xb4d,
 'structure_service_entry_counts':0xa91,
 'structure_service_entry_latches':0xa85,
 'projector_part_presence_flags':0xaa9,
 'station_sequence_index':0xa72,
 'station_event_tick_counter':0x852,
 'station_space_half_rate_toggle':0x854,
 'projector_rebuild_cursor':0x858,
 'growing_projector_part_reference':0x85a,
 'growing_projector_part_type':0x85e,
 'station_construction_steps_remaining':0x868,
 'station_charge_steps_remaining':0x9c4,
 'station_firing_steps_remaining':0x9c6,
 'station_report_primary_message':0x86a,
 'station_report_secondary_message':0x86e,
 'pending_message_count':0x7ae,
 'message_display_countdown':0x7b4,
 'carried_neutron_bomb_reference':0xa76,
 'stardrive_speed_addend':0xa74,
 'stardrive_enabled_word':0x9ae,
 'station_mini_sentinel_count':0xa7a,
 'station_cycle_enabled_flag':0xa7c,
 'neutron_bomb_order_requested_flag':0xa7f,
 'professor_taymar_aboard_flag':0xa80,
 'professor_taymar_delivered_flag':0xa81,
 'bomb_ingredient_set_complete_flag':0xa82,
 'neutron_bomb_collection_enabled_flag':0xa84,
 'neutron_bomb_ready_flag':0xa83,
 'neutron_bomb_spawn_request':0xae3,
 'neutron_bomb_retract_request':0xae4,
 'projector_network_complete_flag':0xaa7,
 'space_station_spawn_request':0xa7d,
}
GLOBALS={0x3b612:(2,0),0x3b614:(2,0),0x3b623:(1,255),0x3b4ca:(2,0),0x3b4cc:(2,0),0x3aa6c:(2,15),0x391e8:(2,65535),0x3b2ea:(2,65535),0x3b2ec:(2,128),0x3b4c6:(1,0),0x3b4c8:(2,200),0x3afa0:(2,0),0x3b61c:(1,0),0x3b61a:(2,65535),0x3b616:(2,0),0x3b618:(2,3),0x3b61d:(1,0),0x3b61e:(1,0),0x3b620:(1,0),0x3b624:(4,0),0x3b628:(2,65535),0x3b62a:(2,0),0x3b61f:(1,255),0x3b621:(1,0),0x3b622:(1,0),0x3b62c:(2,65535)}
EXTRA={0x6da:(1,0),0x720:(4,20),0x9cc:(2,3),0xa9d:(1,0),0x7ea:(1,4),0x9c0:(2,0),0xa70:(2,0),0x862:(2,512),0xbb5:(1,3),0xbb7:(1,255),0x864:(4,0x1e00),0x802:(4,0x1ab3f00),0x806:(4,0x1312d00),0x80a:(4,0x1e84800),0x80e:(4,0x1312d00),0x9b4:(4,8000000),0x9b8:(4,8000000),0x9bc:(4,4000000),0xbb9:(1,255),0x836:(2,1),0x838:(4,0),0x840:(2,0),0xaa4:(1,0),0xaa2:(1,0),0xbb6:(1,0),0xa7e:(1,0),0x9c8:(2,3),0x9ca:(2,0),0x9b0:(4,0)}

def prepare_reset(c,fill=None):
 if fill is not None:c.seed(APP,bytes([fill])*0x6598)
 for address,(width,value)in GLOBALS.items():c.allow_write(address,width)
 header=get(c.memory,0x1a234+99*4);c.allow_write(header+2,2)
 return header

def invoke(c,start,stop=RETURN):
 c.cpu.a[7]=STACK;put(c.memory,STACK,RETURN);return c.run(start,stop,30000)

@pytest.mark.parametrize('platform,fill',[('st',0xa5),('st',0x55),('amiga',255)])
def test_reset_full_workspace_and_source_footprint_preserve_pose_pool_and_unknown_bytes(platform,fill):
 c=base(platform);header=prepare_reset(c,fill)
 for address,(width,value)in GLOBALS.items():c.seed(address,bytes([fill])*width)
 c.seed(header+2,b'\x45\x67');expected=bytearray(c.read(APP,0x6598));source=bytearray(c.read(4096,len(image(platform))))
 for name,size in ARRAYS.items():expected[OFFSETS[name]:OFFSETS[name]+size]=bytes(size)
 for name,(width,value)in SCALARS.items():put(expected,OFFSETS[name],value,width)
 for offset,(width,value)in EXTRA.items():put(expected,offset,value,width)
 for dest,src,n in ((0x87c,0x392d2,272),(0x98c,0x393e2,34)):expected[dest:dest+n]=c.read(src,n)
 put(expected,0x9c2,get(c.memory,0x3aa52,2),2);put(expected,0x82e,get(c.memory,0x3aa40,2),2)
 put(expected,0x7ca,get(c.memory,0x18f02+12))
 for address,(width,value)in GLOBALS.items():put(source,address-4096,value,width)
 put(source,header+2-4096,0,2);invoke(c,RESET)
 assert c.read(APP,0x6598)==expected and c.read(4096,len(source))==source
 assert c.cpu.a[6]==APP and c.cpu.a[7]==STACK+4
 assert c.read(APP+0x852,6)==bytes(6)  # WORD fields, overlapping original CLR.L footprints.

def event(c,n):return get(c.memory,EVENTS+4*n)
def queued(c):return [get(c.memory,QUEUE+4*n)for n in range(get(c.memory,APP+0x7ae,2))]
def expected_queue(messages):
 out=[]
 for p in messages:
  if len(out)>=10 or out and out[-1]==p:continue
  out.append(p)
  if len(out)==1:out.append(BLANK)
 return out

def status_machine(platform='st'):
 c=base(platform);c.allow_write(0xe0c0,0x50);put(c.memory,0xe0c2,0x123456)
 put(c.memory,APP+0x830,4,2);put(c.memory,APP+0x7ae,7,2);put(c.memory,APP+0x7b4,33,2)
 return c

@pytest.mark.parametrize('space,inside,has_report,ordered,delivered,is_ready',[(0,0,False,0,0,0),(0,0,True,0,0,0),(0,0,True,128,0,0),(0,0,True,128,128,0),(0,0,True,255,255,128),(128,0,True,255,255,255),(0,128,True,255,255,255),(0,1,True,255,255,255),(127,0,True,255,127,255),(128,127,False,0,0,0),(0,0,False,255,255,255),(0,0,True,127,255,255)])
def test_status_location_sign_and_outside_zero_are_distinct_from_order_phase(space,inside,has_report,ordered,delivered,is_ready):
 c=status_machine();c.memory[APP+0x77d]=space;c.memory[APP+0x77c]=inside
 for off,v in ((0xa7f,ordered),(0xa81,delivered),(0xa83,is_ready)):c.memory[APP+off]=v
 primary,secondary=0x88000,0x88100;put(c.memory,APP+0x86a,primary if has_report else 0);put(c.memory,APP+0x86e,secondary)
 messages=[event(c,43),event(c,40),event(c,41)if space>=128 else event(c,83)if inside>=128 else get(c.memory,0xf380+132*4)]
 if inside==0:messages.append(event(c,15))
 if has_report:
  if inside==0:messages.extend((primary,secondary))
  if ordered>=128 and inside==0:messages.extend((event(c,82),0x3a673 if delivered<128 else 0x3a70e if is_ready>=128 else 0x3a6dd))
 elif inside==0:messages.append(event(c,19))
 messages.append(event(c,35));saved=c.cpu.d[0],c.cpu.d[1],c.cpu.a[1];invoke(c,STATUS)
 assert queued(c)==expected_queue(messages) and get(c.memory,APP+0x7b4,2)==0
 assert (c.cpu.d[0],c.cpu.d[1],c.cpu.a[1])==saved
 assert [c.memory[APP+o]for o in (0xa7f,0xa81,0xa83)]==[ordered,delivered,is_ready]

@pytest.mark.parametrize('first,second,inside',[(0,0,0),(0x12345678,0x9abcdef0,0),(0xffffffff,7,1)])
def test_aboard_professor_uses_real_rng_and_takes_priority_over_order_text(first,second,inside):
 c=status_machine();put(c.memory,APP+0x60,first);put(c.memory,APP+0x64,second)
 c.memory[APP+0xa80]=128;c.memory[APP+0xa7f]=255;c.memory[APP+0x77c]=inside
 put(c.memory,APP+0x86a,0x88000);put(c.memory,APP+0x86e,0x88100)
 rotated=((first<<3)|(first>>29))&0xffffffff;value=(rotated&0xffff0000)|(((rotated-7)^second)&65535)
 messages=[event(c,43),event(c,40),get(c.memory,0xf380+132*4)]
 if inside==0:messages.extend((event(c,15),0x88000,0x88100))
 messages.extend((event(c,77),event(c,78+(value&3)),event(c,35)));invoke(c,STATUS)
 assert queued(c)==expected_queue(messages)
 assert c.read(APP+0x60,8)==second.to_bytes(4,'big')+value.to_bytes(4,'big')

@pytest.mark.parametrize('delay,repeats',[(1,1),(0,0),(0,1),(0x8000,1),(0x8001,0x8000),(0,0xffff)])
def test_repeat_service_updates_report_pointers_only_after_accepted_word_countdown(delay,repeats):
 c=status_machine();c.allow_write(0x3b616,4);put(c.memory,0x3b616,delay,2);put(c.memory,0x3b618,repeats,2)
 put(c.memory,APP+0x86a,0x123450);put(c.memory,APP+0x86e,0x234560)
 old=c.read(QUEUE,40);ticks=((delay-1)&65535)>=32768;remaining=(repeats-1)&65535 if ticks else repeats;report=ticks and remaining<32768
 invoke(c,0x3904a,0x390ca)
 assert get(c.memory,0x3b616,2)==(256 if ticks else (delay-1)&65535)
 assert get(c.memory,0x3b618,2)==(65535 if ticks and remaining>=32768 else remaining)
 if report:
  assert queued(c)==expected_queue([event(c,n)for n in (15,46,47,48,35)])
  assert [get(c.memory,APP+o)for o in (0x86a,0x86e)]==[event(c,46),event(c,47)]
 else:assert c.read(QUEUE,40)==old and [get(c.memory,APP+o)for o in (0x86a,0x86e)]==[0x123450,0x234560]

@pytest.mark.parametrize('index',(0,6,7,8))
def test_reset_sequence_producer_uses_terminal_sentinel_without_an_arbitrary_index_guard(index):
 c=base();put(c.memory,APP+0xa72,index,2);c.run(0x36c20,0x36c44,100)
 value=get(c.memory,0x3aa40+2*(index+1),2);negative=value>=32768
 assert get(c.memory,APP+0xa72,2)==(index if negative else index+1)
 assert get(c.memory,APP+0x82e,2)==(63 if negative else value)
 if index==8:assert value==0x4000 and not negative  # Adjacent bomb-countdown data.


def test_report_producer_then_reset_closes_the_taymar_status_lifecycle():
 c=status_machine()
 for off in (0xa7f,0xa81,0xa82,0xa83,0xa84):c.memory[APP+off]=255
 invoke(c,STATUS);assert 0x3a70e not in queued(c) and event(c,19)in queued(c)
 c.allow_write(0x3b616,4);put(c.memory,0x3b616,0,2);put(c.memory,0x3b618,1,2)
 invoke(c,0x3904a,0x390ca);invoke(c,STATUS)
 assert event(c,82)in queued(c) and 0x3a70e in queued(c)
 c.seed(0x88000,(98).to_bytes(2,'big'));prepare_reset(c);invoke(c,RESET)
 assert [c.memory[APP+o]for o in (0xa7f,0xa80,0xa81,0xa82,0xa83,0xa84)]==[0]*6
 assert get(c.memory,APP+0x86a)==get(c.memory,APP+0x86e)==get(c.memory,APP+0xa76)==0
 assert get(c.memory,0x88000,2)==98  # Mission reset is distinct from world-pool reset.
 invoke(c,STATUS);assert event(c,19)in queued(c) and event(c,82)not in queued(c)
 before=get(c.memory,APP+0x9c2,2);ready(c);assert get(c.memory,APP+0x9c2,2)==before and c.memory[APP+0xa83]==0

@pytest.mark.parametrize('space,half,tick,mask',[(0,0,31,31),(128,0,31,31),(128,1,31,31),(127,1,1,31),(255,1,65535,511)])
def test_station_clock_consumes_word_fields_cleared_by_the_long_reset_writes(space,half,tick,mask):
 c=base();c.memory[APP+0x77d]=space;put(c.memory,APP+0x854,half,2);put(c.memory,APP+0x852,tick,2);put(c.memory,APP+0x82e,mask,2)
 next_half=((half+1)&1)if space>=128 else half;updates=space<128 or next_half==0
 next_tick=((tick+1)&65535)&mask if updates else tick
 stop=0x3644a if updates and next_tick==0 else 0x36898
 c.run(0x36426,stop,100)
 assert get(c.memory,APP+0x854,2)==next_half and get(c.memory,APP+0x852,2)==next_tick

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='external vasm is the only source build dependency')
def test_compiled_mission_symbols_bind_shared_directories_and_nested_state(tmp_path):
 import struct,subprocess
 from pathlib import Path
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered'
 names=['initialize_mission_and_flight_state','enqueue_current_location_and_mission_status','object_name_pointers','event_message_pointers','model_header_pointers','initial_cached_body_states','initial_body_orbit_angles','SG2MissionWorkspace_neutron_carried_y_offset','SG2MissionWorkspace_clock+SG2StationClock_tick','SG2MissionWorkspace_clock+SG2StationClock_half_rate','SG2MissionWorkspace_report+SG2ReportMsgs_primary','SG2MissionWorkspace_report+SG2ReportMsgs_secondary']
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(names)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert r.returncode==0,r.stdout+r.stderr
 data=out.read_bytes();assert data[:-48]==image('st')
 assert struct.unpack('>12I',data[-48:])==(0x38d64,0x37ccc,0xf380,0x394ba,0x1a234,0x392d2,0x393e2,0x720,0x852,0x854,0x86a,0x86e)

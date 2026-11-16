"""Real partition and complete actor-stage ordering over supplied pool states.

The original main-loop BSR enters and returns from the whole actor service.
No tests manually call the recycler or allocator. These are bounded CPU frame-
stage witnesses, not natural input-driven gameplay or complete-frame timing.
"""
import os
import pytest
from test_starglider2_retail_frame_lists import setup,partition,pointers,POOL,APP,STACK,RETURN
from test_starglider2_retail_workspace import put,get
from test_starglider2_retail_variant_cycles import shared_bytes
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
ORDERS=(('target','creator','missile'),('missile','target','creator'),('target','missile','creator'))

def actor_stage(c):
 c.cpu.a[6]=APP;c.cpu.a[7]=STACK;c.run(0x1314,0x1318,20000)
 assert c.cpu.a[7]==STACK and c.cpu.a[6]==APP

@pytest.mark.parametrize('order',ORDERS)
def test_original_partitioner_and_whole_actor_stage_make_target_reuse_order_observable(order):
 slots=['player',*reversed(order)];kinds={'player':30,'target':14,'creator':23,'missile':12}
 c=setup([(kinds[n],(0,-1000,0))for n in slots]+[(0,(0,0,0))for _ in range(246)])
 at={n:POOL+68*i for i,n in enumerate(slots)}
 for p in at.values():
  c.seed(p+2,b'\0');c.seed(p+28,b'\6\3\xff');c.seed(p+34,b'\0');put(c.memory,p+18,3072,2)
 put(c.memory,APP+0x700,at['player']);put(c.memory,APP+0x708,-1000);put(c.memory,APP+0x44,0x15808);put(c.memory,APP+0x48,0x16008)
 c.seed(APP+0x77d,b'\0');c.seed(APP+0xda6+23,b'\1');c.seed(APP+0x7e9,b'\xff')
 limit=shared_bytes()[0x17e48+14];assert limit<128;c.seed(at['target']+30,bytes([limit]))
 put(c.memory,at['creator']+36,17,2);put(c.memory,at['missile']+36,100,2);put(c.memory,at['missile']+38,0,2)
 put(c.memory,at['missile']+60,at['target']);c.seed(at['missile']+34,b'\xff')
 partition(c);near=pointers(c,0x6c8,0x75e)
 assert near==[at[n]for n in order]+[at['player']]and pointers(c,0x6b8,0x75c)==[]
 assert get(c.memory,APP+0x772,2)==246
 actor_stage(c)
 reused_before_guidance=order==ORDERS[0]
 assert get(c.memory,at['target'],2)==72 and c.read(at['target']+30,1)==b'\xff'
 assert c.read(at['missile']+30,1)==bytes([255 if reused_before_guidance else 0])
 assert get(c.memory,at['missile']+36,2)==(99 if reused_before_guidance else 100)
 assert get(c.memory,at['missile']+60)==at['target']and get(c.memory,APP+0x772,2)==246
 assert get(c.memory,APP+0x6c4)==get(c.memory,APP+0x6c8)+4*len(near)
 assert get(c.memory,APP+0x6c0,2)==0 and c.read(APP+0x7ed,1)==b'\0'
 # The replacement's old snapshot entry was already visited. Its initial
 # budget is still100, despite a later missile observing its new active tag.
 assert get(c.memory,at['target']+36,2)==100

@pytest.mark.parametrize('enabled,which',((False,'near'),(True,'empty'),(True,'near'),(True,'far')))
def test_shared_cursor_and_type12_request_are_actor_local_not_unconditional_frame_cleanup(enabled,which):
 records=[(0,(0,0,0))for _ in range(250)]
 if which!='empty':records[0]=(24,(20000 if which=='far'else 0,0,0))
 c=setup(records);c.seed(POOL+2,b'\0');c.seed(APP+0x7e9,bytes([255 if enabled else 0]));partition(c)
 put(c.memory,APP+0x6c0,0xabcd,2);put(c.memory,APP+0x6c4,0xdeadbeef);c.seed(APP+0x7ed,b'\xff')
 actor_stage(c);processed=enabled and which!='empty'
 assert c.read(APP+0x7ed,1)==bytes([0 if processed else 255])
 assert get(c.memory,APP+0x6c0,2)==(0 if processed else 0xabcd)
 field=0x6b8 if which=='far'else 0x6c8
 assert get(c.memory,APP+0x6c4)==(get(c.memory,APP+field)+4 if processed else 0xdeadbeef)

@pytest.mark.parametrize('repeat_hit',(False,True))
def test_original_contact_writer_drives_the_two_actor_height_step_flags(repeat_hit):
 from test_starglider2_retail_contacts import setup as contact_setup,OUTER,INNER
 c=contact_setup(outer=2,inner=103);c.seed(OUTER+2,b'\0');c.seed(INNER+2,b'\0');c.seed(OUTER+28,b'\4');c.seed(INNER+28,b'\x80');c.seed(INNER+34,b'\1')
 put(c.memory,OUTER+8,-1000);put(c.memory,INNER+8,-1000);before=get(c.memory,OUTER+8)
 def contact():
  put(c.memory,INNER+8,get(c.memory,OUTER+8));c.cpu.a[6]=APP;c.cpu.a[7]=STACK;c.run(0xb568,RETURN,1000)
 contact();assert c.read(OUTER+2,1)==b'\4'and c.read(OUTER+30,1)==b'\xff'
 c.cpu.a[6]=APP;c.cpu.a[0]=OUTER;c.run(0x8002,0x801e,50)
 assert get(c.memory,OUTER+8)==(before-18)&0xffffffff and c.read(OUTER+2,1)==b'\x08'
 if repeat_hit:
  contact();assert c.read(OUTER+2,1)==b'\x0c'
  c.cpu.a[6]=APP;c.cpu.a[0]=OUTER;c.run(0x8002,0x801e,50)
  assert get(c.memory,OUTER+8)==(before-36)&0xffffffff and c.read(OUTER+2,1)==b'\x08'
 c.cpu.a[6]=APP;c.cpu.a[0]=OUTER;c.run(0x8002,0x801e,50)
 assert get(c.memory,OUTER+8)==(before-18*int(repeat_hit))&0xffffffff and c.read(OUTER+2,1)==b'\0'

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='external vasm is the source build dependency')
def test_compiled_actor_stage_contracts_keep_original_code_and_workspace_addresses(tmp_path):
 import struct,subprocess
 from pathlib import Path
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered'
 names={'update_partitioned_world_actors':0x7fdc,'dispatch_next_actor_first_phase':0x7ff4,'dispatch_next_actor_second_phase':0x8202,'apply_pending_hit_height_step':0x8166,'restore_previous_hit_height_step':0x817e,'finish_partitioned_actor_updates':0x83bc,'SG2ActorUpdateWorkspace_actor_snapshot_remaining_minus_one':0x6c0,'SG2ActorUpdateWorkspace_ai_type12_projectile_request':0x7ed}
 asm,out=tmp_path/'symbols.s',tmp_path/'symbols.raw';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(names)+'\n')
 p=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert p.returncode==0,p.stdout+p.stderr
 raw=out.read_bytes();n=len(names)*4;assert raw[:-n]==shared_bytes()and struct.unpack('>'+str(len(names))+'I',raw[-n:])==tuple(names.values())
 text=(directory/'retail-shared.s').read_text();assert 'SG2ActorUpdateWorkspace_actor_snapshot_remaining_minus_one(a6)'in text and 'SG2ActorUpdateWorkspace_ai_type12_projectile_request(a6)'in text

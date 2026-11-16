"""Original retail rating insertion and stored-image text/editor paths.

Palette and disk handoffs are boundaries, not mocks or exercised operations.
Constructed tables and key events are not a natural high-score or live ST
adapter/scanout proof. Only the fifteen visible slots are compared/displayed.
"""
import ctypes,os
import pytest
from tests import test_starglider2_rating_insertion as old
from tests.test_starglider2_text_editor import state,run,put,get,APP,STACK,RETURN
from test_starglider2_retail_input import program
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
SCORES,NAMES,TEXT,CONTROLS=0x12fca,0x1300e,0x12fbe,0x1310e
FIELDS=dict(pilot_rating_score_slots=SCORES,pilot_rating_name_slots=NAMES,player_score_bcd=0x71c,pilot_rating_six_digit_text=TEXT,pilot_rating_saved_control_settings=CONTROLS,format_six_score_nibbles=0xfeb6)

@pytest.fixture(params=('amiga','st'))
def machine(request,monkeypatch):
 image=program(request.param);m=(ctypes.c_uint8*0xa1000)();ctypes.memmove(ctypes.addressof(m)+4096,image[0],len(image[0]))
 def retail_run(image,m,c,stops,*args,**kw):
  c.pc+=0x48;run(image,m,c,{RETURN if p==RETURN else 0xdca0 if p==0xdc68 else p+0x48 for p in stops},*args,**kw)
  if c.pc!=RETURN:c.pc-=0x38 if c.pc==0xdca0 else 0x48
 monkeypatch.setattr(old,'run',retail_run)
 return image,m

@pytest.mark.parametrize('candidate,malformed',((0,False),(0x10000,False),(0x10001,False),(0x1000,False),(0x1001,False),(0x7fffffff,False),(0x80000000,False),(0xffffffff,False),(0,True),(0x80000001,True),(0x7fffffff,True),(0xffffffff,True)))
def test_signed_scan_ties_and_ignored_sixteenth_slot_reuse_independent_oracle(machine,candidate,malformed):
 image,m=machine;old.test_first_strictly_greater_signed_long_wins_and_sixteenth_slot_is_not_compared(image,m,FIELDS,candidate,malformed)

@pytest.mark.parametrize('index,high',((0,0),(7,0xffff0000),(14,0x12340000)))
def test_backward_score_shift_and_live_reload_reuse_original_oracle(machine,index,high):
 image,m=machine;old.test_backward_score_shift_uses_word_counter_and_reloads_live_score(image,m,FIELDS,index,high)

@pytest.mark.parametrize('index,high',((0,0),(7,0x43210000),(14,0)))
def test_fixed_name_stride_and_controls_guard_reuse_original_oracle(machine,index,high):
 image,m=machine;old.test_name_shift_leaves_selected_input_slot_and_controls_tail_intact(image,m,FIELDS,index,high)

@pytest.mark.parametrize('value',(0,1,0x00999999,0x12345678,0x89abcdef,0xffffffff))
def test_six_low_nibbles_and_high_byte_skip_reuse_original_oracle(machine,value):
 image,m=machine;old.test_formatter_skips_high_byte_converts_six_nibbles_and_retains_terminator(image,m,FIELDS,value)


def cursor(m):
 put(m,APP+4,0x70000);put(m,0xdeca,0x70000);m[0xdec3]=m[0xdec4]=m[0xdeba]=0
 assert get(m,0xcc4c,2)==12345  # Stored image's own text acceptance word.

@pytest.mark.parametrize('index,keys,name',((0,(0x20,0x35,0x1c),b'AB'),(7,(0x20,)*16+(0x1c,),b'A'*15),(14,(0x20,0x45),b''),(7,(0x20,0x35,0x41,0x21,0x1c),b'AS')))
def test_shift_and_actual_editor_return_to_disk_call_boundary(machine,index,keys,name):
 image,m=machine;cursor(m);scores=old.SCORES;rows=[bytes([65+i])*15+b'\0'for i in range(16)]
 for i,v in enumerate(scores):put(m,SCORES+4*i,v)
 m[NAMES:NAMES+256]=b''.join(rows);m[CONTROLS:CONTROLS+184]=b'\xa7'*184
 candidate=scores[index]+1;put(m,APP+0x71c,candidate)
 c=state(m,0xfe22);run(image,m,c,{0xfe36});assert c.d[0]==14-index and c.a[3]==SCORES+4*(index+1)
 # Separate continuation conditional on normal palette/clear returns. Neither
 # palette helper is executed or replaced. Original shifts build the real
 # saved name-slot pointer consumed by the later editor continuation.
 c.pc=0xfe50;c.a[1]=SCORES+56;c.d[2]=c.d[0];run(image,m,c,{0xfe92})
 assert get(m,c.a[7])==NAMES+16*index
 queue=iter(keys);events=[];font=bytes(m[0x18620:0x18620+760])
 def key(pc):
  if pc==0xd7da:
   value=next(queue,None);assert value is not None,'unexpected key request'
   m[APP+0x203]=value;events.append(value)
 c.pc=0xfe96;run(image,m,c,{0xfea4},key,limit=150000)
 assert events==list(keys) and list(queue)==[] and c.a[7]==STACK and get(m,0xd930,2)==15
 assert [get(m,SCORES+4*i)for i in range(16)]==scores[:index]+[candidate]+scores[index:15]
 expected=bytearray(b''.join(rows[:index+1]+rows[index:15]));expected[16*index:16*index+len(name)+1]=name+b'\0'
 assert bytes(m[NAMES:NAMES+256])==expected and bytes(m[CONTROLS:CONTROLS+184])==b'\xa7'*184
 assert bytes(m[0x18620:0x18620+760])==font
 # $FEA4 has not executed its BSR to $10266. No disk operation is run.


def test_visible_table_runs_real_text_and_six_digit_consumers_for_fifteen_rows(machine):
 image,m=machine;cursor(m);before=bytes(m[SCORES:CONTROLS]);font=bytes(m[0x18620:0x18620+760]);calls=[]
 def text(pc):
  if pc==0xc4f0:
   at=c.a[1];end=at
   while m[end]:end+=1
   assert end-at<200;calls.append((at,bytes(m[at:end])))
 c=state(m,0xfeae);run(image,m,c,{0xfee8},text,limit=200000)
 assert len(calls)==61 and calls[0][0]==0x12f0c
 for i in range(15):
  prefix,score,colour,name=calls[1+4*i:5+4*i]
  assert prefix[0]==0x12f2d and colour[0]==0x12f35 and score[0]==TEXT and name[0]==NAMES+16*i
  value=get(m,SCORES+4*i);assert score[1]==bytes(48+((value>>shift)&15)for shift in range(20,-1,-4))
 assert c.a[3]==SCORES+60 and c.a[4]==NAMES+240 and bytes(m[SCORES:CONTROLS])==before
 assert bytes(m[0x18620:0x18620+760])==font and any(m[0x70000:0x78000])

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_rating_source_contracts(tmp_path):
 import struct,subprocess
 from pathlib import Path
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered';source=(directory/'retail-shared.s').read_text()
 symbols={'insert_qualifying_pilot_rating':0xfe22,'scan_next_visible_rating_score':0xfe2c,'shift_rating_scores_toward_scratch_slot':0xfe50,'shift_rating_names_toward_scratch_slot':0xfe64,'display_pilot_ratings':0xfeae,'format_six_score_nibbles':0xfefe,'pilot_rating_score_slots':SCORES,'pilot_rating_name_slots':NAMES,'pilot_rating_score_insertion_scratch':SCORES+60,'pilot_rating_name_insertion_scratch':NAMES+240,'pilot_rating_name_entry_prompt':0x12f40,'SG2GameLifecycleWorkspace_player_score_bcd':0x71c,'SG2PilotRatingScore_SIZEOF':4}
 assert 'SG2GameLifecycleWorkspace_player_score_bcd(a6)'in source
 block=source.split('pilot_rating_score_slots:',1)[1].split('pilot_rating_score_insertion_scratch:',1)[0]
 assert 'dc.l' in block and 'dc.b' not in block,block
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert r.returncode==0,r.stdout+r.stderr
 data=out.read_bytes();n=4*len(symbols);assert data[:-n]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',data[-n:])==tuple(symbols.values())

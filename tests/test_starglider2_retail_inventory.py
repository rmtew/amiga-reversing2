"""Retail inventory continuations, bounded original writes and real constructors.

CPU fixtures supply owned items, RAM and keys. UI cases stop at display calls;
separate original-media emulator continuations exercise live empty inventory.
No general buffer capacity, item eligibility or pointer lifetime is implied.
"""
import os
import pytest
from amiga_reversing.disasm.mapped_execution import MappedExecution
from test_starglider2_retail_model_headers import image
from test_starglider2_retail_workspace import put,get
from test_starglider2_retail_input import memory,state,program
from tests.test_starglider2_text_editor import run as original_run
from tests.test_starglider2_inventory_interface import line_for,cstring
from tests.test_starglider2_motion_integration import expected_vector
from tests.test_starglider2_control_normalization import signed
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
APP,STACK,RETURN=0x70000,0xf0000,0xff000
NAMES,EVENTS,COUNTS,QTY,TAGS,POINTERS,LINE=0xf380,0x394ba,APP+0xae5,APP+0xa48,APP+0xa62,APP+0x9ce,APP+0xa2a
CURSOR,INDEX,FREE,ACTOR=APP+0x9c0,APP+0xa70,0x90000,APP+0x2330+7*68
EXCLUDED=(12,91,98,84)

def base(platform='st'):
 c=MappedExecution(0x100000,register_seed=0x12345678);c.seed(0x1000,image(platform));c.seed(APP,bytes(0x6598));c.allow_write(APP,0x6598)
 c.seed(STACK,RETURN.to_bytes(4,'big'));c.allow_write(STACK-512,516);c.cpu.a[6]=APP;c.cpu.a[7]=STACK
 c.allow_write(0x3b4ca,4);c.allow_write(0xe145,1)
 return c

def call(c,pc,stop=RETURN,limit=20000):return c.run(pc,stop,limit)
def dec(value):return 0 if (value-1)&128 else (value-1)&255

def selected(c,kinds,quantities,index=0):
 c.seed(POINTERS,b'\xff'*40);c.seed(QTY,b'\xff'*10);c.seed(TAGS,b'\xff'*10)
 for n,(kind,qty)in enumerate(zip(kinds,quantities)):
  put(c.memory,POINTERS+4*n,get(c.memory,NAMES+4*kind));c.memory[QTY+n]=qty;c.memory[TAGS+n]=kind
 put(c.memory,POINTERS+4*len(kinds),0xffffffff);put(c.memory,CURSOR,4*index,2);put(c.memory,INDEX,index,2)

def line(c,pc=0x1bd2):
 call(c,pc,0x33da);return cstring(c.memory,LINE)+b'\0'

@pytest.mark.parametrize('platform',('amiga','st'))
@pytest.mark.parametrize('kind',range(104))
def test_all_builder_name_indices_and_real_decimal_formatter(platform,kind):
 c=base(platform);selected(c,[kind],[255]);c.memory[LINE-1]=0x5a
 name=cstring(c.memory,get(c.memory,NAMES+4*kind));expected=line_for(name,255)
 assert line(c)==expected and c.cpu.a[1]==LINE and c.cpu.a[7]==STACK-4
 assert c.memory[LINE-1]==0x5a
 if kind==86:assert c.read(QTY,2)==b'5\0'  # Original 32-byte line aliases its 30-byte prefix.

@pytest.mark.parametrize('name',(b'Whale',b'Glass',b'GAS',b'',b'X'))
@pytest.mark.parametrize('quantity',(0,1,10,127,255))
@pytest.mark.parametrize('previous',(ord('s'),ord('X')))
def test_plural_rule_reuses_older_oracle_and_keeps_empty_name_predecessor(name,quantity,previous):
 c=base();selected(c,[0],[quantity]);c.seed(0x88000,name+b'\0');put(c.memory,POINTERS,0x88000);c.memory[LINE-1]=previous
 assert line(c)==line_for(name,quantity,previous)

@pytest.mark.parametrize('kinds',([], [12], [12,91,98,84], [3,24,86]))
def test_builder_descends_all_nonzero_counts_without_touching_tag_sentinel(kinds):
 c=base();c.seed(POINTERS,b'\xcc'*40);c.seed(QTY,b'\xcc'*10);c.seed(TAGS,b'\xcc'*10)
 for n,kind in enumerate(kinds):c.memory[COUNTS+kind]=(1,2,127,255)[n]
 call(c,0x1dce);order=sorted(kinds,reverse=True)
 assert [get(c.memory,POINTERS+4*n)for n in range(len(order))]==[get(c.memory,NAMES+4*k)for k in order]
 assert c.read(QTY,len(order))==bytes(c.memory[COUNTS+k]for k in order) and c.read(TAGS,len(order))==bytes(order)
 assert get(c.memory,POINTERS+4*len(order))==0xffffffff and c.memory[QTY+len(order)]==255
 assert c.memory[TAGS+len(order)]==0xcc and c.cpu.a[7]==STACK+4


def test_dense_builder_preserves_cross_prefix_aliases_instead_of_claiming_ten_slot_bound():
 c=base()
 for kind in range(1,24):c.memory[COUNTS+kind]=1
 call(c,0x1dce)
 assert POINTERS+23*4==LINE and get(c.memory,LINE)==0xffffffff
 assert [get(c.memory,POINTERS+4*i)for i in range(23)]==[get(c.memory,NAMES+4*k)for k in range(23,0,-1)]
 assert c.read(APP+0xa55,10)==b'\1'*10 and get(c.memory,INDEX,2)==0x0908

@pytest.mark.parametrize('size',(0,1,2,3))
@pytest.mark.parametrize('index',(0,65535))
def test_inventory_i_advances_then_wraps_both_words_on_pointer_sentinel(size,index):
 c=base();kinds=[12,11,3][:size];selected(c,kinds,[1,2,3][:size]);put(c.memory,CURSOR,(index*4)&65535,2);put(c.memory,INDEX,index,2)
 call(c,0x1ba4,0x1bd2);expected=0 if index==65535 or size<=1 else 1
 assert get(c.memory,CURSOR,2)==4*expected and get(c.memory,INDEX,2)==expected
 if not size:call(c,0x1bd2,0x1c3e)
 else:assert line(c)==line_for(cstring(c.memory,get(c.memory,NAMES+4*kinds[expected])),[1,2,3][expected])


def test_pointer_and_quantity_cursors_are_independent_word_inputs():
 c=base();selected(c,[12,11],[1,2]);put(c.memory,CURSOR,4,2)
 assert line(c)==line_for(cstring(c.memory,get(c.memory,NAMES+44)),1)


def test_scratch_reset_changes_only_four_ten_entry_prefixes():
 c=base();regions=[(POINTERS,40),(QTY,10),(APP+0xa55,10),(TAGS,10)]
 for p,n in regions:c.seed(p-1,b'\xcc'*(n+2))
 call(c,0x36322)
 for p,n in regions:assert c.read(p,n)==b'\xff'*n and c.read(p-1,1)==c.read(p+n,1)==b'\xcc'

@pytest.mark.parametrize('platform',('amiga','st'))
@pytest.mark.parametrize('raw_key,stop',((0x17,0x1ba4),(0x26,0x1c64),(0x34,0x1e96),(0x32,0x1e0a)))
def test_modal_actual_key_reader_reaches_i_j_v_or_exit(platform,raw_key,stop):
 m=memory(platform);m[APP+0x203]=raw_key;c=state(m,0x1b30)
 for off in(0xa8,0xb8,0xc8,0xd8):put(m,0xdff000+off,0x1234,2)
 original_run(program(platform),m,c,{0x1ba4,0x1c64,0x1e96,0x1e0a},limit=3000)
 assert c.pc==stop and m[APP+0x203]==0 and m[APP+0x6da]==255
 assert [get(m,0xdff000+off,2)for off in(0xa8,0xb8,0xc8,0xd8)]==([0]*4 if platform=='amiga' else [0x1234]*4)


def test_retail_v_returns_from_message_enqueue_into_cleanup_instead_of_old_tail_return():
 c=base();c.memory[APP+0x203]=0x34;c.memory[APP+0x6da]=255;put(c.memory,0xe0c2,0);c.allow_write(0xe0c0,0x50)
 call(c,0x1b5e,0x1e0a)
 assert c.cpu.a[7]==STACK and c.memory[APP+0x6da]==255 and get(c.memory,APP+0x7ae,2)==2
 assert get(c.memory,0xe0c6)==0x27a0

@pytest.mark.parametrize('cursor,index',((0,0),(4,1),(65532,65535)))
def test_modal_cleanup_after_display_clears_mode_and_cursors(cursor,index):
 c=base();put(c.memory,CURSOR,cursor,2);put(c.memory,INDEX,index,2);c.memory[APP+0x6da]=255
 call(c,0x1e0e)
 assert get(c.memory,CURSOR,2)==get(c.memory,INDEX,2)==0 and c.memory[APP+0x6da]==0 and c.cpu.a[7]==STACK+4

@pytest.mark.parametrize('selected_type',range(104))
def test_nonweapon_population_sum_excludes_exact_four_types_and_retains_word_scaled_total(selected_type):
 c=base();c.memory[COUNTS+selected_type]=255;d,a=list(c.cpu.d),list(c.cpu.a);call(c,0x390f6)
 total=0 if selected_type in EXCLUDED else 255
 assert c.cpu.d[7]==total and c.cpu.d[6]&65535==(total<<5)&65535
 assert get(c.memory,0x3b4cc,2)==total and get(c.memory,0x3b4ca,2)==(total<<5)&65535
 assert list(c.cpu.d[:2])==d[:2] and c.cpu.a[1]==a[1] and c.cpu.a[7]==STACK+4


def drop_fixture(kind=3,owned=1,quantity=1,free=2,slot=0,space=0,angles=(0,0,0)):
 c=base();selected(c,[kind],[quantity]);c.memory[COUNTS+kind]=owned
 if kind!=2:c.memory[COUNTS+2]=1  # Keep an unrelated item for stale selected-zero cases.
 put(c.memory,APP+0x772,free,2);c.seed(FREE,ACTOR.to_bytes(4,'big'));put(c.memory,APP+0x6d4,FREE+4)
 c.seed(ACTOR,b'\xcc'*68);put(c.memory,APP+0x44,0x15808);put(c.memory,APP+0x48,0x16008)
 for off,value in zip((0x704,0x708,0x70c),(0xfffffff0,3,32)):put(c.memory,APP+off,value)
 for off,value in zip((0x744,0x746,0x748),angles):put(c.memory,APP+off,value,2)
 for i in range(slot):put(c.memory,APP+0xa02+4*i,APP+0x2330+68*(20+i))
 c.memory[APP+0x77d]=space;put(c.memory,APP+0x6fc,0x0fffffff)
 return c

@pytest.mark.parametrize('kind',EXCLUDED)
@pytest.mark.parametrize('free',(0,1,2,65535))
def test_jettison_reserve_and_weapon_guards_precede_any_quantity_or_record_change(kind,free):
 c=drop_fixture(kind,free=free);before=c.read(ACTOR,68);call(c,0x1c64,0x1dc6)
 assert c.memory[QTY]==1 and c.memory[COUNTS+kind]==1 and get(c.memory,APP+0x772,2)==free
 assert get(c.memory,APP+0x6d4)==FREE+4 and c.read(ACTOR,68)==before

@pytest.mark.parametrize('owned',(0,1,127,128,129,255))
@pytest.mark.parametrize('quantity',(0,1,127,128,255))
def test_jettison_n_only_debits_and_constructor_allocation_depend_on_owned_sign(owned,quantity):
 c=drop_fixture(owned=owned,quantity=quantity);before=c.read(ACTOR,68);call(c,0x1c64,0x1dc6)
 allocate=0<owned<128
 assert c.memory[QTY]==dec(quantity) and c.memory[COUNTS+3]==dec(owned)
 assert get(c.memory,APP+0x772,2)==(1 if allocate else 2) and get(c.memory,APP+0x6d4)==(FREE if allocate else FREE+4)
 if not allocate:assert c.read(ACTOR,68)==before

@pytest.mark.parametrize('kind',(3,73))
@pytest.mark.parametrize('slot',range(11))
@pytest.mark.parametrize('space',(0,128))
@pytest.mark.parametrize('angles',((0,0,0),(1023,2049,77)))
def test_real_constructor_and_motion_helper_publish_jettisoned_record(kind,slot,space,angles):
 c=drop_fixture(kind,slot=slot,space=space,angles=angles);before=c.read(APP+0x2330,250*68)
 distance=((slot<<13)+8000)&65535;vector,_=expected_vector(c.memory,angles,distance,tables=(0x15808,0x16008))
 xyz=[(v+signed(d))&0xffffffff for v,d in zip((0xfffffff0,3,32),vector)]
 if not space and xyz[1]<0x80000000:xyz[1]=0
 xyz[0]&=0x0fffffff;xyz[2]&=0x0fffffff
 call(c,0x1c64,0x1bd2)
 assert get(c.memory,ACTOR,2)==kind and [get(c.memory,ACTOR+o)for o in(4,8,12)]==xyz
 assert c.read(ACTOR+16,6)==b''.join(v.to_bytes(2,'big')for v in angles)
 assert c.memory[ACTOR+30]==(0 if kind==73 else 255) and c.memory[ACTOR+3]==0
 assert c.memory[ACTOR+28]==c.memory[0x195cc+kind] and c.memory[ACTOR+29]==c.memory[0x18b8e+kind]
 assert get(c.memory,ACTOR+32,2)==get(c.memory,0x194f0+2*kind,2) and get(c.memory,ACTOR+60)==0xffffffff
 if slot<10:assert get(c.memory,APP+0xa02+4*slot)==ACTOR
 else:assert all(get(c.memory,APP+0xa02+4*i)!=ACTOR for i in range(10))
 after=c.read(APP+0x2330,250*68);start=ACTOR-(APP+0x2330)
 assert before[:start]==after[:start] and before[start+68:]==after[start+68:]
 assert get(c.memory,APP+0x772,2)==1 and c.memory[QTY]==0 and c.memory[COUNTS+kind]==0
 assert c.cpu.a[6]==APP and c.cpu.a[7]==STACK

@pytest.mark.parametrize('space',(0,128))
@pytest.mark.parametrize('speed',(0,63,64,32767,32768,65535))
@pytest.mark.parametrize('enabled',(0,1,32768,65535))
def test_d_command_targets_stardrive_not_inventory_population(space,speed,enabled):
 c=base();c.allow_write(0xe0c0,0x50);c.memory[APP+0x203]=0x22;c.memory[APP+0x77d]=space
 put(c.memory,APP+0x75a,speed,2);put(c.memory,APP+0x9ae,enabled,2);put(c.memory,0x3b4c8,199,2)
 before=c.read(COUNTS,104);call(c,0x1824)
 allowed=space and not ((speed-64)&32768)
 assert get(c.memory,APP+0x9ae,2)==(65535 if allowed and not enabled else 0)
 assert c.read(COUNTS,104)==before and get(c.memory,APP+0x7ae,2)>0 and c.cpu.a[7]==STACK+4


@pytest.mark.parametrize('free',(0,1))
def test_normal_item_still_requires_more_than_one_free_record(free):
 c=drop_fixture(free=free);call(c,0x1c64,0x1dc6)
 assert c.memory[QTY]==c.memory[COUNTS+3]==1 and get(c.memory,APP+0x6d4)==FREE+4


def test_empty_nonweapon_population_clears_cursors_before_empty_notice():
 c=base();selected(c,[3],[1]);put(c.memory,CURSOR,4,2);put(c.memory,INDEX,1,2)
 call(c,0x1c64,0x1c3e)
 assert c.cpu.d[7]==0 and get(c.memory,CURSOR,2)==get(c.memory,INDEX,2)==0 and c.memory[QTY]==1


def test_unsigned_population_total_and_shift_wrap_with_all_104_counts():
 c=base();c.seed(COUNTS,b'\xff'*104);call(c,0x390f6)
 assert c.cpu.d[7]==25500 and get(c.memory,0x3b4cc,2)==25500 and get(c.memory,0x3b4ca,2)==(25500*32)&65535


def test_null_pointer_is_not_the_inventory_sentinel():
 c=base();selected(c,[],[]);put(c.memory,POINTERS+4,0)
 call(c,0x1ba4,0x1bd2)
 assert get(c.memory,CURSOR,2)==4 and get(c.memory,INDEX,2)==1
 with pytest.raises(ValueError,match='unknown read'):
  call(c,0x1bd2,0x33da)

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='external vasm is the only source build dependency')
def test_compiled_semantic_symbols_distinguish_d_service_from_inventory_counter(tmp_path):
 from pathlib import Path
 import struct,subprocess
 root=Path(__file__).resolve().parents[1];directory=root/'targets/starglider2_retail/rendered'
 names=['try_toggle_stardrive_bridge','try_toggle_stardrive','refresh_counted_model_population','recompute_counted_model_population','object_name_pointers']
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin'
 asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(names)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert r.returncode==0,r.stdout+r.stderr
 data=out.read_bytes();assert data[:-20]==image('st')
 assert struct.unpack('>5I',data[-20:])==(0x33a4,0x31242,0x33bc,0x390f6,0xf380)

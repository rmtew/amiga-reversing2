"""Original distant retirement, encounter gates and partial actor construction.

Constructed CPU states prove ordering and finite table contracts,not a natural
playthrough,PRNG distribution,global actor domains or allocation lifetimes.
"""
import ctypes,os
import pytest
from tests.test_starglider2_text_editor import state,run,put,get,APP,INPUT,STACK,RETURN
from test_starglider2_retail_input import program
from tests.test_starglider2_control_normalization import signed
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
DIRECTORY,CYCLE,TICK,CURSOR,PHASE,GAP,BURST=0x3b2ee,0x3b3f6,0x3b2e6,0x3b2e8,0x3b2e4,0x3b2ea,0x3b2ec
ACTOR,REFS,FREE=INPUT+0x1000,INPUT+0x100,INPUT+0x200

@pytest.fixture(params=('amiga','st'))
def machine(request):
 image=program(request.param);raw=image[0];m=(ctypes.c_uint8*0xa1000)();ctypes.memmove(ctypes.addressof(m)+4096,raw,len(raw));return image,m

def word(m,p,v):put(m,p,v&65535,2)
def rng(a,b):
 r=((a<<3)|(a>>29))&0xffffffff
 return b,(r&0xffff0000)|(((r-7)^b)&65535)
def selected(m,metric,index):
 for threshold,table in((300000000,0x3b476),(150000000,0x3b456),(90000000,0x3b436)):
  if signed(metric-threshold,32)>=0:return table
 return get(m,DIRECTORY+4*index)
def constructor(m,typ,base):
 e=bytearray(base)
 def f(off,value,width=2):e[off:off+width]=(value&((1<<(8*width))-1)).to_bytes(width,'big')
 f(0,typ);f(29,m[0x18b8e+typ],1);f(28,m[0x195cc+typ],1);f(30,255,1);f(3,0,1);f(31,1,1)
 f(32,signed(get(m,0x194f0+2*typ,2))>>1);f(44,0);f(16,1)
 if typ==91:e[2]|=128
 if typ==10:f(36,1000)
 return e

@pytest.mark.parametrize('metric,index,draw',((0,0,0),(0,17,15),(89999999,2,3),(90000000,0,1),(150000000,0,7),(300000000,0,15),(0x80000000,0,4),(0xffffffff,1,9)))
def test_choice_and_partial_constructor_reuse_signed_metric_and_preserved_bytes(machine,metric,index,draw):
 image,m=machine;put(m,APP+0x9b4,metric);word(m,APP+0x830,index);m[ACTOR:ACTOR+68]=b'\xa5'*68
 typ=get(m,selected(m,metric,index)+2*(draw&15),2);expected=constructor(m,typ,bytes(m[ACTOR:ACTOR+68]))
 c=state(m,0x3513e);c.a[4]=ACTOR;c.d[0]=0xfedc0000|draw;run(image,m,c,{0x351f4})
 assert bytes(m[ACTOR:ACTOR+68])==expected and c.d[0]&65535==2*typ

@pytest.mark.parametrize('cursor,tick,count',((0,254,2),(0,255,2),(31,65535,2),(32,255,2),(0,255,0)))
def test_distant_retirement_only_clears_type_and_masks_cursor_after_read(machine,cursor,tick,count):
 image,m=machine;word(m,APP+0x75c,count);put(m,APP+0x6b8,REFS);word(m,TICK,tick);word(m,CURSOR,cursor)
 wanted=get(m,CYCLE+2*cursor,2);m[ACTOR:ACTOR+136]=b'\xa5'*136
 for i,typ in enumerate((wanted,wanted^1)):put(m,REFS+4*i,ACTOR+68*i);word(m,ACTOR+68*i,typ)
 before=bytes(m[ACTOR:ACTOR+136]);c=state(m,0x34fd8);run(image,m,c,{0x35022});expected=bytearray(before)
 if (tick+1)&255==0 and count:expected[:2]=b'\0\0'
 assert bytes(m[ACTOR:ACTOR+136])==expected
 assert get(m,TICK,2)==(tick+1)&255 and get(m,CURSOR,2)==((cursor+1)&31 if(tick+1)&255==0 and count else cursor)

@pytest.mark.parametrize('station,body',((128,0),(255,0),(1,16)))
def test_station_sign_and_body_equality_skip_encounters_without_normalizing_state(machine,station,body):
 image,m=machine;m[APP+0xa7e]=station;word(m,APP+0x830,body);word(m,GAP,0x1234);word(m,BURST,0xabcd)
 c=state(m,0x35022);run(image,m,c,{0x3524c})
 assert get(m,GAP,2)==0x1234 and get(m,BURST,2)==0xabcd

@pytest.mark.parametrize('speed,old_phase,d0',((1,2,0xffff),(1,3,0xffff),(0,7,0),(0,255,0),(0,255,0xff00)))
def test_attempt_cadence_keeps_stationary_byte_only_mask_write(machine,speed,old_phase,d0):
 image,m=machine;word(m,APP+0x75a,speed);word(m,PHASE,old_phase);c=state(m,0x35082);c.d[0]=0x12340000|d0
 run(image,m,c,{0x350a2,0x3524c});mask=3 if speed else(d0&0xff00)|7;answer=(old_phase+1)&65535&mask
 assert get(m,PHASE,2)==answer and c.pc==(0x350a2 if answer==0 else 0x3524c)

@pytest.mark.parametrize('index',(0,17,18,0x4000,65535))
def test_body_directory_index_uses_wrapped_signed_word_without_a_guard(machine,index):
 image,m=machine;word(m,APP+0x830,index);c=state(m,0x3517c);byte_offset=signed(index*4)
 run(image,m,c,{0x3518e});assert c.a[0]==get(m,DIRECTORY+byte_offset)
 if index==18:assert c.a[0]==0x00590011


def test_one_original_service_retires_then_allocates_and_initializes_an_encounter(machine):
 image,m=machine;put(m,APP+0x44,0x15808);put(m,APP+0x48,0x16008)
 for off,value in((0x704,1000),(0x708,2000),(0x70c,3000)):put(m,APP+off,value)
 put(m,APP+0x60,0);put(m,APP+0x64,1);word(m,APP+0x75a,1);word(m,PHASE,3);word(m,GAP,65535);word(m,BURST,1)
 word(m,APP+0x75c,2);put(m,APP+0x6b8,REFS);word(m,TICK,255);word(m,CURSOR,0)
 wanted=get(m,CYCLE,2);far=ACTOR+256;m[far:far+136]=b'\xa5'*136
 for i,typ in enumerate((wanted,wanted^1)):put(m,REFS+4*i,far+68*i);word(m,far+68*i,typ)
 oldfar=bytes(m[far:far+136]);m[ACTOR:ACTOR+68]=b'\xa5'*68;put(m,FREE,ACTOR);put(m,APP+0x6d4,FREE+4);word(m,APP+0x772,151)
 a,b=0,1;draws=[]
 for _ in range(5):a,b=rng(a,b);draws.append(b)
 assert draws[0]&7==0
 typ=get(m,get(m,DIRECTORY)+2*(draws[4]&15),2);assert typ!=40
 expected=constructor(m,typ,bytes(m[ACTOR:ACTOR+68]))
 # Exact fixed-point player-forward vector at zero angles,then PRNG jitter.
 scale=lambda a,b:signed(((a*b*2)&0xffffffff)>>16)
 cosine=get(m,0x16008,2);assert cosine==16383 and get(m,0x15808,2)==0
 forward=scale(cosine,scale(cosine,32767))
 xyz=(1000+(draws[1]&4095)-2048,2000+(draws[2]&1023)-512,3000+forward+(draws[3]&4095)-2048)
 for off,value in zip((4,8,12),xyz):expected[off:off+4]=(value&0xffffffff).to_bytes(4,'big')
 for off,value in((18,draws[1]&4095),(20,draws[3]&4095)):expected[off:off+2]=value.to_bytes(2,'big')
 c=state(m,0x34fd8);run(image,m,c,{0x3524c},limit=2000)
 assert bytes(m[ACTOR:ACTOR+68])==expected and get(m,APP+0x772,2)==150 and get(m,APP+0x6d4)==FREE
 assert bytes(m[far:far+136])==b'\0\0'+oldfar[2:] and get(m,CURSOR,2)==1 and get(m,TICK,2)==0
 assert get(m,APP+0x60)==a and get(m,APP+0x64)==b and get(m,BURST,2)==0

@pytest.mark.parametrize('gap,burst',((1,7),(0,7),(65535,1),(65535,0),(65535,32768),(32768,0),(32767,0)))
def test_gap_and_burst_countdowns_keep_sign_wrap_and_actual_rng_order(machine,gap,burst):
 image,m=machine;word(m,GAP,gap);word(m,BURST,burst);word(m,PHASE,0);word(m,APP+0x75a,1);put(m,APP+0x60,0);put(m,APP+0x64,1)
 a,b=0,1;eg,eb=gap,burst;attempt=True
 if gap<32768:
  eg=(gap-1)&65535
  if eg<32768:attempt=False
  else:a,b=rng(a,b);eg=65535;eb=(b&511)+64
 if attempt:
  eb=(eb-1)&65535
  if eb&32768:a,b=rng(a,b);eb=65535;eg=(b&1023)+256
 c=state(m,0x35034);run(image,m,c,{0x3524c})
 assert (get(m,GAP,2),get(m,BURST,2))==(eg,eb)
 assert (get(m,APP+0x60),get(m,APP+0x64))==(a,b)
 assert get(m,PHASE,2)==int(attempt)

@pytest.mark.parametrize('free',(0,150,151,32768,65535))
def test_encounter_free_reserve_is_unsigned_and_not_a_stack_capacity_guard(machine,free):
 image,m=machine;put(m,APP+0x60,0);put(m,APP+0x64,1);word(m,APP+0x772,free);put(m,APP+0x6d4,FREE+4);put(m,FREE,ACTOR)
 c=state(m,0x350a2);run(image,m,c,{0x350c6,0x3524c})
 allowed=free>150
 assert c.pc==(0x350c6 if allowed else 0x3524c)
 assert get(m,APP+0x772,2)==(free-1 if allowed else free)
 assert get(m,APP+0x6d4)==FREE+(0 if allowed else 4)

@pytest.mark.parametrize('right,motion',((0,5),(1,65535),(0,16384)))
def test_pirate_extra_initialization_preserves_other_bytes_with_warning_latched(machine,right,motion):
 image,m=machine;m[ACTOR:ACTOR+68]=b'\xa5'*68;word(m,ACTOR,40);word(m,ACTOR+32,motion);word(m,0x391e8,0);put(m,APP+0x60,0);put(m,APP+0x64,right)
 a,b=rng(0,right);count=(b&511)+64;expected=bytearray(m[ACTOR:ACTOR+68])
 for off,value in((32,motion*8),(36,count),(40,16 if count&1 else -16)):expected[off:off+2]=(value&65535).to_bytes(2,'big')
 c=state(m,0x351f4);c.a[4]=ACTOR;run(image,m,c,{0x3524c})
 assert bytes(m[ACTOR:ACTOR+68])==expected and get(m,0x391e8,2)==0
 assert (get(m,APP+0x60),get(m,APP+0x64))==(a,b)


def test_directory_relocation_complete_choice_owners_and_finite_types():
 raw=program('st')[0];pointers=[get(raw,DIRECTORY-4096+4*i)for i in range(18)]
 assert set(pointers)=={0x3b336+32*i for i in range(6)}
 for table in set(pointers)|{0x3b436,0x3b456,0x3b476}:
  values=[get(raw,table-4096+2*i,2)for i in range(16)]
  assert all(0<=v<104 for v in values)
 assert DIRECTORY+18*4==0x3b336 and CYCLE+32*2==0x3b436

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_choice_pointer_array_uses_symbols_and_exact_owners(tmp_path):
 import struct,subprocess
 from pathlib import Path
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered';source=(directory/'retail-shared.s').read_text()
 symbols={'encounter_choice_directory_prefix':DIRECTORY,'distant_retirement_type_cycle':CYCLE,'distant_retirement_tick_mod256':TICK,'distant_retirement_type_cursor':CURSOR,'encounter_attempt_phase':PHASE,'encounter_choices_columbus_horatio':0x3b336,'encounter_choices_scrap_bombs':0x3b476,'SG2EncounterWorkspace_system_center_proximity_metric':0x9b4,'SG2EncounterChoiceReference_SIZEOF':4}
 assert 'SG2EncounterWorkspace_system_center_proximity_metric(a6)'in source
 block=source.split('encounter_choice_directory_prefix:',1)[1].split('encounter_choices_columbus_horatio:',1)[0]
 assert block.count('dc.l encounter_choices_')==18 and '$0003B'not in block,block
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert r.returncode==0,r.stdout+r.stderr
 raw=out.read_bytes();size=4*len(symbols)
 assert raw[:-size]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-size:])==tuple(symbols.values())

"""Original retail platform ingress and shared controls.

Anonymous sparse RAM represents external ports for bounded CPU tests. It is not
chipset/interrupt delivery or timing. Separate original emulator continuations
qualify live entry points and the shared key boundary; no input bytes are patched.
"""
import ctypes as C,mmap,os
from functools import cache
import pytest
from tests.test_memory_frame_arithmetic import ConcreteState,ConcreteResult
from tests.test_starglider2_text_editor import run as original_run
from src.tests.test_m68k_simulator_abstract import _disasm_library
from test_starglider2_retail_model_headers import image
from test_starglider2_retail_workspace import put,get
from tests.test_starglider2_control_normalization import centre,signed

pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail images')
APP,STACK,RETURN=0x70000,0xf0000,0xff000
KEYS,GWB,STROOT,MAP,HEADER=0xdece,0x27be,0x3cf2c,0x3f0f6,0x3d0fc
STDATA,ACK,VECTOR=0xfffffc02,0xfffffa11,0x118
POLL,IRQ=0xd19c,0xc8d0

@cache
def program(platform):
    raw=image(platform);code=(C.c_uint8*len(raw)).from_buffer_copy(raw);step=_disasm_library().m68k_simulate_one_concrete_for_cpu
    step.argtypes=[C.POINTER(C.c_uint8),C.c_size_t,C.c_uint8,C.POINTER(C.c_uint8),C.c_size_t,C.POINTER(ConcreteState)];step.restype=ConcreteResult
    return raw,code,step,None,{}

def memory(platform):
    if C.sizeof(C.c_void_p)<8:pytest.skip('Sparse logical address space requires a 64-bit host')
    mapping=mmap.mmap(-1,1<<32);m=(C.c_uint8*(1<<32)).from_buffer(mapping)
    raw=program(platform)[0];C.memmove(C.addressof(m)+4096,raw,len(raw));put(m,GWB,APP)
    return m

def state(m,pc):
    c=ConcreteState();c.pc=pc;c.sr=0x2700;c.d[:]=[0x12340000+i for i in range(8)];c.a[:]=[0x88000+128*i for i in range(8)];c.a[6]=APP;c.a[7]=STACK;put(m,STACK,RETURN);return c

def run(platform,m,c,stop,stimulus=None,limit=1000):
    original_run(program(platform),m,c,{stop},stimulus,limit=limit)

@pytest.mark.parametrize('directions',range(16))
@pytest.mark.parametrize('fire',(0,1,255))
@pytest.mark.parametrize('mode',(0,1,2,3))
def test_shared_joystick_modifier_and_autocentre_accept_both_platform_flag_values(directions,fire,mode):
    m=memory('st');put(m,APP+0x7a2,64,2);put(m,APP+0x7a4,-64,2);put(m,APP+0x7a8,0,2)
    put(m,APP+0x15c,directions,2);m[APP+0x1fd]=fire;m[APP+0x7f0]=mode;c=state(m,0x19d0)
    yaw,pitch,throttle=64,-64,0
    if fire and directions&3:throttle=-16 if directions&1 else 16
    else:
        yaw+=32*bool(directions&8)-32*bool(directions&4);pitch+=32*bool(directions&2)-32*bool(directions&1)
        if not directions:
            if mode&1:yaw=centre(yaw)
            if mode&2:pitch=centre(pitch)
    run('st',m,c,RETURN)
    assert [get(m,APP+o,2)for o in (0x7a2,0x7a4,0x7a8)]==[v&65535 for v in (yaw,pitch,throttle)]

@pytest.mark.parametrize('value',(-32768,-33,-32,-31,-1,0,31,32,33,32767))
@pytest.mark.parametrize('mode',(1,2,3,128))
def test_shared_autocentre_preserves_original_n_only_comparisons(value,mode):
    m=memory('st');put(m,APP+0x7a2,value,2);put(m,APP+0x7a4,value,2);m[APP+0x7f0]=mode
    run('st',m,state(m,0x1a34),RETURN)
    assert get(m,APP+0x7a2,2)==(centre(value)if mode&1 else value&65535)
    assert get(m,APP+0x7a4,2)==(centre(value)if mode&2 else value&65535)

@pytest.mark.parametrize('joy',range(1024))
def test_amiga_joy_counter_bits_decode_to_original_direction_mask(joy):
    m=memory('amiga');m[0xbfe0ff]=255;put(m,0xdff016,1024,2);put(m,0xdff00c,joy,2)
    run('amiga',m,state(m,POLL),RETURN)
    changed=joy^(joy>>1);expected=8*bool(joy&2)+4*bool(joy&512)+2*bool(changed&1)+bool(changed&256)
    assert get(m,APP+0x15c,2)==expected and get(m,0xdff034,2)==0xc00

@pytest.mark.parametrize('previous,current',((0,0),(0,127),(0,128),(0,255),(127,0),(128,0),(255,0),(255,1)))
@pytest.mark.parametrize('secondary',(0,1))
@pytest.mark.parametrize('space',(0,128))
def test_amiga_mouse_wrap_adjusts_by_255_and_routes_vertical_delta(previous,current,secondary,space):
    m=memory('amiga');m[0xbfe0ff]=255;put(m,0xdff016,0 if secondary else 1024,2);put(m,0xdff00a,(current<<8)|current,2)
    m[APP+0x1ff]=m[APP+0x200]=previous;m[APP+0xbb9]=255;m[APP+0x77d]=space;put(m,APP+0x740,3,2)
    for off in (0x7a2,0x7a4,0x7a8):put(m,APP+off,0x7fff,2)
    delta=current-previous
    if delta>=127:delta-=255
    elif delta< -127:delta+=255
    yaw=(delta*16)>>3
    if space&128:yaw>>=2
    run('amiga',m,state(m,POLL),RETURN)
    assert get(m,APP+0x7a2,2)==(0x7fff+yaw)&65535
    assert get(m,APP+(0x7a8 if secondary else 0x7a4),2)==(0x7fff+delta)&65535
    assert get(m,APP+(0x7a4 if secondary else 0x7a8),2)==0x7fff
    assert m[APP+0x1ff]==m[APP+0x200]==current and m[APP+0x202]==(255 if secondary else 0)


def receive(m,byte):
    c=state(m,get(m,VECTOR));c.a[6]=APP+0x2000;c.sr=0x2600;m[STDATA]=byte;m[ACK]=0x55
    put(m,STACK,0x2315,2);put(m,STACK+2,RETURN);d,a=list(c.d),list(c.a);frame=bytes(m[STACK:STACK+6])
    run('st',m,c,RETURN)
    assert list(c.d)==d and list(c.a[:7])==a[:7] and c.a[7]==STACK+6 and c.sr==0x2315
    assert bytes(m[STACK:STACK+6])==frame and m[ACK]==0xbf
    return c

@pytest.mark.parametrize('byte',range(256))
def test_st_ikbd_root_key_translation_and_packet_header_domains(byte):
    m=memory('st');put(m,VECTOR,STROOT);m[KEYS:KEYS+128]=b'\xa5'*128;m[APP+0x203]=0xa9
    before=bytearray(b'\xa5'*128)
    if byte<248:before[m[MAP+(byte&127)]]=0 if byte&128 else 1
    receive(m,byte)
    assert bytes(m[KEYS:KEYS+128])==before
    assert m[APP+0x203]==(m[MAP+byte]if byte<128 else 0xa9)
    assert (get(m,VECTOR)==STROOT)==(byte<248)

@pytest.mark.parametrize('header',(254,255))
@pytest.mark.parametrize('byte',(0,1,15,127,128,255))
def test_st_joystick_packet_selects_ignored_or_published_payload(header,byte):
    m=memory('st');put(m,VECTOR,STROOT);m[APP+0x1fd]=0x63;put(m,APP+0x15c,0xabcd,2)
    receive(m,header);phase=get(m,VECTOR);assert phase!=STROOT and m[HEADER]==header;receive(m,byte)
    assert get(m,VECTOR)==STROOT
    assert m[APP+0x1fd]==(255 if byte&128 else 0)if header&1 else m[APP+0x1fd]==0x63
    assert get(m,APP+0x15c,2)==(byte&15 if header&1 else 0xabcd)

@pytest.mark.parametrize('header',range(248,254))
@pytest.mark.parametrize('delta',(0,1,127,128,255))
@pytest.mark.parametrize('scale',(0,3,32,64))
def test_st_mouse_packet_uses_actual_successor_vectors_and_signed_deltas(header,delta,scale):
    m=memory('st');put(m,VECTOR,STROOT);put(m,APP+0x740,scale,2)
    for off in (0x7a2,0x7a4,0x7a8):put(m,APP+off,0x7fff,2)
    receive(m,header);xphase=get(m,VECTOR);receive(m,delta);yphase=get(m,VECTOR);assert xphase!=yphase
    value=signed(delta,8);expected=value if header&1 else (value*16)>>(scale&63)
    assert get(m,APP+0x7a2,2)==(0x7fff+expected)&65535
    receive(m,delta);assert get(m,VECTOR)==STROOT
    assert get(m,APP+(0x7a8 if header&1 else 0x7a4),2)==(0x7fff+value)&65535

@pytest.mark.parametrize('key',(0,5,33,80,127))
@pytest.mark.parametrize('pressed',(False,True))
def test_amiga_original_port_interrupt_decodes_key_and_restores_exception_context(key,pressed):
    m=memory('amiga');put(m,0xdff01e,8,2);m[0xbfed01]=8;decoded=key if pressed else key|128
    m[0xbfec01]=(~((decoded<<1)|(decoded>>7)))&255;m[APP+0x203]=0x55;put(m,0x68,IRQ)
    c=state(m,IRQ);c.a[6]=APP+0x2000;c.sr=0x2200;put(m,STACK,0x2315,2);put(m,STACK+2,RETURN)
    d,a=list(c.d),list(c.a)
    def clock(pc):
        if pc==0xc97e:m[0xbfd800]=2
    run('amiga',m,c,RETURN,clock)
    assert list(c.d)==d and list(c.a[:7])==a[:7] and c.a[7]==STACK+6 and c.sr==0x2315
    assert m[KEYS+key]==(255 if pressed else 0)and m[APP+0x203]==(key if pressed else 0x55)
    assert m[APP+(0x138 if pressed else 0x13a)]==decoded and get(m,0x68)==IRQ

@pytest.mark.parametrize('platform',('amiga','st'))
@pytest.mark.parametrize('raw_key',range(128))
def test_shared_command_poll_consumes_pending_key_and_preserves_address_register(platform,raw_key):
    m=memory(platform);m[APP+0x203]=raw_key;c=state(m,0xcbfe);a0=c.a[0]
    run(platform,m,c,RETURN)
    assert c.d[0]==(m[0xdf4e+raw_key]if raw_key else 0)
    assert m[APP+0x203]==0 and c.a[0]==a0

@pytest.mark.parametrize('enabled',(0,127,128,255))
@pytest.mark.parametrize('pose',(0,1,254,255))
def test_amiga_mouse_samples_and_buttons_update_even_when_motion_is_gated(enabled,pose):
    m=memory('amiga');m[0xbfe0ff]=0;put(m,0xdff016,0,2);put(m,0xdff00a,0x0101,2)
    m[APP+0xbb9]=enabled;m[APP+0xbba]=pose
    run('amiga',m,state(m,POLL),RETURN)
    assert bytes(m[APP+0x1ff:APP+0x203])==bytes((1,1,255,255)) and m[APP+0x1fd]==255
    assert get(m,APP+0x7a2,2)==(16 if enabled&128 and not pose else 0)
    assert get(m,APP+0x7a8,2)==(1 if enabled&128 and not pose else 0)


def test_st_installer_clears_only_112_key_flags_and_installs_original_root():
    m=memory('st');m[KEYS:KEYS+128]=b'\xa5'*128
    run('st',m,state(m,0x3cd58),0x3cd6e)
    assert get(m,VECTOR)==STROOT and bytes(m[KEYS:KEYS+128])==bytes(112)+b'\xa5'*16


def test_st_make_guard_preserves_original_loop_and_already_published_key():
    m=memory('st');put(m,0xcc5c,0,2);m[STDATA]=6;c=state(m,STROOT)
    run('st',m,c,0x3cf76)
    assert m[APP+0x203]==5 and m[KEYS+5]==1
    run('st',m,c,STROOT)
    assert c.a[7]==STACK-16  # Branch returns to the entry, without an RTE/pop.
    assert get(memory('st'),0xcc5c,2)==0x66e2


def test_st_translation_prefix_ends_at_glyph_table_and_tail_make_codes_alias_it():
    m=memory('st')
    assert bytes(m[MAP+120:MAP+128])==bytes.fromhex('00000003000c000f')
    for byte in range(120,128):
        put(m,VECTOR,STROOT);receive(m,byte)
        assert m[APP+0x203]==m[MAP+byte]


def test_amiga_temporary_rte_stub_keeps_registers_and_consumes_exception_frame():
    m=memory('amiga');c=state(m,0xc8ce);put(m,STACK,0x2315,2);put(m,STACK+2,RETURN);d,a=list(c.d),list(c.a)
    run('amiga',m,c,RETURN)
    assert list(c.d)==d and list(c.a[:7])==a[:7] and c.a[7]==STACK+6 and c.sr==0x2315

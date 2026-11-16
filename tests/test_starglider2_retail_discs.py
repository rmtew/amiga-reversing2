"""Retail radial queue and span contracts using original 68000 instructions.

Representative independent arithmetic/pixel oracles cover supplied states. They
are not a natural-playthrough, arbitrary-input safety or scanout claim.
"""
import ctypes,math,os
import pytest
from tests.test_starglider2_text_editor import state,run,put,get,APP,INPUT,STACK,RETURN
from test_starglider2_retail_input import program
from tests.test_starglider2_control_normalization import signed
from tests.test_starglider2_disc_radius_layers import word,appword,quotient,s32,emit
from tests.test_starglider2_disc_span_builder import circle_widths,accepted
pytestmark=pytest.mark.skipif(os.getenv('SGII_LINKED_FIXTURES')!='1',reason='catalogue-bound retail inputs')
OBJECT,RECORD,LIST=INPUT+0x400,INPUT+0x1000,INPUT+0x100
PRIMARY,SECONDARY,LAYER,FLAGS,DIRECTION=0x6bfa,0x6c22,0x6c4a,0x6c52,0x71b0
WORK,PACKET=0x431f4,0x653c

@pytest.fixture(params=('amiga','st'))
def original_image(request):return program(request.param)

@pytest.fixture
def memory(original_image):
 raw=original_image[0];m=(ctypes.c_uint8*0xa1000)();ctypes.memmove(ctypes.addressof(m)+4096,raw,len(raw));return m

@pytest.mark.parametrize('n',(0,1,1573,1574,65535,65536,65537,0x7fffffff,0xffffffff))
def test_original_root_boundaries_and_path_specific_register_restore(original_image, memory, n):
    m = memory
    cpu = state(m, 0x6b4a)
    cpu.d[0] = n
    cpu.d[1:5] = [305430528, 4275863551, 2779119615, 16842753]
    regs = list(cpu.d)
    addresses = list(cpu.a)
    expected = bytearray(m)
    run(original_image, m, cpu, {RETURN}, limit=1000)
    expected_d0 = 65536 if n == 65536 else math.isqrt(n)
    assert cpu.d[0] == expected_d0
    restored = [signed(v) & 4294967295 for v in regs[1:5]] if 1573 < n < 65536 else regs[1:5]
    assert list(cpu.d[1:5]) == restored and list(cpu.d[5:]) == regs[5:]
    assert list(cpu.a)[:7] == addresses[:7] and cpu.a[7] == STACK + 4
    expected[STACK - 16:STACK] = bytes(m[STACK - 16:STACK])
    assert bytes(m) == expected

@pytest.mark.parametrize('family,count',[(f,n)for f in((128,128,3,0,3,0,0,14),(129,128,0,0,3,0,0,14),(144,128,0,0,0,0,0,14),(145,0,0,0,3,0,0,14),(146,128,0,128,3,0,0,14),(147,128,0,0,3,0,0,14))for n in(0,92,93)])
def test_full_radial_producer_layers_and_failed_link_scratch_order(original_image, memory, family, count):
    kind, space, layer, expansion, station, ramp, atmosphere, shift = family
    m = memory
    m[OBJECT:OBJECT + 68] = b'\x00' * 68
    word(m, OBJECT, kind)
    put(m, OBJECT + 4, 20000000)
    put(m, OBJECT + 12, 20000000)
    put(m, OBJECT + 34, 100)
    x, y, z = (64, -32, 640)
    for off, value in zip([22, 24, 26], [x, y, z]):
        word(m, OBJECT + off, value)
    word(m, OBJECT + 44, shift)
    if kind == 146:
        m[OBJECT + 20] = 164
        m[OBJECT + 21] = 181
        m[OBJECT + 31] = expansion
    if kind == 147:
        word(m, OBJECT + 16, 32540)
    appword(m, 404, 159)
    appword(m, 406, 79)
    appword(m, 2040, count)
    appword(m, 2508, layer)
    appword(m, 2504, station)
    appword(m, 2506, ramp)
    m[APP + 1917] = space
    m[APP + 2999] = atmosphere
    m[DIRECTION] = 128
    put(m, APP + 116, RECORD)
    put(m, APP + 120, LIST)
    put(m, APP + 2484, 0)
    m[RECORD:RECORD + 100] = b'\xa5' * 100
    m[LIST:LIST + 64] = b'\xcc' * 64
    m[FLAGS:FLAGS + 20] = b'\xa5' * 20
    cpu = state(m, 0x680c)
    cpu.a[4] = OBJECT
    regs = list(cpu.d)
    addresses = list(cpu.a)
    expected = bytearray(m)
    put(expected, APP + 2042, PRIMARY)
    put(expected, APP + 2046, PRIMARY if kind == 128 else SECONDARY)
    if kind != 128:
        expected[DIRECTION] = 0
    expected[57669] = 152
    if kind == 144 and station == 0:
        expected[FLAGS + kind - 128] = 255
    else:
        colour = get(m, PRIMARY + 2 * (kind - 128), 2)
        if kind == 144:
            colour = station
        if kind == 146 and expansion & 128:
            colour = 164
        if kind == 147:
            colour = 32540
        px, py = (quotient(x * 128, z), quotient(y * 128, z))
        norm = math.isqrt(x * x + y * y + z * z)
        radius = 14400 // norm
        depth = z << shift >> 14
        for off, value in [(38, px), (40, py), (42, radius)]:
            word(expected, OBJECT + off, value)
        expected[57669] = 104
        records = [(depth, min(radius, 1999), colour, px + 159, py + 79)]
        if kind == 128:
            if layer >= 0:
                for i in range(layer, -1, -1):
                    records.append((32767 if i > 1 else depth + 1 + i, radius + i + 1, get(m, LAYER + 2 * i, 2), px + 159, py + 79))
        elif kind == 145 and (not space & 128):
            if ramp == 0 and (not atmosphere & 128):
                for i in [1, 0]:
                    records.append((norm + i + 1, radius + i + 1, get(m, LAYER + 2 * i, 2), px + 159, py + 79))
        elif kind == 146:
            records.append((depth + 1, radius * 2, 181 if expansion & 128 else 11, px + 159, py + 79))
        elif kind != 147:
            dx = -((radius >> 3) * px >> 7)
            dy = -((radius >> 3) * py >> 7)
            records.append((depth + 1, radius, get(m, SECONDARY + 2 * (kind - 128), 2), px + 159 + dx, py + 79 + dy))
        cursor, ref, n = (RECORD, LIST, count)
        for record in records:
            cursor, ref, n = emit(expected, cursor, ref, n, record)
        put(expected, APP + 116, cursor)
        put(expected, APP + 120, ref)
        appword(expected, 2040, n)
        expected[FLAGS + kind - 128] = 0
    run(original_image, m, cpu, {RETURN}, limit=15000)
    expected[STACK - 96:STACK + 4] = bytes(m[STACK - 96:STACK + 4])
    assert bytes(m) == expected
    assert list(cpu.d) == regs and list(cpu.a)[:7] == addresses[:7] and (cpu.a[7] == STACK + 4)

@pytest.mark.parametrize('radius,direction',((7,0),(8,128),(17,255),(32768,0),(65535,128)))
def test_secondary_disc_offsets_keep_word_shift_long_floor_and_direction_sign(original_image, memory, radius, direction):
    m = memory
    word(m, OBJECT, 129)
    word(m, OBJECT + 42, radius)
    word(m, OBJECT + 38, 13)
    word(m, OBJECT + 40, -15)
    appword(m, 404, 159)
    appword(m, 406, 79)
    appword(m, 2040, 0)
    put(m, APP + 116, RECORD + 10)
    put(m, APP + 120, LIST)
    put(m, APP + 2046, SECONDARY)
    word(m, RECORD, 65535)
    m[DIRECTION] = direction
    cpu = state(m, 0x6a48)
    cpu.a[4] = OBJECT
    cpu.a[1] = RECORD
    expected = bytearray(m)
    step = signed(radius) >> 3
    dx = step * 13 >> 7
    dy = step * -15 >> 7
    if not direction & 128:
        dx = -dx
        dy = -dy
    cursor, ref, count = emit(expected, RECORD + 10, LIST, 0, (0, radius, get(m, SECONDARY + 2, 2), 13 + 159 + dx, -15 + 79 + dy))
    put(expected, APP + 116, cursor)
    put(expected, APP + 120, ref)
    appword(expected, 2040, count)
    run(original_image, m, cpu, {0x6af8})
    expected[STACK - 4:STACK] = bytes(m[STACK - 4:STACK])
    assert bytes(m) == expected

def test_supplied_radial_entry_reaches_zero_divisor_at_norm_boundary(original_image, memory):
    m = memory
    m[OBJECT:OBJECT + 68] = b'\x00' * 68
    word(m, OBJECT, 128)
    word(m, OBJECT + 26, 256)
    word(m, OBJECT + 44, 14)
    put(m, OBJECT + 34, 100)
    put(m, APP + 116, RECORD)
    put(m, APP + 120, LIST)
    appword(m, 404, 159)
    appword(m, 406, 79)
    cpu = state(m, 0x680c)
    cpu.a[4] = OBJECT
    run(original_image, m, cpu, {0x6970}, limit=1000)
    assert cpu.d[0] == 65536 and cpu.d[0] & 65535 == 0 and (cpu.d[4] == 14400)
    assert original_image[0][0x5970:0x5972] == bytes.fromhex('89c0')
    assert get(m, RECORD, 2) == 256 and get(m, APP + 2040, 2) == 0

def generate(image, m, radius, x, y, colour=7):
    cpu = state(m, 0x633e)
    cpu.d[0] = radius & 65535
    cpu.d[1] = colour & 65535
    cpu.d[2] = x & 65535
    cpu.d[3] = y & 65535
    expected = bytearray(m)
    if not accepted(radius, x, y):
        run(image, m, cpu, {0x633c})
        assert bytes(m) == expected
        return (cpu, None)
    widths = circle_widths(radius)
    word(expected, WORK, colour)
    word(expected, WORK + 2, y - radius)
    for i, w in enumerate(widths):
        word(expected, WORK + 4 + 4 * i, max(x - w, 16))
        word(expected, WORK + 6 + 4 * i, min(x + w, 303))
    word(expected, WORK + 4 + 8 * radius, 65535)
    run(image, m, cpu, {0x6436}, limit=3000)
    assert bytes(m) == expected
    assert cpu.a[6] == WORK + 4 + 8 * radius
    return (cpu, widths)

@pytest.mark.parametrize('radius,x,y,colour',((1,160,79,7),(2,17,30,0),(12,302,128,0xf123),(16,0,79,7),(16,320,79,7),(5,160,0,7)))
def test_midpoint_spans_keep_symmetric_stores_x_clamps_and_exact_marker(original_image, memory, radius, x, y, colour):
    generate(original_image, memory, radius, x, y, colour)

@pytest.mark.parametrize('radius,y',((1,30),(2,29),(12,31),(50,0),(64,129),(12,127)))
def test_vertical_packet_header_rebase_and_terminal_marker_keep_original_offsets(original_image, memory, radius, y):
    m = memory
    cpu, widths = generate(original_image, m, radius, 160, y)
    if widths is None:
        return
    expected = bytearray(m)
    first = y - radius
    pointer = WORK
    marker = WORK + 4 + 8 * radius
    if first < 30:
        pointer = WORK + 4 * (30 - first) - 4
        word(expected, pointer, 7)
        word(expected, pointer + 2, 30)
        if marker <= pointer:
            run(original_image, m, cpu, {0x633c})
            assert bytes(m) == expected
            return
    if first > 128:
        run(original_image, m, cpu, {0x633c})
        assert bytes(m) == expected
        return
    excess = first + 2 * radius - 128
    if excess > 0:
        marker -= 4 * excess
        word(expected, marker, 65535)
    run(original_image, m, cpu, {0x64de})
    assert bytes(m) == expected
    assert cpu.a[0] == pointer and cpu.a[6] == marker

@pytest.mark.parametrize('x,radius,colour',((-5,24,0),(15,2,65535),(304,2,7),(320,24,7)))
def test_offscreen_center_trims_matching_prefix_and_suffix_rows(original_image, memory, x, radius, colour):
    m = memory
    cpu, widths = generate(original_image, m, radius, x, 79, colour)
    assert widths is not None
    first = next((i for i, w in enumerate(widths) if (x + w >= 16 if x < 16 else x - w <= 303)))
    expected = bytearray(m)
    pointer = WORK + 4 * first
    marker = WORK + 4 + 8 * radius - 4 * first
    word(expected, pointer, colour)
    word(expected, pointer + 2, 79 - radius + first)
    word(expected, marker, 65535)
    run(original_image, m, cpu, {0x64de}, limit=3000)
    assert bytes(m) == expected
    assert cpu.a[0] == pointer and cpu.a[6] == marker

@pytest.mark.parametrize('depths',([],[-32768],[32767,-32768],[-1,0,1],[0,0,1],[2,-1,2,32767,-32768]))
def test_disc_pointer_sort_is_descending_signed_and_retains_swap_tie_effect(original_image, memory, depths):
    from tests.test_starglider2_text_editor import STACK
    m = memory
    pointers = [INPUT + 512 + 16 * i for i in range(len(depths))]
    for i, (p, d) in enumerate(zip(pointers, depths)):
        put(m, INPUT + 4 * i, p)
        m[p:p + 16] = b'\xa5' * 16
        word(m, p, d)
    cpu = state(m, 0x62e0)
    cpu.a[2] = INPUT
    cpu.a[1] = INPUT + 4 * len(depths)
    expected = bytearray(m)
    run(original_image, m, cpu, {0x6314 if depths else 0x6336})
    actual = [get(m, INPUT + 4 * i) for i in range(len(depths))]
    assert sorted(actual) == sorted(pointers)
    assert [signed(get(m, p, 2)) for p in actual] == sorted(depths, reverse=True)
    if depths == [0, 0, 1]:
        assert actual == [pointers[2], pointers[1], pointers[0]]
    expected[INPUT:INPUT + 4 * len(depths)] = bytes(m[INPUT:INPUT + 4 * len(depths)])
    expected[STACK - 60:STACK] = bytes(m[STACK - 60:STACK])
    assert bytes(m) == expected

@pytest.mark.parametrize('radius,colour',((0,0),(1,15),(2000,32768),(32768,65535),(65535,1)))
def test_queue_record_unpack_sign_extends_words_and_masks_only_colour_low_word(original_image, memory, radius, colour):
    m = memory
    record = INPUT + 512
    put(m, INPUT, record)
    for i, v in enumerate([42405, radius, colour, 32768, 32767]):
        word(m, record + 2 * i, v)
    cpu = state(m, 0x631c)
    cpu.a[2] = INPUT
    expected = bytes(m)
    run(original_image, m, cpu, {0x632c})
    assert bytes(m) == expected
    assert list(cpu.d[:4]) == [signed(radius) & 4294967295, signed(colour) & 4294901760 | colour & 15, 4294934528, 32767]
    assert cpu.a[0] == record + 10 and cpu.a[2] == INPUT + 4

@pytest.mark.parametrize('count,linked',((0,True),(92,True),(93,False),(94,False),(65535,True)))
def test_append_counts_attempts_and_keeps_cursors_on_rejected_link(original_image,memory,count,linked):
 m=memory;put(m,APP+0x74,RECORD);put(m,APP+0x78,LIST);word(m,APP+0x7f8,count);put(m,LIST,0xa5a5a5a5)
 c=state(m,0x6b24);run(original_image,m,c,{RETURN})
 assert get(m,APP+0x7f8,2)==(count+1)&65535
 assert get(m,APP+0x74)==RECORD+(10 if linked else 0)and get(m,APP+0x78)==LIST+(4 if linked else 0)
 assert get(m,LIST)==(RECORD if linked else 0xa5a5a5a5)


from tests.test_starglider2_interleaved_color_kernels import kernels as earlier_image

def test_stored_disc_owners_have_exact_earlier_correspondence(earlier_image,original_image):
 old=earlier_image[0];new=original_image[0]
 for start,end in ((0x6be2,0x6c0a),(0x6c0a,0x6c32),(0x6c32,0x6c3a),(0x6c3a,0x6c58),(0x6c58,0x7018),(0x7018,0x7198),(0x7198,0x7199)):
  assert old[start-4096:end-4096]==new[start+24-4096:end+24-4096]
 # Complete stored arenas: normal append admission is separately qualified.
 assert new[0x6c52-4096:0x71b4-4096]==bytes(1378)


def test_actual_amiga_radial_producer_sorter_and_span_reader_reach_pixel_oracle():
 from test_starglider2_retail_scene_raster import machine
 from tests.test_starglider2_text_editor import FB
 from tests import test_starglider2_planar_span_reader as planar
 platform,m,v=machine('amiga');image=program(platform)
 m[OBJECT:OBJECT+68]=bytes(68);word(m,OBJECT,147);word(m,OBJECT+16,7);put(m,OBJECT+34,100);word(m,OBJECT+44,14)
 for off,value in ((22,64),(24,-32),(26,640)):word(m,OBJECT+off,value)
 appword(m,0x194,159);appword(m,0x196,79);appword(m,0x7f8,0);m[APP+0x77d]=128
 put(m,APP+0x74,RECORD);put(m,APP+0x78,LIST);put(m,APP,FB)
 c=state(m,0x680c);c.a[4]=OBJECT;run(image,m,c,{RETURN})
 radius=14400//math.isqrt(64*64+32*32+640*640);x,y=171,73
 assert [signed(get(m,RECORD+2*i,2))for i in range(5)]==[640,radius,7,x,y]
 put(m,LIST+4,0xffffffff);m[FB-16:FB+0x8010]=b'\xa5'*0x8020
 rows=[(max(16,x-w),min(303,x+w))for w in circle_widths(radius)]
 expected=planar.expected_memory(v,[(7,y-radius,rows)])
 c=state(m,0x62e0);c.a[2]=LIST;c.a[1]=LIST+4;run(image,m,c,{RETURN})
 assert bytes(m[FB-16:FB+0x8010])==bytes(expected[FB-16:FB+0x8010])
 assert get(m,PACKET)==WORK and c.a[7]==STACK+4

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='source build uses external vasm')
def test_compiled_disc_names_and_compact_zero_arenas(tmp_path):
 import struct,subprocess
 from pathlib import Path
 directory=Path(__file__).resolve().parents[1]/'targets/starglider2_retail/rendered';source=(directory/'retail-shared.s').read_text()
 symbols={'sort_and_draw_disc_queue':0x62e0,'draw_clipped_disc_spans':0x633e,'queue_nonmodel_disc_object':0x680c,'compute_radial_norm_root_word':0x6b4a,'disc_primary_colours':PRIMARY,'disc_secondary_colours':SECONDARY,'disc_layer_colours':LAYER,'nonmodel_projection_rejected_flags':FLAGS,'disc_command_records':0x6c70,'disc_command_references':0x7030,'disc_offset_direction_flag':DIRECTION,'SG2DiscCommand_radius':2,'SG2DiscCommand_colour_index':4,'SG2DiscCommand_screen_x':6,'SG2DiscCommand_screen_y':8,'SG2DiscWorkspace_disc_queue_attempt_count':0x7f8,'SG2RadialProjectionActor_projected_radius':42}
 for name in ('disc_command_records','disc_command_references'):
  body=source.split(name+':',1)[1].strip().splitlines()[0];assert body.strip().startswith('dcb.'),body
 assert 'SG2DiscCommand_colour_index(a1)'in source and 'SG2DiscWorkspace_disc_record_write_cursor(a6)'in source
 asm=tmp_path/'symbols.s';out=tmp_path/'symbols.bin';asm.write_text((directory/'retail-st.s').read_text()+'\n dc.l '+','.join(symbols)+'\n')
 r=subprocess.run([os.environ['SGII_RETAIL_VASM'],'-quiet','-Fbin','-m68000','-no-opt','-I'+str(directory),'-o',str(out),str(asm)],cwd=directory,capture_output=True,text=True)
 assert r.returncode==0,r.stdout+r.stderr
 raw=out.read_bytes();size=4*len(symbols)
 assert raw[:-size]==program('st')[0]and struct.unpack('>'+str(len(symbols))+'I',raw[-size:])==tuple(symbols.values())

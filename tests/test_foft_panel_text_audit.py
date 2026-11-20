"""Source text needs both bounded offsets and the separately audited atlas."""

from pathlib import Path

import pytest

from tools.foft_render_contract_audit import panel_text_receipt

FONT = Path(__file__).resolve().parents[1]/'targets/amiga_raw_foft/assets/dataGraphics380_1.bin'
ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ -'


def sample():
    payload = bytearray(0x1F0EE-0x800)
    cursor = 0x1000

    def stream(text):
        nonlocal cursor
        pointer = cursor
        for char in text:
            payload[cursor-0x800:cursor-0x800+2] = (5*ALPHABET.index(char)).to_bytes(2, 'big')
            cursor += 2
        return pointer, len(text)

    for i, (row, text) in enumerate([(36, 'NAME'), (43, 'STARPORT TYPE'), (50, 'DIAMETER'),
        (57, 'ATMOSPHERE'), (64, 'FREE WATER'), (71, 'POPULATION'), (78, 'GOVERNMENT'),
        (92, 'LAW LEVEL'), (85, 'TECH INDEX')]):
        p, n = stream(text); at = 0x1ED96-0x800+10*i
        payload[at:at+4] = p.to_bytes(4, 'big')
        payload[at+6:at+8] = row.to_bytes(2, 'big')
        payload[at+8:at+10] = n.to_bytes(2, 'big')
    for base, count, text in [(0x1F06A, 6, 'GOOD'), (0x1EEFE, 14, 'TRACE'), (0x1EB64, 16, 'FLAG')]:
        for i in range(count):
            p, n = stream(text); at = base-0x800+8*i
            payload[at:at+4] = p.to_bytes(4, 'big')
            payload[at+4:at+8] = n.to_bytes(4, 'big')
    for i, (row, text) in enumerate([(50, 'MILES'), (64, 'PERCENT')]):
        p, n = stream(text); at = 0x1EDF4-0x800+10*i
        payload[at:at+4] = p.to_bytes(4, 'big')
        payload[at+6:at+8] = row.to_bytes(2, 'big')
        payload[at+8:at+10] = n.to_bytes(2, 'big')
    font = FONT.read_bytes()
    words = [int.from_bytes(font[i:i+2], 'big') for i in range(0, 380, 2)]
    for phase, address in [(0, 0xBB2E), (1, 0xB9B2), (2, 0xB836), (3, 0xB6BA)]:
        payload[address-0x800:address-0x800+380] = b''.join(
            (word >> (4*phase)).to_bytes(2, 'big') for word in words)
    return payload, font


def test_text_receipt_pins_atlas_and_retains_unobserved_visibility():
    payload, font = sample()
    result = panel_text_receipt(payload, font)
    assert {'display_row': 43, 'text': 'STARPORT TYPE'} in result['labels']
    assert {'display_row': 57, 'text': 'ATMOSPHERE'} in result['labels']
    assert result['initial_texts']['starport_type'] == ['GOOD']*6
    assert result['runtime_visibility'] == 'not observed'


@pytest.mark.parametrize('change', ['font', 'short_font', 'short_payload', 'pointer',
                                    'zero_count', 'offset', 'slot', 'phase'])
def test_wrong_atlas_or_unbounded_or_unaudited_text_is_rejected(change):
    payload, font = sample()
    if change == 'font':
        font = bytes([font[0] ^ 1])+font[1:]
    elif change == 'short_font':
        font = font[:-1]
    elif change == 'short_payload':
        payload = payload[:-1]
    elif change == 'phase':
        payload[0xB836-0x800] ^= 1
    elif change == 'pointer':
        at = 0x1ED96-0x800
        payload[at:at+4] = (0x1001).to_bytes(4, 'big')
    elif change == 'zero_count':
        at = 0x1ED96-0x800+8
        payload[at:at+2] = bytes(2)
    else:
        payload[0x800:0x802] = (51 if change == 'offset' else 190).to_bytes(2, 'big')
    with pytest.raises(ValueError, match='panel font|panel glyph|panel text'):
        panel_text_receipt(payload, font)

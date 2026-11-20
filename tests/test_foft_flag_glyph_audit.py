"""Bounded initial glyph descriptors do not imply mutable or runtime closure."""

from copy import deepcopy

import pytest

from tools.foft_render_contract_audit import flag_glyph_contract


def sample():
    payload = bytearray(0x1ED96-0x800)
    cursor = 0x1EBE4
    for i in range(16):
        count = 13 if i < 15 else 22
        at = 0x1EB64-0x800+8*i
        payload[at:at+4] = cursor.to_bytes(4, 'big')
        payload[at+4:at+8] = count.to_bytes(4, 'big')
        cursor += 2*count

    def reg(name, width=2):
        return {'memory': False, 'direct_register': name, 'width_bytes': width}

    rows = []

    def put(pc, op, operands, evidence=()):
        rows.append({'source_offset': pc-0x800, 'mnemonic': op,
            'provenance': 'accepted_instruction', 'operand_facts': operands,
            'address_evidence': list(evidence)})

    put(0x1EAD2, 'clr', [reg('D7')])
    for pc, step, name in [(0x1EB16, 1, 'D7'), (0x1EB18, 8, 'A4'), (0x1EB1A, 16, 'D7')]:
        put(pc, 'cmp' if pc == 0x1EB1A else 'addq',
            [{'immediate_value': step}, reg(name)])
    for pc, op, offset, name in [(0x1EADE, 'movea', 0, 'A5'), (0x1EAE0, 'move', 4, 'D6')]:
        put(pc, op, [{'memory': True, 'base_register': 'A4', 'indexed': False,
            'displacement_known': True, 'displacement': offset, 'ea_update': 0,
            'width_bytes': 4}, reg(name, 4)])
    put(0x1EAEC, 'jsr', [{'memory': True, 'width_bytes': 4}],
        [{'operand_index': 0, 'has_address': True, 'address': 0x1B0E2}])
    return payload, rows


def test_counted_initial_descriptors_preserve_source_spans_and_runtime_boundary():
    payload, rows = sample()
    result = flag_glyph_contract(payload, rows)
    assert len(result['initial_streams']) == 16
    assert sum(s['words'] for s in result['initial_streams']) == 217
    assert not result['mutable_contents_or_alias_closure']
    assert result['runtime_visibility'] == 'not observed'


@pytest.mark.parametrize('change', ['count', 'stride', 'width', 'field', 'call',
                                    'unaccepted', 'missing_row', 'short_bytes',
                                    'zero_count', 'wide_count', 'interior_pointer', 'extent'])
def test_incomplete_or_inconsistent_facts_cannot_certify_initial_span(change):
    payload, rows = sample()
    rows = deepcopy(rows)
    lookup = {r['source_offset']+0x800: r for r in rows}
    if change == 'count':
        lookup[0x1EB1A]['operand_facts'][0]['immediate_value'] = 15
    elif change == 'stride':
        lookup[0x1EB18]['operand_facts'][0]['immediate_value'] = 10
    elif change == 'width':
        lookup[0x1EAE0]['operand_facts'][0]['width_bytes'] = 2
    elif change == 'field':
        lookup[0x1EADE]['operand_facts'][0]['displacement'] = 2
    elif change == 'call':
        lookup[0x1EAEC]['address_evidence'][0]['address'] += 2
    elif change == 'unaccepted':
        lookup[0x1EAE0]['provenance'] = 'candidate'
    elif change == 'missing_row':
        rows.remove(lookup[0x1EAE0])
    elif change == 'short_bytes':
        payload = payload[:-1]
    else:
        at = 0x1EB64-0x800
        if change in {'zero_count', 'wide_count'}:
            payload[at+4:at+8] = (0 if change == 'zero_count' else 65536).to_bytes(4, 'big')
        elif change == 'interior_pointer':
            payload[at:at+4] = (0x1EBE6).to_bytes(4, 'big')
        else:
            payload[at+8*15+4:at+8*16] = (23).to_bytes(4, 'big')
    with pytest.raises(ValueError, match='flag glyph|operand'):
        flag_glyph_contract(payload, rows)

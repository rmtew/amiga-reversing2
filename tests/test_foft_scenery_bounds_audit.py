"""Initial scalar headers remain distinct from code and callback effects."""

from copy import deepcopy

import pytest

from tools.foft_render_contract_audit import scenery_bound_headers


def sample():
    payload = bytearray(0x49826)
    targets = [0x12010+32*i for i in range(8)]
    for i, target in enumerate([*targets, targets[0]]):
        at = 0x49802+4*i
        payload[at:at+4] = target.to_bytes(4, 'big')
    for i, target in enumerate(targets):
        at = target-10-0x800
        payload[at:at+2] = (i+1).to_bytes(2, 'big')
        payload[at+2:at+4] = (i+2).to_bytes(2, 'big')
    rows = []

    def reg():
        return {'memory': False, 'direct_register': 'D2', 'width_bytes': 2}

    for pc, offset, double in [(0x4AE62, -10, 0x4AE66), (0x4AE6C, -8, 0x4AE70)]:
        rows.append({'source_offset': pc-0x800, 'size': 4, 'provenance': 'accepted_instruction',
            'mnemonic': 'move', 'operand_facts': [{'memory': True, 'base_register': 'A6',
                'indexed': False, 'displacement_known': True, 'displacement': offset,
                'width_bytes': 2, 'ea_update': 0}, reg()]})
        rows.append({'source_offset': double-0x800, 'size': 2, 'provenance': 'accepted_instruction',
            'mnemonic': 'add', 'operand_facts': [reg(), reg()]})
    return payload, rows


def test_eight_initial_bounds_preserve_shared_cell_without_code_admission():
    payload, rows = sample()
    result = scenery_bound_headers(payload, rows)
    assert len(result['unique_headers']) == 8
    assert result['typed_bytes'] == 32
    assert result['unique_headers'][0]['initial_signed_words'] == [1, 2]
    assert not result['code_admission_or_callback_effects_proved']
    assert not result['other_prefix_bytes_or_lifetime_typed']


@pytest.mark.parametrize('change', ['offset', 'width', 'scale_register', 'unaccepted',
                                    'missing', 'short_bytes', 'sharing', 'odd_pointer',
                                    'out_of_bounds', 'header_overlap', 'instruction_overlap'])
def test_incompatible_headers_and_unproved_readers_are_rejected(change):
    payload, rows = sample(); rows = deepcopy(rows)
    if change == 'offset':
        rows[0]['operand_facts'][0]['displacement'] = -6
    elif change == 'width':
        rows[2]['operand_facts'][0]['width_bytes'] = 4
    elif change == 'scale_register':
        rows[1]['operand_facts'][1]['direct_register'] = 'D3'
    elif change == 'unaccepted':
        rows[0]['provenance'] = 'candidate'
    elif change == 'missing':
        rows.pop()
    elif change == 'short_bytes':
        payload = payload[:-1]
    elif change == 'sharing':
        payload[0x49822:0x49826] = (0x14000).to_bytes(4, 'big')
    elif change == 'header_overlap':
        payload[0x49806:0x4980A] = (0x12012).to_bytes(4, 'big')
    elif change in {'odd_pointer', 'out_of_bounds'}:
        value = 0x12011 if change == 'odd_pointer' else 0
        payload[0x49806:0x4980A] = value.to_bytes(4, 'big')
    else:
        rows.append({'source_offset': 0x12006-0x800, 'size': 2,
                     'provenance': 'accepted_instruction'})
    with pytest.raises(ValueError, match='scenery bounds|operand'):
        scenery_bound_headers(payload, rows)

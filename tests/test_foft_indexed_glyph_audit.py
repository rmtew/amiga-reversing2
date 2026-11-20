"""Shared initial streams retain one extent; readers retain LONG field widths."""

from copy import deepcopy

import pytest

from tools.foft_render_contract_audit import indexed_panel_glyph_contract


def sample():
    payload = bytearray(0x1F0EE-0x800)
    for base, start, counts in [(0x1F06A, 0x1F0A2, [6]*5+[8]),
                                 (0x1EEFE, 0x1EF6E, [9]*12+[18])]:
        cursor, entries = start, []
        for count in counts:
            entries.append((cursor, count)); cursor += 2*count
        if base == 0x1EEFE:
            entries.append(entries[-1])
        for i, (pointer, count) in enumerate(entries):
            at = base-0x800+8*i
            payload[at:at+4] = pointer.to_bytes(4, 'big')
            payload[at+4:at+8] = count.to_bytes(4, 'big')

    def reg(name, width=2):
        return {'memory': False, 'direct_register': name, 'width_bytes': width}

    rows = []

    def put(pc, op, operands, evidence=()):
        rows.append({'source_offset': pc-0x800, 'mnemonic': op,
            'provenance': 'accepted_instruction', 'operand_facts': operands,
            'address_evidence': list(evidence)})

    for load, base in [(0x1E970, 0x1F06A), (0x1E9C0, 0x1EEFE)]:
        for step in [4, 6, 8]:
            put(load+step, 'add', [reg('D0'), reg('D0')])
        put(load+10, 'lea', [{'pc_relative': True, 'displacement_known': True,
            'displacement': base-(load+12)}, reg('A5', 4)])
        put(load+14, 'adda', [reg('D0'), reg('A5')])
        for step, name, offset, dest in [(16, 'move', 4, 'D6'), (20, 'movea', 0, 'A5')]:
            put(load+step, name, [{'memory': True, 'base_register': 'A5',
                'indexed': False, 'displacement_known': True, 'displacement': offset,
                'ea_update': 0, 'width_bytes': 4}, reg(dest, 4)])
        put(load+24, 'moveq', [{'immediate_value': 43 if load == 0x1E970 else 57}, reg('D4', 4)])
        put(load+26, 'jsr', [{'memory': True, 'width_bytes': 4}],
            [{'operand_index': 0, 'has_address': True, 'address': 0x1B0E2}])
    return payload, rows


def test_indexed_views_preserve_exact_shared_stream_and_untouched_extra_entry():
    payload, rows = sample()
    result = indexed_panel_glyph_contract(payload, rows)
    first, second = result['tables']
    assert (first['records'], first['unique_streams'], first['glyph_words']) == (6, 6, 38)
    assert (second['records'], second['unique_streams'], second['glyph_words']) == (14, 13, 126)
    assert second['initial_entries'][12]['runtime'] == second['initial_entries'][13]['runtime']
    assert result['extra_A_descriptor_bytes_not_typed'] == 8
    assert not any(t['all_writer_or_live_bound_proved'] for t in result['tables'])


@pytest.mark.parametrize('change', ['missing_reader', 'width', 'stride', 'source',
                                    'call', 'display_row', 'unaccepted', 'interior', 'shared_extent',
                                    'wide_count', 'missing_bytes'])
def test_different_facts_or_conflicting_source_spans_fail(change):
    payload, rows = sample(); rows = deepcopy(rows)
    lookup = {r['source_offset']+0x800: r for r in rows}
    if change == 'missing_reader':
        rows.remove(lookup[0x1E980])
    elif change == 'width':
        lookup[0x1E9D0]['operand_facts'][0]['width_bytes'] = 2
    elif change == 'stride':
        lookup[0x1E974]['operand_facts'][0]['direct_register'] = 'D1'
    elif change == 'source':
        lookup[0x1E9CA]['operand_facts'][0]['displacement'] += 8
    elif change == 'call':
        lookup[0x1E9DA]['address_evidence'][0]['address'] += 2
    elif change == 'display_row':
        lookup[0x1E9D8]['operand_facts'][0]['immediate_value'] = 43
    elif change == 'unaccepted':
        lookup[0x1E984]['provenance'] = 'candidate'
    elif change == 'interior':
        at = 0x1F06A-0x800
        payload[at:at+4] = (0x1F0A4).to_bytes(4, 'big')
    elif change == 'shared_extent':
        at = 0x1EEFE-0x800+13*8+4
        payload[at:at+4] = (17).to_bytes(4, 'big')
    elif change == 'wide_count':
        at = 0x1F06A-0x800+4
        payload[at:at+4] = (65536).to_bytes(4, 'big')
    else:
        payload = payload[:-1]
    with pytest.raises(ValueError, match='indexed glyph|operand'):
        indexed_panel_glyph_contract(payload, rows)

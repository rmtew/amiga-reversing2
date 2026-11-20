"""Native fact receipt checks preserve the distinct original hit operators."""

from copy import deepcopy

import pytest

from tools.foft_render_contract_audit import hit_record_contract


def sample():
    rows = []

    def reg(name, width=2):
        return {'direct_register': name, 'memory': False, 'width_bytes': width}

    def imm(value):
        return {'immediate_value': value, 'memory': False, 'width_bytes': 2}

    def mem(base, offset):
        return {'memory': True, 'base_register': base, 'indexed': False,
                'displacement_known': True, 'displacement': offset, 'ea_update': 0,
                'width_bytes': 2}

    def put(pc, op, operands, *, size=2, address=None):
        if address is not None:
            operands[0]['absolute_address'] = address
        rows.append({'source_offset': pc-0x800, 'size': size, 'mnemonic': op,
            'provenance': 'accepted_instruction', 'operand_facts': operands,
            'address_evidence': [] if address is None else [
                {'operand_index': 0, 'has_address': True, 'address': address}]})

    for start, last in [(0x2DBFC, 'A6'), (0x2E41A, 'A0')]:
        for i, base, dest in [(0, 0x4ED18, 'A6'), (8, 0x4E818, 'A0'), (16, 0x4ED18, 'A6')]:
            put(start+i, 'lea', [{'memory': True, 'width_bytes': 4}, reg(dest, 4)],
                size=6, address=base)
        for i, dest in [(6, 'A6'), (14, 'A0'), (22, last)]:
            put(start+i, 'adda', [reg('D5'), reg(dest)])
    for pc, op, source in [(0x2D898, 'add', reg('D0')), (0x2DC58, 'asl', imm(2)),
                           (0x2E476, 'asl', imm(4)), (0x2E834, 'asl', imm(5))]:
        put(pc, op, [source, reg('D0')])
    for first, second, reserve in [(0x2D8A6, 0x2D89E, 0x2D8BA),
                                    (0x2DC66, 0x2DC5E, 0x2DC7A),
                                    (0x2E484, 0x2E47C, 0x2E498)]:
        for pc, offset in [(first, 0), (second, 2), (reserve, 6)]:
            put(pc, 'sub', [reg('D0'), mem('A6', offset)])
    for load, store, clear, offset in [(0x2E83C, 0x2E846, 0x2E844, 0),
                                      (0x2E84E, 0x2E85A, 0x2E858, 2)]:
        put(load, 'move', [mem('A0', offset), reg('D2')])
        put(store, 'move', [reg('D2'), mem('A0', offset)])
        put(clear, 'clr', [reg('D2')])
    put(0x2E85E, 'add', [reg('D3'), mem('A0', 6)])
    for pc, offset, amount in [(0x2E986, 2, 100), (0x2E98C, 0, 100), (0x2E9AA, 6, 50)]:
        put(pc, 'subi', [imm(amount), mem('A6', offset)])
    put(0x2B27A, 'mulu', [imm(50), reg('D0')])
    put(0x2B27E, 'sub', [reg('D0'), mem('A6', 0)])
    for pc, offset, value in [(0x2A1B8, 4, 10), (0x2A1C4, 8, 256), (0x2A1CA, 10, 4096),
                              (0x2A938, 4, 100), (0x2A944, 8, 256), (0x2A94A, 10, 4096),
                              (0x2A9B0, 4, 1), (0x2A9BC, 8, 6), (0x2A9C2, 10, 0)]:
        put(pc, 'move', [imm(value), mem('A3', offset)])
    return sorted(rows, key=lambda r: r['source_offset'])


def test_distinct_source_setups_and_reserve_operators_remain_distinct():
    contract = hit_record_contract(sample())
    assert [(x['action_offset_copies'], x['state_offset_copies'])
            for x in contract['setups']] == [(1, 1), (0, 2)]
    assert [x['word_scale'] for x in contract['direct_arms']] == [2, 4, 16]
    assert contract['fusion_reserve_operator'] == 'ADD.W D3'
    assert len(contract['direct_base_leas']) == 4
    assert len(contract['initialized_neutral_words']) == 9
    assert not contract['all_aliases_or_writers_closed']
    assert not contract['runtime_reachability_or_visible_result_proved']


@pytest.mark.parametrize('change', ['plasma_register', 'scale', 'reserve_register',
                                    'pool_offset', 'impact_amount', 'initializer', 'model_scale',
                                    'unaccepted', 'gap'])
def test_different_or_incomplete_source_facts_cannot_certify_contract(change):
    rows = deepcopy(sample())
    lookup = {r['source_offset']+0x800: r for r in rows}
    if change == 'plasma_register':
        lookup[0x2E430]['operand_facts'][1]['direct_register'] = 'A6'
    elif change == 'scale':
        lookup[0x2DC58]['operand_facts'][0]['immediate_value'] = 3
    elif change == 'reserve_register':
        lookup[0x2E85E]['operand_facts'][0]['direct_register'] = 'D0'
    elif change == 'pool_offset':
        lookup[0x2D89E]['operand_facts'][1]['displacement'] = 4
    elif change == 'impact_amount':
        lookup[0x2E9AA]['operand_facts'][0]['immediate_value'] = 100
    elif change == 'initializer':
        lookup[0x2A938]['operand_facts'][1]['width_bytes'] = 4
    elif change == 'model_scale':
        lookup[0x2B27A]['operand_facts'][0]['immediate_value'] = 100
    elif change == 'unaccepted':
        lookup[0x2E484]['provenance'] = 'candidate'
    else:
        rows.remove(lookup[0x2E422])
    with pytest.raises(ValueError, match="hit record|contract window|operand"):
        hit_record_contract(rows)

"""Explicit effects are checked separately from reviewed entry/branch dominance."""

from copy import deepcopy

import pytest

from tools.foft_render_contract_audit import panel_mask_inventory


def sample():
    rows = {pc: {'source_offset': pc-0x800, 'size': 2, 'mnemonic': 'nop',
                 'provenance': 'accepted_instruction', 'operand_facts': [], 'address_evidence': []}
            for start, end in [(0x1FA32, 0x1FC86), (0x1B436, 0x1B460)]
            for pc in range(start, end, 2)}

    def reg(name, width=2, access='register_write'):
        return {'memory': False, 'direct_register': name, 'width_bytes': width, 'access': access}

    def put(pc, size, op, facts, evidence=()):
        for following in range(pc+2, pc+size, 2):
            del rows[following]
        rows[pc].update(size=size, mnemonic=op, operand_facts=facts, address_evidence=list(evidence))

    put(0x1FA32, 2, 'clr', [reg('D6')])
    put(0x1FA34, 6, 'jsr', [{'memory': True, 'width_bytes': 4}],
        [{'operand_index': 0, 'has_address': True, 'address': 0x1B436}])
    for pc, name, value in [(0x1FA58, 'bset', 0), (0x1FA5C, 'bset', 14),
                             (0x1FA66, 'bclr', 0), (0x1FB1E, 'andi', 0x7FFF)]:
        put(pc, 4, name, [{'immediate_value': value}, reg('D6', 2 if name == 'andi' else 4)])
    put(0x1FC80, 6, 'move', [reg('D6', access='register_read'),
        {'memory': True, 'width_bytes': 2}],
        [{'operand_index': 1, 'has_address': True, 'address': 0x1FD62}])
    put(0x1B45E, 2, 'rts', [])
    return sorted(rows.values(), key=lambda r: r['source_offset'])


def test_mask_inventory_keeps_conditional_source_proof_distinct_from_runtime():
    result = panel_mask_inventory(sample())
    assert result['bset_bits'] == [0, 14]
    assert result['helper_d6_preserved']
    assert result['bit15_clear_on_reviewed_ordinary_producer']
    assert result['entry_and_branch_dominance_review'] == 'foft-panel-flag-glyphs.md'
    assert not result['all_writers_or_runtime_visibility_proved']


@pytest.mark.parametrize('change', ['bit15', 'wide_mask', 'explicit_clobber', 'helper_clobber',
                                    'unknown_call', 'implicit_effect', 'missing', 'unaccepted',
                                    'wrong_store', 'wrong_clear', 'helper_implicit', 'missing_helper'])
def test_changed_effects_or_incomplete_source_cannot_support_inventory(change):
    rows = deepcopy(sample()); lookup = {r['source_offset']+0x800: r for r in rows}
    if change == 'bit15':
        lookup[0x1FA5C]['operand_facts'][0]['immediate_value'] = 15
    elif change == 'wide_mask':
        lookup[0x1FB1E]['operand_facts'][1]['width_bytes'] = 4
    elif change in {'explicit_clobber', 'helper_clobber'}:
        row = lookup[0x1FA62 if change == 'explicit_clobber' else 0x1B43C]
        row['mnemonic'] = 'move'
        row['operand_facts'] = [
            {'memory': False, 'direct_register': 'D0', 'width_bytes': 2, 'access': 'register_read'},
            {'memory': False, 'direct_register': 'D6', 'width_bytes': 2, 'access': 'register_write'}]
    elif change == 'unknown_call':
        lookup[0x1FA34]['address_evidence'][0]['address'] += 2
    elif change == 'implicit_effect':
        lookup[0x1FA62]['mnemonic'] = 'trap'
    elif change == 'missing':
        rows.remove(lookup[0x1FA62])
    elif change == 'unaccepted':
        lookup[0x1FA62]['provenance'] = 'candidate'
    elif change == 'wrong_store':
        lookup[0x1FC80]['address_evidence'][0]['address'] += 2
    elif change == 'wrong_clear':
        lookup[0x1FA32]['operand_facts'][0]['direct_register'] = 'D5'
    elif change == 'helper_implicit':
        lookup[0x1B43C]['mnemonic'] = 'trap'
    else:
        rows.remove(lookup[0x1B43C])
    with pytest.raises(ValueError, match='panel mask|operand|contract window'):
        panel_mask_inventory(rows)

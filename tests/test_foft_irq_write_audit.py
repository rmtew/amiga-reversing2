"""Source-domain checks fail closed; no original game bytes are test inputs."""
from copy import deepcopy

import pytest

from tools.foft_irq_write_audit import acknowledge, collect, keyboard_alias_band


def sample():
    start = 0x2000
    names = ['move', 'move', 'andi', 'and', 'move', 'move', 'lsr', 'move', 'move', 'rte']
    sizes = [2, 6, 4, 6, 6, 6, 2, 6, 2, 2]
    def reg():
        return {'memory': False, 'direct_register': 'D0'}
    def memory(access, *, base=None, address=None, update=0):
        return {'memory': True, 'access': access, 'width_bytes': 2, 'base_register': base,
                'absolute_address': address, 'displacement': 0, 'displacement_known': True,
                'ea_update': update, 'indexed': False, 'bulk_transfer': False}
    facts = [[reg(), memory('memory_write', base='A7', update=2)],
             [memory('memory_read', address=0xDFF01E), reg()],
             [{'immediate_value': 0x780}, reg()],
             [memory('memory_read', address=0xDFF01C), reg()],
             [reg(), memory('memory_write', address=0xDFF09A)],
             [reg(), memory('memory_write', address=0xDFF09C)],
             [{'immediate_value': 7}, reg()],
             [reg(), memory('memory_write', address=0xDFF096)],
             [memory('memory_read', base='A7', update=1), reg()], []]
    rows = []
    cursor = start
    for name, size, operands in zip(names, sizes, facts, strict=True):
        rows.append({'source_offset': cursor - 0x800, 'provenance': 'accepted_instruction',
                     'mnemonic': name, 'size': size, 'operand_facts': operands})
        cursor += size
    return rows


def test_audio_acknowledge_only_claims_non_stack_component():
    proof = acknowledge(sample(), 0x2000)
    assert proof['accepted_instructions'] == 10
    assert proof['non_stack_ram_writes'] == []
    assert not proof['stack_lifetime_or_alias_proved']


@pytest.mark.parametrize('change', ['ram', 'width', 'extra', 'unaccepted', 'register', 'mask', 'gap'])
def test_audio_acknowledge_rejects_changed_native_contract(change):
    rows = deepcopy(sample())
    if change == 'ram': rows[4]['operand_facts'][1]['absolute_address'] = 0xE81C
    elif change == 'width': rows[4]['operand_facts'][1]['width_bytes'] = 4
    elif change == 'extra': rows[9]['operand_facts'].append(rows[4]['operand_facts'][1])
    elif change == 'unaccepted': rows[0]['provenance'] = 'raw_data'
    elif change == 'register': rows[8]['operand_facts'][1]['direct_register'] = 'A0'
    elif change == 'mask': rows[2]['operand_facts'][0]['immediate_value'] = 1
    elif change == 'gap': rows[2]['source_offset'] += 2
    with pytest.raises(ValueError, match="differ|unexpected|accepted|extent"): acknowledge(rows, 0x2000)


def test_keyboard_initial_domain_is_distinct_from_current_mutable_domain():
    assert keyboard_alias_band(range(128)) == [0x102F6, 0x103F6]
    assert keyboard_alias_band([0]) == [0x102F6, 0x102F8]
    assert keyboard_alias_band() == [0x82F6, 0x182F6]
    assert keyboard_alias_band([0x4000, 0xBFFF]) == [0x82F6, 0x182F6]


@pytest.mark.parametrize('values', [[], [-1], [65536], [1.5]])
def test_keyboard_domain_requires_word_values(values):
    with pytest.raises(ValueError, match="WORD|empty"): keyboard_alias_band(values)


def test_member_check_rejects_missing_or_wrong_bytes_before_source_proof():
    with pytest.raises(ValueError, match='identity'): collect([], b'')
    with pytest.raises(ValueError, match='identity'): collect([], b'\0' * 489472)


def test_direct_write_inventory_keeps_bulk_and_indirect_domains_open():
    from tools.foft_irq_write_audit import direct_write_inventory
    def row(offset, **operand):
        return {'source_offset': offset, 'operand_facts': [
            {'access': 'memory_write', 'width_bytes': 2, **operand}]}
    rows = [row(0, absolute_address=0x4E726),
            row(2, absolute_address=0x4A000, width_bytes=4),
            row(4, base_register='A0', displacement=6),
            row(6, absolute_address=0x4A002, bulk_transfer=True),
            row(8, absolute_address=0x4A026)]
    proof = direct_write_inventory(rows)
    assert proof['direct_nonbulk_operands'] == 3
    assert proof['other_write_operands'] == 2
    assert [r['runtime'] for r in proof['direct_intersections']['scenery_callback_cells']] == [0x802]
    assert [r['runtime'] for r in proof['direct_intersections']['draw_count_word']] == [0x800]
    assert not proof['whole_memory_alias_closure']


def graph_sample():
    blocks = [{'start_offset': 0, 'end_offset': 2, 'edge_start': 0, 'edge_count': 2},
              {'start_offset': 2, 'end_offset': 4, 'edge_start': 2, 'edge_count': 1},
              {'start_offset': 4, 'end_offset': 6, 'edge_start': 3, 'edge_count': 1}]
    edges = [{'source_block_index': 0, 'source_offset': 0, 'target_block_index': 1, 'kind': 3},
             {'source_block_index': 0, 'source_offset': 0, 'target_block_index': 2, 'kind': 0},
             {'source_block_index': 1, 'source_offset': 2, 'target_block_index': -1, 'kind': 5},
             {'source_block_index': 2, 'source_offset': 4, 'target_block_index': -1, 'kind': 3}]
    rows = [{'source_offset': i, 'operand_facts': [{'access': 'memory_write',
             'width_bytes': 2, 'absolute_address': 0x4E726 if i == 2 else 0x2000}]}
            for i in [0, 2, 4]]
    return rows, {'blocks': blocks, 'edges': edges}


def test_callback_cfg_union_follows_calls_and_fallthrough_and_keeps_unknown_edges():
    from tools.foft_irq_write_audit import reachable_write_inventory
    rows, analysis = graph_sample()
    proof = reachable_write_inventory(rows, analysis, [0])
    assert proof['blocks'] == proof['instructions'] == 3
    assert proof['direct_intersections']['draw_count_word'][0]['runtime'] == 0x802
    assert proof['unresolved_nonreturn_edges'] == [{'runtime': 0x804, 'kind': 3}]
    assert not proof['runtime_target_set_closed']
    assert proof['excludes_async_interrupts']


@pytest.mark.parametrize('change', ['root', 'overlap', 'edge_owner', 'edge_span'])
def test_callback_cfg_union_rejects_missing_or_contradictory_native_ownership(change):
    from tools.foft_irq_write_audit import reachable_write_inventory
    rows, analysis = graph_sample()
    roots = [0]
    if change == 'root': roots = [1]
    elif change == 'overlap': analysis['blocks'][0]['end_offset'] = 3
    elif change == 'edge_owner': analysis['edges'][0]['source_block_index'] = 2
    elif change == 'edge_span': analysis['blocks'][0]['edge_count'] = 20
    with pytest.raises(ValueError, match='block|edge'): reachable_write_inventory(rows, analysis, roots)


def coper_sample():
    pcs = [0x10CEA,0x10CEC,0x10CEE,0x10CF4,0x10CFA,0x10D00,0x10D04,0x10D08,
           0x10D10,0x10D14,0x10D16,0x10D18,0x10D1A,0x10D1C,0x10D1E,0x10D22,
           0x10D28,0x10D2A,0x10D2C,0x10D2E]
    names = ['move','move','lea','addq','move','cmp','bne','move','movea',
             'move','move','move','move','subq','adda','move','movea','movea','move','rte']
    rows = [{'source_offset': pc-0x800, 'size': (pcs+[0x10D30])[i+1]-pc,
             'mnemonic': names[i], 'provenance': 'accepted_instruction',
             'operand_facts': [], 'address_evidence': []}for i,pc in enumerate(pcs)]
    def reg(name, width=2):
        return {'memory': False, 'direct_register': name, 'access': 'register_write', 'width_bytes': width}
    def memory(access, width=2, base=None, absolute=None, update=0):
        return {'memory': True, 'access': access, 'width_bytes': width, 'base_register': base,
                'absolute_address': absolute, 'ea_update': update, 'displacement': 0,
                'displacement_known': True, 'indexed': False, 'bulk_transfer': False}
    rows[0]['operand_facts'] = [reg('A0',4), memory('memory_write',4,'A7',update=2)]
    rows[1]['operand_facts'] = [reg('A1',4), memory('memory_write',4,'A7',update=2)]
    rows[0]['operand_facts'][0]['access'] = 'register_read'
    rows[1]['operand_facts'][0]['access'] = 'register_read'
    rows[2]['operand_facts'] = [memory('address',4,absolute=0xDFF192),reg('A1',4)]
    rows[2]['address_evidence'] = [{'operand_index':0,'has_address':True,'address':0xDFF192}]
    for i,address,width in [(3,0x10D38,2),(7,0x10D34,2),(15,0x10D30,4)]:
        rows[i]['operand_facts'] = [reg('D0'),memory('memory_write',width,absolute=address)]
    rows[8]['operand_facts'] = [{**memory('memory_read',4),'pc_relative':True},reg('A0',4)]
    for i in range(9,13):
        rows[i]['operand_facts'] = [memory('memory_read',base='A0',update=1 if i<12 else 0),
                                   memory('memory_write',base='A1',update=1 if i<12 else 0)]
    for i,name,width in [(16,'A1',4),(17,'A0',4),(18,'D0',2)]:
        rows[i]['operand_facts'] = [memory('memory_read',width,'A7',update=1),reg(name,width)]
    return rows


def test_coper_mutable_read_cursor_does_not_become_a_ram_write_receiver():
    from tools.foft_irq_write_audit import coper
    proof = coper(coper_sample())
    assert proof['mutable_cursor_is_read_receiver']
    assert proof['hardware_word_destinations'] == [0xDFF192,0xDFF194,0xDFF196,0xDFF198]
    assert not proof['cursor_read_extent_proved']
    assert not proof['stack_lifetime_or_alias_proved']


@pytest.mark.parametrize('change', ['root','cursor_write','stride','extra','restore'])
def test_coper_rejects_changed_write_domains_or_frame_contract(change):
    from tools.foft_irq_write_audit import coper
    rows = coper_sample()
    if change == 'root': rows[2]['address_evidence'][0]['address'] = 0xE816
    elif change == 'cursor_write': rows[9]['operand_facts'][1]['base_register'] = 'A0'
    elif change == 'stride': rows[10]['operand_facts'][1]['ea_update'] = 0
    elif change == 'extra': rows[19]['operand_facts'] = rows[15]['operand_facts']
    elif change == 'restore': rows[16]['operand_facts'][1]['direct_register'] = 'A0'
    with pytest.raises(ValueError, match='differ|unexpected'): coper(rows)

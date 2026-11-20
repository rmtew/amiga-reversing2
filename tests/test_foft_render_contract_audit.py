"""Synthetic fact-contract rejection; no guest code or original bytes."""

import copy

import pytest

from tools.foft_render_contract_audit import audit, composition, transpose


def reg(name, width=2):
    return {'direct_register':name,'memory':False,'width_bytes':width}


def mem(width=2):
    return {'direct_register':None,'memory':True,'width_bytes':width}


def row(at, size, name, operands, addresses=()):
    return {'source_offset':at-0x800,'size':size,'mnemonic':name,
            'provenance':'accepted_instruction','operand_facts':operands,
            'address_evidence':[{'operand_index':i,'has_address':True,'address':a}
                                for i,a in addresses]}


def transpose_rows():
    rows=[]
    for i in range(9):
        at=0xFC24+12*i
        rows.extend([
            row(at,4,'move',[mem(),reg('D0')],[(0,0xFCD4+2*i)]),
            row(at+4,2,'add',[reg('D0'),reg('D0')]),
            row(at+6,6,'move',[reg('D0'),mem()],[(1,0xFC92+2*((i%3)*3+i//3))]),
        ])
    rows.append(row(0xFC90,2,'rts',[]))
    return rows


def test_word_transpose_retains_distinct_cell_addresses():
    cells=transpose(transpose_rows())
    assert [c['basis_offset']for c in cells]==[0,6,12,2,8,14,4,10,16]
    assert [c['orientation_offset']for c in cells]==list(range(0,18,2))


@pytest.mark.parametrize('change',['destination','width','double','gap','unaccepted','conflict'])
def test_transpose_rejects_incompatible_or_incomplete_native_facts(change):
    rows=copy.deepcopy(transpose_rows())
    if change=='destination':rows[5]['address_evidence'][0]['address']+=2
    if change=='width':rows[0]['operand_facts'][0]['width_bytes']=4
    if change=='double':rows[1]['mnemonic']='sub'
    if change=='gap':rows.pop(7)
    if change=='unaccepted':rows[0]['provenance']='candidate'
    if change=='conflict':rows[0]['address_evidence'][0]['conflicted']=True
    with pytest.raises(ValueError,match='differs|contiguous'):transpose(rows)


def test_reference_resolution_can_supply_pc_relative_source_without_decoding_it():
    rows=transpose_rows()
    for r in rows:
        r['resolved_reference_addresses']=r.pop('address_evidence')
        r['address_evidence']=[]
    assert len(transpose(rows))==9


def test_composition_requires_complete_accepted_window():
    with pytest.raises(ValueError,match='extent'):
        composition([])


def test_source_identity_is_required_before_accepting_semantic_contracts():
    with pytest.raises(ValueError,match='identity'):
        audit(bytes(489472),[])


def composition_rows():
    rows=[]
    cursor=0xF16E
    def emit(size,name,operands,addresses=()):
        nonlocal cursor
        rows.append(row(cursor,size,name,operands,addresses));cursor+=size
    for col in range(3):
        for k in range(3):
            emit(6,'move',[mem(),reg(f'D{k}')],[(0,0xFCBE+2*(3*k+col))])
        for r in range(3):
            emit(6,'move',[mem(),reg('D3')],[(0,0xFC92+6*r)])
            emit(2,'muls',[reg('D0'),reg('D3')])
            emit(6,'move',[mem(),reg('D4')],[(0,0xFC94+6*r)])
            emit(2,'muls',[reg('D1'),reg('D4')])
            emit(2,'add',[reg('D4',4),reg('D3',4)])
            emit(6,'move',[mem(),reg('D4')],[(0,0xFC96+6*r)])
            emit(2,'muls',[reg('D2'),reg('D4')])
            emit(2,'add',[reg('D4',4),reg('D3',4)])
            emit(2,'swap',[reg('D3',4)])
            emit(6,'move',[reg('D3'),mem()],[(1,0xFCA8+2*(3*r+col))])
    emit(2,'rts',[])
    return rows


def test_product_is_column_input_row_output_with_long_sums():
    cells=composition(composition_rows())
    assert [c['output_offset']for c in cells]==[0,6,12,2,8,14,4,10,16]


@pytest.mark.parametrize('change',['input','output','product','sum_width','swap_width','gap'])
def test_product_rejects_changed_cell_or_arithmetic_contract(change):
    rows=composition_rows()
    if change=='input':rows[1]['address_evidence'][0]['address']+=2
    if change=='output':rows[12]['address_evidence'][0]['address']+=2
    if change=='product':rows[4]['mnemonic']='mulu'
    if change=='sum_width':rows[7]['operand_facts'][0]['width_bytes']=2
    if change=='swap_width':rows[11]['operand_facts'][0]['width_bytes']=2
    if change=='gap':rows.pop(17)
    with pytest.raises(ValueError,match='differs|contiguous'):
        composition(rows)


def test_direct_count_inventory_does_not_claim_indirect_alias_closure():
    from tools.foft_render_contract_audit import frame_inventory
    rows=[row(0x2000,6,'move',[reg('D7'),mem()]),row(0x2006,6,'move',[mem(),reg('D0')])]
    rows[0]['operand_facts'][1].update(absolute_address=0x4E726,access='memory_write')
    rows[1]['operand_facts'][0].update(absolute_address=0x4E726,access='memory_read')
    r=frame_inventory(rows)
    assert [x['runtime']for x in r['direct_count_writers']]==[0x2000]
    assert [x['runtime']for x in r['direct_count_readers']]==[0x2006]
    assert not r['indirect_alias_copy_effect_closure']


def test_scenery_probe_crosswalk_keeps_callback_halves_and_tail_distinct():
    from tools.foft_render_contract_audit import scenery_probe_crosswalk
    rows = scenery_probe_crosswalk(16)
    assert [r['phase'] for r in rows[:6]] == [0, 10, 8, 6, 4, 2]
    assert [r['reads'][-1]['producer_field'] for r in rows[:6]] == [
        'tail', 'callbackLow', 'callbackHigh', 'z', 'y', 'x']
    assert rows[3]['reads'][2] == {'consumer': 'divisor', 'byte_offset': 34,
                                  'producer_row': 2, 'producer_field': 'tail'}
    assert rows[-1]['reads'][-1]['byte_offset'] + 2 == 162
    assert rows[-1]['reads'][-1]['producer_row'] == 13


@pytest.mark.parametrize('count', [0, -1, 17, True, 1.0, None])
def test_scenery_probe_crosswalk_refuses_unproved_snapshot_extent(count):
    from tools.foft_render_contract_audit import scenery_probe_crosswalk
    with pytest.raises(ValueError, match='1..16'):
        scenery_probe_crosswalk(count)


@pytest.mark.parametrize('count', range(1, 17))
def test_scenery_probe_crosswalk_accesses_stay_in_conditional_snapshot(count):
    from tools.foft_render_contract_audit import scenery_probe_crosswalk
    rows = scenery_probe_crosswalk(count)
    assert len(rows) == count
    assert all(0 <= read['byte_offset'] <= 12 * count - 2
               for r in rows for read in r['reads'])


def test_scenery_reader_requires_real_accepted_instruction_coverage():
    from tools.foft_render_contract_audit import scenery_probe_contract
    with pytest.raises(ValueError, match='instruction missing'):
        scenery_probe_contract([])


def pending_damage_rows():
    framing = [(0x2EE34, 4, 'movem'), (0x2EE38, 4, 'bsr'),
               (0x2EE3C, 6, 'move'), (0x2EE42, 4, 'beq'),
               (0x2EE46, 2, 'add'), (0x2EE48, 4, 'bsr'),
               (0x2EE4C, 6, 'clr'), (0x2EE52, 4, 'movem'),
               (0x2EE56, 2, 'rts')]
    rows = [row(pc, size, name, []) for pc, size, name in framing]
    at = {r['source_offset'] + 0x800: r for r in rows}
    for pc, index in [(0x2EE3C, 0), (0x2EE4C, 0)]:
        at[pc]['operand_facts'] = [dict(mem(), absolute_address=0x4E69C,
                                     access='memory_read' if pc == 0x2EE3C else 'memory_write')]
        at[pc]['address_evidence'] = [{'operand_index': index, 'has_address': True,
                                      'address': 0x4E69C}]
    at[0x2EE3C]['operand_facts'].append(reg('D1'))
    at[0x2EE46]['operand_facts'] = [reg('D1'), reg('D1')]
    for pc, value in [(0x275AE, 10), (0x275C8, 10), (0x284A2, 5), (0x284B6, 5)]:
        rows.append(row(pc, 8, 'addi', [{'immediate_value': value},
                        dict(mem(), absolute_address=0x4E69C, access='memory_write')],
                        [(1, 0x4E69C)]))
    for pc, doubles, load, lea, mask, base in [
            (0x2EE6C, [0x2EE70, 0x2EE72], 0x2EE74, 0x2EE62, 15, 0x2EF02),
            (0x2EEA8, [0x2EEB0, 0x2EEB2], 0x2EEB4, 0x2EEAC, 3, 0x2EF42)]:
        rows.append(row(pc, 4, 'andi', [{'immediate_value': mask}, reg('D0')]))
        rows.extend(row(pc, 2, 'add', [reg('D0'), reg('D0')]) for pc in doubles)
        rows.append(row(load, 4, 'movea', [dict(mem(4), base_register='A0',
            indexed=True, index_register='D0', index_width_bytes=2, index_scale=1,
            ea_update=0, displacement_known=True, displacement=0), reg('A0', 4)]))
        rows.append(row(lea, 4, 'lea', [mem(4), reg('A0', 4)], [(0, base)]))
    for pc, value in [(0x2EE78,0x2EF6E),(0x2EE9A,0xffffffff)]:
        rows.append(row(pc, 6, 'cmpa', [{'immediate_value':value},reg('A0',4)]))
    return sorted(rows, key=lambda r: r['source_offset'])


def test_pending_damage_links_word_accumulator_to_distinct_bounded_selector_lists():
    from tools.foft_render_contract_audit import pending_system_damage_contract
    result = pending_system_damage_contract(pending_damage_rows())
    assert [t['row_count'] for t in result['selector_tables']] == [16, 4]
    assert [t['source_runtime_span'] for t in result['selector_tables']] == [
        [0x2EF02, 0x2EF42], [0x2EF42, 0x2EF52]]
    assert len(result['direct_absolute_uses']) == 6
    assert not result['complete_writer_alias_or_value_domain']


@pytest.mark.parametrize('change', ['mask', 'scale', 'index_width', 'double',
                                    'target', 'amount', 'word_width', 'unaccepted', 'special_selector'])
def test_pending_damage_rejects_changed_source_relationships(change):
    from tools.foft_render_contract_audit import pending_system_damage_contract
    rows = pending_damage_rows()
    at = {r['source_offset'] + 0x800: r for r in rows}
    if change == 'special_selector': at[0x2EE78]['operand_facts'][0]['immediate_value'] += 4
    if change == 'mask': at[0x2EE6C]['operand_facts'][0]['immediate_value'] = 31
    if change == 'scale': at[0x2EE74]['operand_facts'][0]['index_scale'] = 2
    if change == 'index_width': at[0x2EE74]['operand_facts'][0]['index_width_bytes'] = 4
    if change == 'double': at[0x2EE70]['mnemonic'] = 'sub'
    if change == 'target': at[0x2EE62]['address_evidence'][0]['address'] += 4
    if change == 'amount': at[0x275AE]['operand_facts'][0]['immediate_value'] = 5
    if change == 'word_width': at[0x2EE3C]['operand_facts'][0]['width_bytes'] = 4
    if change == 'unaccepted': at[0x2EE46]['provenance'] = 'candidate'
    with pytest.raises(ValueError, match='differs|accepted'):
        pending_system_damage_contract(rows)


def scenery_probe_rows_and_edges():
    pairs = [(0x4AEB2,'lea'),(0x4AEB8,'move'),(0x4AEBE,'subq'),(0x4AEC0,'bmi'),
        (0x4AEC4,'move'),(0x4AEC6,'move'),(0x4AECA,'move'),(0x4AECE,'ext'),
        (0x4AED0,'ext'),(0x4AED2,'asl'),(0x4AED4,'asl'),(0x4AED6,'divs'),
        (0x4AED8,'divs'),(0x4AEDA,'addi'),(0x4AEDE,'moveq'),(0x4AEE0,'sub'),
        (0x4AEE2,'sub'),(0x4AEE8,'bpl'),(0x4AEEA,'neg'),(0x4AEEC,'cmp'),
        (0x4AEF0,'bgt'),(0x4AEF2,'sub'),(0x4AEF8,'bpl'),(0x4AEFA,'neg'),
        (0x4AEFC,'cmp'),(0x4AF00,'bgt'),(0x4AF02,'st'),(0x4AF08,'move'),
        (0x4AF0E,'btst'),(0x4AF12,'beq'),(0x4AF14,'tst'),(0x4AF18,'bne'),
        (0x4AF1A,'move'),(0x4AF20,'move'),(0x4AF28,'move'),(0x4AF30,'addi'),
        (0x4AF3A,'st'),(0x4AF40,'movem'),(0x4AF44,'moveq'),(0x4AF46,'jsr'),
        (0x4AF4C,'movem'),(0x4AF50,'move'),(0x4AF56,'bra'),(0x4AF5A,'lea'),(0x4AF5E,'dbf')]
    rows = [row(pc, (pairs[i+1][0] if i+1 < len(pairs) else 0x4AF62)-pc,
                name, [{}]) for i, (pc, name) in enumerate(pairs)]
    at = {r['source_offset']+0x800: r for r in rows}
    def a0(offset, width=2):
        return dict(mem(width), base_register='A0', indexed=False, ea_update=0,
                    displacement_known=True, displacement=offset, access='memory_read')
    for pc, offset, dest in [(0x4AEC4,0,'D0'),(0x4AEC6,2,'D1'),(0x4AECA,4,'D2')]:
        at[pc]['operand_facts'] = [a0(offset),reg(dest)]
    for pc, address, dest, width in [(0x4AEB2,0xE816,'A0',4),(0x4AEB8,0x4E726,'D7',2)]:
        at[pc]['operand_facts'] = [mem(width),reg(dest,width)]
        at[pc]['address_evidence'] = [{'operand_index':0,'has_address':True,'address':address}]
    at[0x4AEBE]['operand_facts'] = [{'immediate_value':1},reg('D7')]
    for pc, dest in [(0x4AED6,'D0'),(0x4AED8,'D1')]:
        at[pc]['operand_facts'] = [reg('D2'),reg(dest)]
    at[0x4AF14]['operand_facts'] = [a0(10)]
    at[0x4AF5A]['operand_facts'] = [a0(10,4),reg('A0',4)]
    at[0x4AF5E]['operand_facts'] = [reg('D7')]
    edges = []
    for pc, name, target in [(0x4AEC0,'bmi',0x4AF62),(0x4AEF0,'bgt',0x4AF5A),
            (0x4AF00,'bgt',0x4AF5A),(0x4AF12,'beq',0x4AF62),(0x4AF18,'bne',0x4AF62),
            (0x4AF56,'bra',0x4AF62),(0x4AF5E,'dbf',0x4AEC4)]:
        edges.append({'source_offset':pc-0x800,'target_section_index':0,
                      'target_offset':target-0x800,'status':'resolved',
                      'kind':'jump' if name == 'bra' else 'branch'})
        if name != 'bra':
            edges.append({**edges[-1],'kind':'fallthrough',
                          'target_offset':pc+at[pc]['size']-0x800})
    return rows, edges


def test_scenery_probe_source_contract_retains_reload_and_conditional_status():
    from tools.foft_render_contract_audit import scenery_probe_contract
    rows, edges = scenery_probe_rows_and_edges()
    result = scenery_probe_contract(rows, edges)
    assert result['post_return_count_source_runtime'] == 0x4E726
    assert result['consumer_stride'] == 10
    assert result['conditional_count_domain'] == [1, 16]
    assert not result['consumer_guard_proves_that_domain']
    assert not result['snapshot_or_count_preservation_proved']
    assert not result['live_execution_or_fault_observed']


@pytest.mark.parametrize('change', ['count_root','view_root','count_adjust','stride',
                                    'gate_width','divisor','edge','unresolved','missing','candidate'])
def test_scenery_probe_rejects_changed_native_read_or_control_contract(change):
    from tools.foft_render_contract_audit import scenery_probe_contract
    rows, edges = scenery_probe_rows_and_edges()
    at = {r['source_offset']+0x800:r for r in rows}
    if change == 'count_root': at[0x4AEB8]['address_evidence'][0]['address'] += 2
    if change == 'view_root': at[0x4AEB2]['address_evidence'][0]['address'] += 2
    if change == 'count_adjust': at[0x4AEBE]['operand_facts'][0]['immediate_value'] = 2
    if change == 'stride': at[0x4AF5A]['operand_facts'][0]['displacement'] = 12
    if change == 'gate_width': at[0x4AF14]['operand_facts'][0]['width_bytes'] = 1
    if change == 'divisor': at[0x4AED6]['operand_facts'][0]['direct_register'] = 'D3'
    if change == 'edge': edges[-2]['target_offset'] += 2
    if change == 'unresolved': edges[0]['status'] = 'unresolved'
    if change == 'missing': rows.remove(at[0x4AECE])
    if change == 'candidate': at[0x4AEC4]['provenance'] = 'candidate'
    with pytest.raises(ValueError, match='differs|differ|accepted|contiguous|missing'):
        scenery_probe_contract(rows, edges)

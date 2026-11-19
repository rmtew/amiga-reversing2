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

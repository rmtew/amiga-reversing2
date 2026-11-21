"""Original finite-WORD arithmetic and conservative source-fact tests, no guest run."""
from copy import deepcopy

import pytest

from tools.foft_flight_motion_audit import (
    local_translation,
    translation_word,
    wrap_local,
)
from tools.foft_trig_view_audit import signed_word


def test_single_wrap_preserves_coarse_local_value_modulo_word_coarse_extent():
    for coarse in (0,0x7FFF,0xFFFF):
        for local in range(65536):
            c,v=wrap_local(coarse,local)
            assert (coarse*16384+signed_word(local))%(1<<30)==(c*16384+signed_word(v))%(1<<30)
            assert -16384<=signed_word(v)<=16383


@pytest.mark.parametrize('value',[8192,(-8192)&65535])
def test_strict_boundary_words_do_not_transfer_a_coarse_unit(value):
    assert wrap_local(19,value)==(19,value)


def test_single_correction_does_not_prove_canonical_local_bounds():
    assert wrap_local(0,32767)==(1,16383)
    assert wrap_local(0,0x8000)==(0xFFFF,0xC000)
    assert wrap_local(0xFFFF,8193)==(0,(-8191)&65535)
    assert wrap_local(0,(-8193)&65535)==(0xFFFF,8191)


@pytest.mark.parametrize('value',[-1,65536,True])
def test_arithmetic_contract_rejects_non_word_assertions(value):
    with pytest.raises(ValueError,match='WORD'):wrap_local(value,0)
    with pytest.raises(ValueError,match='WORD'):translation_word(0,value)


def test_two_translation_paths_keep_their_distinct_product_extractions():
    for component in range(65536):
        for step in (0,1,0x7FFF,0x8000,0xFFFF):
            product=signed_word(component)*signed_word(step)
            assert translation_word(component,step)==(product>>15)&65535
            assert translation_word(component,step,coarse=True)==(product>>16)&65535
    assert translation_word(0x7FFF,1)==0
    assert translation_word(0x7FFF,2)==1
    assert translation_word(0x7FFF,2,coarse=True)==0


def local_rows():
    rows=[]
    def reg(n,width=2):return {'memory':False,'direct_register':n,'width_bytes':width}
    def absolute(address):return {'memory':True,'absolute_address':address,'width_bytes':2}
    def put(op,operands):
        pc=0xBF24+2*len(rows)
        rows.append({'source_offset':pc-0x800,'mnemonic':op,'operand_facts':operands,
                     'address_evidence':[{'operand_index':i,'has_address':True,'address':p['absolute_address']}for i,p in enumerate(operands)if p.get('absolute_address')is not None]})
    for axis in range(3):
        pc=0xBF24+2*len(rows)
        put('move',[{'width_bytes':2,'pc_relative':True,'indexed':False,'displacement_known':True,'displacement':0xC1F4+2*axis-pc-2},reg('D0')])
        put('move',[reg('D0'),absolute(0xC200+2*axis)])
        put('muls',[reg('D1'),reg('D0')]);put('swap',[reg('D0',4)]);put('rol',[{'immediate_value':1},reg('D0',4)])
        effects=[('add',0x14DE6+2*axis),('move',0xC216+2*axis)]
        if axis==2:effects.reverse()
        for op,address in effects:put(op,[reg('D0'),absolute(address)])
    return rows


def test_source_contract_retains_third_component_save_before_position_add():
    result=local_translation(local_rows())
    assert all(r['position_add_runtime']<r['delta_store_runtime']for r in result[:2])
    assert result[2]['delta_store_runtime']<result[2]['position_add_runtime']


@pytest.mark.parametrize('change',['truncated','third_order','wrong_cache','wide_add','wide_read','wrong_basis','reduction'])
def test_local_translation_requires_exact_width_roots_and_order(change):
    rows=deepcopy(local_rows())
    if change=='truncated':rows.pop()
    if change=='third_order':rows[19],rows[20]=rows[20],rows[19]
    if change=='wrong_cache':rows[1]['address_evidence'][0]['address']+=2
    if change=='wide_add':rows[5]['operand_facts'][1]['width_bytes']=4
    if change=='wide_read':rows[0]['operand_facts'][0]['width_bytes']=4
    if change=='wrong_basis':rows[0]['operand_facts'][0]['displacement']+=2
    if change=='reduction':rows[4]['operand_facts'][0]['immediate_value']=2
    with pytest.raises(ValueError,match='translation|operand|PC-relative|Q15'):
        local_translation(rows)

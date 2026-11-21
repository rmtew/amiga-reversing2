"""Host arithmetic/source-contract checks; no guest inputs or execution."""
import math
from copy import deepcopy

import pytest

from tools.foft_trig_view_audit import (
    clamp_word,
    phase_pair,
    q15_product_word,
    q15_reductions,
    sampled_cycles,
    signed_word,
)


def cycles():
    sine=[max(-32767,min(32767,round(32768*math.sin(2*math.pi*i/512))))for i in range(512)]
    return sine+[sine[0]],[sine[(i+128)%512]for i in range(513)]


def test_cycle_contract_is_quadrature_data_not_a_regeneration_rule():
    result=sampled_cycles(*cycles())
    assert result['period']==512 and result['stored_words_per_cycle']==513
    assert result['cosine_phase_shift']==128
    assert not result['generation_rounding_rule_proved']and not result['current_table_constness_proved']


@pytest.mark.parametrize('change',['length','endpoint','phase','amplitude'])
def test_cycle_extent_phase_and_sample_roles_require_all_evidence(change):
    sine,cosine=cycles()
    if change=='length':sine.pop()
    if change=='endpoint':sine[-1]=1
    if change=='phase':cosine[17]+=2
    if change=='amplitude':
        sine[37]+=16;sine[293]=-sine[37]
        cosine=[sine[(i+128)%512]for i in range(513)]
    with pytest.raises(ValueError,match='cycle|phase|samples'):
        sampled_cycles(sine,cosine)


def test_one_wrap_is_modulo_only_under_the_canonical_phase_contract():
    for a in range(512):
        for b in range(512):
            total,difference=phase_pair(a,b)
            assert (total,difference)==((a+b)%512,(a-b)%512)
            assert 0<=2*total<=1022 and 0<=2*difference<=1022


@pytest.mark.parametrize(('a','b'),[(-1,0),(512,0),(0,512),(True,0),(0,False)])
def test_unknown_or_noncanonical_model_phase_is_not_promoted_to_an_index_bound(a,b):
    with pytest.raises(ValueError,match='canonical'):phase_pair(a,b)


def test_original_product_sequence_matches_shift15_modulo_word_including_overflow():
    for a in range(65536):
        for b in (0,1,0x7FFF,0x8000,0xFFFF,0x4000,0xC000):
            assert q15_product_word(a,b)==((signed_word(a)*signed_word(b))>>15)&0xFFFF


def test_per_product_reduction_is_not_a_real_identity_or_a_sum_then_reduce():
    assert q15_product_word(0x3FFF,0x7FFF)==0x3FFE
    assert q15_product_word(1,0x4000)+q15_product_word(1,0x4000)==0
    assert (1*0x4000+1*0x4000)>>15==1
    assert ((32767*1)>>16)*3==0 and (32767*1*3)>>16==1


def test_original_clamp_preserves_the_minimum_word_without_global_normalization():
    for value in range(65536):
        signed=signed_word(value)
        expected=0x8000 if value==0x8000 else ((-1 if signed<0 else 1)*min(abs(signed),0x3FFF))&0xFFFF
        result=clamp_word(value)
        assert result==expected
        assert result==0x8000 or -0x3FFF<=signed_word(result)<=0x3FFF
    assert (clamp_word(0x8000)*2)&0xFFFF==0


def product_rows():
    def reg(name,width):return {'memory':False,'width_bytes':width,'direct_register':name}
    return [{'mnemonic':'muls','source_offset':0,'operand_facts':[reg('D1',2),reg('D0',2)]},
            {'mnemonic':'swap','source_offset':2,'operand_facts':[reg('D0',4)]},
            {'mnemonic':'rol','source_offset':4,'operand_facts':[{'immediate_value':1},reg('D0',4)]}]


def test_native_operand_contract_owns_the_product_extract_proof():
    assert q15_reductions(product_rows())==[{'runtime':2048,'register':'D0','low_word_shift':15}]


@pytest.mark.parametrize('change',['truncate','swap_reg','width','count','operation'])
def test_different_native_sequences_do_not_receive_a_q15_summary(change):
    rows=deepcopy(product_rows())
    if change=='truncate':rows.pop()
    if change=='swap_reg':rows[1]['operand_facts'][0]['direct_register']='D2'
    if change=='width':rows[0]['operand_facts'][1]['width_bytes']=4
    if change=='count':rows[2]['operand_facts'][0]['immediate_value']=2
    if change=='operation':rows[2]['mnemonic']='asr'
    with pytest.raises(ValueError,match='product|operand|Q15'):
        q15_reductions(rows)

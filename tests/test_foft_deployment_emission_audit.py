"""Packed-word algebra is conditional, not a guest execution or reachability test."""
import pytest

from tools.foft_deployment_emission_audit import (
    action_fields,
    conditional_flag_paths,
    middle_reload_update,
    upper_debit,
)


@pytest.mark.parametrize('value',[-1,65536,True,1.5,None])
def test_action_contract_requires_an_exact_word(value):
    for f in(action_fields,conditional_flag_paths,middle_reload_update,upper_debit):
        with pytest.raises(ValueError,match='WORD'):f(value)


def test_three_encoded_parts_are_distinct():
    assert action_fields(0xAB35)==(0x35,0xB,0xA)


@pytest.mark.parametrize('high',range(16))
def test_upper_debit_uses_signed_post_subtraction_not_unsigned_nonzero(high):
    original=(high<<12)|0x234
    changed=upper_debit(original)
    assert(changed is not None)==(1<=high<=8)
    if changed is not None:
        assert changed==((original-0x1000)&65535)
        assert changed&0xFFF==original&0xFFF


@pytest.mark.parametrize('middle',range(1,16))
def test_preserved_positive_middle_debit_keeps_other_fields(middle):
    original=0xA035|(middle<<8)
    result=middle_reload_update(original)
    assert action_fields(result)==(0x35,middle-1,0xA)


def test_unknown_reload_cannot_be_treated_as_the_gating_word():
    gating=0x1230;reloaded=0
    assert action_fields(gating)[1]>0
    assert middle_reload_update(reloaded)==0xFF00
    assert middle_reload_update(gating)==0x1130


@pytest.mark.parametrize(('word','paths'),[
    (0x5021,('effect_flag5',)),
    (0x4020,('effect_flag5',)),
    (0x0410,('emit_missile',)),
    (0x0010,('advance',)),
    (0x0111,('emit_missile',)),
    (0x1101,('emit_flapper',)),
    (0x8101,('emit_flapper',)),
    (0x9101,('advance',)),
    (0x0101,('advance',)),
    (0x5109,('effect_flag3',)),
    (0x5105,('effect_flag2',)),
    (0x5103,('effect_flag1',)),
    (0x5121,('effect_flag5','emit_flapper')),
    (0x5131,('effect_flag5','emit_missile')),
    (0x0000,('advance',)),
])
def test_priority_paths_preserve_dominance_and_conditionals(word,paths):
    assert conditional_flag_paths(word)==paths


def test_additional_seed_has_a_conditional_five_debit_flapper_path():
    value=0x5081
    for _ in range(5):
        assert conditional_flag_paths(value)==('emit_flapper',)
        value=upper_debit(value)
    assert value==0x0081
    assert conditional_flag_paths(value)==('advance',)
    assert conditional_flag_paths(0x4020)==('effect_flag5',)


def test_middle_budget_exhaustion_does_not_stop_other_flag_effects():
    value=0x1230
    assert conditional_flag_paths(value)==('effect_flag5','emit_missile')
    value=middle_reload_update(middle_reload_update(value))
    assert value==0x1030
    assert conditional_flag_paths(value)==('effect_flag5',)

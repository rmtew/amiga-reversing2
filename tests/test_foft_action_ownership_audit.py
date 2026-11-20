"""Host-side conditional source contracts; no guest execution or admission."""
import pytest

from tools.foft_action_ownership_audit import (
    ACTION,
    STATE,
    bounded_emission,
    intersects,
    rng_effect_inventory,
    saved_offset_matches_base,
    signed_word,
)


@pytest.mark.parametrize(('encoded','value'),[(0,0),(32767,32767),(32768,-32768),(65535,-1)])
def test_signed_index_is_low_word_not_unbounded_product(encoded,value):
    assert signed_word(encoded)==value


@pytest.mark.parametrize('value',[-1,65536,True,None])
def test_index_requires_actual_word(value):
    with pytest.raises(ValueError,match="WORD"):signed_word(value)


@pytest.mark.parametrize('count',range(1,33))
@pytest.mark.parametrize('kind',['missile','flapper'])
def test_bounded_pass_preserves_scanned_action_rows(count,kind):
    for row in range(count):
        proof=bounded_emission(count,row,kind)
        assert proof['signed_displacement']==20*count
        assert proof['state_slot']==count and proof['action_slot']==count+row
        assert proof['same_state_action_slot']==(row==0)
        source=(ACTION,ACTION+20*count)
        assert all(not intersects(span,source)for span in proof['child_write_spans'])
        assert proof['child_write_spans'][0]==[STATE+20*count,STATE+20*count+20]
        assert all(not intersects(span,view)for span in proof['child_write_spans']for view in(proof['scanned_state_span'],proof['caller_instrument_span']))
        assert proof['orientation_allocation_or_lifetime_proved']is False


@pytest.mark.parametrize(('count','row','kind'),[(0,0,'missile'),(33,0,'flapper'),(32,32,'missile'),(3,-1,'flapper'),(True,0,'missile'),(1,False,'missile'),(1,0,'unknown')])
def test_certificate_refuses_missing_count_cursor_or_kind_premise(count,row,kind):
    with pytest.raises(ValueError,match="conditional count|original pass|unknown emitter"):bounded_emission(count,row,kind)


@pytest.mark.parametrize('base',range(1,16))
def test_recreation_needs_equality_not_just_two_bounded_slots(base):
    assert saved_offset_matches_base(20*base,base)
    for deployment_count in range(1,16):
        assert saved_offset_matches_base(20*deployment_count,base)==(deployment_count==base)


@pytest.mark.parametrize('base',[0,16,True])
def test_recreation_certificate_does_not_invent_wider_base_range(base):
    with pytest.raises(ValueError,match="fresh encounter base"):saved_offset_matches_base(20,base)


def test_half_open_write_windows_preserve_adjacent_words():
    assert not intersects((0,14),(14,16))
    assert not intersects((16,20),(14,16))
    assert intersects((12,16),(14,16))


def test_fixed_rng_effects_preserve_carried_registers():
    rows=[{'mnemonic':'move','operand_facts':[{'access':'register_write','direct_register':'D0'}]},
          {'mnemonic':'addq','operand_facts':[{'access':'memory_write','memory':True,'absolute_address':0x1B420,'width_bytes':4}]}]
    assert rng_effect_inventory(rows)['explicit_register_writes']==['D0']


@pytest.mark.parametrize('row',[
    {'mnemonic':'jsr','operand_facts':[]},
    {'mnemonic':'move','operand_facts':[{'access':'register_write','direct_register':'A2'}]},
    {'mnemonic':'move','operand_facts':[{'access':'register_write','direct_register':'D2'}]},
    {'mnemonic':'move','operand_facts':[{'access':'memory_write','memory':True,'absolute_address':None,'width_bytes':2}]},
])
def test_rng_effect_inventory_refuses_missing_preservation(row):
    with pytest.raises(ValueError,match='unsupported RNG|unknown RNG|clobbers'):
        rng_effect_inventory([row])

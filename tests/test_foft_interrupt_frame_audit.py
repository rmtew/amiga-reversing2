"""Interrupt-local certificates; synthetic facts only, no guest execution."""
from copy import deepcopy

import pytest

from tools.foft_interrupt_frame_audit import (
    REGS15,
    exclude_domains,
    keyboard_domains_under_preserved_maps,
    local_writes,
    setup_sound_fields,
    stack_transfer,
)


def transfer(regs, restore=False):
    reg={'register_list':sorted(regs),'width_bytes':4,
         'access':'register_list_write'if restore else'register_list_read'}
    mem={'memory':True,'base_register':'A7','indexed':False,'displacement':0,
         'displacement_known':True,'absolute_address':None,'ea_update':1 if restore else 2,
         'width_bytes':4,'bulk_transfer':True,'access':'memory_read'if restore else'memory_write'}
    return {'mnemonic':'movem','operand_facts':[mem,reg]if restore else[reg,mem]}


@pytest.mark.parametrize('restore',[False,True])
def test_all_register_draw_snapshot_is_64_bytes_and_outer_irq_frames_are_60(restore):
    assert stack_transfer(transfer(REGS15|{'A7'},restore),REGS15|{'A7'},restore=restore)==64
    assert stack_transfer(transfer(REGS15,restore),REGS15,restore=restore)==60
    with pytest.raises(ValueError,match='mask'):
        stack_transfer(transfer(REGS15,restore),REGS15|{'A7'},restore=restore)


@pytest.mark.parametrize(('key','value'),[('base_register','A6'),('ea_update',0),
                                         ('width_bytes',2),('indexed',True),
                                         ('displacement',4),('bulk_transfer',False)])
def test_stack_receiver_or_extent_changes_do_not_reuse_frame_certificate(key,value):
    row=transfer(REGS15);row['operand_facts'][1][key]=value
    with pytest.raises(ValueError,match='receiver'):
        stack_transfer(row,REGS15)


def test_duplicate_register_does_not_turn_a_mask_into_more_saved_storage():
    row=transfer(REGS15);row['operand_facts'][0]['register_list'].append('D0')
    with pytest.raises(ValueError,match='mask'):
        stack_transfer(row,REGS15)


def test_exact_adjacent_domain_is_allowed_but_partial_word_alias_is_rejected():
    assert exclude_domains([{'span':[0x1000,0x1002]}],{'word':(0x1002,0x1004)})
    with pytest.raises(ValueError,match='word'):
        exclude_domains([{'span':[0x1000,0x1003]}],{'word':(0x1002,0x1004)})


@pytest.mark.parametrize('span',[[3,3],[4,2],[-1,4],[0,2**32+1]])
def test_bad_numeric_domains_are_not_accepted_as_disjoint(span):
    with pytest.raises(ValueError,match='extent'):
        exclude_domains([{'span':span}],{})


def row(pc,mnemonic,operands):
    return {'source_offset':pc-0x800,'size':2,'provenance':'accepted_instruction',
            'mnemonic':mnemonic,'operand_facts':operands}


def test_local_body_retains_call_boundary_instead_of_claiming_callee_purity():
    facts=[row(0x1000,'jsr',[]),row(0x1002,'move',[{
        'access':'memory_write','width_bytes':2,'bulk_transfer':False,
        'base_register':None,'indexed':False,'absolute_address':0x2000}])]
    r=local_writes(facts,0x1000,0x1004)
    assert r['callee_effects_excluded_at']==[0x1000]
    assert r['non_stack_cpu_write_domains']==[{'runtime':0x1002,'operand_index':0,'span':[0x2000,0x2002]}]
    unknown=deepcopy(facts);unknown[1]['operand_facts'][0].update(base_register='A2',absolute_address=None)
    with pytest.raises(ValueError,match='uncovered'):
        local_writes(unknown,0x1000,0x1004)


def test_finite_sound_state_fields_do_not_give_the_gap_write_ownership():
    p={'memory':True,'access':'memory_write','base_register':'A1','width_bytes':2,
       'displacement_known':True,'displacement':6,'indexed':False,'ea_update':0,'bulk_transfer':False}
    assert setup_sound_fields(p)==[{'span':[0x4F33C,0x4F33E]},{'span':[0x4F34C,0x4F34E]}]
    assert exclude_domains(setup_sound_fields(p),{'channel2_offset':(0x4F34A,0x4F34C)})
    p['displacement']=4
    with pytest.raises(ValueError,match='field'):
        setup_sound_fields(p)


def test_preserved_map_refinement_is_explicit_and_does_not_mutate_unknown_map_case():
    section={'non_stack_cpu_write_domains':[{'runtime':0x10B56,'span':[0x82F6,0x182F6]}]}
    old=deepcopy(section)
    narrowed=keyboard_domains_under_preserved_maps(section)
    assert narrowed==[{'runtime':0x10B56,'span':[0x102F6,0x103F6]}] and section==old
    assert exclude_domains(narrowed,{'guard':(0x102F0,0x102F2)})
    with pytest.raises(ValueError,match='guard'):
        exclude_domains(section['non_stack_cpu_write_domains'],{'guard':(0x102F0,0x102F2)})
    with pytest.raises(ValueError,match='missing'):
        keyboard_domains_under_preserved_maps({'non_stack_cpu_write_domains':[]})
    with pytest.raises(ValueError,match='band'):
        keyboard_domains_under_preserved_maps({'non_stack_cpu_write_domains':[{'runtime':0x10B56,'span':[0,1]}]})

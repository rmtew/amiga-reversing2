"""Host-only source-contract checks; no game inputs or device execution."""
from copy import deepcopy

import pytest

from tools.foft_music_voice_effects_audit import (
    VOICES,
    audio_header,
    audio_only_control,
    bounded_writes,
    fixed_cursor_writes,
    indexed_word_band,
    leaf_graph,
    protected_registers,
)


def row(*facts, mnemonic='move', pc=0x1000):
    return {'source_offset':pc-0x800,'size':2,'provenance':'accepted_instruction',
            'mnemonic':mnemonic,'operand_facts':list(facts)}


def store(base,off,width=2):
    return {'access':'memory_write','base_register':base,'displacement':off,
            'displacement_known':True,'width_bytes':width,'absolute_address':None,
            'indexed':False,'bulk_transfer':False,'ea_update':0}


def test_four_initial_headers_are_audio_only_but_the_property_is_not_inferred_from_a_word():
    for i in range(4):
        h=audio_header(i);assert audio_only_control(h)
        for key,value in [('dma_mask',0x40),('irq_mask',0x20),('custom_offset',0x40)]:
            assert not audio_only_control({**h,key:value})
        assert not audio_only_control({**h,'dma_mask':True})
    with pytest.raises(ValueError,match='voice index'):audio_header(4)


def test_signed_word_hull_includes_width_without_claiming_that_every_value_occurs():
    assert indexed_word_band(0x58B00,0,1)==[0x50B00,0x60B00]
    assert indexed_word_band(0xDFF000,10,4)==[0xDF700A,0xE0700D]
    for v in VOICES:
        assert 0x50B00<=v+26<v+30<=0x60B00
    for base,width in [(0,1),(2**32,2),(0x10000,8)]:
        with pytest.raises(ValueError,match='EA'):indexed_word_band(base,0,width)


def test_voice_fields_are_four_separate_spans_not_a_hull_or_a_pointee():
    p=bounded_writes([row(store('A3',26,4))],'A3','A1')
    assert p['stores'][0]['spans']==[[v+26,v+30]for v in VOICES]
    assert p['stores'][0]['kind']=='caller_bound_voice'
    assert not p['explicit_stack_writes']


@pytest.mark.parametrize(('offset','width'),[(0,2),(4,4),(32,4),(-2,2)])
def test_local_writes_cannot_silently_reach_header_or_next_record(offset,width):
    with pytest.raises(ValueError,match='header'):bounded_writes([row(store('A3',offset,width))],'A3','A1')


def test_hardware_and_stack_domains_stay_distinct():
    s=store('A7',0);s['ea_update']=2
    r=bounded_writes([row(store('A1',8)),row(store('A6',0x96)),row(s)],'A3','A1')
    assert [x['kind']for x in r['stores']]==['custom_plus_current_signed_word','fixed_custom']
    assert r['stores'][1]['spans']==[[0xDFF096,0xDFF098]]
    assert r['explicit_stack_writes']==[{'runtime':0x1000,'width':2}]


@pytest.mark.parametrize('change',[{'base_register':'A0'},{'indexed':True},{'bulk_transfer':True},
                                   {'ea_update':1},{'width_bytes':8},{'displacement_known':False}])
def test_uncovered_receiver_effects_refuse(change):
    s=store('A3',12);s.update(change)
    with pytest.raises(ValueError,match='voice write|write root|write cursor'):bounded_writes([row(s)],'A3','A1')


@pytest.mark.parametrize('effect',[{'access':'register_write','direct_register':'A3'},
    {'access':'memory_read','base_register':'A2','ea_update':1},
    {'access':'register_list_write','register_list':['D0','A6']}])
def test_a_matching_return_does_not_prove_retained_receivers(effect):
    with pytest.raises(ValueError,match='receiver'):protected_registers([row(effect)])


def test_delegated_callees_and_frame_restores_need_their_own_contract():
    for name in ('jsr','bsr','movem','rte'):
        with pytest.raises(ValueError,match='callee|restore'):protected_registers([row(mnemonic=name)])
    assert protected_registers([row({'access':'register_write','direct_register':'A0'}),row(mnemonic='rts')])


def test_leaf_native_graph_requires_bounded_known_returns_and_refuses_call_edges():
    r=[row(mnemonic='rts')]
    a={'blocks':[{'start_offset':0x800,'end_offset':0x802,'edge_start':0,'edge_count':1}],
       'edges':[{'source_block_index':0,'kind':5,'target_block_index':2**32-1}]}
    assert leaf_graph(a,r,0x1000,0x1000,0x1002)['preserved_address_registers']==['A1','A2','A3','A6']
    for kind in (3,4):
        b=deepcopy(a);b['edges'][0]['kind']=kind
        with pytest.raises(ValueError,match='return'):leaf_graph(b,r,0x1000,0x1000,0x1002)
    with pytest.raises(ValueError,match='escapes'):leaf_graph(a,r,0x1000,0x1002,0x1004)


def test_fixed_cursor_requires_literal_roots_and_rejects_intervening_call_or_update():
    define=row({'absolute_address':0x5850C,'displacement_known':True,'access':'address'},
               {'direct_register':'A0','access':'register_write'},mnemonic='lea')
    write=row(store('A0',0))
    assert fixed_cursor_writes([define,write])['stores'][0]['spans']==[[0x5850C,0x5850E]]
    for middle in (row(mnemonic='bsr'),row({'base_register':'A0','ea_update':1,'access':'memory_read'})):
        with pytest.raises(ValueError,match='cursor'):fixed_cursor_writes([define,middle,write])
    with pytest.raises(ValueError,match='cursor'):fixed_cursor_writes([write])


def test_same_size_unrelated_bytes_cannot_supply_a_pinned_music_effect_certificate():
    from tools.foft_music_voice_effects_audit import check_source
    with pytest.raises(ValueError,match='member identity'):
        check_source([],{},bytes(489472))

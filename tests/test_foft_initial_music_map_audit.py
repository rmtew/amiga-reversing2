"""Synthetic serialized-program properties, not guest execution or input probes."""
import pytest

from tools.foft_initial_music_map_audit import (
    scoped_static_references,
    selected_map_cell,
    serialized_contract,
)


def test_each_known_base_and_masked_selector_has_separate_map_cell_and_bounded_header():
    cells=[]
    for base in(0,8,16,24):
        for selector in range(8):
            c=selected_map_cell(base,selector);cells.append(c['map_runtime'])
            assert 0<=c['index']<32 and 0x58B00<=c['map_runtime']<0x58B20
            assert c['initialized_word_offset']==4*selector
            assert 0x590D0<=c['header_runtime']<0x591B0
    assert len(set(cells))==32
    assert selected_map_cell(0,3)['header_runtime']==selected_map_cell(8,3)['header_runtime']
    assert selected_map_cell(0,3)['map_runtime']!=selected_map_cell(8,3)['map_runtime']


@pytest.mark.parametrize(('base','selector'),[(1,0),(32,0),(0,8),(0,-1),(True,0),(0,True)])
def test_a_source_table_extent_does_not_validate_an_unknown_base_or_unmasked_selector(base,selector):
    with pytest.raises(ValueError,match='base|masked'):selected_map_cell(base,selector)


def run(pattern,order,base=0):
    data=bytes(pattern+order)
    return serialized_contract(data,[(0,len(pattern))],[(len(pattern),len(data))],[base])[0]


def test_valid_transpose_and_fade_parameters_are_not_reinterpreted_as_order_opcodes():
    r=run([0x80,0x20,2,0xFF],[0xFE,0xF0,0xFD,0xFF,0,0xFF])
    assert not r['remap_packets']
    assert len(r['parameter_packets'])==2
    assert r['instrument_indices']==[0]
    assert r['first_serialized_note']['preceded_by_serialized_select']


def test_a_supported_remap_packet_remains_an_explicit_unclosed_writer_class():
    r=run([0x81,0x20,2,0xFF],[0xF0,0x80,0,0xFF],base=8)
    assert r['remap_packets']==[{'source_offset':4,'selector':0}]
    assert r['map_indices']==[9]


def test_note_prefix_evidence_does_not_assume_initial_cached_instrument_is_a_header():
    r=run([0x20,2,0xFF],[0,0xFF])
    assert not r['first_serialized_note']['preceded_by_serialized_select']
    assert not r['instrument_indices']


def test_rest_has_no_note_or_new_instrument_claim_and_parameter_ff_is_consumed():
    r=run([0x7F,0xFF,0xFF],[0,0xFF])
    assert r['first_serialized_note']is None and not r['explicit_select_sites']


def test_repeated_pattern_reference_does_not_duplicate_a_static_selection_site():
    r=run([0x82,0x20,2,0xFF],[0,0,0xFF],base=16)
    assert len(r['explicit_select_sites'])==1 and r['map_indices']==[18]
    assert r['pattern_indices']==[0]


def test_channel_order_pairing_is_not_assumed_from_equal_pattern_contents():
    with pytest.raises(ValueError,match='correspondence'):
        serialized_contract(bytes([0xFF,0xFF]),[(0,1)],[(1,2)],[])


def test_local_reference_check_retains_source_coordinates_without_a_new_control_edge():
    r=scoped_static_references({'code_start_refs':[{'offset':0x820,'source_offset':0x810}]},
                              {0x1020:(0x1000,0x1100)})
    assert r==[{'local_runtime':0x1020,'owner_runtime':0x1000,'known_static_sources':[0x1010]}]


@pytest.mark.parametrize('source',[0x700,None])
def test_foreign_or_unknown_static_reference_is_not_relabelled_as_a_proven_local(source):
    with pytest.raises(ValueError,match='foreign|unknown'):
        scoped_static_references({'code_start_refs':[{'offset':0x820,'source_offset':source}]},
                                 {0x1020:(0x1000,0x1100)})

"""Source arithmetic and certificate rejection; no game bytes or guest execution."""
from itertools import product

import pytest

from tools.foft_near_scenery_audit import (
    PROTECTED,
    chain_indices,
    cover_stores,
    edge_envelope,
    glyph_cycle,
    mask_rectangle,
    store_domain,
)


def test_all_small_order_ties_have_bounded_forward_and_reverse_chains():
    for n in range(3,7):
        for ys in product((-32768,15,32767),repeat=n):
            for direction in (-1,1):
                chain=chain_indices(ys,direction)
                assert 2<=len(chain)<=n<=6
                assert ys[chain[0]]==min(ys) and ys[chain[-1]]==max(ys)
                assert all(b==(a+direction)%n for a,b in zip(chain,chain[1:],strict=False))


@pytest.mark.parametrize(('ys','direction'),[([0,1],1),([0]*7,-1),([32768]*3,1),([0]*3,0)])
def test_chain_contract_refuses_unproved_count_word_or_direction(ys,direction):
    with pytest.raises(ValueError,match='requires'):
        chain_indices(ys,direction)


def test_every_admitted_minimum_has_at_most_113_edge_slots_without_assuming_positive_minimum():
    for minimum in range(-32768,128):
        for last in (max(15,minimum),127):
            for side in (0,1):
                lo,hi=edge_envelope(minimum,last,side)
                assert 0x16110<=lo<hi<=0x162D4
                assert (hi-lo-2)//4+1<=113


@pytest.mark.parametrize(('minimum','last','side'),[(128,128,0),(-32769,127,0),(16,15,0),(0,14,1),(0,127,2)])
def test_edge_envelope_keeps_clipped_control_premises(minimum,last,side):
    with pytest.raises(ValueError,match='requires'):
        edge_envelope(minimum,last,side)


def test_all_clipped_horizontal_pairs_have_safe_programmed_rectangles_not_dma_evidence():
    for left in range(25,295):
        for right in range(left,295):
            for bank in (0,0x8000):
                p=mask_rectangle(left,right,15,127,bank)
                assert p['rows']==113 and 2<=p['words_per_row']<=18
                assert 0x166B2<=p['programmed_mask_and_cleanup'][0]<p['programmed_mask_and_cleanup'][1]<=0x17858
                for plane in p['programmed_planes']:
                    assert not any(plane[0]<end and start<plane[1] for start,end in PROTECTED.values())
                assert not p['actual_dma_quiescence_or_visibility_proved']


@pytest.mark.parametrize('args',[(24,30,15,127,0),(25,295,15,127,0),(25,30,14,127,0),
                                 (25,30,15,128,0),(25,30,15,127,1),(30,25,15,127,0)])
def test_rectangles_refuse_missing_clip_or_bank_premise(args):
    with pytest.raises(ValueError,match='requires'):
        mask_rectangle(*args)


def site(pc,base=None,absolute=None,width=2,displacement=0,indexed=False,update=0):
    return {'runtime':pc,'operand_index':1,'operand':{
        'memory':True,'base_register':base,'absolute_address':absolute,'width_bytes':width,
        'displacement':displacement,'indexed':indexed,'ea_update':update,'bulk_transfer':False}}


def test_complete_cover_retains_read_modify_write_width_and_rejects_an_alias():
    safe=site(0x100,absolute=0x2000,width=4)
    cover,counts=cover_stores([safe],{},PROTECTED)
    assert counts=={'fixed_cpu_store':1} and cover[0]['byte_envelope']==[0x2000,0x2004]
    with pytest.raises(ValueError,match='intersects'):
        cover_stores([site(0x100,absolute=0x4E724,width=4)],{},PROTECTED)


def test_new_unknown_store_is_not_silently_assumed_pure_or_disjoint():
    with pytest.raises(ValueError,match='uncovered writer'):
        cover_stores([site(0x100,'A0')],{},PROTECTED)


def test_duplicate_sites_cannot_inflate_complete_coverage():
    s=site(0x100,absolute=0x2000)
    with pytest.raises(ValueError,match='duplicate'):
        cover_stores([s,s],{},PROTECTED)


@pytest.mark.parametrize('s',[site(0x15F20,'A5',displacement=14),site(0x4F382,'A1',displacement=12),
                            site(0x2763E,'A1',width=4),site(0x100,'A7',indexed=True,update=2)])
def test_writer_shape_changes_fail_instead_of_reusing_old_domains(s):
    with pytest.raises(ValueError,match='differs|escaped|unexpected'):
        store_domain(s,{0x2763E:[0x15BD0,0x15BD2]})


def test_glyph_cycle_is_conditional_on_original_word_protocol():
    assert [glyph_cycle(v)for v in (49,51,53,55)]==[51,53,55,49]
    assert glyph_cycle(0)==2 and glyph_cycle(32767)==32769
    # ST to the first big-endian BYTE is idempotent; it is not an event counter.
    for low in range(256):
        pending=0xFF00|low
        assert (pending|0xFF00)==pending


def test_main_code_nonintersection_is_not_assumed_for_an_indirect_domain():
    from tools.foft_near_scenery_audit import exclude_accepted_code
    cover=[{'byte_envelope':[0x1000,0x1004]}]
    assert exclude_accepted_code(cover,[(0x1004,0x2000)])
    with pytest.raises(ValueError,match='intersects accepted code'):
        exclude_accepted_code(cover,[(0x1002,0x2000)])

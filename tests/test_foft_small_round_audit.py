"""Bounded source-data partitions, not guest programs or runtime probes."""
import pytest

from tools.foft_small_round_audit import profile_partition, span_word_envelope


def test_adjacent_profiles_keep_shared_interior_pointer_slots_and_dbf_extra_row():
    data=bytes.fromhex('00000001000200010003000400050006')
    r=profile_partition(data,[0,6,6],0,len(data))
    assert r==[{'runtime':0,'end_runtime':6,'rows':1,'row_count_minus_one':0,'pointer_slots':[0]},
               {'runtime':6,'end_runtime':16,'rows':2,'row_count_minus_one':1,'pointer_slots':[1,2]}]


def test_source_origin_is_independent_of_physical_pointer_identity():
    data=bytes(6)
    r=profile_partition(data,[0x800,0x800],0x800,0x806,origin=0x800)
    assert r[0]['pointer_slots']==[0,1] and r[0]['end_runtime']==0x806


@pytest.mark.parametrize(('pointers','start','end'),[
    ([0],0,5),([0],0,7),([2],0,6),([1],0,6),([-2],0,6),([6],0,6),
    ([True],0,6),([],0,6),([0,2],0,6),([0],-1,6),([0],0,8),
])
def test_inexact_or_outside_partition_never_acquires_an_ownership_claim(pointers,start,end):
    with pytest.raises(ValueError,match="profile"):
        profile_partition(bytes(7),pointers,start,end)


def test_count_word_is_unsigned_and_cannot_hide_an_out_of_bounds_body_first_loop():
    with pytest.raises(ValueError,match='exact extent'):
        profile_partition(bytes.fromhex('ffff00000000'),[0],0,6)


def test_word_envelope_keeps_planes_separate_and_includes_masked_boundary_words():
    spans=span_word_envelope()
    assert len(spans)==4*112
    assert spans[0]==[642,678] and spans[111]==[5082,5118]
    assert spans[112]==[8192+642,8192+678]
    assert all(hi-lo==36 for lo,hi in spans)
    assert spans[-1][1]<4*8192


@pytest.mark.parametrize('values',[(15,128,25,295),(16,129,25,295),(16,128,24,295),(16,128,25,296)])
def test_different_clip_bounds_need_their_own_source_proof(values):
    with pytest.raises(ValueError,match='unproved'):span_word_envelope(*values)


def span_copy_fixture():
    from copy import deepcopy
    first=[{'source_offset':0,'mnemonic':'move','operand_facts':[
        {'access':'memory_read','base_register':'A5','width_bytes':2,'displacement':6},
        {'access':'register_write','direct_register':'D0','width_bytes':2}]},
        {'source_offset':2,'mnemonic':'bne','operand_facts':[{'access':'branch_target','width_bytes':2}]},
        {'source_offset':4,'mnemonic':'rts','operand_facts':[]}]
    second=deepcopy(first)
    for r in second:r['source_offset']+=100
    second[0]['operand_facts'][0]['displacement']=14
    second[1]['operand_facts'][0]['width_bytes']=1
    edges=[{'source_offset':0,'target_offset':2,'kind':1},
           {'source_offset':2,'target_offset':4,'kind':2},
           {'source_offset':2,'target_offset':4,'kind':1},
           {'source_offset':4,'target_offset':0xFFFFFFFF,'kind':5},
           {'source_offset':102,'target_offset':4,'kind':2},
           {'source_offset':102,'target_offset':104,'kind':1},
           {'source_offset':104,'target_offset':0xFFFFFFFF,'kind':5}]
    return first,second,edges


def test_span_copy_keeps_pattern_shift_short_branch_and_shared_return_distinct():
    from tools.foft_small_round_audit import matching_span_contract
    a,b,edges=span_copy_fixture()
    result=matching_span_contract(a,b,edges)
    assert result['pattern_read_field_shift']==8 and result['shared_clipped_return_checked']


@pytest.mark.parametrize('change',['field','width','root','branch','external','fallthrough','missing'])
def test_span_copy_does_not_hide_changed_fields_effects_or_successors(change):
    from tools.foft_small_round_audit import matching_span_contract
    a,b,edges=span_copy_fixture()
    if change=='field':b[0]['operand_facts'][0]['displacement']=16
    if change=='width':b[0]['operand_facts'][0]['width_bytes']=4
    if change=='root':b[0]['operand_facts'][0]['base_register']='A3'
    if change=='branch':edges[4]['target_offset']=100
    if change=='external':edges[4]['target_offset']=200
    if change=='missing':edges=[e for e in edges if e['kind']!=2]
    if change=='fallthrough':edges.append({'source_offset':100,'target_offset':104,'kind':1})
    with pytest.raises(ValueError,match='span copy'):matching_span_contract(a,b,edges)

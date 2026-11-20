"""Bounded prefix/data-flow arithmetic; no game bytes or guest execution."""
from copy import deepcopy

import pytest

from tools.foft_model_header_audit import (
    first_read_address,
    fold_iteration_paths,
    prefix_regions,
    storage_forms,
    stream_regions,
)


def test_prefix_write_extent_and_final_nonincremented_cursor_are_distinct():
    r,=prefix_regions([0x1006])
    assert r['span']==[0x1000,0x1006]
    assert r['word_spans']==[[0x1000,0x1002],[0x1002,0x1004],[0x1004,0x1006]]
    assert r['final_writer_cursor']==0x1004


@pytest.mark.parametrize('values',[[0x1006,0x1006],[0x1006,0x1008],[0x801],[0x804],[0x78002]])
def test_unmapped_odd_duplicate_and_overlapping_prefixes_refuse(values):
    with pytest.raises(ValueError,match='prefix|duplicate'):prefix_regions(values)


def test_every_word_counter_visit_has_linear_source_output_separation():
    for i in range(65536):
        last=stream_regions(i,i);first=stream_regions(i,0)
        assert first['view'][1]<=last['view'][1]<=last['state'][0]
        assert not last['physical_bus_alias_or_execution_proved']
    assert stream_regions(63,63)['inside_two_existing_64_record_prefixes']
    assert not stream_regions(64,64)['inside_two_existing_64_record_prefixes']


@pytest.mark.parametrize(('i','j'),[(-1,0),(0,1),(65536,0),(True,0),(1,-1)])
def test_lineage_cannot_be_assumed_for_an_arbitrary_index_pair(i,j):
    with pytest.raises(ValueError,match='lineage'):stream_regions(i,j)


def test_an_altered_source_output_root_is_not_accepted_by_the_count_bound():
    with pytest.raises(ValueError,match='alias'):stream_regions(0,0,source=0x1000,dest=0x1000)


def test_decoded_pc_relative_first_word_has_a_signed_source_address():
    row={'source_offset':0x800,'operand_facts':[{'access':'memory_read','width_bytes':2,
         'pc_relative':True,'indexed':False,'displacement_known':True,'displacement':-8,'ea_shape_id':8}]}
    assert first_read_address(row)==0xFFA
    row['operand_facts'][0]['indexed']=True
    assert first_read_address(row)is None
    row['operand_facts'][0].update(indexed=False,ea_shape_id=7)
    with pytest.raises(ValueError,match='shape'):first_read_address(row)


def metadata(model=0x1006):
    lo=model-6-0x800
    return {'custom_structs':[{'name':'ModelOrientationPrefix','size':6,'fields':[
        {'name':'orientation'+str(i),'offset':i*2,'size':2,'type':'WORD'}for i in range(3)]}],
        'data_block_layouts':[{'name':'header','source_start':lo,'source_end':lo+6,
        'default_unit':'word','elements':[{'offset':0,'width':6,'array_count':1,'array_stride':6,
        'type_binding':{'binding_kind':'custom_struct','bound_type_id':'ModelOrientationPrefix','element_width':6}}]}]}


def test_source_schema_requires_one_contained_matching_binding():
    m=metadata();assert storage_forms(m,{0x1006})[0]['kind']=='existing_record_binding'
    for change in ('owner','type','competing'):
        x=deepcopy(m)
        if change=='owner':x['data_block_layouts'][0]['source_end']-=2
        elif change=='type':x['custom_structs'][0]['fields'][0]['type']='APTR'
        else:x['data_block_layouts'].append(deepcopy(x['data_block_layouts'][0]))
        with pytest.raises(ValueError,match='prefix|schema'):storage_forms(x,{0x1006})


def test_independent_hartley_scalar_partition_is_preserved_not_replaced():
    m=metadata(0x25A54);m['data_block_layouts'][0]['elements']=[
        {'offset':i*2,'width':2,'kind':'scalar'}for i in range(3)]
    old=deepcopy(m)
    assert storage_forms(m,{0x25A54})[0]['kind']=='preserved_independent_scalar_partition'
    assert m==old
    m['data_block_layouts'][0]['elements'][1]['reference_interpretation']={'kind':'pointer'}
    with pytest.raises(ValueError,match='partition'):storage_forms(m,{0x25A54})


def test_iteration_fold_proves_both_paths_and_keeps_extra_advance_visible():
    graph={0:{'cost':(0,0,0),'terminal':False,'successors':[1,2]},
           1:{'cost':(1,1,1),'terminal':True,'successors':[]},
           2:{'cost':(1,0,1),'terminal':True,'successors':[]}}
    assert fold_iteration_paths(graph,0)=={(1,1,1),(1,0,1)}
    graph[0]['cost']=(1,0,0)
    assert fold_iteration_paths(graph,0)=={(2,1,1),(2,0,1)}
    graph[2].update(terminal=False,successors=[0])
    with pytest.raises(ValueError,match='cycle'):fold_iteration_paths(graph,0)
    graph[2]['successors']=[]
    with pytest.raises(ValueError,match='boundary'):fold_iteration_paths(graph,0)

"""Pinned native operand/CFG contracts do not manufacture callee effects."""

from copy import deepcopy

import pytest

from tools.foft_render_contract_audit import packed_draw_return_contract


def sample():
    pairs=[(0xE78E,'move'),(0xE792,'bmi'),(0xE796,'move'),(0xE79A,'move'),
           (0xE79C,'bpl'),(0xE79E,'neg'),(0xE7A0,'tst'),(0xE7A2,'bpl'),
           (0xE7A4,'neg'),(0xE7A6,'cmp'),(0xE7A8,'ble'),(0xE7AC,'cmp'),
           (0xE7AE,'ble'),(0xE7B2,'movea'),(0xE7B6,'movem'),(0xE7BA,'move'),
           (0xE7C0,'move'),(0xE7C8,'move'),(0xE7D0,'move'),(0xE7D6,'cmp'),
           (0xE7DA,'ble'),(0xE7DC,'move'),(0xE7E2,'move'),(0xE7EA,'move'),
           (0xE7F0,'clr'),(0xE7F2,'jsr'),(0xE7F8,'move'),(0xE7FE,'move'),
           (0xE804,'jsr'),(0xE80A,'bra'),(0xE80E,'jsr'),(0xE810,'movem'),(0xE814,'rts')]
    rows=[{'source_offset':pc-0x800,'mnemonic':name,'provenance':'accepted_instruction',
           'size':(pairs[i+1][0]if i+1<len(pairs)else 0xE816)-pc,
           'operand_facts':[],'address_evidence':[]}for i,(pc,name)in enumerate(pairs)]
    at={r['source_offset']+0x800:r for r in rows}
    def reg(name,width=2):return {'direct_register':name,'memory':False,'width_bytes':width}
    def memory(offset=0,width=2,base='A0'):
        return {'memory':True,'base_register':base,'indexed':False,'ea_update':0,
                'displacement_known':True,'displacement':offset,'width_bytes':width}
    def address(row,index,value,width=2):
        p=memory(width=width,base=None)
        row['address_evidence'].append({'operand_index':index,'has_address':True,'address':value})
        return p
    for pc,offset,dest in [(0xE78E,4,'D2'),(0xE796,2,'D0'),(0xE79A,0,'D1')]:
        at[pc]['operand_facts']=[memory(offset),reg(dest)]
    at[0xE7B2]['operand_facts']=[memory(6,4),reg('A1',4)]
    for pc,dest in [(0xE79E,'D1'),(0xE7A0,'D0'),(0xE7A4,'D0')]:at[pc]['operand_facts']=[reg(dest)]
    for pc,source in [(0xE7A6,'D1'),(0xE7AC,'D0')]:at[pc]['operand_facts']=[reg(source),reg('D2')]
    for pc,write in [(0xE7B6,True),(0xE810,False)]:
        rs={'access':'register_list_read'if write else'register_list_write','width_bytes':4,
            'bulk_transfer':True,'register_list':[f'{k}{n}'for k in ['D','A']for n in range(8)]}
        mem={**memory(width=4,base='A7'),'access':'memory_write'if write else'memory_read',
             'bulk_transfer':True,'ea_update':2 if write else 1}
        at[pc]['operand_facts']=[rs,mem]if write else[mem,rs]
    for pc,offset,target in [(0xE7BA,0,0x15E5A),(0xE7C0,2,0x15E5C),(0xE7C8,4,0x15E5E)]:
        at[pc]['operand_facts']=[memory(offset),address(at[pc],1,target)]
    at[0xE7D0]['operand_facts']=[address(at[0xE7D0],0,0x15E5E),reg('D0')]
    at[0xE7D6]['operand_facts']=[{'immediate_value':0x4000},reg('D0')]
    at[0xE80E]['operand_facts']=[memory(width=0,base='A1')]
    for pc,dest,target in [(0xE6F0,'A0',0xE816),(0xE6F4,'A1',0xEB16),
                           (0xE706,'A0',0xE816),(0xE770,'A1',0xE816),(0xE774,'A0',0xEB16)]:
        row={'source_offset':pc-0x800,'mnemonic':'lea','provenance':'accepted_instruction',
             'size':4,'operand_facts':[],'address_evidence':[]}
        row['operand_facts']=[address(row,0,target,4),reg(dest,4)];rows.append(row)
    edges=[]
    for pc,target in [(0xE792,0xE814),(0xE79C,0xE7A0),(0xE7A2,0xE7A6),
                      (0xE7A8,0xE814),(0xE7AE,0xE814),(0xE7DA,0xE80E),(0xE80A,0xE810)]:
        for kind,dest in [('jump'if pc==0xE80A else'branch',target),*([('fallthrough',pc+at[pc]['size'])]if pc!=0xE80A else[])]:
            edges.append({'source_offset':pc-0x800,'kind':kind,'target_offset':dest-0x800,
                          'target_section_index':0,'status':'resolved'})
    edges+=[{'source_offset':0xE80E-0x800,'kind':'call','target_offset':0x19906-0x800,
             'target_section_index':0,'status':'resolved'},
            {'source_offset':0xE80E-0x800,'kind':'call','target_offset':None,
             'target_section_index':None,'status':'unresolved'}]
    summaries=[{'callable_kind':'direct','callable_section_index':0,'entry_offset':0x19906-0x800,
                'function_summary_id':'fixture','terminal_reason':'none',
                'effects':{k:{'state':'unknown'}for k in ['registers','memory','escapes']}}]
    return sorted(rows,key=lambda r:r['source_offset']),edges,summaries


def test_snapshot_and_return_receipt_retains_all_conditions():
    result=packed_draw_return_contract(*sample())
    assert result['near_call_A1_equals_current_row_LONG']
    assert result['frame_bytes']==64
    assert result['byte_equality_count_bound']==16
    assert result['copy_spans_disjoint_within_bound']
    assert any('post-draw M bound is not proved'in c for c in result['conditional_multi_row_return']['conditions'])
    assert result['snapshot_overwritten_entry_registers']==['D0.W','D1.W','D2.W','A1']
    assert not result['unconditional_entry_register_preservation']
    assert not result['memory_restored_by_register_reload']
    assert not result['global_count_or_record_preservation_proved']
    assert not result['individual_effects_close_dispatch']
    assert result['unresolved_call_edges']==1
    assert result['conditional_multi_row_return']['D7.W']==65535
    assert result['conditional_single_row_return']['D7.W']==0
    assert result['target_effects'][0]['memory_state']=='unknown'


@pytest.mark.parametrize('change',['field','width','frame_register','frame_update','restore',
    'branch','unexpected_fallthrough','overwritten_a1','call_offset','call_register','root','missing','unaccepted','threshold','no_summary','duplicate_summary'])
def test_changed_source_or_incomplete_effects_refuses_a_witness(change):
    rows,edges,summaries=deepcopy(sample());at={r['source_offset']+0x800:r for r in rows}
    if change=='field':at[0xE7B2]['operand_facts'][0]['displacement']=4
    elif change=='width':at[0xE7B2]['operand_facts'][0]['width_bytes']=2
    elif change=='frame_register':at[0xE7B6]['operand_facts'][0]['register_list'].pop()
    elif change=='frame_update':at[0xE7B6]['operand_facts'][1]['ea_update']=1
    elif change=='restore':at[0xE810]['operand_facts'][1]['access']='register_list_read'
    elif change=='branch':edges[0]['target_offset']+=2
    elif change=='unexpected_fallthrough':edges.append({'source_offset':0xE80A-0x800,'target_offset':0xE80E-0x800,'kind':'fallthrough','target_section_index':0,'status':'resolved'})
    elif change=='overwritten_a1':at[0xE7BA]['operand_facts'][1].update(direct_register='A1',access='register_write')
    elif change=='call_offset':at[0xE80E]['operand_facts'][0]['displacement']=4
    elif change=='call_register':at[0xE80E]['operand_facts'][0]['base_register']='A2'
    elif change=='root':at[0xE774]['address_evidence'][0]['address']+=4
    elif change=='missing':rows.remove(at[0xE7D0])
    elif change=='unaccepted':at[0xE7B2]['provenance']='candidate'
    elif change=='threshold':at[0xE7D6]['operand_facts'][0]['immediate_value']=0x2000
    elif change=='no_summary':summaries.clear()
    else:summaries*=2
    with pytest.raises(ValueError,match='draw return|operand|contract window'):
        packed_draw_return_contract(rows,edges,summaries)

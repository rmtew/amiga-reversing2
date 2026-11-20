"""Opaque copy fragments share a row; no source bytes become pointer values."""

from copy import deepcopy

import pytest

from tools.foft_render_contract_audit import scenery_record_copy_contract


def sample():
    rows=[]
    def ea(offset=0,index=None,base='A0',update=0):
        return {'memory':True,'base_register':base,'indexed':index is not None,
                'index_register':index,'index_width_bytes':2,'ea_update':update,
                'width_bytes':4,'displacement_known':True,'displacement':offset}
    def reg(name,width=4):return {'memory':False,'direct_register':name,'width_bytes':width}
    def put(pc,name,ops,size):
        r={'source_offset':pc-0x800,'size':size,'mnemonic':name,
           'provenance':'accepted_instruction','operand_facts':ops,'address_evidence':[]}
        rows.append(r);return r
    for pc,offset in [(0xE6C8,0),(0xE6CE,4),(0xE6D4,8)]:put(pc,'move',[ea(offset,'D5'),ea(offset,'D6')],6)
    for pc,offset,size in [(0xE754,0,4),(0xE758,4,6),(0xE75E,8,6)]:put(pc,'move',[ea(offset,'D6'),ea(offset)],size)
    for pcs,offset,sizes in [([0xE722,0xE724,0xE728],0,[2,4,4]),
                            ([0xE72C,0xE730,0xE736],4,[4,6,4]),
                            ([0xE73A,0xE73E,0xE744],8,[4,6,4])]:
        put(pcs[0],'move',[ea(offset),reg('D2')],sizes[0])
        put(pcs[1],'move',[ea(offset,'D6'),ea(offset)],sizes[1])
        put(pcs[2],'move',[reg('D2'),ea(offset,'D6')],sizes[2])
    for first in [0xE6FA,0xE780]:
        for i in range(4):put(first+2*i,'move',[ea(update=1),ea(base='A1',update=1)],2)
    for pc,name,dest in [(0xE572,'mulu','D6'),(0xE6A0,'subi','D6'),(0xE6DA,'subi','D5'),
                         (0xE712,'mulu','D7'),(0xE748,'subi','D6'),(0xE764,'subi','D7')]:
        put(pc,name,[{'immediate_value':12},reg(dest,2)],4)
    put(0xE6E8,'tst',[reg('D7',2)],2)
    for pc,source,dest in [(0xE6EE,'D7','D6'),(0xE70A,'D6','D7')]:
        put(pc,'move',[reg(source,2),reg(dest,2)],2)
    for pc in [0xE6F8,0xE70C]:put(pc,'subq',[{'immediate_value':1},reg('D7',2)],2)
    put(0xE7B2,'movea',[ea(6),reg('A1')],4)
    put(0xE80E,'jsr',[ea(base='A1')],2)
    r=put(0xE778,'move',[{'memory':True,'width_bytes':2},reg('D7',2)],6)
    r['address_evidence']=[{'operand_index':0,'has_address':True,'address':0x4E726}]
    put(0xE77E,'subq',[{'immediate_value':1},reg('D7',2)],2)
    put(0xE78C,'rts',[],2)
    edges=[]
    for pc,name,target,size in [(0xE6EA,'ble',0xE814,4),(0xE702,'dbf',0xE6FA,4),
                                 (0xE70E,'beq',0xE78E,4),(0xE788,'dbf',0xE780,4)]:
        put(pc,name,[reg('D7',2)]if name=='dbf'else[],size)
        edges += [{'source_offset':pc-0x800,'target_offset':target_pc-0x800,
                   'target_section_index':0,'kind':kind,'status':'resolved'}
                  for kind,target_pc in [('branch',target),('fallthrough',pc+size)]]
    return sorted(rows,key=lambda r:r['source_offset']),edges


def test_copy_receipt_keeps_pointer_halves_opaque_and_restore_count_separate():
    rows,edges=sample();result=scenery_record_copy_contract(rows,edges)
    assert result['pointer_byte_span']==[6,10]
    assert [f['pointer_byte_offset']for f in result['pointer_fragments']]==[0,2]
    assert result['backup_chunk_bytes']==16
    assert result['fragments_require_same_source_row']
    assert not result['long_copies_are_whole_pointer_values']
    assert not result['loaded_value_or_callable_closure']
    assert not result['callee_or_alias_effects_proved']
    assert result['positive_restore_count_required_for_count_sized_copy']
    assert not result['restore_count_rechecked_locally']
    assert not result['positive_restore_count_proved']


@pytest.mark.parametrize('change',['copy_index','copy_offset','update','width','temp',
                                  'missing','unaccepted','count','call','loop','guard','decrement',
                                  'backup_count','singleton_count','entry_count','backup_loop','stride_provenance'])
def test_copy_and_consumer_mismatches_are_refused(change):
    rows,edges=deepcopy(sample());at={r['source_offset']+0x800:r for r in rows}
    if change=='copy_index':at[0xE6CE]['operand_facts'][0]['index_register']='D4'
    elif change=='copy_offset':at[0xE6D4]['operand_facts'][0]['displacement']=6
    elif change=='update':at[0xE6CE]['operand_facts'][0]['ea_update']=1
    elif change=='width':at[0xE6CE]['operand_facts'][0]['width_bytes']=2
    elif change=='temp':at[0xE736]['operand_facts'][0]['direct_register']='D3'
    elif change=='missing':rows.remove(at[0xE780])
    elif change=='unaccepted':at[0xE722]['provenance']='candidate'
    elif change=='count':at[0xE778]['address_evidence'][0]['address']+=2
    elif change=='loop':edges[-2]['target_offset']+=2
    elif change=='guard':at[0xE77E]['mnemonic']='tst'
    elif change=='backup_count':at[0xE6EE]['operand_facts'][0]['direct_register']='D5'
    elif change=='singleton_count':at[0xE70C]['operand_facts'][0]['immediate_value']=2
    elif change=='entry_count':at[0xE6E8]['operand_facts'][0]['direct_register']='D5'
    elif change=='backup_loop':at[0xE702]['operand_facts'][0]['direct_register']='D5'
    elif change=='stride_provenance':at[0xE572]['provenance']='candidate'
    elif change=='decrement':at[0xE77E]['operand_facts'][0]['immediate_value']=2
    else:at[0xE80E]['operand_facts'][0]['base_register']='A2'
    with pytest.raises(ValueError,match='scenery|operand|contract window|operation'):
        scenery_record_copy_contract(rows,edges)

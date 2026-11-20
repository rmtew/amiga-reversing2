"""Synthetic operand/CFG witnesses; no game bytes or guest execution."""

from copy import deepcopy

import pytest

from tools.foft_render_contract_audit import scenery_compacting_append_contract


def sample():
    def p(reg=None,*,access='register_read',width=2,base=None,update=0,index=None,offset=0,immediate=None):
        return {'direct_register': reg,'access': access,'width_bytes': width,'memory': base is not None,
                    'base_register': base,'ea_update': update,'indexed': index is not None,
                    'index_register': index,'index_width_bytes': 2,'displacement_known': True,
                    'displacement': offset,'immediate_value': immediate}
    rows={pc:{'source_offset': pc-0x800,'size': 2,'provenance': 'accepted_instruction',
                 'mnemonic': 'nop','operand_facts': [],'typed_accesses': [],'address_evidence': []}
          for pc in range(0x4AE0A,0x4AE94,2)}
    def put(pc,name,ops,size=2,address=None):
        for at in range(pc+2,pc+size,2):rows.pop(at,None)
        rows[pc]={'source_offset': pc-0x800,'size': size,'provenance': 'accepted_instruction',
                      'mnemonic': name,'operand_facts': ops,'typed_accesses': [],'address_evidence': []}
        if address is not None:
            rows[pc]['address_evidence']=[{'operand_index': 0,'has_address': True,'address': address}]
        return rows[pc]
    put(0x4AE0A,'clr',[p('D0',access='register_write')])
    put(0x4AE0C,'move',[p('D0'),p('D7',access='register_write')])
    for pc,reg,addr in [(0x4AE0E,'A0',0xE816),(0x4AE14,'A1',0x15BD0),(0x4AE1A,'A4',0x4A002)]:
        q=p(access='compute_address',width=4);q['memory']=True
        put(pc,'lea',[q,p(reg,access='register_write',width=4)],6,addr)
    def imm(pc,name,value,reg,width=2,size=2):
        put(pc,name,[p(access='immediate',width=width,immediate=value),p(reg,access='register_write',width=width)],size)
    imm(0x4AE20,'moveq',15,'D6',4)
    row=put(0x4AE22,'movea',[p(width=4),p('A2',access='register_write',width=4)],4,0x4BC00)
    row['operand_facts'][0]['memory']=True
    put(0x4AE26,'move',[p(base='A2',update=1,access='memory_read'),p('D1',access='register_write')])
    imm(0x4AE2A,'addq',1,'D7')
    put(0x4AE2C,'move',[p(base='A1',index='D0',width=4,access='memory_read'),p(base='A0',update=1,width=4,access='memory_write')],4)
    put(0x4AE30,'move',[p(base='A1',index='D0',offset=4,access='memory_read'),p(base='A0',update=1,access='memory_write')],4)
    imm(0x4AE34,'andi',0xF00,'D1',size=4);imm(0x4AE38,'lsr',8,'D1')
    for pc in [0x4AE3A,0x4AE3C]:put(pc,'add',[p('D1'),p('D1',access='register_write')])
    put(0x4AE3E,'cmp',[p(access='immediate',immediate=32),p('D1')],4)
    imm(0x4AE44,'moveq',32,'D1',4)
    for pc in [0x4AE46,0x4AE56]:
        second=p(base='A0',update=1,width=4,access='memory_write') if pc==0x4AE46 else p('A6',width=4,access='register_write')
        row=put(pc,'move' if pc==0x4AE46 else 'movea',[p(base='A4',index='D1',width=4,access='memory_read'),second],4)
        row['typed_accesses']=[{'operand_index': 0,'root_struct_name': 'SceneryCallbackCell','field_name': 'drawAddress','word_index': {'record_count': 9,'index_width': 2,'access_width': 4,'index_domain': {'lower_bound': 0,'upper_bound': 32,'known_bits_mask': 0xFFC3,'known_bits_value': 0}}}]
    put(0x4AE4A,'clr',[p(base='A0',update=1,access='memory_write')])
    row=put(0x4AE7E,'st',[p(access='memory_write',width=1)],6,0x4E2B8);row['operand_facts'][0]['memory']=True
    row=put(0x4AE84,'move',[p(access='immediate',immediate=12),p(access='memory_write')],8)
    row['operand_facts'][1]['memory']=True;row['address_evidence']=[{'operand_index': 1,'has_address': True,'address': 0x2F7DA}]
    imm(0x4AE8C,'addi',10,'D0',size=4)
    edges=[]
    for pc,name,target,size in [(0x4AE28,'beq',0x4AE8C,2),(0x4AE42,'ble',0x4AE46,2),
            (0x4AE52,'beq',0x4AE8C,4),(0x4AE5E,'bpl',0x4AE62,2),
            (0x4AE6A,'bgt',0x4AE8C,2),(0x4AE76,'bpl',0x4AE7A,2),
            (0x4AE7C,'bgt',0x4AE8C,2),(0x4AE90,'dbf',0x4AE26,4)]:
        put(pc,name,([p('D6')]if name=='dbf'else[])+[p(access='branch_target')],size)
        edges += [{'source_offset': pc-0x800,'target_offset': dest-0x800,
                       'target_section_index': 0,'status': 'resolved','kind': kind}
                  for kind,dest in [('branch',target),('fallthrough',pc+size)]]
    return sorted(rows.values(),key=lambda r:r['source_offset']),edges


def test_counted_compaction_proves_a_coupled_cursor_not_a_callback_set():
    rows,edges=sample();result=scenery_compacting_append_contract(rows,edges)
    assert result['appended_count_range']==[0,16]
    assert result['maximum_written_bytes']==192
    assert result['point_read_extent_bytes']==156
    assert not result['bounds_checks_can_retract_append']
    assert not result['post_cull_or_callback_preservation_proved']
    assert not result['allocation_or_live_capacity_proved']
    assert not result['upper_halves_proved']
    assert result['count_register']=='D7.W'


@pytest.mark.parametrize('change',['count','counter','cursor','call','edge','missing_edge',
    'footprint','update','field','domain','alignment','point_step','descriptor','write','missing','counted_owner','return','trap','source_index','duplicate_update'])
def test_incomplete_or_contradictory_compaction_witness_is_refused(change):
    rows,edges=sample();rows=deepcopy(rows);at={r['source_offset']+0x800:r for r in rows}
    if change=='count':at[0x4AE20]['operand_facts'][0]['immediate_value']=16
    elif change in {'counter','cursor'}:
        at[0x4AE5A]['operand_facts']=[{'access': 'register_write','direct_register': 'D6'if change=='counter'else'A0','ea_update': 0}]
    elif change=='call':at[0x4AE5A]['operand_facts']=[{'access': 'branch_target'}]
    elif change=='edge':edges[0]['target_offset']-=2
    elif change=='missing_edge':edges.pop()
    elif change=='footprint':at[0x4AE46]['operand_facts'][1]['width_bytes']=2
    elif change=='update':at[0x4AE46]['operand_facts'][1]['ea_update']=2
    elif change=='field':at[0x4AE46]['typed_accesses']=[]
    elif change in {'domain','alignment','counted_owner'}:
        w=at[0x4AE46]['typed_accesses'][0]['word_index']
        if change=='domain':w['index_domain']['upper_bound']=65535
        elif change=='alignment':w['index_domain']['known_bits_mask']=0xFFC2
        else:w['record_count']=8
    elif change in {'return','trap'}:at[0x4AE5A]['mnemonic']='rts'if change=='return'else'trap'
    elif change=='source_index':at[0x4AE46]['operand_facts'][0]['index_width_bytes']=4
    elif change=='duplicate_update':at[0x4AE46]['operand_facts'].append(deepcopy(at[0x4AE46]['operand_facts'][1]))
    elif change=='point_step':at[0x4AE8C]['operand_facts'][0]['immediate_value']=12
    elif change=='descriptor':at[0x4AE26]['operand_facts'][0]['ea_update']=2
    elif change=='write':at[0x4AE5A]['operand_facts']=[{'access': 'memory_write','direct_register': None,'ea_update': 0}]
    else:rows.remove(at[0x4AE5A])
    with pytest.raises(ValueError, match="compacting|contract window|operand|operation"):scenery_compacting_append_contract(rows,edges)

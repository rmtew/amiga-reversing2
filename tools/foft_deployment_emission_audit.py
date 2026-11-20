"""Pinned type-6 and packed-action data contracts, not a runtime emulator.

Flag outcomes below are conditional possibilities after the original entry,
category/gate/proximity tests and returning helpers. Random correlations,
competing writes, ownership and actual visibility are not established here.
"""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from tools.foft_irq_write_audit import mem, require
from tools.foft_object_motion_count_audit import (
    check_indexed_action_write,
    copied_field_source,
)
from tools.foft_render_contract_audit import MAIN_SHA256, operand, window


def word(value):
    require(type(value)is int and 0<=value<=65535,'expected a WORD value')
    return value


def action_fields(value):
    value=word(value)
    return value&255,(value>>8)&15,(value>>12)&15


def middle_reload_update(value):
    value=word(value)
    middle=(value>>8)&15
    return (value&0xF0FF)|((((middle-1)&65535)<<8)&65535)


def upper_debit(value):
    value=word(value);candidate=(value-0x1000)&65535
    return None if candidate&0x8000 else candidate


def conditional_flag_paths(value):
    flags,middle,_=action_fields(value);out=[]
    if flags&32:
        out.append('effect_flag5')
        if middle==0:return tuple(out)
    if flags&16:return (*out,'emit_missile'if middle else'advance')
    for bit in (3,2,1):
        if flags&(1<<bit):return (*out,f'effect_flag{bit}')
    if flags&1:return (*out,'emit_flapper'if upper_debit(value)is not None else'advance')
    return (*out,'advance')


def check_grammar(rows,analysis):
    at={r['source_offset']+0x800:r for r in rows}
    for pc,src,dst,width in [(0x2EAD0,'D2','D3',1),(0x2EAD4,'D2','D4',1),
                             (0x2EC12,'D2','D3',2),(0x2EC22,'D3','D2',2)]:
        require(at[pc]['mnemonic']==('or'if pc==0x2EC22 else'move'),'packed register transfer differs')
        operand(at[pc],0,register=src,width=width);operand(at[pc],1,register=dst,width=width)
    for pc,op,value,reg in [(0x2EAD2,'lsr',8,'D2'),(0x2EAD6,'andi',15,'D4'),
        (0x2EADA,'lsr',4,'D2'),(0x2EADC,'andi',15,'D2'),(0x2EC14,'lsr',8,'D3'),
        (0x2EC16,'andi',15,'D3'),(0x2EC1A,'subq',1,'D3'),(0x2EC1C,'lsl',8,'D3'),
        (0x2EC1E,'andi',0xF0FF,'D2'),(0x2EC8E,'subi',0x1000,'D2')]:
        require(at[pc]['mnemonic']==op and at[pc]['operand_facts'][0].get('immediate_value')==value,
                'packed WORD operation differs')
        operand(at[pc],1,register=reg)
    for pc,bit in [(0x2EAE0,5),(0x2EB6C,4),(0x2EC2C,3),(0x2EC42,2),(0x2EC58,1),(0x2EC6C,0),(0x2EC74,5)]:
        require(at[pc]['mnemonic']=='btst'and at[pc]['operand_facts'][0].get('immediate_value')==bit
                and at[pc]['operand_facts'][1].get('direct_register')=='D3','flag priority read differs')
    links={(x['source_offset']+0x800,x['target_offset']+0x800)for x in analysis['edges']if x.get('target_offset',-1)>=0}
    for pc,op,target in [(0x2EAE4,'beq',0x2EB6C),(0x2EAEA,'beq',0x2EB00),
        (0x2EAFC,'ble',0x2EB6C),(0x2EB70,'beq',0x2EC2C),(0x2EB76,'beq',0x2ED2C),
        (0x2EC30,'beq',0x2EC42),(0x2EC46,'beq',0x2EC58),(0x2EC5C,'beq',0x2EC6C),
        (0x2EC70,'beq',0x2ED2C),(0x2EC78,'beq',0x2EC8A),(0x2EC86,'bne',0x2EB00),
        (0x2EC92,'bmi',0x2ED2C)]:
        require(at[pc]['mnemonic']==op and(pc,target)in links,'flag priority edge differs')
    for pc in (0x2EBE6,0x2EC8A):
        mem(at[pc]['operand_facts'][0],access='memory_read',width=2,base='A2',displacement=14)
    for pc in (0x2EC24,0x2EC96):
        mem(at[pc]['operand_facts'][1],access='memory_write',width=2,base='A2',displacement=14)
    check_indexed_action_write(at[0x2EBBC],4);check_indexed_action_write(at[0x2ECD4],2)
    return {'flags_byte_bits_tested':[5,4,3,2,1,0],'middle_nibble_bits':[8,11],
            'upper_nibble_bits':[12,15],'middle_reload_runtime':0x2EBE6,
            'middle_store_runtime':0x2EC24,'upper_debit_runtime':0x2EC8E,
            'upper_store_runtime':0x2EC96,'upper_debit_admitted_nibbles':list(range(1,9)),
            'reload_equals_gating_word_proved':False,'post_child_write_budget_preservation_proved':False}


def collect(rows,analysis,data):
    require(len(data)==489472 and hashlib.sha256(data).hexdigest()==MAIN_SHA256,'main identity differs')
    require(len(rows)==30616 and len({r['source_offset']for r in rows})==30616
            and all(r['provenance']=='accepted_instruction'and
                    data[r['source_offset']:r['source_offset']+r['size']]==bytes.fromhex(r['bytes'])for r in rows),
            'accepted facts do not match member')
    at={r['source_offset']+0x800:r for r in rows}
    spans=[('activation',0x2DE5E,0x2DF94),('update',0x2E88C,0x2E9BE),
           ('encounter_recreation',0x2A08E,0x2A130),('nearby_action',0x2E9C8,0x2ED46)]
    windows={n:{'start_runtime':a,'end_runtime':b,'instructions':len(window(rows,a,b))}for n,a,b in spans}
    for base,slot,value in [(0x2D752,6,0x2DE5E),(0x2DFE6,6,0x2E88C),(0x32936,6,0x4E2EA)]:
        off=base-0x800+4*slot
        require(int.from_bytes(data[off:off+4],'big')==value,'registered type-6 relation differs')
    uses={a:[]for a in(0x4E6A0,0x4E6A2,0x4E6A4,0x4E2EA)}
    for row in rows:
        for p in row['operand_facts']:
            address=p.get('absolute_address')
            if address in uses and p.get('access')in('memory_read','memory_write'):
                uses[address].append({'runtime':row['source_offset']+0x800,'access':p['access'],'width':p['width_bytes']})
    require([x['runtime']for x in uses[0x4E6A4]if x['access']=='memory_write']==[0x2DE8A],
            'saved-offset direct writers changed')
    operand(at[0x2DE8A],0,register='D1');operand(at[0x2DE8A],1,address=0x4E6A4)
    # Compare the WORD-negated magnitude but retain the original signed Z.
    operand(at[0x2E8CE],0,register='D4');operand(at[0x2E8CE],1,register='D6')
    mem(at[0x2E8D2]['operand_facts'][0],access='memory_read',width=2,base='A5',displacement=4)
    operand(at[0x2E8D2],1,register='D6')
    # These are value/field relations, not code admission or body decoding.
    models={0x29B16:(0x2A0D4,0x2DED4),0x20FF4:(0x2EBB4,),0x1A0C2:(0x2ECCC,)}
    for value,sites in models.items():
        for pc in sites:
            require(at[pc]['mnemonic']=='move'and at[pc]['operand_facts'][0].get('immediate_value')==value,
                    'deployment/emission model identity differs')
    known={r['offset']+0x800 for r in analysis['code_start_refs']if r.get('source_offset')==0xE80E-0x800}
    require(len(known)==43,'draw target set changed')
    defaults=[]
    for address in uses:
        require(address >= 0x4E2C4 and address+2<=0x4F6C4,
                'field is outside initial resource-1 load/save inclusion')
        src=copied_field_source(0x13D24,0x4E2C6,4178,address,2)
        defaults.append({'runtime':address,'handoff_word':int.from_bytes(data[address-0x800:address-0x800+2],'big'),
                         'reset_source_runtime':src,'reset_word':int.from_bytes(data[src-0x800:src-0x800+2],'big'),
                         'inside_initial_save_and_load_spans':True})
    grammar=check_grammar(rows,analysis)
    paths={};counts=Counter();words=[]
    for i in range(32):
        offset=0x2B786-0x800+4*i;value=int.from_bytes(data[offset:offset+2],'big');words.append(value)
        p=conditional_flag_paths(value);paths[str(i)]=list(p);counts.update(p)
    require(not any('emit_flapper'in p for p in paths.values()),'review initial flag-0 reachability result')
    extra=[]
    for pc in (0x2A1D6,0x2A956):
        row=at[pc];require(row['mnemonic']=='move'and
            row['operand_facts'][0].get('immediate_value')==0x5081,'additional packed seed differs')
        mem(row['operand_facts'][1],access='memory_write',width=2,base='A3',displacement=14)
        previous=rows[rows.index(row)-1]
        require(previous['source_offset']+0x800+previous['size']==pc
            and previous['mnemonic']=='move'and previous['operand_facts'][0].get('immediate_value')==0,
            'additional seed gate initializer differs')
        mem(previous['operand_facts'][1],access='memory_write',width=2,base='A3',displacement=12)
        extra.append({'store_runtime':pc,'packed_word':0x5081,'initial_gate_word':0,
                      'conditional_paths':list(conditional_flag_paths(0x5081))})
    for pc in (0x2DAA4,0x2DAB6):
        require(at[pc]['mnemonic']=='move'and
                at[pc]['operand_facts'][0].get('immediate_value')==65535,'target gate arm differs')
        mem(at[pc]['operand_facts'][1],access='memory_write',width=2,base='A5',displacement=12)
    return {'main_sha256':MAIN_SHA256,'cpu':'68000','runtime_executed':False,
            'instruction_windows':windows,'accepted_source_instructions':sum(v['instructions']for v in windows.values()),
            'type6_direct_field_uses':uses,'initial_and_reset_words':defaults,'saved_offset_directly_rebound_by_encounter_recreation':False,
            'type6_target_is_nearest_absolute_depth_proved':False,
            'model_relations':[{'value':v,'store_sites':list(s),'known_draw_destination':v in known}for v,s in models.items()],
            'orientation_write_views':[{'runtime':v-6,'size':6,'body_admitted':v in known}for v in(0x29B16,0x20FF4)],
            'packed_action_grammar':grammar,'initial_seed_conditional_paths':paths,
            'initial_seed_path_counts':dict(sorted(counts.items())),
            'additional_packed_seed_producers':extra,'missile_target_gate_arm_sites':[0x2DAA4,0x2DAB6],
            'known_unadmitted_model_identities':[v for v in(0x20FF4,0x23FB8,0x26A4A,0x26D7C,0x296FE,0x29B16,0x29D3C,0x29DF8)if v not in known],
            'initial_upper_nibble_range':[min(w>>12 for w in words),max(w>>12 for w in words)],
            'initial_middle_nibble_range':[min((w>>8)&15 for w in words),max((w>>8)&15 for w in words)],
            'scope_of_seed_paths':'after original eligibility gates, unchanged packed WORD and returning helpers; random choices overapproximated',
            'runtime_seed_word_preservation_proved':False,'new_code_admissions':0,
            'child_state_action_orientation_share_one_slot_proved':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in('rows','analysis','member','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();r=collect(json.loads(a.rows.read_text()),json.loads(a.analysis.read_text()),a.member.read_bytes())
    a.output.write_text(json.dumps(r,indent=2)+'\n')


if __name__=='__main__':main()

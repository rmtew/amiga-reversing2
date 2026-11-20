"""Recheck original count writers and accepted object-motion contracts.

This consumes native facts; it does not emulate, admit code or infer global
live-count/alias bounds from an initialized prefix or an initial descriptor.
"""
import argparse
import hashlib
import json
from pathlib import Path

from tools.foft_irq_write_audit import mem, require
from tools.foft_render_contract_audit import MAIN_SHA256, operand, window

COUNT = 0x4F218


def copied_field_source(source, destination, length, field, width):
    require(all(type(x) is int for x in (source,destination,length,field,width))
            and min(source,destination,field)>=0 and length>0 and width>0
            and max(source+length,destination+length,field+width)<=0x100000000,
            'invalid copy span')
    require(destination<=field and field+width<=destination+length,
            'field is not fully inside copy')
    return source+field-destination


def masked_zero_fallback(mask, fallback):
    require(type(mask)is int and type(fallback)is int and 0<=mask<=65535
            and mask&(mask+1)==0 and 0<=fallback<=65535,'invalid count mask')
    return sorted({fallback,*range(1,mask+1)})


def absolute_count_writes(rows, address=COUNT):
    result=[]
    for row in rows:
        for i,p in enumerate(row['operand_facts']):
            base=p.get('absolute_address');width=p.get('width_bytes')
            if (p.get('access')!='memory_write' or not p.get('memory')
                    or type(base)is not int or type(width)is not int or width not in (1,2,4)
                    or p.get('bulk_transfer')):continue
            if base<address+2 and address<base+width:
                require(row['provenance']=='accepted_instruction','writer is not accepted code')
                result.append({'runtime':row['source_offset']+0x800,'operand':i,
                               'mnemonic':row['mnemonic'],'width':width,'address':base})
    return result


def category_contract(rows, analysis):
    at={r['source_offset']+0x800:r for r in rows}
    links={(e['source_offset']+0x800,e['target_offset']+0x800)
           for e in analysis['edges']if e.get('target_offset',-1)>=0}
    pairs=[(0x2AA9A,6,0x2ADF6),(0x2AAA2,5,0x2B2B4),(0x2AAAA,4,0x2AFA4),
           (0x2AAB2,1,0x2AB84),(0x2AABA,9,0x2AB84),(0x2AAC2,10,0x2AF8E),
           (0x2AACA,11,0x2AB84),(0x2AAD2,12,0x2AF8E),(0x2AADA,7,0x2AB84),
           (0x2AAE2,8,0x2AB96),(0x2AAEA,13,0x2AC1C),(0x2AAF2,3,0x2AAFA)]
    result={'0':0x2AC48}
    require(at[0x2AA92]['mnemonic']=='move' and at[0x2AA96]['mnemonic']=='beq'
            and (0x2AA96,0x2AC48)in links,'zero category dispatch differs')
    mem(at[0x2AA92]['operand_facts'][0],access='memory_read',width=2,base='A0',displacement=14)
    operand(at[0x2AA92],1,register='D1')
    for pc,value,target in pairs:
        row=at[pc];branch=at[pc+row['size']]
        require(row['mnemonic']=='cmp' and row['operand_facts'][0].get('immediate_value')==value,
                'category comparison differs')
        operand(row,1,register='D1');require(row['operand_facts'][0]['width_bytes']==2,'category width differs')
        if value==3:
            require(branch['mnemonic']=='bne'and(branch['source_offset']+0x800,0x2AC48)in links
                    and branch['source_offset']+0x800+branch['size']==target,'fallback dispatch differs')
        else:
            require(branch['mnemonic']=='beq'and(branch['source_offset']+0x800,target)in links,
                    'category edge differs')
        result[str(value)]=target
    return {'explicit_categories':result,'other_categories':0x2AC48,
            'recognized_body_instructions':len(window(rows,0x2AA4C,0x2B2DA))}


def check_indexed_action_write(row, width):
    require(row['mnemonic']=='move' and len(row['operand_facts'])==2
            and type(width)is int and width in (2,4),'indexed action shape differs')
    p=row['operand_facts'][1]
    require(p.get('memory') and p.get('access')=='memory_write'
            and p.get('width_bytes')==width and p.get('indexed')
            and p.get('base_register')=='A2' and p.get('index_register')=='D6'
            and p.get('index_width_bytes')==2 and p.get('index_scale')==1
            and p.get('displacement_known') and p.get('displacement')==0
            and p.get('ea_update')==0 and not p.get('bulk_transfer')
            and not p.get('pc_relative') and p.get('absolute_address')is None,
            'indexed action receiver differs')


def check_view_key_copy(row):
    require(row['mnemonic']=='move','held-key store differs')
    mem(row['operand_facts'][0],access='memory_read',width=2,base='A6',displacement=10)
    operand(row,1,address=0x4E720)


def missile_contract(rows):
    at={r['source_offset']+0x800:r for r in rows}
    spans=[(0x2D99A,0x2DAD6),(0x2E006,0x2E1CE),(0x2E1D8,0x2E2AE)]
    windows=[{'start_runtime':a,'end_runtime':b,'instructions':len(window(rows,a,b))}for a,b in spans]
    # The original held key is a WORD copied from view +10, not an APTR.
    check_view_key_copy(at[0x2E26E])
    require([x['runtime']for x in absolute_count_writes(rows,0x4E720)]==[0x2E26E],
            'held-key direct writers differ')
    for pc in (0x2AFAA,0x2B266,0x2B282):operand(at[pc],0,address=0x4E720)
    for pc in (0x2E14A,0x2E168,0x2E186,0x2E1A4):
        require(at[pc]['mnemonic']=='jsr','reticle line call differs')
        operand(at[pc],0,address=0x1916E,width=4)
    for lo,hi,values in [(0x2E0AC,0x2E0CE,[147,173,59,85]),
                         (0x2E10C,0x2E12E,[25,295,15,127]),
                         (0x2E228,0x2E266,[173,147,76,52])]:
        actual=[r['operand_facts'][0].get('immediate_value')for r in rows
                if lo<=r['source_offset']+0x800<hi and r['mnemonic']in('cmp','cmpi')]
        require(actual==values,'distinct reticle comparison window differs')
    require(at[0x2DA3E]['operand_facts'][0].get('immediate_value')==4
            and at[0x2DA42]['operand_facts'][0].get('immediate_value')==0x20FF4,
            'missile state identity differs')
    return {'instruction_windows':windows,'accepted_instructions':sum(w['instructions']for w in windows),
            'held_key_store_runtime':0x2E26E,'held_key_from_view_offset':10,
            'held_key_width':2,'held_key_is_valid_receiver_proved':False,
            'reticle_line_calls':[0x2E14A,0x2E168,0x2E186,0x2E1A4],
            'distinct_initial_selection_window':{'x':[147,173],'y':[52,76]},
            'retained_center_window':{'x':[147,173],'y':[59,85]},
            'retained_outer_window':{'x':[25,295],'y':[15,127]},
            'same_frame_freshness_proved':False}


def collect(rows, analysis, data):
    require(len(data)==489472 and hashlib.sha256(data).hexdigest()==MAIN_SHA256,'main identity differs')
    require(len(rows)==30616 and len({r['source_offset']for r in rows})==30616
            and all(r['provenance']=='accepted_instruction'and
                    data[r['source_offset']:r['source_offset']+r['size']]==bytes.fromhex(r['bytes'])
                    for r in rows),'accepted facts do not match member')
    at={r['source_offset']+0x800:r for r in rows}
    direct=absolute_count_writes(rows)
    expected={0xDFE,0x2A064,0x2A120,0x2A1F0,0x2A2EA,0x2A362,0x2A37C,
              0x2A60E,0x2A97E,0x2AA10,0x2BFAA,0x2BFE8,0x2DA48,
              0x2DD50,0x2DE06,0x2DF2A,0x2EC0C,0x2ED26}
    require({x['runtime']for x in direct}==expected and all(x['width']==2 for x in direct),
            'review changed absolute writer set')
    require(at[0x29F32]['mnemonic']=='andi'and
            at[0x29F32]['operand_facts'][0].get('immediate_value')==15
            and at[0x29F38]['operand_facts'][0].get('immediate_value')==3,'base count mask differs')
    operand(at[0x2A064],0,register='D5');operand(at[0x2A064],1,address=COUNT)
    reset_source=copied_field_source(0x13D24,0x4E2C6,4178,COUNT,2)
    require(reset_source==0x14C76 and data[reset_source-0x800:reset_source-0x800+2]==b'\0\0',
            'reset count default differs')
    # Recheck the existing template sentinel bound at WORD alignment.
    template=data[0x13D24-0x800:0x14D7A-0x800]
    require(next(i for i in range(0,len(template)-3,2)if template[i:i+4]==b'\xff'*4)==4178,
            'reset template extent differs')
    descriptor=[int.from_bytes(data[0x403B0-0x800+i:0x403B0-0x800+i+4],'big')for i in range(0,16,4)]
    require(descriptor==[0x4E2C4,1,0,5120],'initial load resource differs')
    require(at[0x1318]['mnemonic']=='moveq'and
            at[0x1318]['operand_facts'][0].get('immediate_value')==1,'load resource selector differs')
    require(at[0x131A]['mnemonic']=='jsr','load request differs')
    operand(at[0x131A],0,address=0x46D44,width=4)
    transfers={'reset':{'source_runtime':reset_source,'default_word':0,'copy_bytes':4178},
               'save':{'field_offset':COUNT-0x4E2C4,'request_bytes':6000},
               'load':{'request_call_runtime':0x131A,'loader_runtime':0x46D44,'field_offset':COUNT-0x4E2C4,'initial_request_bytes':5120,
                       'restored_value_known':False,'descriptor_constness_proved':False}}
    for size in (5120,6000):copied_field_source(0,0x4E2C4,size,COUNT,2)
    # Local initializer prefix only: normal loop/stack/helper preservation and
    # no intervening alias/async writes are explicit preconditions, not facts.
    operand(at[0x2A154],0,address=0x4E818,width=4)
    operand(at[0x2A15A],0,address=COUNT)
    require(at[0x2A160]['mnemonic']=='mulu'and
            at[0x2A160]['operand_facts'][0].get('immediate_value')==20,
            'pirate append scale differs')
    for pc,model in [(0x2A19A,0x26D7C),(0x2A2A2,0x26A4A)]:
        require(at[pc]['mnemonic']=='move'and
                at[pc]['operand_facts'][0].get('immediate_value')==model,
                'initial append model differs')
        mem(at[pc]['operand_facts'][1],access='memory_write',width=4,base='A0',displacement=16)
    # Shared frame-count snapshot is used to choose both emitter destinations.
    for pc in (0x2A694,):operand(at[pc],1,address=0x2F094)
    operand(at[0x2E9D2],0,address=0x4ED18,width=4)
    operand(at[0x2E9D2],1,register='A2',width=4)
    require(at[0x2ED30]['mnemonic']=='lea'and
            at[0x2ED30]['operand_facts'][0].get('base_register')=='A2'and
            at[0x2ED30]['operand_facts'][0].get('displacement')==20,'current action cursor differs')
    operand(at[0x2ED30],1,register='A2',width=4)
    for pc,width in [(0x2EBBC,4),(0x2ECD4,2)]:check_indexed_action_write(at[pc],width)
    emitters=[]
    for lo,hi,increment in [(0x2EB82,0x2EC14,0x2EC0C),(0x2EC9A,0x2ED2C,0x2ED26)]:
        block=[r for r in rows if lo<=r['source_offset']+0x800<hi]
        reads=[r for r in block if any(p.get('access')=='memory_read'and p.get('absolute_address')==0x2F094
                                     for p in r['operand_facts'])]
        require(len(reads)==1,'emitter saved count differs')
        require(at[increment]['mnemonic']=='addq'and
                at[increment]['operand_facts'][0].get('immediate_value')==1,'emitter increment differs')
        read=reads[0];base=read['source_offset']+0x800
        multiply=at[base+6];require(multiply['mnemonic']=='mulu'and
            multiply['operand_facts'][0].get('immediate_value')==20,'emitter count scale differs')
        operand(multiply,1,register='D6')
        operand(at[base+10],0,address=0x4E818,width=4)
        operand(at[base+16],0,register='D6');operand(at[base+16],1,register='A3')
        emitters.append({'increment_runtime':increment,'saved_count_read_runtime':reads[0]['source_offset']+0x800,
                         'global_capacity_guard_proved':False,
                         'action_write_runtime':0x2EBBC if increment==0x2EC0C else 0x2ECD4,
                         'action_receiver':'current A2 cursor plus D6.W; not a fresh action root',
                         'shared_child_action_ownership_proved':False})
    # Three components: producer order may differ, field order does not.
    refs={base:{'long_reads':[],'long_writes':[]}for base in (0x2BB94,0x2BB98,0x2BB9C)}
    for row in window(rows,0x2AA4C,0x2B2DA):
        for p in row['operand_facts']:
            base=p.get('absolute_address')
            if base in refs and p.get('access')in('memory_read','memory_write'):
                require(p.get('width_bytes')==4,'relative component is not LONG')
                refs[base]['long_reads'if p['access']=='memory_read'else'long_writes'].append(row['source_offset']+0x800)
    require(all(v['long_reads']and v['long_writes']for v in refs.values()),'relative component evidence incomplete')
    require(at[0x2AEC0]['mnemonic']=='cmp'and at[0x2AEC0]['operand_facts'][0]['width_bytes']==2,
            'preserved mixed comparison width differs')
    for pc,stride,reg in [(0x2AF8E,20,'A0'),(0x2AF92,10,'A1'),(0x2AF96,20,'A4')]:
        require(at[pc]['mnemonic']=='lea','receiver stride differs')
        p=at[pc]['operand_facts'][0]
        require(p.get('base_register')==reg and p.get('displacement')==stride,'receiver stride source differs')
        operand(at[pc],1,register=reg,width=4)
    return {'main_sha256':MAIN_SHA256,'runtime_executed':False,'absolute_count_writers':direct,
            'absolute_writer_scope':'ordinary fixed-width absolute operands only; bulk and unresolved receivers excluded',
            'base_initializer_count_domain':masked_zero_fallback(15,3),'transfers':transfers,
            'emitter_obligations':emitters,'global_count_bound_proved':False,
            'indirect_or_copy_writer_closure':False,
            'initial_append_prefix':{'state_slot_min':1,'state_slot_max':16,
                'conditional_state_end':0x4E818+17*20,
                'preconditions':'ordinary initializer loop and stack/helper preservation; no intervening alias or async writer',
                'native_receiver_fact_emitted':False},'category_dispatch':category_contract(rows,analysis),
            'relative_component_uses':refs,'missile_contract':missile_contract(rows),'new_code_admissions':0,
            'current_row_delta_freshness_proved':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('rows','analysis','member','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();r=collect(json.loads(a.rows.read_text()),json.loads(a.analysis.read_text()),a.member.read_bytes())
    a.output.write_text(json.dumps(r,indent=2)+'\n')


if __name__=='__main__':main()

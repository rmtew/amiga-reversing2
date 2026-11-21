"""Recheck original small-round row profiles and their accepted raster consumer.

No guest execution, data scanning, control admission or live-bank assertion.
"""
import argparse
import hashlib
import json
from pathlib import Path

from tools.foft_irq_write_audit import mem, require
from tools.foft_music_voice_effects_audit import ea
from tools.foft_render_contract_audit import MAIN_SHA256, operand, window


def profile_partition(data, pointers, start, end, *, origin=0):
    """Partition an explicitly bounded data family, retaining pointer aliases."""
    require(0 <= start-origin < end-origin <= len(data), 'profile owner bounds differ')
    require(bool(pointers) and all(type(p) is int and start <= p < end
                                  and (p-start) % 2 == 0 for p in pointers),
            'profile pointer outside owner or unaligned')
    starts = sorted(set(pointers))
    require(starts[0] == start, 'unclaimed profile prefix')
    result = []
    for p, limit in zip(starts, [*starts[1:], end], strict=True):
        require(p+2 <= limit, 'missing profile header')
        count = int.from_bytes(data[p-origin:p-origin+2], 'big')
        rows = count+1  # DBF's body executes before the decrement/test.
        require(p+2+4*rows == limit, 'profile row count does not consume exact extent')
        result.append({'runtime': p, 'end_runtime': limit, 'rows': rows,
                       'row_count_minus_one': count,
                       'pointer_slots': [i for i, q in enumerate(pointers) if p == q]})
    return result


def span_word_envelope(y_min=16, y_end=128, x_min=25, x_end=295):
    """WORD-access envelope, separate from masked half-open pixel coverage."""
    require((y_min,y_end,x_min,x_end)==(16,128,25,295), 'unproved clip rectangle')
    return [[plane*0x2000+y*40+2*(x_min//16),
             plane*0x2000+y*40+2*(x_end//16)+2]
            for plane in range(4) for y in range(y_min,y_end)]


def matching_span_contract(first, second, edges):
    """Check the copied span body, its field shift and actual successor graph."""
    require(len(first)==len(second) and first and first[-1]['mnemonic']==second[-1]['mnemonic']=='rts', 'span copy framing differs')
    for a,b in zip(first,second,strict=True):
        require(a['mnemonic']==b['mnemonic'], 'span copy operation differs')
        require(len(a['operand_facts'])==len(b['operand_facts']), 'span copy operands differ')
        for p,q in zip(a['operand_facts'],b['operand_facts'],strict=True):
            if p['access']=='branch_target':
                require(q['access']=='branch_target','span copy branch operand differs')
                continue  # Branch widths differ; compare native successor edges below.
            expected=dict(p)
            if p['access']=='memory_read' and p['base_register']=='A5':
                require(p['width_bytes']==2 and p['displacement']in(6,8,10,12), 'unproved pattern field')
                expected['displacement']+=8
            require(q==expected, 'span copy field or effect differs')
    returns={first[-1]['source_offset'],second[-1]['source_offset']}
    def graph(block):
        indices={r['source_offset']:i for i,r in enumerate(block)}
        result=[]
        for row in block:
            outgoing=[e for e in edges if e['source_offset']==row['source_offset']]
            branch=any(p['access']=='branch_target'for p in row['operand_facts'])
            require(sum(e['kind']in(2,4)for e in outgoing)==int(branch), 'span copy branch witness incomplete')
            require(sum(e['kind']==5 for e in outgoing)==int(row['mnemonic']=='rts'), 'span copy return witness incomplete')
        for e in edges:
            if e['source_offset'] not in indices:continue
            destination=e['target_offset']
            if e['kind']==1:
                i=indices[e['source_offset']]
                require(i+1<len(block) and destination==block[i+1]['source_offset'], 'span copy fallthrough differs')
                continue  # Native block boundaries differ at the shared return.
            require(e['kind']in(2,4,5),'span copy has an unproved edge kind')
            if e['kind']==5:
                require(e['source_offset'] in returns,'nonterminal return edge')
                target='return'
            elif destination in returns:target='return'
            else:
                require(destination in indices,'span copy has an external successor')
                target=indices[destination]
            result.append((indices[e['source_offset']],e['kind'],target))
        return sorted(result,key=str)
    require(graph(first)==graph(second), 'span copy control graph differs')
    return {'instructions':len(second),'pattern_read_field_shift':8,'same_plane_write_and_clip_contract':True,'shared_clipped_return_checked':True}


def check_source(rows, analysis, data):
    require(hashlib.sha256(data).hexdigest()==MAIN_SHA256, 'main identity differs')
    require(all(r['provenance']=='accepted_instruction' and data[r['source_offset']:r['source_offset']+r['size']]==bytes.fromhex(r['bytes']) for r in rows), 'accepted instruction bytes differ')
    at={r['source_offset']+0x800:r for r in rows}
    for pc, reg, address in [(0xFDFC,'A5',0x1015A),(0xFE00,'A6',0x10138),(0xFE04,'A4',0x10116),(0x10186,'A3',0x101AE)]:
        ea(at[pc],0,address);operand(at[pc],1,register=reg,width=4)
    operand(at[0xFF26],0,address=0x70000,width=4)
    operand(at[0xFF2C],0,address=0x16E2,width=4)
    mem(at[0xFE0C]['operand_facts'][0],access='memory_read',width=2,base='A5',displacement=22)
    operand(at[0xFE0C],1,register='D5')
    for pc in (0x2BD9E,0x2C2AE):
        operand(at[pc],0,address=0x1015A,width=4);operand(at[pc],1,register='A0',width=4)
    small=window(rows,0x10178,0x101AE)
    require([r['mnemonic']for r in small]==['cmp','bge','moveq','sub','asl','lea',
        'movea','move','move','add','move','sub','move','move','bsr','move','addq','dbf','rts'],
        'small round consumer differs')
    for pc, value, reg in [(0xFE10,9,'D5'),(0x10178,1,'D5')]:
        require(at[pc]['mnemonic']=='cmp' and at[pc]['operand_facts'][0]['immediate_value']==value,
                'signed size comparison differs')
        operand(at[pc],1,register=reg)
    require(at[0xFE14]['mnemonic']=='blt' and at[0x1017C]['mnemonic']=='bge',
            'signed size gate differs')
    require(at[0x1017E]['operand_facts'][0]['immediate_value']==1,'lower clamp differs')
    operand(at[0x1017E],1,register='D5',width=4)
    require(at[0x10184]['operand_facts'][0]['immediate_value']==2,'pointer stride differs')
    operand(at[0x10184],1,register='D5')
    # The only accepted incoming reference to this helper is the signed <9 branch.
    incoming=[r for r in analysis['code_start_refs']if r['offset']+0x800==0x10178]
    require(len(incoming)==1 and incoming[0]['source_offset']+0x800==0xFE14,
            'small helper has another incoming source')
    require(any(e['source_offset']+0x800==0x1019E and e['target_offset']+0x800==0xFEEE
                and e['kind']==3 for e in analysis['edges']), 'span call differs')
    require(any(e['source_offset']+0x800==0x101A8 and e['target_offset']+0x800==0x10190
                and e['kind']==2 for e in analysis['edges']), 'row DBF differs')
    p=at[0x1018A]['operand_facts'][0]
    require(p['memory'] and p['indexed'] and p['base_register']=='A3'
            and p['index_register']=='D5' and p['width_bytes']==4 and p['displacement']==0,
            'profile pointer load differs')
    for pc,reg in [(0x1018E,'D5'),(0x10190,'D0'),(0x10196,'D1')]:
        mem(at[pc]['operand_facts'][0],access='memory_read',width=2,base='A3',update=1)
        operand(at[pc],1,register=reg)
    for pc in (0x10180,0x101A4):
        mem(at[pc]['operand_facts'][1],access='memory_write',width=2,base='A5',displacement=2)
    mem(at[0x1019C]['operand_facts'][1],access='memory_write',width=2,base='A7',update=2)
    mem(at[0x101A2]['operand_facts'][0],access='memory_read',width=2,base='A7',update=1)
    for pc in (0x1019C,0x101A2):operand(at[pc],0 if pc==0x1019C else 1,register='D5')
    span=window(rows,0xFEEE,0x10006)
    require(span[-1]['mnemonic']=='rts' and not any(r['mnemonic']in('bsr','jsr','jmp')for r in span),
            'span has an unproved delegated effect')
    require([r['mnemonic']for r in window(rows,0xFEEE,0xFF26)]==['cmp','blt','cmp','bge','cmp','blt','exg','cmp','ble','cmp','bge','moveq','cmp','bge','cmp','ble','move'], 'clip branch order differs')
    writes=[]
    for r in span:
        for p in r['operand_facts']:
            require(not(p['access']=='register_write' and p['direct_register']in('A3','A5')),
                    'span changes the profile or state root')
            if p['access']=='memory_write':
                require(p['base_register']=='A0' and p['width_bytes']==2
                        and p['displacement']in(0,0x2000,0x4000,0x6000),
                        'span write escapes plane WORD contract')
                writes.append({'runtime':r['source_offset']+0x800,'plane_offset':p['displacement'],'width':p['width_bytes']})
    for pc,reg,value in [(0xFEEE,'D2',16),(0xFEF6,'D2',128),
                          (0xFF04,'D1',25),(0xFF0C,'D0',25),
                          (0xFF14,'D0',295),(0xFF1C,'D1',295)]:
        require(at[pc]['operand_facts'][0]['immediate_value']==value,'clip immediate differs')
        operand(at[pc],1,register=reg)
    for pc, value in [(0xFF32,3),(0xFF36,2),(0xFF40,4),(0xFF48,4)]:
        require(at[pc]['operand_facts'][0]['immediate_value']==value, 'row or column stride differs')
    for pc in (0xFF4E,0xFF52):
        require(at[pc]['mnemonic']=='andi' and at[pc]['operand_facts'][0]['immediate_value']==15, 'mask index differs')
    prefix=[int.from_bytes(data[p-0x800:p-0x800+2],'big')for p in range(0x10116,0x10136,2)]
    suffix=[int.from_bytes(data[p-0x800:p-0x800+2],'big')for p in range(0x10138,0x10158,2)]
    require(prefix==[(0xFFFF<<(16-i))&0xFFFF for i in range(16)] and suffix==[0xFFFF>>i for i in range(16)], 'half-open pixel masks differ')
    span_b=window(rows,0x10006,0x10116)
    span_b_contract=matching_span_contract(span,span_b,analysis['edges'])
    title_calls=[]
    for entry, call, reset in [(0x2BD6E,0x2BD98,0x2BD92),(0x2BFB6,0x2BFD4,None),(0x2C244,0x2C26E,0x2C268)]:
        block=window(rows,entry,call+6)
        require([r['mnemonic']for r in block]==(['jsr']*5+(['lea','move']if reset else[])+['jsr']), 'title preparation order differs')
        require(any(e['source_offset']+0x800==call and e['target_offset']+0x800==0xFDFC and e['kind']==3 for e in analysis['edges']), 'title round call differs')
        if reset:
            require(at[reset]['operand_facts'][0]['immediate_value']==64, 'title Y reset differs')
            mem(at[reset]['operand_facts'][1],access='memory_write',width=2,base='A0',displacement=2)
            operand(at[reset-6],0,address=0x1015A,width=4)
        title_calls.append({'entry_runtime':entry,'round_call_runtime':call,'immediate_y_reset_runtime':reset})
    for pc, op in [(0x2BDA4,'addq'),(0x2C2B4,'subq')]:
        require(at[pc]['mnemonic']==op and at[pc]['operand_facts'][0]['immediate_value']==1, 'title scale step differs')
        mem(at[pc]['operand_facts'][1],access='memory_write',width=2,base='A0',displacement=22)
    require(at[0x2BDAC]['operand_facts'][0]['immediate_value']==65 and at[0x2BDB0]['mnemonic']=='ble' and at[0x2C2B8]['mnemonic']=='bpl', 'title scale continuation differs')
    pointers=[int.from_bytes(data[p-0x800:p-0x800+4],'big')for p in range(0x101AE,0x101D2,4)]
    profiles=profile_partition(data,pointers,0x101D2,0x102EE,origin=0x800)
    require([p['rows']for p in profiles]==[3,4,5,7,9,11,13,15], 'original profile schedule differs')
    require(pointers[7]==pointers[8] and len(set(pointers))==8, 'original shared profile differs')
    return {'main_sha256':MAIN_SHA256, 'profile_pointer_span':[0x101AE,0x101D2],
        'profile_data_span':[0x101D2,0x102EE], 'data_bytes':320, 'pointer_slots':9,
        'distinct_profiles':8,'total_row_pairs':67,'profiles':profiles,
        'normal_selected_slots':[1,2,3,4,5,6,7,8], 'unused_normal_slot':0,
        'small_consumer_instructions':len(small),'span_a_instructions':len(span),
        'span_b_contract':span_b_contract,
        'span_a_plane_word_writes':writes,'span_a_write_operand_count':len(writes),
        'title_preparation_calls':title_calls,
        'post_loop_y':'entry Y minus clamped size plus selected row count, modulo WORD',
        'span_pixel_rectangle_half_open':[25,16,295,128],
        'conditional_plane_word_access':{'plane_offsets':[0,8192,16384,24576], 'row_first':16,'row_end_exclusive':128,'row_stride':40,'row_byte_start':2,'row_byte_end_exclusive':38,'separate_row_intervals':len(span_word_envelope())},
        'requirements':['original profile/table/code bytes','unchanged A5 state root and valid mask roots',
                        'valid current draw-bank root','intact return/stack frames',
                        'no intervening alias/device writes'],
        'runtime_observed':False,'native_code_or_receiver_facts_emitted':False,
        'current_bank_or_global_alias_lifetime_proved':False,
        'scenery_twelve_ten_handoff_closed':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--main',type=Path,required=True)
    p.add_argument('--rows',type=Path,required=True)
    p.add_argument('--analysis',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    report=check_source(json.loads(a.rows.read_text()),json.loads(a.analysis.read_text()),a.main.read_bytes())
    a.output.write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()

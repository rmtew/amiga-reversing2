"""Initial serialized music programs and indexed-map contracts, not live closure."""
import argparse
import hashlib
import json
from pathlib import Path

from tools.foft_audio_layout_probe import decode_order, decode_pattern, probe
from tools.foft_irq_write_audit import mem, require
from tools.foft_music_voice_effects_audit import check_source as voice_contract
from tools.foft_music_voice_effects_audit import ea
from tools.foft_render_contract_audit import MAIN_SHA256, operand, window


def selected_map_cell(base,selector):
    require(type(base)is int and base in(0,8,16,24),'unknown current track base')
    require(type(selector)is int and 0<=selector<8,'selector is not WORD-masked')
    index=base+selector
    return {'index':index,'map_runtime':0x58B00+index,'initialized_word_offset':4*selector,
            'instrument_index':selector,'header_runtime':0x590D0+28*selector}


def serialized_contract(data,pattern_spans,order_spans,bases):
    """Reuse packet boundaries, never scan parameter bytes as new commands.

    The prefix property is lexical data evidence, not a tick/guest interpreter.
    There is no time, call, state-machine simulation or mutable cursor claim.
    """
    require(len(bases)==len(order_spans),'track/order correspondence differs')
    patterns=[]
    for lo,hi in pattern_spans:patterns.append(decode_pattern(data,lo,hi))
    result=[]
    for (lo,hi),base in zip(order_spans,bases,strict=True):
        events,indices=decode_order(data,lo,hi,len(patterns))
        remaps=[];selects=[];parameters=[];selected=False;first_note=None
        for e in events:
            at=lo+e['offset'];op=data[at]
            if 0xF0<=op<=0xFC:remaps.append({'source_offset':at,'selector':op-0xF0})
            if e['width']==2:parameters.append({'source_offset':at,'opcode':op})
            if op>=200:continue
            start=pattern_spans[op][0]
            for packet in patterns[op]:
                p=start+packet['offset'];kind=packet['kind']
                if kind=='instrument_select':
                    selected=True;selects.append({'source_offset':p,**selected_map_cell(base,data[p]&7)})
                if first_note is None and kind in('note','held_note'):
                    first_note={'source_offset':p,'preceded_by_serialized_select':selected}
        unique={s['source_offset']:s for s in selects}
        result.append({'track_base':base,'source_span':[lo,hi],
            'pattern_indices':indices,'order_packets':len(events),'remap_packets':remaps,
            'parameter_packets':parameters,'explicit_select_sites':sorted(unique.values(),key=lambda s:s['source_offset']),
            'map_indices':sorted({s['index']for s in unique.values()}),
            'instrument_indices':sorted({s['instrument_index']for s in unique.values()}),
            'first_serialized_note':first_note})
    return result



def scoped_static_references(analysis,owners):
    result=[]
    for target,(lo,hi)in owners.items():
        refs=[r for r in analysis['code_start_refs']if r['offset']+0x800==target]
        require(bool(refs),'local lacks a known static source reference')
        sources=[r.get('source_offset')for r in refs]
        require(all(type(s)is int and lo<=s+0x800<hi for s in sources),
                'local has foreign or unknown static source reference')
        result.append({'local_runtime':target,'owner_runtime':lo,
                       'known_static_sources':sorted(s+0x800 for s in sources)})
    return result


def check_source(rows,analysis,data):
    prior=voice_contract(rows,analysis,data);at={r['source_offset']+0x800:r for r in rows}
    layout=probe(data)
    starts=[(p['source_start'],p['source_end'])for p in layout['patterns']]
    orders=[(p['source_start'],p['source_end'])for p in layout['orders']]
    bases=[int.from_bytes(data[0x589F0-0x800+68*i:0x589F2-0x800+68*i],'big')for i in range(4)]
    require(bases==[0,8,16,24] and data[0x58B00-0x800:0x58B20-0x800]==bytes(32),'initial track/map bytes differ')
    report=serialized_contract(data,starts,orders,bases)
    require(all(not r['remap_packets']for r in report),'initial order program has a remap')
    require([r['instrument_indices']for r in report]==[[0],[3,4,6],[2,5,6,7],[1]],'initial channel selection envelope differs')
    require(all(r['first_serialized_note']['preceded_by_serialized_select']for r in report),'initial note prefix differs')
    fill=window(rows,0x58C54,0x58C6C)
    require([r['mnemonic']for r in fill]==['lea','moveq','moveq','moveq','move','add','cmp','bne','dbf'],'map fill differs')
    ea(at[0x58C54],0,0x58B00);operand(at[0x58C54],1,register='A0',width=4)
    for pc,reg,value in [(0x58C58,'D0',3),(0x58C5A,'D1',4),(0x58C5C,'D2',0)]:
        require(at[pc]['operand_facts'][0]['immediate_value']==value,'map loop initializer differs')
        operand(at[pc],1,register=reg,width=4)
    mem(at[0x58C5E]['operand_facts'][1],access='memory_write',width=1,base='A0',update=1)
    operand(at[0x58C5E],0,register='D2',width=1)
    operand(at[0x58C60],0,register='D1',width=1);operand(at[0x58C60],1,register='D2',width=1)
    require(at[0x58C62]['operand_facts'][0]['immediate_value']==32,'map fill stop differs')
    operand(at[0x58C62],1,register='D2',width=1)
    for pc,expected in [(0x58C66,{(2,0x58C5E),(1,0x58C68)}),(0x58C68,{(2,0x58C5C),(1,0x58C6C)})]:
        require({(e['kind'],e['target_offset']+0x800)for e in analysis['edges']if e['source_offset']+0x800==pc}==expected,'map loop successors differ')
    for pc,reg in [(0x58C6E,'A1'),(0x58C72,'A2'),(0x58C76,'A3'),(0x58C7A,'A4')]:
        mem(at[pc]['operand_facts'][1],access='memory_write',width=1,base=reg,displacement=22)
    require(at[0x58C6C]['mnemonic']=='moveq'and at[0x58C6C]['operand_facts'][0]['immediate_value']==255,'active initializer differs')
    ea(at[0x58C7E],0,0x58008);mem(at[0x58C82]['operand_facts'][1],access='memory_write',width=1,base='A0')
    # Pattern select clears the whole index WORD, not just its low byte.
    require(at[0x58EBC]['mnemonic']=='andi'and at[0x58EBC]['operand_facts'][0]['immediate_value']==7,'selector mask differs')
    operand(at[0x58EBC],1,register='D0',width=2)
    mem(at[0x58EC0]['operand_facts'][0],access='memory_read',width=2,base='A4')
    operand(at[0x58EC0],1,register='D0',width=2)
    for pc,target in [(0x58EC2,0x58B00),(0x58ECA,0x590B0)]:ea(at[pc],0,target)
    for pc,width in [(0x58EC6,1),(0x58ECE,4)]:
        p=at[pc]['operand_facts'][0]
        require(p.get('access')=='memory_read'and p.get('base_register')=='A0'and p.get('index_register')=='D0'
                and p.get('index_width_bytes')==2 and p.get('index_scale')==1 and p.get('indexed')
                and p.get('width_bytes')==width and p.get('displacement')==0,'map/table indexed read differs')
    mem(at[0x58ED2]['operand_facts'][1],access='memory_write',width=4,base='A4',displacement=14)
    # The uncommitted local cursor on order FF does not walk into the next stream.
    require([r['mnemonic']for r in window(rows,0x58D36,0x58D50)]==['cmp','bne','move','beq','cmp','bne','clr','rts'],'order end/wait body differs')
    mem(at[0x58D4A]['operand_facts'][0],access='memory_write',width=1,base='A4',displacement=22)
    require([r['mnemonic']for r in window(rows,0x10CD6,0x10CDE)]==['jsr','rts'],
            'installed-player start wrapper differs')
    require({e['target_offset']+0x800 for e in analysis['edges']
             if e['source_offset']+0x800==0x10CD6 and e['kind']==3}=={0x58000},
            'installed-player start call differs')
    for pc in(0x9A0,0x9D0,0xA00):
        require(at[pc]['mnemonic']=='moveq'and at[pc]['operand_facts'][0]['immediate_value']==0,
                'explicit descriptor-zero caller differs')
        operand(at[pc],1,register='D0',width=4)
        require({e['target_offset']+0x800 for e in analysis['edges']
                 if e['source_offset']+0x800==pc+2 and e['kind']==3}=={0x10CD6},
                'zero-argument start wrapper call differs')
    locals_=scoped_static_references(analysis,{
        **dict.fromkeys((363612, 363614), (363296, 363670)),
        **dict.fromkeys((363798, 363808, 363850, 363856, 363874, 363890, 363906, 363936, 363940, 363960, 363978, 364202), (363754, 364212))})
    # No data/type/receiver/control facts are emitted by this audit.
    return {'main_sha256':MAIN_SHA256,'verification_scope':'member','runtime_executed':False,
        'initial_player_voice_contract_rechecked':True,'whole_tick_effects_closed':prior['whole_tick_effects_closed'],
        'start_wrapper':{'runtime':0x10CD6,'loads_or_authenticates_bank':False,
            'explicit_zero_argument_call_sites':[0x9A2,0x9D2,0xA02],
            'subsong_argument_does_not_identify_current_bank':True},
        'source_pattern_streams':17,'source_order_streams':4,'pattern_packets':sum(layout['pattern_event_counts'].values()),'scoped_local_static_references':locals_,
        'initial_raw_map_zero_filled':True,'map_fill':{'group_count':4,'entries_per_group':8,
            'table_span':[0x58B00,0x58B20],'final_cursor':0x58B20,'word_offsets_per_group':list(range(0,32,4)),
            'map_fill_precedes_track_active_and_song_run_stores':True},
        'channel_serialized_envelopes':report,'serialized_order_remap_packets':0,
        'source_program_patterns_sha256':hashlib.sha256(data[0x58536-0x800:0x5892C-0x800]).hexdigest(),
        'source_program_orders_sha256':hashlib.sha256(data[orders[0][0]:orders[-1][1]]).hexdigest(),
        'native_current_target_set_closed':False,'native_receiver_or_control_facts_emitted':False,
        'current_map_base_contents_cursors_or_bank_identity_proved':False,
        'runtime_note_dominance_or_callback_initialization_proved':False,
        'shared_model_header_orientation_stability_implied':False,
        'conditional_interpretation':'For the original descriptor/program and initialized preserved map/base state, explicit instrument-select packets choose the reported in-range cells and headers; no serialized order packet invokes the remap writer. Other writes/current execution remain separate.'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in('rows','analysis','member','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();r=check_source(json.loads(a.rows.read_text()),json.loads(a.analysis.read_text()),a.member.read_bytes())
    a.output.write_text(json.dumps(r,indent=2)+'\n')


if __name__=='__main__':main()

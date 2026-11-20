"""Pinned initial-player voice effects; no closed callback or device-lifetime fact."""
import argparse
import hashlib
import json
from pathlib import Path

from tools.foft_interrupt_frame_audit import exclude_domains
from tools.foft_irq_write_audit import acknowledge, mem, require
from tools.foft_near_scenery_audit import PROTECTED
from tools.foft_render_contract_audit import MAIN_SHA256, operand, window

VOICES=tuple(0x581F8+34*i for i in range(4))
CANDIDATES=(0x58406,0x58448,0x58458)
KEEP={'A1','A2','A3','A6'}


def indexed_word_band(base,displacement,width):
    """Linear signed-WORD EA hull, not a physical mapping or current index."""
    require(type(base)is int and type(displacement)is int and type(width)is int and width in (1,2,4),'invalid EA parameters')
    lo=base-32768+displacement;hi=base+32767+displacement+width
    require(0<=lo<hi<=2**32,'EA hull wraps')
    return [lo,hi]


def audio_header(index):
    require(type(index)is int and 0<=index<4,'voice index differs')
    return {'dma_mask':1<<index,'irq_mask':0x80<<index,'custom_offset':0xA0+16*index}


def audio_only_control(header):
    """A bit-domain check only. It does not authenticate mutable header values."""
    return (all(type(header.get(k))is int and 0<=header[k]<=65535
                for k in ('dma_mask','irq_mask','custom_offset'))
            and header['dma_mask']&~0xF==0 and header['irq_mask']&~0x780==0
            and header['custom_offset']in(0xA0,0xB0,0xC0,0xD0))


def protected_registers(rows,registers=KEEP):
    for row in rows:
        require(row['mnemonic']not in ('jsr','bsr','rte','movem'),'unsummarized callee or register restore')
        for p in row['operand_facts']:
            require(not(p.get('direct_register')in registers and 'write'in p.get('access','')),
                    'callback changes retained receiver')
            require(not(p.get('base_register')in registers and p.get('ea_update')),
                    'callback updates retained receiver implicitly')
            require(not(set(p.get('register_list',[]))&registers and 'write'in p.get('access','')),
                    'callback reloads retained receivers')
    return True


def bounded_writes(rows,voice_register,hardware_register):
    """Caller-bound four voices and custom+signed-WORD root; no pointee inference."""
    result=[];stack=[]
    for row in rows:
        for i,p in enumerate(row['operand_facts']):
            if p.get('access')not in('memory_write','memory_read_write'):continue
            width=p.get('width_bytes');base=p.get('base_register');off=p.get('displacement')
            require(width in(1,2,4)and not p.get('indexed')and not p.get('bulk_transfer')
                    and p.get('displacement_known')and p.get('absolute_address')is None,'unknown voice write')
            if base=='A7':
                require(p.get('ea_update')==2 and width==2,'unexpected local stack write')
                stack.append({'runtime':row['source_offset']+0x800,'width':2});continue
            require(not p.get('ea_update'),'unaccounted write cursor')
            if base==voice_register:
                require(off>=6 and off+width<=34,'voice write reaches preserved-header premise')
                spans=[[v+off,v+off+width]for v in VOICES];kind='caller_bound_voice'
            elif base==hardware_register:
                spans=[indexed_word_band(0xDFF000,off,width)];kind='custom_plus_current_signed_word'
            elif base=='A6':spans=[[0xDFF000+off,0xDFF000+off+width]];kind='fixed_custom'
            else:raise ValueError('unknown voice write root')
            result.append({'runtime':row['source_offset']+0x800,'operand_index':i,'kind':kind,'spans':spans})
    return {'stores':result,'explicit_stack_writes':stack}


def fixed_cursor_writes(rows):
    """Literal LEA roots in the original mute/fade leaves; no alias or call walk."""
    roots={};result=[]
    for row in rows:
        require(row['mnemonic']not in ('jsr','bsr','movem','rte'),'unsummarized fixed-cursor call or restore')
        for p in row['operand_facts']:
            require(not(p.get('base_register')in roots and p.get('ea_update')),'implicit fixed cursor update')
            reg=p.get('direct_register')
            if reg in ('A0','A6')and 'write'in p.get('access',''):
                require(row['mnemonic']=='lea','fixed cursor is overwritten')
                q=row['operand_facts'][0]
                require(not q.get('indexed')and not q.get('base_register')
                        and q.get('displacement_known'),'fixed cursor is not literal')
                address=q.get('absolute_address')
                if q.get('pc_relative'):address=row['source_offset']+0x802+q['displacement']
                require(type(address)is int,'missing fixed cursor value');roots[reg]=address
        for i,p in enumerate(row['operand_facts']):
            if p.get('access')not in ('memory_write','memory_read_write'):continue
            require(p.get('base_register')in roots and p.get('width_bytes')==2
                    and p.get('displacement_known')and not p.get('indexed')
                    and not p.get('ea_update')and not p.get('bulk_transfer')
                    and p.get('absolute_address')is None,'uncovered fixed cursor write')
            address=roots[p['base_register']]+p['displacement']
            result.append({'runtime':row['source_offset']+0x800,'operand_index':i,
                           'kind':'literal_cursor','spans':[[address,address+2]]})
    return {'stores':result,'explicit_stack_writes':[]}


def leaf_graph(analysis,rows,root,lo,hi):
    """Follow only existing native non-call edges of one bounded leaf."""
    blocks=analysis['blocks'];starts={b['start_offset']:i for i,b in enumerate(blocks)}
    require(root-0x800 in starts,'leaf lacks accepted native entry');pending=[starts[root-0x800]];seen=set();returns=[]
    while pending:
        n=pending.pop()
        if n in seen:continue
        seen.add(n);b=blocks[n];start=b['start_offset']+0x800;end=b['end_offset']+0x800
        require((lo<=start<end<=hi)or(start==0x58382 and end==0x58384),'leaf escapes checked source')
        part=window(rows,start,end);tail=part[-1]
        es=analysis['edges'][b['edge_start']:b['edge_start']+b['edge_count']]
        require(bool(es)and all(e['source_block_index']==n for e in es),'leaf edge owner differs')
        if tail['mnemonic']=='rts':
            require(len(es)==1 and es[0]['kind']==5,'leaf return differs');returns.append(start);continue
        for e in es:
            require(e['kind']in(1,2,4)and 0<=e['target_block_index']<len(blocks),'unknown leaf control')
            pending.append(e['target_block_index'])
    require(bool(returns),'leaf lacks normal return')
    selected=[r for r in rows if any(blocks[n]['start_offset']<=r['source_offset']<blocks[n]['end_offset']for n in seen)]
    protected_registers(selected)
    return {'root':root,'blocks':len(seen),'instructions':len(selected),'return_blocks':sorted(returns),
            'preserved_address_registers':sorted(KEEP),'conditional_on_intact_code_frames_and_memory':True}


def ea(row,index,target):
    p=row['operand_facts'][index]
    require(p.get('pc_relative')and not p.get('indexed')and p.get('displacement_known')
            and row['source_offset']+0x802+p['displacement']==target,'PC-relative source differs')


def check_source(rows,analysis,data):
    require(len(data)==489472 and hashlib.sha256(data).hexdigest()==MAIN_SHA256,'whole member identity differs')
    require(len(rows)==30616 and all(r['provenance']=='accepted_instruction'and
            data[r['source_offset']:r['source_offset']+r['size']]==bytes.fromhex(r['bytes'])for r in rows),
            'accepted rows do not match member')
    at={r['source_offset']+0x800:r for r in rows}
    headers=[]
    for i,v in enumerate(VOICES):
        raw=data[v-0x800:v-0x800+34];h=audio_header(i)
        require([int.from_bytes(raw[n:n+2],'big')for n in(0,2,4)]==list(h.values())
                and raw[6:]==bytes(28),'initial voice record differs')
        headers.append({'voice':v,**h,'initial_phase':0,'initial_callback':0})
    initializer=window(rows,0x58280,0x58340);local=window(rows,0x583AA,0x58406)
    for part,retained,allowed in [(initializer,{'A1','A2','A6'},{0x58280,0x5829A}),
                                   (local,{'A1','A3','A6'},{0x583CC})]:
        for row in part:
            for p in row['operand_facts']:
                if p.get('direct_register')in retained and 'write'in p.get('access',''):
                    require(row['source_offset']+0x800 in allowed,'local root clobber')
                require(not(p.get('base_register')in retained and p.get('ea_update')),
                        'implicit local root clobber')
    handlers=window(rows,0x58406,0x584A4);mod=window(rows,0x584A4,0x584DE)
    require(initializer[-1]['mnemonic']=='rte'and initializer[1]['mnemonic']=='move'
            and initializer[2]['mnemonic']=='ori'and initializer[2]['operand_facts'][0]['immediate_value']==0x700,
            'initializer SR order differs')
    operand(at[0x58280],0,address=0xDFF000,width=4);operand(at[0x58280],1,register='A6',width=4)
    mem(at[0x58296]['operand_facts'][0],access='memory_read',width=2,base='A1',displacement=4)
    q=at[0x5829A]['operand_facts'][0]
    require(q.get('base_register')=='A6'and q.get('index_register')=='D5'and q.get('indexed')
            and q.get('index_width_bytes')==2 and q.get('index_scale')==1
            and q.get('displacement')==0,'initializer channel root differs')
    operand(at[0x5829A],1,register='A2',width=4)
    require([at[p]['mnemonic']for p in(0x583AA,0x583AE,0x583B0,0x583B2)]==
            ['tst','bne','rts','movea'],'phase gate differs')
    require({(e['kind'],e['target_offset']+0x800)for e in analysis['edges']
             if e['source_offset']+0x800==0x583AE}=={(2,0x583B2),(1,0x583B0)},'phase successors differ')
    for pc,reg,target in [(0x58314,'A3',0x58406),(0x5831E,'A3',0x58458),(0x58416,'A0',0x58448)]:
        ea(at[pc],0,target);operand(at[pc],1,register=reg,width=4)
    for pc,base,off,width in [(0x58334,'A1',26,4),(0x58338,'A1',6,2),(0x5841A,'A3',26,4)]:
        mem(at[pc]['operand_facts'][1],access='memory_write',width=width,base=base,displacement=off)
    require(at[0x58338]['operand_facts'][0]['immediate_value']==2,'active phase differs')
    for pc,offset in [(0x583AA,6),(0x583B2,30),(0x583C4,26),(0x583C8,4)]:
        mem(at[pc]['operand_facts'][0],access='memory_read',width=4 if offset in(26,30)else 2,base='A3',displacement=offset)
    p=at[0x583CC]['operand_facts'][0]
    require(p.get('base_register')=='A6'and p.get('index_register')=='D0'and p.get('index_width_bytes')==2
            and p.get('index_scale')==1 and p.get('indexed')and p.get('displacement')==0,'custom index differs')
    operand(at[0x583CC],1,register='A1',width=4)
    require(at[0x583D0]['mnemonic']=='jsr'and at[0x583D0]['operand_facts'][0]['base_register']=='A0','voice call differs')
    require([(r['source_offset']+0x800,r['mnemonic'])for r in local if r['mnemonic']in('jsr','bsr')]==[(0x583C0,'bsr'),(0x583D0,'jsr')],'local frontier differs')
    leaves=[leaf_graph(analysis,rows,r,lo,hi)for r,lo,hi in [(0x58406,0x58406,0x58448),(0x58448,0x58448,0x58458),(0x58458,0x58458,0x584A4),(0x584A4,0x584A4,0x584DE)]]
    summaries={name:bounded_writes(part,vr,hr)for name,part,vr,hr in[
        ('initializer',initializer,'A1','A2'),('voice_wrapper_excluding_callees',local,'A3','A1'),
        ('three_candidate_bodies',handlers,'A3','A1'),('period_modulation',mod,'A3','A1')]}
    summaries['mute']=fixed_cursor_writes(window(rows,0x58340,0x58384))
    summaries['master_fade_excluding_tail_to_mute']=fixed_cursor_writes(window(rows,0x5850E,0x58536))
    domains=[{'span':s}for a in summaries.values()for w in a['stores']for s in w['spans']]
    exclude_domains(domains,PROTECTED)
    exclude_domains(domains,{'model_header_cohort':(0x20FEE,0x29DF8),'current_source_prefix':(0x4E818,0x4ED18)})
    # Explicit initialization roots, not post-call type assumptions.
    for pc,v in [(0x5838E,VOICES[0]),(0x58396,VOICES[1]),(0x5839E,VOICES[2]),(0x583A6,VOICES[3])]:
        ea(at[pc],0,v);operand(at[pc],1,register='A3',width=4)
    operand(at[0x58388],0,address=0xDFF000,width=4);operand(at[0x58388],1,register='A6',width=4)
    # The indexed map write has a distinct root and mutable WORD addend.
    ea(at[0x58D78],0,0x58B00)
    p=at[0x58D7C]['operand_facts'][1]
    require(p.get('memory')and p.get('access')=='memory_write'and p.get('width_bytes')==1
            and p.get('base_register')=='A0'and p.get('index_register')=='D0'and p.get('indexed')
            and p.get('index_width_bytes')==2 and p.get('index_scale')==1 and not p.get('ea_update')
            and p.get('displacement')==0,'map writer differs')
    mem(at[0x58D76]['operand_facts'][0],access='memory_read',width=2,base='A4')
    map_band=indexed_word_band(0x58B00,0,1)
    callback_cells=[[v+26,v+30]for v in VOICES]
    require(all(map_band[0]<=lo<hi<=map_band[1]for lo,hi in callback_cells),'map alias band differs')
    for pc,target in [(0x5850E,0x5850A),(0x58516,0x5850C),(0x58522,0x58508),(0x5852C,0x58008),(0x58B3C,0x5850A),(0x58D5A,0x5850A)]:ea(at[pc],0,target)
    require(at[0x58D58]['mnemonic']=='ext'and at[0x58D58]['operand_facts'][0]['width_bytes']==2,'fade operand signed extension differs')
    require(at[0x58B40]['mnemonic']=='clr'and at[0x5851A]['mnemonic']=='subq'
            and at[0x58526]['mnemonic']=='subq','fade/reset sequence differs')
    # The original enabled tick has a narrower no-pattern branch after voices.
    require([r['mnemonic']for r in window(rows,0x58384,0x583AA)]==
            ['bsr','lea','lea','bsr','lea','bsr','lea','bsr','lea'],'voice-selection wrapper differs')
    for pc,target in [(0x58C96,0x58384),(0x58384,0x5850E),(0x58392,0x583AA),
                      (0x5839A,0x583AA),(0x583A2,0x583AA),(0x583C0,0x584A4)]:
        require({e['target_offset']+0x800 for e in analysis['edges']
                 if e['source_offset']+0x800==pc and e['kind']==3}=={target},'voice wrapper call differs')
    require([r['mnemonic']for r in window(rows,0x58C96,0x58CA4)]==
            ['bsr','lea','tst','beq'],'post-voice run gate differs')
    ea(at[0x58C9A],0,0x58008)
    mem(at[0x58C9E]['operand_facts'][0],access='memory_read',width=1,base='A0')
    require({(e['kind'],e['target_offset']+0x800)for e in analysis['edges']
             if e['source_offset']+0x800==0x58CA0}=={(2,0x58382),(1,0x58CA4)},'run gate successors differ')
    run_writers=[w for a in summaries.values()for w in a['stores']
                 if any(lo<0x58009 and hi>0x58008 for lo,hi in w['spans'])]
    require([w['runtime']for w in run_writers]==[0x58530]and at[0x58530]['mnemonic']=='clr',
            'known voice path can publish a nonzero run byte')
    site=[s for s in analysis['recovered_indirect_sites']if s['source_offset']==0x583D0-0x800]
    require(len(site)==1 and not site[0]['runtime_target_set_closed'],'voice site unexpectedly closed')
    require({r['offset']+0x800 for r in analysis['code_start_refs']if r.get('source_offset')==0x583D0-0x800}==set(CANDIDATES),'native candidate set differs')
    return {'main_sha256':MAIN_SHA256,'verification_scope':'member','runtime_executed':False,
        'initial_voice_headers':headers,'source_callback_candidates':list(CANDIDATES),
        'callback_cells':callback_cells,'initial_bank_audio_acknowledge':acknowledge(rows,0x584DE),'local_leaf_contracts':leaves,'local_write_summaries':summaries,
        'all_local_nonstack_domains_exclude_reviewed_render_storage':True,
        'first_six_voice_bytes_not_written_by_these_local_bodies':True,
        'hardware_root_with_arbitrary_current_WORD_is_not_audio_only':True,
        'audio_only_programming_requires_current_header_masks_and_offsets':True,
        'audio_DMA_reads_or_hardware_quiescence_proved':False,
        'map_byte_writer':{'runtime':0x58D7C,'signed_word_linear_hull':map_band,
            'intersects_all_four_callback_cells':True,'current_index_observed':False,
            'bounded_case':'current instrument_map_base in {0,8,16,24} and current map selector in 0..7',
            'table_extent_does_not_prove_current_index':True},
        'installed_bank_identity_and_global_writer_set_closed':False,
        'native_callback_target_set_closed':False,'native_post_call_facts_emitted':False,
        'enabled_voice_only_tick':{'post_voice_run_test':0x58C9E,'zero_returns_to':0x58382,
            'entry_zero_preserved_by_known_local_nonstack_writes':True,
            'requires':'intact initial player and normal nonaliasing frames, four caller-bound voices, each active callback in the three checked candidates, valid reads and no external write',
            'does_not_require_music_suppression':True,'nonzero_run_pattern_branch_excluded':True,
            'actual_entry_conditions_observed':False},
        'whole_tick_effects_closed':False,'original_media_and_placements_checked':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in('rows','analysis','member','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();r=check_source(json.loads(a.rows.read_text()),json.loads(a.analysis.read_text()),a.member.read_bytes())
    a.output.write_text(json.dumps(r,indent=2)+'\n')


if __name__=='__main__':main()

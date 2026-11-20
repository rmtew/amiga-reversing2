"""Source-bound model header/cohort and streaming-copy contracts; no admission."""
import argparse
import hashlib
import json
from pathlib import Path

from tools.foft_interrupt_frame_audit import (
    REGS15,
    exclude_domains,
    keyboard_domains_under_preserved_maps,
    stack_transfer,
)
from tools.foft_interrupt_frame_audit import (
    check_source as interrupt_contract,
)
from tools.foft_irq_write_audit import mem, require
from tools.foft_near_scenery_audit import PROTECTED, SPECS
from tools.foft_projectile_state_audit import collect as projectile_contract
from tools.foft_render_contract_audit import MAIN_SHA256, operand, window

SPECIAL = {0x26A4A,0x26D7C,0x29D3C,0x29DF8,0x23FB8,0x296FE,0x29B16,0x20FF4}
WRITERS = {0x2A0D4:0x29B16,0x2A19A:0x26D7C,0x2A2A2:0x26A4A,
           0x2A514:0x296FE,0x2A91A:0x26D7C,0x2A9FE:0x23FB8,
           0x2DA42:0x20FF4,0x2DD4A:0x29DF8,0x2DE00:0x29D3C,
           0x2DED4:0x29B16,0x2EBB4:0x20FF4}


def prefix_regions(values, low=0x800, high=0x78000):
    require(len(values)==len(set(values)), 'duplicate model values')
    result=[]
    for p in sorted(values):
        require(type(p)is int and p%2==0 and low<=p-6<p<=high, 'unmapped or odd prefix')
        require(not result or result[-1]['span'][1]<=p-6,'overlapping prefixes')
        result.append({'model_value':p,'span':[p-6,p],
                       'word_spans':[[p-6+2*i,p-4+2*i]for i in range(3)],
                       'final_writer_cursor':p-2})
    return result


def stream_regions(i,j,source=0x4E818,dest=0xE816):
    """Linear address algebra only; no extent or physical bus claim above 63."""
    require(type(i)is int and type(j)is int and 0<=j<=i<=65535,'invalid scan/output lineage')
    state=[source+20*i,source+20*i+20];view=[dest+12*j,dest+12*j+12]
    require(0<=view[0]<view[1]<=state[0]<state[1]<=2**32,'stream write may alias current source')
    return {'state':state,'view':view,'model_read':[state[0]+16,state[0]+20],
            'inside_two_existing_64_record_prefixes':i<64 and j<64,
            'physical_bus_alias_or_execution_proved':False}


def first_read_address(row):
    """Numeric EA of an already decoded first source operand, not a type fact."""
    if not row['operand_facts']:return None
    p=row['operand_facts'][0]
    if p.get('access')!='memory_read' or p.get('width_bytes')!=2:return None
    if p.get('pc_relative') and not p.get('indexed') and p.get('displacement_known'):
        require(p.get('ea_shape_id')==8,'different PC-relative source shape')
        return row['source_offset']+0x800+2+p['displacement']
    return p.get('absolute_address')if not p.get('base_register')and not p.get('indexed')else None


def storage_forms(metadata,values):
    structs=[s for s in metadata['custom_structs']if s['name']=='ModelOrientationPrefix']
    require(len(structs)==1 and structs[0]['size']==6 and
            [(f['name'],f['offset'],f['size'],f['type'])for f in structs[0]['fields']]==
            [('orientation'+str(i),2*i,2,'WORD')for i in range(3)], 'prefix type differs')
    result=[]
    for p in sorted(values):
        lo=p-6-0x800;found=[]
        for layout in metadata['data_block_layouts']:
            if not (layout['source_start']<=lo and lo+6<=layout['source_end']):continue
            for e in layout['elements']:
                if layout['source_start']+e['offset']==lo and e['width']==6:
                    b=e.get('type_binding')or{}
                    if b.get('binding_kind')=='custom_struct' and b.get('bound_type_id')=='ModelOrientationPrefix' and b.get('element_width')==6 and e.get('array_count')==1 and e.get('array_stride')==6:
                        found.append({'model_value':p,'kind':'existing_record_binding','owner':layout['name']})
        if not found and p==0x25A54:
            layouts=[l for l in metadata['data_block_layouts']if l['source_start']==lo and l['source_end']==lo+6]
            require(len(layouts)==1,'Hartley source owner differs')
            require(layouts[0]['default_unit']=='word' and all(not e.get('type_binding') and not e.get('reference_interpretation') and not e.get('representation')for e in layouts[0]['elements']) and [(e['offset'],e['width'],e['kind'])for e in layouts[0]['elements']]==[(0,2,'scalar'),(2,2,'scalar'),(4,2,'scalar')], 'Hartley scalar partition differs')
            found=[{'model_value':p,'kind':'preserved_independent_scalar_partition','owner':layouts[0]['name']}]
        require(len(found)==1,'missing or competing header schema')
        result.extend(found)
    return result



def fold_iteration_paths(nodes,root):
    """Fold verified step counts on an existing acyclic iteration graph."""
    active=set();memo={}
    def visit(n):
        require(n in nodes,'iteration leaves checked graph')
        require(n not in active,'unaccounted iteration cycle')
        if n in memo:return memo[n]
        active.add(n);node=nodes[n];cost=node['cost']
        require(len(cost)==3 and all(type(x)is int and x>=0 for x in cost),'invalid step cost')
        if node['terminal']:
            require(not node['successors'],'terminal has unchecked continuation')
            result={tuple(cost)}
        else:
            require(bool(node['successors']),'iteration has no counter boundary')
            result={tuple(a+b for a,b in zip(cost,end,strict=True))
                    for nxt in node['successors'] for end in visit(nxt)}
        active.remove(n);memo[n]=result;return result
    return visit(root)


def native_iteration(analysis,rows):
    blocks=analysis['blocks'];edges=analysis['edges'];root=0x2A6A2-0x800
    starts={b['start_offset']:i for i,b in enumerate(blocks)}
    require(root in starts,'scan is not a native block entry')
    advances={0x2A864:(1,0,0),0x2A868:(0,1,0),0x2A86C:(0,0,1),
              0x2AA2E:(1,0,0),0x2AA32:(0,0,1)}
    terminals={0x2A874:(0x2A878-0x800),0x2AA44:(0x2AA48-0x800)}
    nodes={};pending=[starts[root]];calls=[]
    while pending:
        i=pending.pop()
        if i in nodes:continue
        b=blocks[i];pc=b['start_offset']+0x800
        require(0x2A6A2<=pc<0x2A878 or 0x2AA2E<=pc<0x2AA48,'iteration escaped source windows')
        selected=[r for r in rows if b['start_offset']<=r['source_offset']<b['end_offset']]
        require(bool(selected),'empty native iteration block')
        cost=tuple(sum(advances.get(r['source_offset']+0x800,(0,0,0))[j]for r in selected)for j in range(3))
        tail=selected[-1]['source_offset']+0x800
        es=edges[b['edge_start']:b['edge_start']+b['edge_count']]
        require(all(e['source_block_index']==i for e in es),'edge owner differs')
        if tail in terminals:
            require({(e['kind'],e['target_offset'])for e in es}=={(2,root),(1,terminals[tail])},'counter successors differ')
            nodes[i]={'cost':cost,'terminal':True,'successors':[]};continue
        nxt=[]
        for e in es:
            if e['kind']==3:
                require(e['source_offset']+0x800==0x2A7BC and e['target_offset']+0x800==0x4F572,'unaccounted loop call')
                calls.append(e['source_offset']+0x800);continue
            require(e['kind']in(1,2,4) and 0<=e['target_block_index']<len(blocks),'unresolved loop control')
            nxt.append(e['target_block_index'])
        nodes[i]={'cost':cost,'terminal':False,'successors':nxt};pending.extend(nxt)
    outcomes=fold_iteration_paths(nodes,starts[root])
    require(outcomes=={(1,1,1),(1,0,1)} and calls==[0x2A7BC],'iteration does not preserve scan/output lineage')
    return {'native_blocks':len(nodes),'step_vectors_state_view_orientation':sorted(outcomes),
            'counter_boundaries':sorted(terminals),'normal_saved_call_boundary':calls,
            'new_cfg_or_code_facts_emitted':False}


def check_source(rows,analysis,data,mapping,metadata=None):
    prior=projectile_contract(rows,analysis,data)
    irq=interrupt_contract(rows,analysis,data)
    at={r['source_offset']+0x800:r for r in rows}
    table=mapping['table'];part=data[table['runtime_start']-0x800:table['runtime_end']-0x800]
    require(len(part)==128 and hashlib.sha256(part).hexdigest()==table['sha256'],'model table differs')
    models={int.from_bytes(part[i:i+4],'big')for i in range(0,128,4)}
    require(len(models)==32 and models=={e['entry_runtime']for e in mapping['entries']},'table mapping differs')
    accepted={r['offset']+0x800 for r in analysis['code_start_refs']if r.get('source_offset')==0xE80E-0x800}
    scenery={s[1]for s in SPECS};titles={0x223FE,0x228A2,0x22DA0}
    require(accepted==models|scenery|titles and not accepted&SPECIAL,'draw/cohort partition differs')
    cohort=models|SPECIAL|titles;regions=prefix_regions(list(cohort));require(len(regions)==43,'cohort differs')
    code={str(i):(b['start_offset']+0x800,b['end_offset']+0x800)for i,b in enumerate(analysis['blocks'])}
    exclude_domains(regions,{**PROTECTED,**code})
    require(all(r['span'][0]>=0x16850 for r in regions),'header enters work restore window')
    # Exact two-read/three-write body. No pointee or current-value fact follows.
    outer_regs={f'D{i}'for i in range(4)}|{f'A{i}'for i in range(5)}
    require(stack_transfer(at[0x2A662],outer_regs)==36 and
            stack_transfer(at[0x2AA28],outer_regs,restore=True)==36,'builder outer frame differs')
    body=window(rows,0x2A71A,0x2A736)
    require([r['mnemonic']for r in body]==['move','movea','suba','move','move','move'],'model header body differs')
    mem(body[0]['operand_facts'][0],access='memory_read',width=4,base='A0',displacement=16)
    mem(body[0]['operand_facts'][1],access='memory_write',width=4,base='A1',displacement=6)
    mem(body[1]['operand_facts'][0],access='memory_read',width=4,base='A0',displacement=16)
    operand(body[1],1,register='A3',width=4)
    require(body[2]['operand_facts'][0].get('immediate_value')==6,'header displacement differs')
    operand(body[2],1,register='A3',width=4)
    for i,row in enumerate(body[3:]):
        mem(row['operand_facts'][0],access='memory_read',width=2,base='A2',displacement=i*2)
        mem(row['operand_facts'][1],access='memory_write',width=2,base='A3',update=1 if i<2 else 0)
    for pc,value in WRITERS.items():
        row=at[pc];require(row['mnemonic']=='move'and row['operand_facts'][0].get('immediate_value')==value,'state literal differs')
        p=row['operand_facts'][1]
        expected=('A0',16,0)if pc in (0x2A0D4,0x2A19A,0x2A2A2,0x2A514,0x2A91A,0x2A9FE)else ('A6',0,1)if pc==0x2DA42 else ('A6',0,0)if pc in(0x2DD4A,0x2DE00)else ('A6',16,0)if pc==0x2DED4 else ('A3',16,0)
        mem(p,access='memory_write',width=4,base=expected[0],displacement=expected[1],update=expected[2])
    # Native cursor definitions: accepted versus rejected row, same DBF counter.
    for pc,root,reg in [(0x2A676,0x4E818,'A0'),(0x2A67C,0xE816,'A1'),(0x2A682,0x2B994,'A2')]:
        operand(at[pc],0,address=root,width=4);operand(at[pc],1,register=reg,width=4)
    advances={0x2A864:('A0',20),0x2A868:('A1',12),0x2A86C:('A2',10),
              0x2AA2E:('A0',20),0x2AA32:('A2',10)}
    for pc,(reg,step)in advances.items():
        p=at[pc]['operand_facts'][0]
        require(at[pc]['mnemonic']=='lea'and p.get('base_register')==reg and p.get('displacement')==step and not p.get('indexed'),'cursor advance differs')
        operand(at[pc],1,register=reg,width=4)
    require(stack_transfer(at[0x2A7B6],REGS15)==60 and stack_transfer(at[0x2A7C2],REGS15,restore=True)==60,'loop call frame differs')
    loop=window(rows,0x2A6A2,0x2A878)+window(rows,0x2AA2E,0x2AA4C)
    require([r['source_offset']+0x800 for r in loop if r['mnemonic']in ('jsr','bsr')]==[0x2A7BC],'loop call frontier differs')
    for r in loop:
        for p in r['operand_facts']:
            if p.get('direct_register')in ('A0','A1','A2','D7')and 'write'in p.get('access',''):
                require(r['source_offset']+0x800 in advances,'loop cursor clobber')
    for r in loop:
        for p in r['operand_facts']:
            require(not(p.get('base_register')in ('A0','A1','A2')and p.get('ea_update')), 'implicit loop cursor update')
            if p.get('access')=='register_list_write' and set(p.get('register_list',[]))&{'A0','A1','A2','D7'}:
                require(r['source_offset']+0x800==0x2A7C2,'unaccounted loop register reload')
    iteration=native_iteration(analysis,rows)
    for pc in (0x2A874,0x2AA44):
        require(at[pc]['mnemonic']=='dbf'and at[pc]['operand_facts'][0].get('direct_register')=='D7','scan counter differs')
    source_prefix=(0x4E818,0x4ED18)
    irq_domains=[*irq['vblank']['non_stack_cpu_write_domains'],
                 *keyboard_domains_under_preserved_maps(irq['keyboard']),
                 *irq['joystick']['non_stack_cpu_write_domains'],
                 *[{'span':s}for s in [[0x10D30,0x10D34],[0x10D34,0x10D36],[0x10D38,0x10D3A]]],
                 *[{'span':[base+off,base+off+2]}for base in(0x4F336,0x4F346)for off in(6,10)]]
    exclude_domains(irq_domains,{'current_source_prefix':source_prefix})
    readers=[]
    for e in mapping['entries']:
        b=e['recognized_body'];lo,hi=b['runtime_start'],b['runtime_end'];p=e['entry_runtime']
        require(hashlib.sha256(data[lo-0x800:hi-0x800]).hexdigest()==b['sha256'],'model body fingerprint differs')
        found={}
        for r in rows:
            if lo<=r['source_offset']+0x800<hi:
                a=first_read_address(r)
                if a in (p-6,p-4,p-2):found.setdefault(a-p+6,r['source_offset']+0x800)
        require(set(found)=={0,2,4},'model header reader differs')
        readers.append({'index':e['index'],'model':p,'word_read_witnesses':sorted(found.items())})
    # Preserve the separate already-typed launch span; do not conflate it with P-6.
    for pc,source,dest in [(0x2DE30,0xFCF0,0x29D30),(0x2DE3A,0xFCEE,0x29D32),(0x2DE44,0xFCEC,0x29D34)]:
        operand(at[pc],0,address=source,width=2);operand(at[pc],1,address=dest,width=2)
    return {'main_sha256':MAIN_SHA256,'runtime_executed':False,
            'native_accepted_draw_values':sorted(accepted),'state_literal_cohort':sorted(SPECIAL),
            'state_literal_values_outside_accepted_draw_set':sorted(SPECIAL-accepted),
            'native_current_target_set_closed':False,'code_admission_performed':False,
            'table_values':32,'header_value_cohort':43,'header_bytes':258,
            'prefix_regions':regions,'source_literal_writers':[{'runtime':pc,'value':v}for pc,v in WRITERS.items()],
            'known_headers_disjoint_from_accepted_code_and_reviewed_storage':True,
            'known_headers_outside_scenery_work_window':True,
            'builder_register_save_bytes':36,'builder_saved_count_word_separate':True,
            'model_header_cursor_is_not_returned_A3_contract':True,
            'native_iteration_certificate':iteration,
            'stream_linear_bounds':[stream_regions(0,0),stream_regions(63,63),stream_regions(65535,65535)],
            'copy_and_reload_equality':{'kind':'conditional_source_result','current_source_slot_must_be_in_prefix':True,
                'own_view_store_cannot_alias_current_state_under_cursor_lineage':True,
                'covered_music_suppressed_irq_components_exclude_current_source_prefix':True,
                'entry_conditions_observed':False,'requires':'intact original code, normal nonaliasing call/IRQ frames, valid mapped current source slot, prior music-suppressed IRQ premises and no interfering device/other write'},
            'readers':readers,'raw_special_body_readers_or_entries_inferred':False,
            'fusion_launch_span':[0x29D30,0x29D36],'fusion_model_prefix':[0x29D36,0x29D3C],
            'launch_and_draw_prefix_equated':False,'prior_projectile_contract_rechecked':prior['main_sha256'],
            'bound_storage_forms':storage_forms(metadata,cohort)if metadata is not None else None}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('rows','analysis','member','map','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--metadata',type=Path);a=p.parse_args()
    r=check_source(json.loads(a.rows.read_text()),json.loads(a.analysis.read_text()),a.member.read_bytes(),json.loads(a.map.read_text()),json.loads(a.metadata.read_text())if a.metadata else None)
    a.output.write_text(json.dumps(r,indent=2)+'\n')


if __name__=='__main__':main()

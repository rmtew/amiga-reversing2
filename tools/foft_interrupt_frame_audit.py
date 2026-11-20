"""Pinned interrupt-local frame/write contracts, not global asynchronous closure."""
import argparse
import hashlib
import json
from pathlib import Path

from tools.foft_irq_write_audit import (
    collect,
    keyboard_alias_band,
    reachable_write_inventory,
    require,
)
from tools.foft_near_scenery_audit import PROTECTED
from tools.foft_near_scenery_audit import check_source as scenery_contract
from tools.foft_render_contract_audit import MAIN_SHA256, operand, window

REGS15 = {f'D{i}' for i in range(8)} | {f'A{i}' for i in range(7)}


def stack_transfer(row, registers, *, restore=False, width=4):
    """Count original MOVEM bits; never omit the selected SP register."""
    facts = row['operand_facts']
    require(row['mnemonic'] == 'movem' and len(facts) == 2, 'not a MOVEM pair')
    reg, mem = (facts[1], facts[0]) if restore else facts
    require(set(reg.get('register_list', [])) == set(registers)
            and len(reg['register_list']) == len(registers)
            and reg.get('access') == ('register_list_write' if restore else 'register_list_read')
            and reg.get('width_bytes') == width, 'register mask or width differs')
    require(mem.get('memory') and mem.get('base_register') == 'A7'
            and not mem.get('indexed') and mem.get('displacement') == 0
            and mem.get('displacement_known') and mem.get('absolute_address') is None
            and mem.get('ea_update') == (1 if restore else 2)
            and mem.get('width_bytes') == width and mem.get('bulk_transfer')
            and mem.get('access') == ('memory_read' if restore else 'memory_write'),
            'stack transfer receiver differs')
    return len(registers)*width


def exclude_domains(domains, protected):
    for site in domains:
        lo, hi = site['span']
        require(type(lo) is int and type(hi) is int and 0 <= lo < hi <= 2**32,
                'invalid domain extent')
        for name, (a, b) in protected.items():
            require(not (lo < b and a < hi), f'IRQ domain intersects {name}')
    return True


def local_writes(rows, lo, hi, *, fixed_base=None, indexed=None):
    """Inspect a bounded body; calls are reported separately, never summarized pure."""
    part = window(rows, lo, hi)
    domains, stack, calls = [], [], []
    for row in part:
        pc = row['source_offset']+0x800
        if row['mnemonic'] in ('jsr', 'bsr'):
            calls.append(pc)
        for i, p in enumerate(row['operand_facts']):
            if p.get('access') not in ('memory_write', 'memory_read_write'):
                continue
            base = p.get('base_register'); width = p.get('width_bytes')
            if base == 'A7':
                require(not p.get('indexed') and p.get('ea_update') == 2,
                        'unexpected interrupt stack write')
                stack.append({'runtime': pc, 'operand_index': i})
                continue
            require(width in (1, 2, 4) and not p.get('bulk_transfer'), 'unknown IRQ write width')
            address = p.get('absolute_address')
            if base is None and not p.get('indexed') and address is not None:
                span = [address, address+width]
            elif indexed and pc == indexed[0]:
                require(base == 'A1' and p.get('indexed') and width == 2,
                        'keyboard store differs')
                span = indexed[1]
            else:
                require(fixed_base and base == fixed_base[0] and not p.get('indexed')
                        and not p.get('ea_update') and p.get('displacement_known'),
                        'uncovered interrupt-local writer')
                address = fixed_base[1] + p['displacement']; span = [address, address+width]
            domains.append({'runtime': pc, 'operand_index': i, 'span': span})
    return {'non_stack_cpu_write_domains': domains, 'stack_sites': stack,
            'callee_effects_excluded_at': calls}



def setup_sound_fields(p):
    """Refine two caller-bound states into disjoint fields, not one hull."""
    require(p.get('base_register')=='A1' and p.get('memory')
            and p.get('access')=='memory_write' and p.get('width_bytes')==2
            and p.get('displacement_known') and p.get('displacement') in (6,10)
            and not p.get('indexed') and not p.get('ea_update') and not p.get('bulk_transfer'),
            'sound field differs')
    return [{'span':[base+p['displacement'],base+p['displacement']+2]}
            for base in (0x4F336,0x4F346)]



def keyboard_domains_under_preserved_maps(section):
    """An explicit conditional refinement, not a current-map assertion."""
    result=[]; seen=0
    for s in section['non_stack_cpu_write_domains']:
        if s['runtime']==0x10B56:
            require(s['span']==keyboard_alias_band(), 'keyboard source band differs')
            result.append({**s,'span':[0x102F6,0x103F6]});seen+=1
        else:result.append(s)
    require(seen==1,'missing keyboard indexed store')
    return result


def check_source(rows, analysis, data):
    require(len(data) == 489472 and hashlib.sha256(data).hexdigest() == MAIN_SHA256,
            'whole main identity differs')
    # Reuses original map, sound, acknowledge, COPER and accepted-row checks.
    previous = collect(rows, data, analysis)
    scenery = scenery_contract(rows, analysis, data)
    initial_tick=reachable_write_inventory(rows,analysis,[0x58004-0x800])
    require(initial_tick['instructions']==453 and initial_tick['blocks']==141
            and initial_tick['other_write_operands']==132
            and initial_tick['unresolved_nonreturn_edges']==[{'runtime':0x583D0,'kind':3}],
            'initial tick CFG frontier differs')
    bypc = {r['source_offset']+0x800:r for r in rows}
    require(bypc[0x80E]['operand_facts'][0].get('immediate_value') == 0xB3CE, 'initial stack top differs')
    operand(bypc[0x80E], 1, register='A7', width=4)
    vectors=[]
    expected_vectors={0x1079A:(0x6C,0x10880),0x107A2:(0x68,0x10AE4),
                      0x4F580:(0x70,0x4F458),0x58B30:(0x70,0x584DE)}
    for r in rows:
        pc=r['source_offset']+0x800
        for p in r['operand_facts']:
            if p.get('absolute_address') not in (0x68,0x6C,0x70) or p.get('access') not in ('memory_write','memory_read_write'):
                continue
            require(pc in expected_vectors and p.get('width_bytes')==4
                    and not p.get('indexed') and not p.get('base_register')
                    and not p.get('bulk_transfer'), 'direct vector writer differs')
            address,target=expected_vectors[pc]
            require(p['absolute_address']==address, 'vector receiver differs')
            if pc!=0x58B30:
                require(r['operand_facts'][0].get('immediate_value')==target, 'vector value differs')
            else:
                pair=window(rows,0x58B2C,0x58B34);q=pair[0]['operand_facts'][0]
                require(pair[0]['mnemonic']=='lea' and q.get('pc_relative')
                        and q.get('displacement_known') and q.get('displacement')==target-0x58B2E,
                        'bank vector address producer differs')
                operand(pair[0],1,register='A0',width=4)
                operand(pair[1],0,register='A0',width=4)
            vectors.append({'runtime':pc,'vector':address,'target':target})
    require(len(vectors)==4,'missing direct vector writer')
    frames = []
    for save, restore, regs, name in [
        (0xE7B6, 0xE810, REGS15 | {'A7'}, 'draw_callback'),
        (0x4AE06, 0x4AF62, REGS15, 'outer_scenery'),
        (0x108A6, 0x10A90, REGS15, 'vertical_blank')]:
        size = stack_transfer(bypc[save], regs)
        require(stack_transfer(bypc[restore], regs, restore=True) == size,
                'mismatched restore mask')
        frames.append({'name':name, 'save':save, 'restore':restore, 'bytes':size,
                       'includes_A7_in_mask':'A7' in regs,
                       'valid_frames_and_normal_return_required':True})
    # The four local branches have exact single-register save/pop sequences.
    singles = [(0x10880,0x10898,'D0',2),(0x10880,0x10D2C,'D0',2),(0x10880,0x108A4,'D0',2),
               (0x10AE4,0x10B8C,'D0',2),(0x10AE6,0x10B8A,'A0',4),
               (0x10B16,0x10B5C,'D1',2),(0x10B34,0x10B5A,'A1',4),
               (0x10CEA,0x10D2A,'A0',4),(0x10CEC,0x10D28,'A1',4)]
    # COPER restore A0 is at 10D2A; its final entry D0 pop is 10D2C.
    for save, restore, reg, width in singles:
        for pc, pop in [(save,False),(restore,True)]:
            r = bypc[pc]; p = r['operand_facts']; mem, val = (p[0],p[1]) if pop else (p[1],p[0])
            require(r['mnemonic'] in ('move','movea') and val.get('direct_register') == reg
                    and val.get('width_bytes') == width and mem.get('base_register') == 'A7'
                    and mem.get('memory') and not mem.get('indexed') and not mem.get('bulk_transfer')
                    and mem.get('displacement_known') and mem.get('displacement')==0
                    and mem.get('width_bytes') == width and mem.get('ea_update') == (1 if pop else 2)
                    and val.get('access')==('register_write'if pop else'register_read')
                    and mem.get('access') == ('memory_read' if pop else 'memory_write'),
                    'single-register frame differs')
    vblank=local_writes(rows,0x10880,0x10A9C,fixed_base=('A0',0x25A54))
    require(vblank['callee_effects_excluded_at']==[0x1091A,0x1092C,0x10932],
            'VBlank call boundary differs')
    # Only the orientation section writes via A0, rooted once before all those writes.
    orientation=window(rows,0x10944,0x109DC)
    operand(orientation[0],0,address=0x25A54,width=4)
    operand(orientation[0],1,register='A0',width=4)
    require(all(not (p.get('direct_register')=='A0' and 'write' in p.get('access',''))
                for r in orientation[1:] for p in r['operand_facts']), 'orientation root clobber')
    for s in vblank['non_stack_cpu_write_domains']:
        p=bypc[s['runtime']]['operand_facts'][s['operand_index']]
        if p.get('base_register')=='A0':
            require(0x10950<=s['runtime']<0x109DC and p.get('width_bytes')==2
                    and p.get('displacement') in (-4,-2), 'orientation write escaped')
    keyboard=local_writes(rows,0x10AE4,0x10B90,fixed_base=('A0',0xBFE001),
                          indexed=(0x10B56,keyboard_alias_band()))
    operand(bypc[0x10AE8],0,address=0xBFE001,width=4)
    operand(bypc[0x10AE8],1,register='A0',width=4)
    require(all(not(p.get('direct_register')=='A0' and 'write' in p.get('access',''))
                for r in window(rows,0x10AEE,0x10B8A) for p in r['operand_facts']),
            'keyboard root clobber')
    joystick=local_writes(rows,0x10C76,0x10CC4)
    protected={**PROTECTED}
    for section in (vblank,joystick):
        exclude_domains(section['non_stack_cpu_write_domains'],protected)
    # Even an unconstrained current map cannot write the high cells/count/backups.
    high={k:v for k,v in protected.items()if k not in ('view_snapshot','draw_backup','draw_bank','span_table')}
    exclude_domains(keyboard['non_stack_cpu_write_domains'],high)
    audio_offsets={'aud0_offset_word':(0x4F33A,0x4F33C),
                   'aud2_offset_word':(0x4F34A,0x4F34C)}
    values=[int.from_bytes(data[lo-0x800:hi-0x800],'big')for lo,hi in audio_offsets.values()]
    require(values==[0xA0,0xC0], 'initial audio offsets differ')
    refined=[]
    for site in scenery['write_cover']:
        if site['domain']=='audio_software':
            refined.extend(setup_sound_fields(bypc[site['runtime']]['operand_facts'][site['operand_index']]))
        elif site['byte_envelope']is not None:
            refined.append({'span':site['byte_envelope']})
    exclude_domains(refined,audio_offsets)
    exclude_domains([{'span':s}for s in previous['sound_updater']['software_write_byte_spans']],audio_offsets)
    for section in (vblank,keyboard,joystick):
        exclude_domains(section['non_stack_cpu_write_domains'],audio_offsets)
    # Source implication: nonzero music suppression is stable within these
    # components, so the known VBlank branch does not delegate to bank tick.
    # No current guard/map/vector/stack values are supplied or asserted here.
    for pc,mnemonic,value in [(0x10B2A,'bclr',7),(0x10B3C,'andi',255)]:
        r=bypc[pc];require(r['mnemonic']==mnemonic and
                r['operand_facts'][0].get('immediate_value')==value,
                'raw-key range control differs')
    guarded={**scenery['protected_intervals'],**audio_offsets,
             'music_suppression':(0x102F0,0x102F2),
             'raw_key_map_prefix':(0x10B96,0x10C16),
             'active_logical_map_prefix':(0x11298,0x11398),
             'level2_vector':(0x68,0x6C),'level3_vector':(0x6C,0x70)}
    irq_domains=[*vblank['non_stack_cpu_write_domains'],
                 *keyboard_domains_under_preserved_maps(keyboard),
                 *joystick['non_stack_cpu_write_domains'],
                 *[{'span':s}for s in previous['coper']['software_write_byte_spans']],
                 *[{'span':s}for s in previous['sound_updater']['software_write_byte_spans']]]
    exclude_domains(refined,guarded);exclude_domains(irq_domains,guarded)
    code=[(b['start_offset']+0x800,b['end_offset']+0x800)for b in analysis['blocks']]
    exclude_domains(irq_domains,{str(i):s for i,s in enumerate(code)})
    allowed_level4=[]
    for s in scenery['write_cover']:
        e=s['byte_envelope']
        if e and e[0]<0x74 and e[1] > 0x70:
            require(s['runtime']==0x4F580 and e==[0x70,0x74],
                    'unexpected covered level4 vector writer')
            allowed_level4.append(s['runtime'])
    require(allowed_level4==[0x4F580],'sound vector installation missing')
    exclude_domains(irq_domains,{'level4_vector':(0x70,0x74)})
    return {'main_sha256':MAIN_SHA256,'cpu':'68000','runtime_executed':False,
            'initial_supervisor_stack_top':0xB3CE,'stack_allocation_or_global_bound_proved':False,
            'direct_vector_installations_in_pinned_main':vectors,
            'current_vector_values_or_indirect_vector_writers_closed':False,
            'frames':frames,'irq_local_frame_bytes_including_standard_six_byte_exception':
            {'level3_no_service':8,'coper':16,'vblank_outside_calls':66,
             'keyboard_serial':18,'keyboard_timer_or_idle':12,'audio_acknowledge':8},
            'nested_calls_exceptions_and_installed_bank_not_in_local_frame_totals':True,
            'vblank':vblank,'keyboard':keyboard,'joystick':joystick,
            'vblank_local_excludes_protected_ranges':True,
            'keyboard_unconstrained_excludes_high_protected_ranges':True,
            'keyboard_unconstrained_can_alias_low_snapshots_and_code':True,
            'unconstrained_keyboard_band_contains_initial_stack_top':keyboard_alias_band()[0]<=0xB3CE<keyboard_alias_band()[1],
            'sound_and_coper_components_rechecked':True,
            'audio_offset_words':audio_offsets,'initial_audio_offsets':values,
            'initial_audio_offsets_preserved_by_covered_scenery_and_irq_local_cpu_domains':True,
            'conditional_audio_setup_byte_domains':[[base+off,base+off+width]for base in (0xDFF0A0,0xDFF0C0)for off,width in ((0,4),(4,2),(6,2),(8,2))],
            'conditional_audio_updater_clear_domains':[[base+10,base+12]for base in (0xDFF0A0,0xDFF0C0)],
            'audio_register_note':'Setup writes LONG at +0, WORD at +4/+6/+8; updater clears WORD at +10. Not a contiguous transfer or global current-offset invariant.',
            'replaceable_music_tick':previous['replacement_music_tick_runtime'],
            'initial_bank_tick_accepted_cfg_frontier':initial_tick,
            'music_suppressed_component_invariant':{
                'kind':'conditional_source_implication','entry_conditions_observed':False,
                'entry_premises':['nonzero musicTickSuppressed WORD',
                    'raw and active logical key maps retain proved domains',
                    'known level2/level3 and one of the two covered level4 bodies, intact code',
                    'initial scenery cell/face/span/root contracts and audio offsets',
                    'normal intact nonaliasing frames; no other handlers, faults or unrelated writers'],
                'components_preserve_guard_maps_vectors_code_and_reviewed_storage':True,
                'bank_tick_not_selected_under_stable_guard':True,
                'known_level4_transition':{'writer':0x4F580,'target':0x4F458},
                'actual_dma_order_or_whole_game_invariant_proved':False},
            'current_writable_callback_set_closed':False,
            'global_stack_irq_dma_lifetime_proved':False,
            'protected_ranges':protected}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('rows','analysis','member','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();r=check_source(json.loads(a.rows.read_text()),json.loads(a.analysis.read_text()),a.member.read_bytes())
    a.output.write_text(json.dumps(r,indent=2)+'\n')


if __name__=='__main__':main()

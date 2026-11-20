"""Recheck accepted projectile producer/lifecycle contracts, without admitting code.

The modular domains below are host integer algebra for pinned WORD arithmetic.
They are conditional address domains, not live-count, allocation or IRQ proofs.
"""
import argparse
import bisect
import hashlib
import json
from math import gcd
from pathlib import Path

from tools.foft_irq_write_audit import mem, require
from tools.foft_render_contract_audit import MAIN_SHA256, operand, window


def word_packet_domain(base, coefficient, width):
    require(all(type(v) is int for v in (base, coefficient, width))
            and 0 <= base <= 0xFFFFFFFF and coefficient > 0 and width > 0,
            'invalid affine packet')
    step = gcd(coefficient, 65536)
    first = base - (32768 // step) * step
    last = base + (32767 // step) * step
    require(first >= 0 and last + width <= 0x100000000, 'address wrapping needs a separate domain')
    return {'first_start': first, 'last_start': last, 'start_stride': step,
            'packet_bytes': width, 'byte_band': [first, last + width],
            'index_scope': 'all WORD bit patterns', 'live_count_bound_proved': False}


def can_intersect(domain, start, size):
    require(type(start) is int and type(size) is int and start >= 0 and size > 0
            and start + size <= 0x100000000,
            'invalid comparison span')
    lo = max(domain['first_start'], start - domain['packet_bytes'] + 1)
    hi = min(domain['last_start'], start + size - 1)
    aligned = lo + (domain['first_start'] - lo) % domain['start_stride']
    return aligned <= hi


def packet(rows, start, end, *, model=None, category=None, orientation_step=None):
    is_state = model is not None
    require((is_state and type(model) is int and type(category) is int
             and 0 <= model <= 0xFFFFFFFF and 0 <= category <= 65535 and orientation_step is None)
            or (not is_state and category is None and type(orientation_step) is int
                and 0 <= orientation_step <= 65535), 'packet literals require an explicit contract')
    block = window(rows, start, end)
    require(len(block) == (9 if is_state else 5), 'packet instruction count differs')
    cursor = 0
    for i, row in enumerate(block):
        clear = i == (6 if is_state else 3)
        require(row['mnemonic'] == ('clr' if clear else 'move'), 'packet opcode differs')
        require(len(row['operand_facts']) == (1 if clear else 2), 'packet operand count differs')
        index = 0 if clear else 1
        width = 4 if is_state and i == 8 else 2
        mem(row['operand_facts'][index], access='memory_write', width=width,
            base='A6', update=0 if i == len(block)-1 else 1)
        if not clear:
            p = row['operand_facts'][0]
            if i == len(block)-1:
                require(p.get('immediate_value') == (model if is_state else orientation_step)
                        and p.get('width_bytes') == width, 'packet final literal differs')
            elif is_state and i == 7:
                require(p.get('immediate_value') == category and p.get('width_bytes') == 2,
                        'state category differs')
            else:
                require(p.get('access') == 'memory_read' and p.get('width_bytes') == 2,
                        'packet source WORD differs')
        cursor += width
    require(cursor == (20 if is_state else 10), 'packet width differs')
    return {'start_runtime': start, 'end_runtime': end, 'bytes_written': cursor,
            'model_value': model, 'category_word': category,
            'orientation_step_word': orientation_step}


def multiply_add(rows, multiply, add, coefficient, reg):
    at = {r['source_offset'] + 0x800: r for r in rows}
    a, b = at[multiply], at[add]
    require(a['mnemonic'] == 'mulu' and b['mnemonic'] == 'adda', 'index arithmetic differs')
    require(a['operand_facts'][0].get('immediate_value') == coefficient
            and a['operand_facts'][0].get('width_bytes') == 2, 'WORD coefficient differs')
    operand(a, 1, register=reg); operand(b, 0, register=reg, width=2); operand(b, 1, register='A6')


def known_draw_membership(analysis, entries):
    blocks, edges = analysis['blocks'], analysis['edges']
    starts = [b['start_offset'] for b in blocks]
    roots = {r['offset'] for r in analysis['code_start_refs']
             if r.get('source_offset') == 0xE80E-0x800}
    require(len(roots) == 43, 'review changed draw candidate set first')
    pending = [bisect.bisect_right(starts, p)-1 for p in roots]
    require(all(n >= 0 and blocks[n]['start_offset'] in roots for n in pending),
            'draw entry is not an accepted block')
    seen = set()
    while pending:
        n = pending.pop()
        if n in seen: continue
        seen.add(n)
        b = blocks[n]
        for e in edges[b['edge_start']:b['edge_start']+b['edge_count']]:
            require(e['source_block_index'] == n, 'edge owner differs')
            t = e['target_block_index']
            if 0 <= t < len(blocks): pending.append(t)
    result = {}
    for name, pc in entries.items():
        n = bisect.bisect_right(starts, pc-0x800)-1
        result[name] = n in seen and pc-0x800 < blocks[n]['end_offset']
    return {'scope': 'existing accepted 43-target native CFG, excluding async entry',
            'entries_reachable': result, 'runtime_target_set_closed': False}


def collect(rows, analysis, data):
    require(len(data) == 489472 and hashlib.sha256(data).hexdigest() == MAIN_SHA256,
            'complete member identity differs')
    require(len(rows) == 30616 and len({r['source_offset'] for r in rows}) == len(rows)
            and all(r['provenance'] == 'accepted_instruction'
                    and data[r['source_offset']:r['source_offset']+r['size']] == bytes.fromhex(r['bytes'])
                    for r in rows), 'native accepted rows differ from member')
    at = {r['source_offset'] + 0x800: r for r in rows}
    for base, targets in [(0x2D752, (0x2DCD8, 0x2DD8A)),
                          (0x2DFE6, (0x2E620, 0x2E6FA))]:
        for slot, target in zip((4, 5), targets, strict=True):
            offset = base - 0x800 + slot * 4
            require(int.from_bytes(data[offset:offset+4], 'big') == target,
                    'system registry entry differs')
    windows = {name: len(window(rows, start, end)) for name,start,end in [
        ('launch_type4',0x2DCD8,0x2DD82),('launch_fusion',0x2DD8A,0x2DE56),
        ('update_type4',0x2E620,0x2E6F8),('update_fusion',0x2E6FA,0x2E88A)]}
    packets = []
    for state, orientation, tracker, mul, add, omul, oadd, first, last, ofirst, olast, model, cat, step in [
        (0x2DD06,0x2DD56,0x2DD82,0x2DD14,0x2DD18,0x2DD5C,0x2DD60,0x2DD20,0x2DD50,0x2DD62,0x2DD7A,0x29DF8,10,16),
        (0x2DDBC,0x2DE0C,0x2DE56,0x2DDCA,0x2DDCE,0x2DE12,0x2DE16,0x2DDD6,0x2DE06,0x2DE18,0x2DE30,0x29D3C,5,8),
    ]:
        for pc, root in [(state,0x4E818),(orientation,0x2B994)]:
            require(at[pc]['mnemonic'] == 'lea', 'packet root producer differs')
            operand(at[pc],0,address=root,width=4); operand(at[pc],1,register='A6',width=4)
        read, clone = at[state+6], at[state+12]
        require(read['mnemonic']=='move' and clone['mnemonic']=='move','count capture differs')
        operand(read,0,address=0x4F218,width=2); operand(read,1,register='D0',width=2)
        operand(clone,0,register='D0',width=2); operand(clone,1,register='D1',width=2)
        multiply_add(rows,mul,add,20,'D0'); multiply_add(rows,omul,oadd,10,'D1')
        increment=at[last]
        require(increment['mnemonic']=='addq' and
                increment['operand_facts'][0].get('immediate_value')==1,'count update differs')
        operand(increment,1,address=0x4F218,width=2)
        save = at[add+2]
        require(save['mnemonic'] == 'move', 'saved-address store differs')
        operand(save,0,register='A6',width=4); operand(save,1,address=tracker,width=4)
        packets.append(packet(rows,first,last,model=model,category=cat))
        packets.append(packet(rows,ofirst,olast,orientation_step=step))
    # Direct Fusion launch words are separate from its later callback-6 prefix.
    for pc, source, destination in [(0x2DE30,0xFCF0,0x29D30),
            (0x2DE3A,0xFCEE,0x29D32),(0x2DE44,0xFCEC,0x29D34)]:
        require(at[pc]['mnemonic']=='move','launch-header copy differs')
        operand(at[pc],0,address=source,width=2); operand(at[pc],1,address=destination,width=2)
    # The miss step really changes A0, while A1 is the fixed first-state root.
    operand(at[0x2E75C],0,address=0x4E818,width=4); operand(at[0x2E75C],1,register='A1',width=4)
    require(at[0x2E876]['mnemonic']=='lea','Fusion miss cursor differs')
    p = at[0x2E876]['operand_facts'][0]
    require(p.get('base_register')=='A0' and p.get('displacement')==20,'Fusion source cursor differs')
    operand(at[0x2E876],1,register='A0',width=4)
    # Ordinary caller order is a source path, not a universal or timed frame.
    for pc, target in [(0xF24,0xE6E8),(0xF2A,0x2DF96),(0xF76,0x2D6F2)]:
        require(at[pc]['mnemonic']=='jsr','ordinary caller differs')
        operand(at[pc],0,address=target,width=4)
    state = word_packet_domain(0x4E818,20,20)
    orientation = word_packet_domain(0x2B994,10,10)
    marker = word_packet_domain(0x4E818+12,20,2)
    spans = {'draw_count_word':(0x4E726,2),'state_count_word':(0x4F218,2),
             'scenery_cells':(0x4A002,36),'type4_tracker':(0x2DD82,8),
             'fusion_tracker':(0x2DE56,8),'scenery_backup_prefix':(0xEB16,256)}
    effects = {name:{'domain':d,'possible_intersections':{k:can_intersect(d,*v)for k,v in spans.items()}}
               for name,d in [('state_packet',state),('orientation_packet',orientation),('fresh_saved_marker',marker)]}
    return {'main_sha256':MAIN_SHA256,'cpu':'68000','runtime_executed':False,
        'instruction_windows':windows,'packet_writes':packets,'address_domains':effects,
        'fresh_saved_address_requires_no_intervening_alias_write':True,
        'backup_comparison_scope':'only the sealed scenery pre-draw <=16-row snapshot prefix; no global backup extent',
        'conditional_valid_64_slots':{'state_span':[0x4E818,0x4ED18],
                                    'orientation_span':[0x2B994,0x2BC14],
                                    'live_count_invariant_proved':False},
        'known_draw_cfg_membership':known_draw_membership(analysis,{
            'launch_type4':0x2DCD8,'launch_fusion':0x2DD8A,
            'update_type4':0x2E620,'update_fusion':0x2E6FA}),
        'new_control_targets_admitted':0,'whole_handler_memory_closure':False,
        'callee_boundaries':[0x2E6CC,0x2E864],
        'registered_types':{'type4':4,'fusion':5},'fusion_header_span':[0x29D30,0x29D36]}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--rows',type=Path,required=True);p.add_argument('--analysis',type=Path,required=True)
    p.add_argument('--member',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    result=collect(json.loads(a.rows.read_text()),json.loads(a.analysis.read_text()),a.member.read_bytes())
    a.output.write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()

"""Narrow, pinned source write domains; never a global callback-effect proof.

Consumes accepted native operand facts, not disassembled text or an interpreter.
The caller must bind the whole main member. No code admission or effect seeds
are produced. Mutable maps, stack aliasing and replacement banks remain open.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path

from tools.foft_render_contract_audit import MAIN_SHA256, operand, window


def require(ok, message):
    if not ok:
        raise ValueError(message)


def mem(p, *, access, width, base=None, displacement=0, absolute=None, update=0):
    require(p.get('memory') and p.get('access') == access
            and p.get('width_bytes') == width and not p.get('bulk_transfer')
            and not p.get('indexed') and p.get('base_register') == base
            and p.get('displacement_known') and p.get('displacement') == displacement
            and p.get('ea_update') == update
            and p.get('absolute_address') == absolute, 'memory contract differs')


def acknowledge(rows, start):
    """Check the complete ten-instruction body, including every memory access."""
    block = window(rows, start, start + 42)
    require([r['mnemonic'] for r in block] ==
            ['move', 'move', 'andi', 'and', 'move', 'move', 'lsr', 'move', 'move', 'rte'],
            'audio acknowledge sequence differs')
    require([r['size'] for r in block] == [2, 6, 4, 6, 6, 6, 2, 6, 2, 2],
            'audio acknowledge widths differ')
    expected = {
        (0, 1): ('memory_write', 'A7', None, 2),
        (1, 0): ('memory_read', None, 0xDFF01E, 0),
        (3, 0): ('memory_read', None, 0xDFF01C, 0),
        (4, 1): ('memory_write', None, 0xDFF09A, 0),
        (5, 1): ('memory_write', None, 0xDFF09C, 0),
        (7, 1): ('memory_write', None, 0xDFF096, 0),
        (8, 0): ('memory_read', 'A7', None, 1),
    }
    seen = set()
    for i, row in enumerate(block):
        for j, p in enumerate(row['operand_facts']):
            if p.get('memory'):
                require((i, j) in expected, 'unexpected memory access')
                access, base, absolute, update = expected[i, j]
                mem(p, access=access, width=2, base=base, absolute=absolute, update=update)
                seen.add((i, j))
            else:
                require(p.get('direct_register') in (None, 'D0'), 'unexpected register effect')
    require(seen == expected.keys(), 'missing acknowledge access')
    require(block[2]['operand_facts'][0].get('immediate_value') == 0x780
            and block[6]['operand_facts'][0].get('immediate_value') == 7,
            'acknowledge masks differ')
    return {'entry_runtime': start, 'end_runtime': start + 42,
            'accepted_instructions': len(block), 'non_stack_ram_writes': [],
            'stack_write': {'width': 2, 'register': 'A7', 'update': 'predecrement'},
            'hardware_word_writes': [0xDFF09A, 0xDFF09C, 0xDFF096],
            'stack_lifetime_or_alias_proved': False}


def coper(rows):
    """Mutable palette cursor is a read receiver, not the write destination."""
    block = window(rows, 0x10CEA, 0x10D30)
    require([r['mnemonic'] for r in block] ==
            ['move', 'move', 'lea', 'addq', 'move', 'cmp', 'bne', 'move', 'movea',
             'move', 'move', 'move', 'move', 'subq', 'adda', 'move', 'movea', 'movea',
             'move', 'rte'], 'COPER source sequence differs')
    operand(block[2], 0, address=0xDFF192, width=4)
    operand(block[2], 1, register='A1', width=4)
    operand(block[0], 0, register='A0', width=4)
    operand(block[1], 0, register='A1', width=4)
    for i in range(9, 13):
        mem(block[i]['operand_facts'][0], access='memory_read', width=2,
            base='A0', update=1 if i < 12 else 0)
    for i, register, width in [(16, 'A1', 4), (17, 'A0', 4), (18, 'D0', 2)]:
        mem(block[i]['operand_facts'][0], access='memory_read', width=width, base='A7', update=1)
        operand(block[i], 1, register=register, width=width)
    operand(block[8], 1, register='A0', width=4)
    pointer = block[8]['operand_facts'][0]
    require(pointer.get('memory') and pointer.get('pc_relative') and
            pointer.get('access') == 'memory_read' and pointer.get('width_bytes') == 4,
            'COPER cursor load differs')
    writes = []
    expected = {0x10CEA: (4, 'A7', None, 2), 0x10CEC: (4, 'A7', None, 2),
                0x10CF4: (2, None, 0x10D38, 0), 0x10D08: (2, None, 0x10D34, 0),
                0x10D14: (2, 'A1', None, 1), 0x10D16: (2, 'A1', None, 1),
                0x10D18: (2, 'A1', None, 1), 0x10D1A: (2, 'A1', None, 0),
                0x10D22: (4, None, 0x10D30, 0)}
    for row in block:
        pc = row['source_offset'] + 0x800
        for p in row['operand_facts']:
            if p.get('direct_register') == 'A1' and p.get('access') == 'register_write':
                require(pc in (0x10CEE, 0x10D28), 'COPER write root is clobbered')
            if p.get('access') != 'memory_write':
                continue
            require(pc in expected and pc not in writes, 'unexpected COPER write')
            width, base, absolute, update = expected[pc]
            mem(p, access='memory_write', width=width, base=base, absolute=absolute, update=update)
            writes.append(pc)
    require(set(writes) == expected.keys(), 'missing COPER write')
    return {'entry_runtime': 0x10CEA, 'end_runtime': 0x10D30,
            'software_write_byte_spans': [[0x10D30, 0x10D34], [0x10D34, 0x10D36],
                                          [0x10D38, 0x10D3A]],
            'hardware_word_destinations': [0xDFF192, 0xDFF194, 0xDFF196, 0xDFF198],
            'stack_saved_longs': ['A0', 'A1'], 'requires_entry_saved_word': 'D0',
            'mutable_cursor_is_read_receiver': True, 'cursor_read_extent_proved': False,
            'stack_lifetime_or_alias_proved': False, 'live_irq_timing_proved': False}


def keyboard_alias_band(values=None):
    """Host algebra for the checked WORD-double/WORD-index source sequence."""
    if values is None:
        values = range(65536)
    offsets = []
    for value in values:
        require(isinstance(value, int) and 0 <= value <= 65535, 'not a WORD')
        doubled = (value * 2) & 65535
        offsets.append(doubled if doubled < 32768 else doubled - 65536)
    require(bool(offsets), 'empty value domain')
    return [0x102F6 + min(offsets), 0x102F6 + max(offsets) + 2]


def direct_write_inventory(rows, *, spans=None):
    """Only explicit, non-bulk absolute extents; all other stores stay open."""
    if spans is None:
        spans = {'scenery_callback_cells': (0x4A002, 0x4A026),
                 'draw_count_word': (0x4E726, 0x4E728)}
    require(all(isinstance(name, str) and name and len(span) == 2 and
                all(type(v) is int for v in span) and 0 <= span[0] < span[1] <= 2**32
                for name, span in spans.items()), 'invalid reviewed write span')
    intersections = {name: [] for name in spans}
    direct = other = 0
    for row in rows:
        for p in row['operand_facts']:
            if p.get('access') not in ('memory_write', 'memory_read_write'):
                continue
            address, width = p.get('absolute_address'), p.get('width_bytes')
            if (address is None or not isinstance(width, int) or width <= 0
                    or p.get('bulk_transfer') or p.get('indexed') or p.get('base_register')):
                other += 1
                continue
            direct += 1
            for name, (start, end) in spans.items():
                if address < end and start < address + width:
                    intersections[name].append({'runtime': row['source_offset'] + 0x800,
                                                'address': address, 'width': width})
    return {'scope': 'supplied_accepted_rows', 'direct_nonbulk_operands': direct,
            'other_write_operands': other, 'direct_intersections': intersections,
            'whole_memory_alias_closure': False}


def reachable_write_inventory(rows, analysis, roots, *, spans=None):
    """Union the existing native CFG, not a new call graph or alias analysis."""
    blocks, edges = analysis['blocks'], analysis['edges']
    starts = [b['start_offset'] for b in blocks]
    require(starts == sorted(set(starts)) and all(b['start_offset'] < b['end_offset']
            and (i == 0 or blocks[i-1]['end_offset'] <= b['start_offset'])
            for i, b in enumerate(blocks)), 'native block extents differ')
    pending = []
    for root in roots:
        n = bisect.bisect_right(starts, root) - 1
        require(n >= 0 and starts[n] == root, 'callback is not an accepted block entry')
        pending.append(n)
    seen, unresolved = set(), []
    while pending:
        n = pending.pop()
        if n in seen:
            continue
        seen.add(n)
        block = blocks[n]
        start, count = block['edge_start'], block['edge_count']
        require(start >= 0 and count >= 0 and start + count <= len(edges), 'edge span differs')
        for edge in edges[start:start+count]:
            require(edge['source_block_index'] == n and
                    block['start_offset'] <= edge['source_offset'] < block['end_offset'],
                    'native edge owner differs')
            target = edge['target_block_index']
            if 0 <= target < len(blocks):
                pending.append(target)
            elif edge['kind'] != 5:  # M68K_CFG_EDGE_RETURN, src/m68k_ir.h.
                unresolved.append({'runtime': edge['source_offset'] + 0x800, 'kind': edge['kind']})
    selected = []
    for row in rows:
        at = row['source_offset']
        n = bisect.bisect_right(starts, at) - 1
        if n in seen and at < blocks[n]['end_offset']:
            selected.append(row)
    result = direct_write_inventory(selected, spans=spans)
    result.update(callback_roots=len(set(roots)), blocks=len(seen), instructions=len(selected),
                  unresolved_nonreturn_edges=unresolved, excludes_async_interrupts=True,
                  runtime_target_set_closed=False)
    return result


def collect(rows, data, analysis=None):
    require(len(data) == 489472 and hashlib.sha256(data).hexdigest() == MAIN_SHA256,
            'whole main member identity differs')
    require(all(r['provenance'] == 'accepted_instruction'
                and data[r['source_offset']:r['source_offset'] + r['size']] == bytes.fromhex(r['bytes'])
                for r in rows), 'native rows do not match pinned member bytes')
    bypc = {r['source_offset'] + 0x800: r for r in rows}
    require(len(rows) == len(bypc) == 30616, 'accepted row inventory differs')
    # These native operations establish WORD doubling and the fixed-base store.
    part = window(rows, 0x10B4A, 0x10B5A)
    require([r['mnemonic'] for r in part] == ['move', 'add', 'lea', 'move'],
            'keyboard sequence differs')
    result = _collect(rows, data, bypc)
    if analysis is not None:
        roots = {r['offset'] for r in analysis['code_start_refs']
                 if r.get('source_offset') == 0xE80E - 0x800}
        require(len(roots) == 43, 'native callback candidates differ')
        result['accepted_callback_cfg_write_inventory'] = reachable_write_inventory(rows, analysis, roots)
    return result


def _collect(rows, data, bypc):
    for pc, index, access in [(0x10B4A, 0, 'memory_read'), (0x10B56, 1, 'memory_write')]:
        p = bypc[pc]['operand_facts'][index]
        require(p.get('memory') and p.get('indexed') and p.get('base_register') == 'A1'
                and p.get('index_register') == 'D0' and p.get('index_width_bytes') == 2
                and p.get('index_scale') == 1 and p.get('displacement') == 0
                and p.get('displacement_known') and p.get('width_bytes') == 2
                and p.get('access') == access and not p.get('bulk_transfer')
                and not p.get('ea_update'), 'keyboard indexed access differs')
    operand(bypc[0x10B4A], 1, register='D0')
    operand(bypc[0x10B56], 0, register='D1')
    double = bypc[0x10B4E]
    require(double['mnemonic'] == 'add' and len(double['operand_facts']) == 2
            and all(p.get('direct_register') == 'D0' and p.get('width_bytes') == 2
                    and not p.get('memory') for p in double['operand_facts']),
            'keyboard WORD double differs')
    root = bypc[0x10B50]
    require(root['mnemonic'] == 'lea'
            and root['operand_facts'][0].get('absolute_address') == 0x102F6
            and root['operand_facts'][1].get('direct_register') == 'A1', 'keyboard root differs')
    raw_map = data[0x10B96-0x800:0x10B96-0x800+128]
    require(len(raw_map) == 128 and max(raw_map) <= 127, 'initial raw-key map differs')
    maps = []
    for name, start in [('French', 0x10F92), ('English', 0x11094), ('German', 0x11196),
                        ('active_initial', 0x11298)]:
        span = data[start-0x800:start-0x800+256]
        values = [int.from_bytes(span[i:i+2], 'big') for i in range(0, 256, 2)]
        require(min(values) >= 0 and max(values) <= 127, 'original language map differs')
        maps.append({'name': name, 'runtime': start, 'count': 128, 'width': 2,
                     'minimum': min(values), 'maximum': max(values),
                     'sha256': hashlib.sha256(span).hexdigest(),
                     'conditional_write_byte_extent': keyboard_alias_band(values)})
    for pc, address, register in [(0x10B46, 0x11298, 'A1'),
                                   (0x4F3DE, 0x4F336, 'A3'),
                                   (0x4F3E6, 0x4F346, 'A3')]:
        require(bypc[pc]['mnemonic'] == 'lea', 'fixed root producer differs')
        operand(bypc[pc], 0, address=address, width=4)
        operand(bypc[pc], 1, register=register, width=4)
    operand(bypc[0x4F3D8], 0, address=0xDFF000, width=4)
    operand(bypc[0x4F3D8], 1, register='A6', width=4)
    channel = window(rows, 0x4F3D8, 0x4F458)
    allowed_register_definitions = {'A3': {0x4F3DE, 0x4F3E6},
                                    'A6': {0x4F3D8}, 'A1': {0x4F3F8}, 'A2': {0x4F3F0}}
    for row in channel:
        for p in row['operand_facts']:
            reg = p.get('direct_register')
            if reg in allowed_register_definitions and p.get('access') == 'register_write':
                require(row['source_offset'] + 0x800 in allowed_register_definitions[reg],
                        'channel root clobber differs')
            require(not (p.get('base_register') == 'A2' or
                         (reg == 'A2' and p.get('access') != 'register_write')),
                    'loaded channel LONG is used')
    loaded = bypc[0x4F3F0]
    mem(loaded['operand_facts'][0], access='memory_read', width=4, base='A3', displacement=12)
    require(loaded['mnemonic'] == 'movea' and
            loaded['operand_facts'][1].get('direct_register') == 'A2', 'channel LONG load differs')
    custom = bypc[0x4F3F8]['operand_facts'][0]
    require(bypc[0x4F3F8]['mnemonic'] == 'lea' and custom.get('indexed')
            and custom.get('base_register') == 'A6' and custom.get('index_register') == 'D0'
            and custom.get('index_width_bytes') == 2 and custom.get('index_scale') == 1
            and custom.get('displacement_known') and custom.get('displacement') == 0,
            'custom-register offset producer differs')
    operand(bypc[0x4F3F4], 1, register='D0')
    operand(bypc[0x4F3F8], 1, register='A1', width=4)
    mem(bypc[0x4F3F4]['operand_facts'][0], access='memory_read', width=2,
        base='A3', displacement=4)
    writes = []
    for row in channel:
        for p in row['operand_facts']:
            if p.get('access') != 'memory_write':
                continue
            base, offset = p.get('base_register'), p.get('displacement')
            require(not p.get('indexed') and not p.get('ea_update')
                    and p.get('width_bytes') == 2 and not p.get('bulk_transfer')
                    and p.get('displacement_known') and p.get('absolute_address') is None
                    and ((base == 'A3' and offset in (6, 10))
                         or (base == 'A6' and offset in (0x96, 0x9A, 0x9C))
                         or (base == 'A1' and offset == 10)), 'sound updater write differs')
            writes.append({'runtime': row['source_offset'] + 0x800, 'base_register': base,
                           'displacement': offset, 'width': 2})
    return {'main_sha256': MAIN_SHA256, 'scope': 'pinned_non_stack_source_components',
            'global_callback_effect_closure': False, 'runtime_executed': False,
            'audio_acknowledge': [acknowledge(rows, p) for p in (0x4F458, 0x584DE)],
            'coper': coper(rows),
            'keyboard': {'store_runtime': 0x10B56, 'root_runtime': 0x102F6,
                         'unconstrained_current_map_write_byte_extent': keyboard_alias_band(),
                         'current_map_constness_proved': False, 'initial_maps': maps,
                         'initial_raw_key_map': {'runtime': 0x10B96, 'checked_prefix_bytes': 128,
                             'physical_allocation_proved': False,
                             'minimum': min(raw_map), 'maximum': max(raw_map),
                             'sha256': hashlib.sha256(raw_map).hexdigest()},
                         'initial_domain_requires_unchanged_raw_and_logical_maps': True},
            'sound_updater': {'entry_runtime': 0x4F3D8, 'end_runtime': 0x4F458,
                              'software_roots': [0x4F336, 0x4F346],
                              'writes': writes, 'root_bindings_required': True,
                              'software_write_byte_spans': [[base+offset, base+offset+2]
                                  for base in [0x4F336, 0x4F346] for offset in [6, 10]],
                              'custom_derived_clear_write_byte_band':
                                  [0xDFF000-32768+10, 0xDFF000+32767+12],
                              'whole_irq_effect_closure': False},
            'whole_main_absolute_write_inventory': direct_write_inventory(rows),
            'replacement_music_tick_runtime': 0x58004,
            'replacement_music_bank_effects_closed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rows', type=Path, required=True)
    parser.add_argument('--member', type=Path, required=True)
    parser.add_argument('--analysis', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = collect(json.loads(args.rows.read_text()), args.member.read_bytes(),
                     json.loads(args.analysis.read_text()))
    args.output.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()

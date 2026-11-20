"""Recheck pinned FoFT render source contracts using accepted native operand facts.

This is a source-contract check, not a decoder, interpreter, code-admission path
or claim about callback effects and live framebuffer contents.
"""

import argparse
import hashlib
import json
from pathlib import Path

MAIN_SHA256 = '85e2684b03badc7308e7eaa059b7c717441808798f55b4642e1d8b1895914c9b'


def window(rows, start, end):
    selected = [r for r in rows if start <= r['source_offset'] + 0x800 < end]
    cursor = start
    for r in selected:
        if r['provenance'] != 'accepted_instruction' or r['source_offset'] + 0x800 != cursor:
            raise ValueError('contract window is not contiguous accepted code')
        cursor += r['size']
    if cursor != end:
        raise ValueError('contract window extent differs')
    return selected


def operand(row, index, *, register=None, address=None, width=2):
    p = row['operand_facts'][index]
    if p['width_bytes'] != width:
        raise ValueError('operand width differs')
    if register is not None and (p['direct_register'] != register or p['memory']):
        raise ValueError('operand register differs')
    if address is not None:
        evidence = [e for e in row['address_evidence'] + row.get('resolved_reference_addresses', [])
                    if e['operand_index'] == index and e.get('has_address')]
        if (not p['memory'] or any(e.get('conflicted') for e in evidence)
                or {e['address'] for e in evidence} != {address}):
            raise ValueError('operand source address differs')


def operation(row, mnemonic):
    if row['mnemonic'] != mnemonic:
        raise ValueError('operation differs')


def transpose(rows):
    block = window(rows, 0xFC24, 0xFC92)
    if len(block) != 28 or block[-1]['mnemonic'] != 'rts':
        raise ValueError('transpose framing differs')
    cells = []
    for i in range(9):
        load, double, store = block[3*i:3*i+3]
        for row, name in [(load, 'move'), (double, 'add'), (store, 'move')]:
            operation(row, name)
        source, target = 0xFCD4+2*i, 0xFC92+2*((i % 3)*3+i//3)
        operand(load, 0, address=source); operand(load, 1, register='D0')
        operand(double, 0, register='D0'); operand(double, 1, register='D0')
        operand(store, 0, register='D0'); operand(store, 1, address=target)
        cells.append({'orientation_offset':source-0xFCD4, 'basis_offset':target-0xFC92})
    return cells


def composition(rows):
    block = window(rows, 0xF16E, 0xF2EA)
    if len(block) != 100 or block[-1]['mnemonic'] != 'rts':
        raise ValueError('composition framing differs')
    cursor, cells = 0, []
    for col in range(3):
        for k in range(3):
            load = block[cursor]; cursor += 1
            operation(load, 'move')
            operand(load, 0, address=0xFCBE+2*(3*k+col))
            operand(load, 1, register=f'D{k}')
        for row in range(3):
            part = block[cursor:cursor+10]; cursor += 10
            for j, name in enumerate(['move','muls','move','muls','add','move','muls','add','swap','move']):
                operation(part[j], name)
            for j,k,reg in [(0,0,'D3'),(2,1,'D4'),(5,2,'D4')]:
                operand(part[j],0,address=0xFC92+2*(3*row+k)); operand(part[j],1,register=reg)
            for j,k,reg in [(1,0,'D3'),(3,1,'D4'),(6,2,'D4')]:
                operand(part[j],0,register=f'D{k}'); operand(part[j],1,register=reg)
            for j in [4,7]:
                operand(part[j],0,register='D4',width=4); operand(part[j],1,register='D3',width=4)
            operand(part[8],0,register='D3',width=4)
            operand(part[9],0,register='D3'); operand(part[9],1,address=0xFCA8+2*(3*row+col))
            cells.append({'row':row,'column':col,'output_offset':2*(3*row+col),
                          'operation':'three signed WORD products, LONG sums, SWAP then low WORD store'})
    return cells


def frame_inventory(rows):
    """Inventory accepted direct uses, deliberately not an alias/effect proof."""
    names = ['BuildPackedObjectViewRecords', 'TransformAndCullObjectViewRecords',
             'DrawDepthOrderedObjectViews', 'DrawPackedObjectViewRecord',
             'ProcessSceneryObjectRow', 'TransformSortAndDrawSystemBodies',
             'DrawAndAdvanceProjectedBurst', 'WaitIrqAndPresentDrawBuffer']
    calls = {name: [] for name in names}
    writes, reads = [], []
    for row in rows:
        if row['provenance'] != 'accepted_instruction':
            raise ValueError('frame inventory requires accepted instructions')
        runtime = row['source_offset']+0x800
        # These are canonical native-rendered exact symbol operands, not text
        # decoded as instructions or new control edges. Conditional tails stay
        # distinguished from calls by their original native mnemonic.
        tokens = row.get('text', '').split()
        target = tokens[-1] if tokens else ''
        if target.endswith(('.l', '.w', '.b', '.s')):
            target = target[:-2]
        for name in names:
            if (target == name and (row['mnemonic'] in ('jsr', 'jmp')
                                   or row['mnemonic'].startswith('b'))):
                calls[name].append({'runtime':runtime, 'mnemonic':row['mnemonic']})
        for operand in row['operand_facts']:
            if operand.get('absolute_address') == 0x4E726:
                record = {'runtime':runtime, 'width':operand['width_bytes'],
                          'access':operand['access']}
                if operand['access'] in ('memory_write', 'memory_read_write'):
                    writes.append(record)
                elif operand['access'] == 'memory_read':
                    reads.append(record)
    return {'accepted_instructions':len(rows), 'direct_count_writers':writes,
            'direct_count_readers':reads, 'recognized_named_transfers':calls,
            'indirect_alias_copy_effect_closure':False,
            'count_equality_or_runtime_reachability_proved':False}


def body_work_chain(rows):
    """Check the ordered copy protocol; no virtual CPU or inferred callback."""
    def memory(row, index, base, access, update=0, *, displacement=0, indexed=False):
        p = row['operand_facts'][index]
        expected = {'memory': True, 'base_register': base, 'access': access,
                    'ea_update': update, 'displacement': displacement,
                    'displacement_known': True, 'indexed': indexed, 'width_bytes': 4}
        if any(p.get(k) != v for k, v in expected.items()):
            raise ValueError('body copy operand differs')
        if indexed and (p.get('index_register') != 'D0' or
                        p.get('index_width_bytes') != 2 or p.get('index_scale') != 1):
            raise ValueError('body copy index differs')

    swaps = window(rows, 0xF4F0, 0xF526)
    if len(swaps) != 27:
        raise ValueError('body exchange length differs')
    for i in range(9):
        load, first, second = swaps[3*i:3*i+3]
        for r in (load, first, second):
            operation(r, 'move')
        memory(load, 0, 'A0', 'memory_read')
        operand(load, 1, register='D1', width=4)
        memory(first, 0, 'A1', 'memory_read')
        memory(first, 1, 'A0', 'memory_write', 1)
        operand(second, 0, register='D1', width=4)
        memory(second, 1, 'A1', 'memory_write', 1)
    removes = window(rows, 0xF582, 0xF5A2)
    if len(removes) != 8:
        raise ValueError('body removal length differs')
    for r in removes:
        operation(r, 'move')
        memory(r, 0, 'A0', 'memory_read', displacement=32, indexed=True)
        memory(r, 1, 'A0', 'memory_write', 1)
    draw = window(rows, 0xF52C, 0xF56C)
    inputs = []
    for r in draw:
        operation(r, 'move')
        src = r['operand_facts'][0]
        if (src.get('base_register') != 'A0' or not src.get('memory') or
                src.get('indexed') or src.get('ea_update') or
                src.get('access') != 'memory_read'):
            raise ValueError('body draw source differs')
        inputs.append((src['displacement'], src['width_bytes']))
    expected = [(6, 2), (8, 2), (10, 2), (12, 4), (16, 4), (20, 4), (24, 4), (28, 4)]
    if inputs != expected:
        raise ValueError('body draw extent differs')
    return {'exchange_long_count': 9, 'exchange_bytes': 36,
            'removal_long_count': 8, 'row_stride_bytes': 32,
            'draw_inputs': [{'offset': a, 'size': b} for a, b in inputs],
            'draw_input_extent': [6, 32],
            'selected_row_contract': 'positive row index; selection and lifetime proofs remain separate',
            'extra_exchange_span': [32, 36],
            'adjacent_exchange_overlap_bytes': 4,
            'intent_or_global_alias_closure': False}


def glyph_stream_inventory(rows):
    """Exact direct-transfer/cell inventory, not an indirect effect analysis."""
    calls = {0x1B0E2: [], 0x1B24C: []}
    sign_uses = []
    for row in rows:
        if row['provenance'] != 'accepted_instruction':
            raise ValueError('glyph inventory requires accepted instructions')
        at = row['source_offset'] + 0x800
        for p in row['operand_facts']:
            address = p.get('absolute_address')
            if row['mnemonic'] in ('jsr', 'jmp') and address in calls:
                calls[address].append({'runtime': at, 'mnemonic': row['mnemonic']})
            if address == 0x1B2D8:
                sign_uses.append({'runtime': at, 'access': p['access'], 'width': p['width_bytes']})
    return {'five_row_draw_transfers': calls[0x1B0E2],
            'numeric_preparation_calls': calls[0x1B24C],
            'encoded_sign_cell_uses': sign_uses,
            'indirect_alias_or_input_range_closure': False}


def audit(payload, rows):
    if len(payload) != 489472 or hashlib.sha256(payload).hexdigest() != MAIN_SHA256:
        raise ValueError('main member identity differs')
    for r in rows:
        offset = r['source_offset']
        if payload[offset:offset+r['size']].hex() != r['bytes'].lower():
            raise ValueError('native row bytes differ from authenticated member')
    return {'kind':'foft_render_matrix_contracts','size':len(payload),'sha256':MAIN_SHA256,
            'transpose':transpose(rows),'composition':composition(rows),
            'runtime':'not executed','media_verification':'not_performed',
            'matrix_shape_is_not_value_identity':True}


def fixed_point_receiver(rows):
    """Recheck existing native body-only witnesses; never create a receiver."""
    expected = [(0x1AB12, 'position0', 0), (0x1AB14, 'position1', 2),
                (0x1AB16, 'position2', 4), (0x1AB18, 'planeFlagWord', 6)]
    result = []
    for runtime, name, offset in expected:
        selected = [r for r in rows if r['source_offset'] + 0x800 == runtime]
        if len(selected) != 1 or selected[0].get('provenance') != 'accepted_instruction':
            raise ValueError('point receiver requires its accepted native source instruction')
        facts = [f for f in selected[0].get('typed_accesses', ())
                 if f.get('root_struct_name') == 'ProjectedPointInput' and f.get('operand_index') == 0]
        if len(facts) != 1:
            raise ValueError('point receiver native field witness is missing or ambiguous')
        field = facts[0]
        domain = {'header_offset': 0x1A312, 'tail_offset': 0x1A41A,
                  'iteration_count': 150, 'iteration_stride': 8, 'access_width': 2,
                  'counter_register': 5, 'access_kind': 1, 'first_offset': offset,
                  'record_count': 150, 'base_record_index': 0, 'body_only': True}
        if (field.get('record_cursor_loop') != domain or field.get('base_register') != 'A6'
                or field.get('field_name') != name or field.get('field_offset') != offset
                or field.get('struct_size') != 8 or field.get('field_size') != 2
                or field.get('word_index')):
            raise ValueError('point receiver native field/extent contract differs')
        result.append({'runtime': runtime, 'field': name, 'offset': offset,
                       'last_access_end': 149 * 8 + offset + 2})
    return {'fields': result, 'rows': 150, 'stride': 8, 'bytes': 1200,
            'body_only': True, 'pointee_or_value_closure': False}


def hit_record_contract(rows):
    """Check bounded native setup/operators, not runtime reachability or values."""
    def at(pc, mnemonic):
        found = [r for r in rows if r['source_offset'] + 0x800 == pc]
        if len(found) != 1 or found[0].get('provenance') != 'accepted_instruction':
            raise ValueError('hit record requires unique accepted native instructions')
        operation(found[0], mnemonic)
        return found[0]

    def memory(row, index, base, offset, width=2):
        field = row['operand_facts'][index]
        if (not field['memory'] or field['base_register'] != base or field['indexed']
                or not field['displacement_known'] or field['displacement'] != offset
                or field['width_bytes'] != width or field['ea_update']):
            raise ValueError('hit record operand differs from its bounded source contract')

    setups = []
    for start, end, final in [(0x2DBFC, 0x2DC14, 'A6'), (0x2E41A, 0x2E432, 'A0')]:
        block = window(rows, start, end)
        if len(block) != 6:
            raise ValueError('hit record setup extent differs')
        for i, base, reg in [(0, 0x4ED18, 'A6'), (2, 0x4E818, 'A0'), (4, 0x4ED18, 'A6')]:
            operation(block[i], 'lea')
            operand(block[i], 0, address=base, width=4)
            operand(block[i], 1, register=reg, width=4)
        for i, reg in [(1, 'A6'), (3, 'A0'), (5, final)]:
            operation(block[i], 'adda')
            operand(block[i], 0, register='D5')
            operand(block[i], 1, register=reg)
        setups.append({'runtime': start, 'action_offset_copies': int(final == 'A6'),
                       'state_offset_copies': 1 + int(final == 'A0'),
                       'offset_kind': 'sign-extended D5.W', 'fallthrough_sequence_only': True})
    arms = []
    for name, pool0, pool2, reserve, scale, shift in [
            ('laser', 0x2D8A6, 0x2D89E, 0x2D8BA, 0x2D898, 1),
            ('gauss', 0x2DC66, 0x2DC5E, 0x2DC7A, 0x2DC58, 2),
            ('plasma', 0x2E484, 0x2E47C, 0x2E498, 0x2E476, 4)]:
        scaling = at(scale, 'add' if name == 'laser' else 'asl')
        operand(scaling, 1, register='D0')
        if name == 'laser':
            operand(scaling, 0, register='D0')
        elif scaling['operand_facts'][0]['immediate_value'] != shift:
            raise ValueError('hit record WORD scale differs')
        for pc, offset in [(pool0, 0), (pool2, 2), (reserve, 6)]:
            row = at(pc, 'sub')
            operand(row, 0, register='D0'); memory(row, 1, 'A6', offset)
        arms.append({'family': name, 'pool0_runtime': pool0, 'pool2_runtime': pool2,
                     'reserve_runtime': reserve, 'reserve_operator': 'SUB.W D0',
                     'word_scale': 1 << shift, 'value_range_proved': False})
    # The two Fusion arms store a zero-clamped pool; their common reserve
    # operator is ADD.W D3 rather than the direct arms' full-amount SUB.W D0.
    for load, store, clear, offset in [(0x2E83C, 0x2E846, 0x2E844, 0),
                                      (0x2E84E, 0x2E85A, 0x2E858, 2)]:
        row = at(load, 'move'); memory(row, 0, 'A0', offset); operand(row, 1, register='D2')
        row = at(store, 'move'); operand(row, 0, register='D2'); memory(row, 1, 'A0', offset)
        operand(at(clear, 'clr'), 0, register='D2')
    row = at(0x2E85E, 'add'); operand(row, 0, register='D3'); memory(row, 1, 'A0', 6)
    scaling = at(0x2E834, 'asl'); operand(scaling, 1, register='D0')
    if scaling['operand_facts'][0]['immediate_value'] != 5:
        raise ValueError('hit record Fusion WORD scale differs')
    for pc, offset, amount in [(0x2E986, 2, 100), (0x2E98C, 0, 100), (0x2E9AA, 6, 50)]:
        row = at(pc, 'subi'); memory(row, 1, 'A6', offset)
        if row['operand_facts'][0]['immediate_value'] != amount:
            raise ValueError('hit record constant debit differs')
    model_scale = at(0x2B27A, 'mulu'); operand(model_scale, 1, register='D0')
    if model_scale['operand_facts'][0]['immediate_value'] != 50:
        raise ValueError('hit record dispatcher model scale differs')
    row = at(0x2B27E, 'sub'); operand(row, 0, register='D0'); memory(row, 1, 'A6', 0)
    initialized = []
    for pc, offset, value in [(0x2A1B8, 4, 10), (0x2A1C4, 8, 256), (0x2A1CA, 10, 4096),
                              (0x2A938, 4, 100), (0x2A944, 8, 256), (0x2A94A, 10, 4096),
                              (0x2A9B0, 4, 1), (0x2A9BC, 8, 6), (0x2A9C2, 10, 0)]:
        row = at(pc, 'move'); memory(row, 1, 'A3', offset)
        if row['operand_facts'][0]['immediate_value'] != value:
            raise ValueError('hit record initialized WORD value differs')
        initialized.append({'runtime': pc, 'offset': offset, 'width': 2, 'initial_value': value})
    direct_bases = []
    for row in rows:
        if row['mnemonic'] == 'lea' and row['operand_facts'][0].get('absolute_address') == 0x4ED18:
            if row.get('provenance') != 'accepted_instruction':
                raise ValueError('hit record base inventory requires accepted native instructions')
            direct_bases.append({'runtime': row['source_offset'] + 0x800,
                                 'register': row['operand_facts'][1]['direct_register']})
    return {'setups': setups, 'direct_arms': arms,
            'fusion_reserve_runtime': 0x2E85E, 'fusion_reserve_operator': 'ADD.W D3',
            'fusion_word_scale': 32,
            'impact_debit_order': [2, 0, 6], 'impact_debits': [100, 100, 50],
            'dispatcher_model_scaled_pool0_runtime': 0x2B27E, 'dispatcher_model_scale': 50,
            'initialized_neutral_words': initialized, 'direct_base_leas': direct_bases,
            'all_aliases_or_writers_closed': False,
            'branch_order_evidence': 'pinned accepted source, reviewed in foft-action-hit-records.md',
            'runtime_reachability_or_visible_result_proved': False}



def flag_glyph_contract(payload, rows):
    """Initial counted source spans and selected accepted reader operands only."""
    def at(pc, mnemonic):
        selected = [r for r in rows if r['source_offset'] + 0x800 == pc]
        if len(selected) != 1 or selected[0]['provenance'] != 'accepted_instruction':
            raise ValueError('flag glyph requires unique accepted reader instructions')
        operation(selected[0], mnemonic)
        return selected[0]

    operand(at(0x1EAD2, 'clr'), 0, register='D7')
    for pc, step, reg in [(0x1EB16, 1, 'D7'), (0x1EB18, 8, 'A4')]:
        row = at(pc, 'addq')
        if row['operand_facts'][0].get('immediate_value') != step:
            raise ValueError('flag glyph cursor step differs')
        operand(row, 1, register=reg)
    row = at(0x1EB1A, 'cmp')
    if row['operand_facts'][0].get('immediate_value') != 16:
        raise ValueError('flag glyph count differs')
    operand(row, 1, register='D7')
    for pc, name, offset, reg in [(0x1EADE, 'movea', 0, 'A5'),
                                  (0x1EAE0, 'move', 4, 'D6')]:
        row = at(pc, name)
        field = row['operand_facts'][0]
        if (not field['memory'] or field['base_register'] != 'A4'
                or field['indexed'] or not field['displacement_known']
                or field['displacement'] != offset or field['ea_update']
                or field['width_bytes'] != 4):
            raise ValueError('flag glyph field reader differs')
        operand(row, 1, register=reg, width=4)
    operand(at(0x1EAEC, 'jsr'), 0, address=0x1B0E2, width=4)
    # These are source contracts, not an interpreter or a live sentinel scan.
    start, end, cursor, streams = 0x1EB64, 0x1EBE4, 0x1EBE4, []
    if len(payload) < 0x1ED96 - 0x800:
        raise ValueError('flag glyph source bytes missing')
    for bit in range(16):
        offset = start - 0x800 + 8 * bit
        pointer = int.from_bytes(payload[offset:offset+4], 'big')
        count = int.from_bytes(payload[offset+4:offset+8], 'big')
        if pointer != cursor or not 0 < count <= 0xFFFF:
            raise ValueError('flag glyph initial pointer/count extent differs')
        cursor = pointer + 2 * count
        if cursor > 0x1ED96:
            raise ValueError('flag glyph stream extends outside its source span')
        streams.append({'bit': bit, 'runtime': pointer, 'words': count,
                        'end_runtime': cursor})
    if cursor != 0x1ED96:
        raise ValueError('flag glyph streams do not cover the exact source span')
    return {'descriptor_runtime': start, 'descriptor_end_runtime': end,
            'records': 16, 'stride': 8, 'initial_streams': streams,
            'glyph_words': 217, 'glyph_bytes': 434,
            'draw_runtime': 0x1B0E2, 'count_consumption': 'D6.W after LONG load',
            'branch_and_register_preservation_review': 'foft-panel-flag-glyphs.md',
            'mutable_contents_or_alias_closure': False, 'runtime_visibility': 'not observed'}



def indexed_panel_glyph_contract(payload, rows):
    """Bound initial table views; producer range derivations remain conditional."""
    def at(pc, name):
        found = [r for r in rows if r['source_offset'] + 0x800 == pc]
        if len(found) != 1 or found[0]['provenance'] != 'accepted_instruction':
            raise ValueError('indexed glyph requires unique accepted reader instructions')
        operation(found[0], name)
        return found[0]

    result = []
    for tag, base, count, start, end, load, lea, add, read_count, read_pointer, call in [
            ('A', 0x1F06A, 6, 0x1F0A2, 0x1F0EE,
             0x1E970, 0x1E97A, 0x1E97E, 0x1E980, 0x1E984, 0x1E98A),
            ('B', 0x1EEFE, 14, 0x1EF6E, 0x1F06A,
             0x1E9C0, 0x1E9CA, 0x1E9CE, 0x1E9D0, 0x1E9D4, 0x1E9DA)]:
        for pc in [load + 4, load + 6, load + 8]:
            row = at(pc, 'add')
            operand(row, 0, register='D0'); operand(row, 1, register='D0')
        row = at(lea, 'lea'); source = row['operand_facts'][0]
        if (not source.get('pc_relative') or not source.get('displacement_known')
                or source.get('displacement') != base - (lea + 2)):
            raise ValueError('indexed glyph table source differs')
        operand(row, 1, register='A5', width=4)
        row = at(add, 'adda')
        operand(row, 0, register='D0'); operand(row, 1, register='A5')
        for pc, name, offset, reg in [(read_count, 'move', 4, 'D6'),
                                      (read_pointer, 'movea', 0, 'A5')]:
            row = at(pc, name); field = row['operand_facts'][0]
            if (not field['memory'] or field['base_register'] != 'A5'
                    or field['indexed'] or not field['displacement_known']
                    or field['displacement'] != offset or field['ea_update']
                    or field['width_bytes'] != 4):
                raise ValueError('indexed glyph field differs')
            operand(row, 1, register=reg, width=4)
        operand(at(call, 'jsr'), 0, address=0x1B0E2, width=4)
        display_row = 43 if tag == 'A' else 57
        draw_row = at(call-2, 'moveq')
        if draw_row['operand_facts'][0].get('immediate_value') != display_row:
            raise ValueError('indexed glyph display row differs')
        operand(draw_row, 1, register='D4', width=4)
        if len(payload) < end - 0x800:
            raise ValueError('indexed glyph source bytes missing')
        entries, unique = [], {}
        for index in range(count):
            offset = base - 0x800 + 8 * index
            pointer = int.from_bytes(payload[offset:offset+4], 'big')
            words = int.from_bytes(payload[offset+4:offset+8], 'big')
            if (pointer % 2 or not start <= pointer < end or not 0 < words <= 0xFFFF
                    or pointer + 2 * words > end):
                raise ValueError('indexed glyph source extent differs')
            if pointer in unique and unique[pointer] != words:
                raise ValueError('indexed glyph shared stream extent differs')
            unique[pointer] = words
            entries.append({'index': index, 'runtime': pointer, 'words': words})
        cursor = start
        for pointer, words in sorted(unique.items()):
            if pointer != cursor:
                raise ValueError('indexed glyph streams overlap or leave a gap')
            cursor = pointer + 2 * words
        if cursor != end:
            raise ValueError('indexed glyph streams do not cover their source span')
        result.append({'table': tag, 'runtime': base, 'records': count, 'stride': 8, 'display_row': display_row,
            'normal_producer_index_range': [0, count-1], 'initial_entries': entries,
            'unique_streams': len(unique), 'glyph_words': sum(unique.values()),
            'source_end_runtime': end, 'all_writer_or_live_bound_proved': False})
    return {'tables': result, 'count_consumption': 'D6.W after LONG load',
            'range_and_branch_review': 'foft-panel-flag-glyphs.md',
            'extra_A_descriptor_bytes_not_typed': 8, 'runtime': 'not executed'}



def scenery_bound_headers(payload, rows):
    """Initial data views behind pointer values, never callable admission."""
    for pc, offset, double in [(0x4AE62, -10, 0x4AE66), (0x4AE6C, -8, 0x4AE70)]:
        selected = [r for r in rows if r['source_offset'] + 0x800 == pc]
        doubled = [r for r in rows if r['source_offset'] + 0x800 == double]
        if (len(selected) != 1 or len(doubled) != 1
                or any(r['provenance'] != 'accepted_instruction' for r in selected + doubled)):
            raise ValueError('scenery bounds require accepted reader instructions')
        operation(selected[0], 'move'); field = selected[0]['operand_facts'][0]
        if (not field['memory'] or field['base_register'] != 'A6' or field['indexed']
                or not field['displacement_known'] or field['displacement'] != offset
                or field['width_bytes'] != 2 or field['ea_update']):
            raise ValueError('scenery bounds reader differs')
        operand(selected[0], 1, register='D2')
        operation(doubled[0], 'add')
        operand(doubled[0], 0, register='D2'); operand(doubled[0], 1, register='D2')
    if len(payload) < 0x4A026 - 0x800:
        raise ValueError('scenery bounds table bytes missing')
    targets = [int.from_bytes(payload[0x49802+4*i:0x49806+4*i], 'big') for i in range(9)]
    if len(set(targets)) != 8 or targets[0] != targets[-1]:
        raise ValueError('scenery bounds initial sharing differs')
    spans = sorted((target-10, target-6) for target in set(targets))
    if any(start < previous_end for (_, previous_end), (start, _) in zip(spans, spans[1:], strict=False)):
        raise ValueError('scenery bounds initial headers overlap')
    headers = []
    for target in dict.fromkeys(targets):
        start, end = target - 10, target - 6
        if target % 2 or start < 0x800 or end - 0x800 > len(payload):
            raise ValueError('scenery bounds header outside source')
        if any(r['source_offset'] + 0x800 < end
               and r['source_offset'] + 0x800 + r.get('size', 0) > start
               for r in rows if r['provenance'] == 'accepted_instruction'):
            raise ValueError('scenery bounds overlap accepted instruction bytes')
        words = [int.from_bytes(payload[start-0x800+i:start-0x800+i+2], 'big', signed=True)
                 for i in (0, 2)]
        headers.append({'target_runtime': target, 'header_runtime': start,
                        'end_runtime': end, 'initial_signed_words': words})
    return {'initial_cells': 9, 'unique_headers': headers, 'typed_bytes': 32,
            'reader_offsets': [-10, -8], 'word_multiplier': 2,
            'code_admission_or_callback_effects_proved': False,
            'other_prefix_bytes_or_lifetime_typed': False}



def scenery_compacting_append_contract(rows, edges):
    """Recheck the exact accepted producer, not callback values or a new solver."""
    block = window(rows, 0x4AE0A, 0x4AE94)
    at = {r['source_offset']+0x800:r for r in block}
    allowed = {'nop','clr','move','movea','moveq','lea','beq','addq','andi','lsr',
               'add','cmp','ble','tst','bpl','neg','bgt','st','addi','dbf'}
    if any(r['mnemonic'] not in allowed for r in block):
        raise ValueError('compacting producer has an unsupported operation')

    def ins(pc, name):
        row = at.get(pc)
        if row is None:
            raise ValueError('compacting producer instruction missing')
        operation(row,name)
        return row

    def immediate(pc,name,value,reg,width=2):
        row=ins(pc,name)
        if row['operand_facts'][0].get('immediate_value')!=value:
            raise ValueError('compacting producer immediate differs')
        operand(row,1,register=reg,width=width)

    operand(ins(0x4AE0A,'clr'),0,register='D0')
    operand(ins(0x4AE0C,'move'),0,register='D0')
    operand(at[0x4AE0C],1,register='D7')
    for pc,reg,address in [(0x4AE0E,'A0',0xE816),(0x4AE14,'A1',0x15BD0),
                           (0x4AE1A,'A4',0x4A002)]:
        operand(ins(pc,'lea'),0,address=address,width=4)
        operand(at[pc],1,register=reg,width=4)
    immediate(0x4AE20,'moveq',15,'D6',4)
    operand(ins(0x4AE22,'movea'),0,address=0x4BC00,width=4)
    operand(at[0x4AE22],1,register='A2',width=4)
    descriptor=ins(0x4AE26,'move')['operand_facts'][0]
    if (not descriptor['memory'] or descriptor['base_register']!='A2'
            or descriptor['ea_update']!=1 or descriptor['width_bytes']!=2):
        raise ValueError('compacting descriptor cursor differs')
    operand(at[0x4AE26],1,register='D1')
    immediate(0x4AE2A,'addq',1,'D7')
    immediate(0x4AE34,'andi',0xF00,'D1')
    immediate(0x4AE38,'lsr',8,'D1')
    for pc in [0x4AE3A,0x4AE3C]:
        operand(ins(pc,'add'),0,register='D1');operand(at[pc],1,register='D1')
    immediate(0x4AE3E,'cmp',32,'D1')
    immediate(0x4AE44,'moveq',32,'D1',4)
    immediate(0x4AE8C,'addi',10,'D0')
    operand(ins(0x4AE90,'dbf'),0,register='D6')
    stores=[(0x4AE2C,4,0),(0x4AE30,2,4),(0x4AE46,4,6),(0x4AE4A,2,10)]
    for pc,width,_ in stores:
        row=ins(pc,'clr' if pc==0x4AE4A else 'move')
        p=row['operand_facts'][0 if pc==0x4AE4A else 1]
        if (not p['memory'] or p['access']!='memory_write' or p['base_register']!='A0'
                or p['ea_update']!=1 or p['width_bytes']!=width):
            raise ValueError('compacting append footprint differs')
    for pc,offset,width in [(0x4AE2C,0,4),(0x4AE30,4,2)]:
        p=at[pc]['operand_facts'][0]
        if (not p['memory'] or p['base_register']!='A1' or not p['indexed']
                or p['index_register']!='D0' or p['index_width_bytes']!=2
                or not p['displacement_known'] or p['displacement']!=offset
                or p['ea_update'] or p['width_bytes']!=width):
            raise ValueError('compacting point source differs')
    operand(ins(0x4AE56,'movea'),1,register='A6',width=4)
    for pc in [0x4AE46,0x4AE56]:
        source=at[pc]['operand_facts'][0]
        if (not source['memory'] or source['base_register']!='A4' or not source['indexed']
                or source['index_register']!='D1' or source['index_width_bytes']!=2
                or not source['displacement_known'] or source['displacement']
                or source['ea_update'] or source['width_bytes']!=4):
            raise ValueError('compacting callback source differs')
        witnesses=[p for p in at[pc]['typed_accesses'] if p['operand_index']==0
                   and p.get('root_struct_name')=='SceneryCallbackCell'
                   and p.get('field_name')=='drawAddress']
        if len(witnesses)!=1:
            raise ValueError('compacting source requires its native indexed-field proof')
        w=witnesses[0].get('word_index',{});domain=w.get('index_domain',{})
        if (w.get('record_count')!=9 or w.get('index_width')!=2 or w.get('access_width')!=4
                or domain.get('lower_bound')!=0 or domain.get('upper_bound')!=32
                or domain.get('known_bits_mask',0)&3!=3
                or domain.get('known_bits_value',0)&3):
            raise ValueError('compacting selector domain differs')
    branches={0x4AE28:('beq',0x4AE8C),0x4AE42:('ble',0x4AE46),
              0x4AE52:('beq',0x4AE8C),0x4AE5E:('bpl',0x4AE62),
              0x4AE6A:('bgt',0x4AE8C),0x4AE76:('bpl',0x4AE7A),
              0x4AE7C:('bgt',0x4AE8C),0x4AE90:('dbf',0x4AE26)}
    for pc,(name,target) in branches.items():
        row=ins(pc,name)
        observed=[e for e in edges if e['source_offset']+0x800==pc]
        wanted={('branch',target-0x800),('fallthrough',pc+row['size']-0x800)}
        if (len(observed)!=2 or any(e['status']!='resolved' or e['target_section_index']!=0
                                   for e in observed)
                or {(e['kind'],e['target_offset'])for e in observed}!=wanted):
            raise ValueError('compacting branch or loop edge differs')
    flow={r['source_offset']+0x800 for r in block
          if any(p['access']=='branch_target'for p in r['operand_facts'])}
    if flow!=set(branches):
        raise ValueError('compacting producer has an unsupported control edge')
    expected_writes={'A0':{0x4AE0E},'A1':{0x4AE14},'A2':{0x4AE22},'A4':{0x4AE1A},
                     'D0':{0x4AE0A,0x4AE8C},'D6':{0x4AE20},'D7':{0x4AE0C,0x4AE2A}}
    writes={reg:set()for reg in expected_writes};updates=[];memory=[]
    for row in block:
        pc=row['source_offset']+0x800
        for i,p in enumerate(row['operand_facts']):
            if p['access']=='register_list_write':
                raise ValueError('compacting producer has an unknown register-list write')
            if p['direct_register']in writes and p['access']=='register_write':
                writes[p['direct_register']].add(pc)
            if p['ea_update']:
                updates.append((pc,p['base_register'],p['ea_update'],p['width_bytes']))
            if p['access']=='memory_write':
                memory.append((pc,i))
    if writes!=expected_writes or sorted(updates)!=sorted([(pc,'A0',1,w)for pc,w,_ in stores]+[(0x4AE26,'A2',1,2)]):
        raise ValueError('compacting producer has an unproved cursor/counter write')
    if sorted(memory)!=sorted([(pc,0 if pc==0x4AE4A else 1)for pc,_,_ in stores]+[(0x4AE7E,0),(0x4AE84,1)]):
        raise ValueError('compacting producer has an unproved memory write')
    operand(ins(0x4AE7E,'st'),0,address=0x4E2B8,width=1)
    operand(ins(0x4AE84,'move'),1,address=0x2F7DA)
    # Induction over the two checked paths: skip changes neither counter nor
    # destination; append changes them by 1 and 12 before every bounds branch.
    return {'entry_contract_runtime':0x4AE0A,
            'scope':'ordinary initializer-to-loop paths; external entries are not closed',
            'external_entries_or_aliases_closed':False,
            'descriptor_iterations':16,'descriptor_step_bytes':2,'descriptor_cell_runtime':0x4BC00,
            'descriptor_read_extent_bytes':32,'point_step_bytes':10,
            'point_read_extent_bytes':156,'appended_count_range':[0,16],
            'append_stride':12,'append_fields':[{'offset':o,'width':w}for _,w,o in stores],
            'destination_runtime':0xE816,'maximum_written_bytes':192,
            'count_register':'D7.W','point_index_register':'D0.W','upper_halves_proved':False,
            'header_invariant':'A0 = viewObjectRecords + 12*count; count = unsigned(D7.W) = appended nonzero descriptors',
            'bounds_checks_can_retract_append':False,'native_source_field_witnesses':2,
            'post_cull_or_callback_preservation_proved':False,'allocation_or_live_capacity_proved':False}


def scenery_record_copy_contract(rows, edges):
    """Exact opaque row/copy shapes; no scalarization of pointer fragments."""
    def ea(row,index,offset,selector=None,update=0):
        p=row['operand_facts'][index]
        if (not p['memory'] or p['base_register']!='A0' or p['width_bytes']!=4
                or p['ea_update']!=update or not p['displacement_known']
                or p['displacement']!=offset or p['indexed']!=(selector is not None)
                or selector is not None and (p['index_register']!=selector or p['index_width_bytes']!=2)):
            raise ValueError('scenery row copy EA differs')
    def triple(start,end,source_index,dest_index):
        part=window(rows,start,end)
        if len(part)!=3:raise ValueError('scenery row copy extent differs')
        for offset,row in zip([0,4,8],part,strict=True):
            operation(row,'move');ea(row,0,offset,source_index);ea(row,1,offset,dest_index)
    triple(0xE6C8,0xE6DA,'D5','D6')
    triple(0xE754,0xE764,'D6',None)
    swap=window(rows,0xE722,0xE748)
    if len(swap)!=9:raise ValueError('scenery row swap extent differs')
    for i,offset in enumerate([0,4,8]):
        load,replace,restore=swap[3*i:3*i+3]
        for row in [load,replace,restore]:operation(row,'move')
        ea(load,0,offset);operand(load,1,register='D2',width=4)
        ea(replace,0,offset,'D6');ea(replace,1,offset)
        operand(restore,0,register='D2',width=4);ea(restore,1,offset,'D6')
    for start,end in [(0xE6FA,0xE702),(0xE780,0xE788)]:
        part=window(rows,start,end)
        if len(part)!=4:raise ValueError('scenery backup chunk extent differs')
        for row in part:
            operation(row,'move')
            for i,base in [(0,'A0'),(1,'A1')]:
                p=row['operand_facts'][i]
                if (not p['memory'] or p['base_register']!=base or p['indexed']
                        or p['ea_update']!=1 or p['width_bytes']!=4):
                    raise ValueError('scenery backup cursor differs')
    at={r['source_offset']+0x800:r for r in rows}
    for pc,name,reg in [(0xE572,'mulu','D6'),(0xE6A0,'subi','D6'),(0xE6DA,'subi','D5'),
                        (0xE712,'mulu','D7'),(0xE748,'subi','D6'),(0xE764,'subi','D7')]:
        row=at.get(pc)
        if not row or row['provenance']!='accepted_instruction':
            raise ValueError('scenery row stride instruction missing')
        operation(row,name)
        if row['operand_facts'][0].get('immediate_value')!=12:
            raise ValueError('scenery row stride differs')
        operand(row,1,register=reg)
    # The backup count and singleton decision retain their WORD source. This
    # proves the local contract only, not preservation after the draw call.
    for pc,name,source,dest in [(0xE6EE,'move','D7','D6'),(0xE70A,'move','D6','D7')]:
        row=at.get(pc)
        if row is None or row['provenance']!='accepted_instruction':
            raise ValueError('scenery count transport missing')
        operation(row,name);operand(row,0,register=source);operand(row,1,register=dest)
    for pc,name in [(0xE6E8,'tst'),(0xE6F8,'subq'),(0xE70C,'subq')]:
        row=at.get(pc)
        if row is None or row['provenance']!='accepted_instruction':
            raise ValueError('scenery count adjustment missing')
        operation(row,name);operand(row,0 if name=='tst'else 1,register='D7')
        if name=='subq'and row['operand_facts'][0].get('immediate_value')!=1:
            raise ValueError('scenery count adjustment differs')
    load=at.get(0xE7B2);call=at.get(0xE80E);count=at.get(0xE778)
    if any(r is None or r['provenance']!='accepted_instruction'for r in [load,call,count]):
        raise ValueError('scenery draw/count instructions missing')
    operation(load,'movea');ea(load,0,6);operand(load,1,register='A1',width=4)
    operation(call,'jsr');p=call['operand_facts'][0]
    if not p['memory']or p['base_register']!='A1'or p['indexed']or p['ea_update']:
        raise ValueError('scenery callback register differs')
    operation(count,'move');operand(count,0,address=0x4E726);operand(count,1,register='D7')
    restore=window(rows,0xE778,0xE78E)
    if [r['mnemonic']for r in restore]!=['move','subq','move','move','move','move','dbf','rts']:
        raise ValueError('scenery restore control differs')
    operand(restore[1],1,register='D7');operand(restore[-2],0,register='D7')
    if restore[1]['operand_facts'][0].get('immediate_value')!=1:
        raise ValueError('scenery restore count adjustment differs')
    for pc,name,target in [(0xE6EA,'ble',0xE814),(0xE702,'dbf',0xE6FA),
                           (0xE70E,'beq',0xE78E),(0xE788,'dbf',0xE780)]:
        row=at.get(pc)
        if row is None or row['provenance']!='accepted_instruction':
            raise ValueError('scenery count branch missing')
        operation(row,name)
        if name=='dbf':operand(row,0,register='D7')
        selected=[e for e in edges if e['source_offset']+0x800==pc]
        if (len(selected)!=2 or any(e['status']!='resolved' or e['target_section_index']!=0 for e in selected)
                or {(e['kind'],e['target_offset'])for e in selected}!=
                    {('branch',target-0x800),('fallthrough',pc+row['size']-0x800)}):
            raise ValueError('scenery count branch differs')

    return {'record_stride':12,'record_copy_long_offsets':[0,4,8],
            'cull_copy_runtime':0xE6C8,'sort_swap_runtime':0xE722,
            'post_draw_replacement_runtime':0xE754,'backup_chunk_bytes':16,
            'restore_count_source_runtime':0x4E726,
            'positive_restore_count_required_for_count_sized_copy':True,
            'restore_count_rechecked_locally':False,'positive_restore_count_proved':False,
            'single_row_skips_restore':True,'pointer_byte_span':[6,10],
            'pointer_fragments':[{'long_offset':4,'long_byte_offset':2,'pointer_byte_offset':0,'bytes':2},
                                 {'long_offset':8,'long_byte_offset':0,'pointer_byte_offset':2,'bytes':2}],
            'long_copies_are_whole_pointer_values':False,'fragments_require_same_source_row':True,
            'loaded_value_or_callable_closure':False,'callee_or_alias_effects_proved':False,
            'conditional_source_lineage_review':'foft-scenery-compaction.md'}



def packed_draw_return_contract(rows, edges, summaries):
    """Pinned load/call/snapshot contracts; never a closed callback effect set."""
    block=window(rows,0xE78E,0xE816)
    at={r['source_offset']+0x800:r for r in rows}
    wanted=[(0xE78E,'move'),(0xE792,'bmi'),(0xE796,'move'),(0xE79A,'move'),
            (0xE79C,'bpl'),(0xE79E,'neg'),(0xE7A0,'tst'),(0xE7A2,'bpl'),
            (0xE7A4,'neg'),(0xE7A6,'cmp'),(0xE7A8,'ble'),(0xE7AC,'cmp'),
            (0xE7AE,'ble'),(0xE7B2,'movea'),(0xE7B6,'movem'),(0xE7BA,'move'),
            (0xE7C0,'move'),(0xE7C8,'move'),(0xE7D0,'move'),(0xE7D6,'cmp'),
            (0xE7DA,'ble'),(0xE7DC,'move'),(0xE7E2,'move'),(0xE7EA,'move'),
            (0xE7F0,'clr'),(0xE7F2,'jsr'),(0xE7F8,'move'),(0xE7FE,'move'),
            (0xE804,'jsr'),(0xE80A,'bra'),(0xE80E,'jsr'),(0xE810,'movem'),(0xE814,'rts')]
    if [(r['source_offset']+0x800,r['mnemonic'])for r in block]!=wanted:
        raise ValueError('draw return instruction window differs')
    def memory(pc,index,offset,width=2):
        p=at[pc]['operand_facts'][index]
        if (not p['memory']or p['base_register']!='A0'or p['indexed']or p['ea_update']
                or not p['displacement_known']or p['displacement']!=offset or p['width_bytes']!=width):
            raise ValueError('draw return view read differs')
    for pc,off,reg in [(0xE78E,4,'D2'),(0xE796,2,'D0'),(0xE79A,0,'D1')]:
        memory(pc,0,off);operand(at[pc],1,register=reg)
    memory(0xE7B2,0,6,4);operand(at[0xE7B2],1,register='A1',width=4)
    for pc,reg in [(0xE79E,'D1'),(0xE7A0,'D0'),(0xE7A4,'D0')]:operand(at[pc],0,register=reg)
    for pc,reg in [(0xE7A6,'D1'),(0xE7AC,'D0')]:
        operand(at[pc],0,register=reg);operand(at[pc],1,register='D2')
    all_regs={f'{kind}{n}'for kind in ['D','A']for n in range(8)}
    for pc,write in [(0xE7B6,True),(0xE810,False)]:
        row=at[pc];reg,mem=row['operand_facts'][0 if write else 1],row['operand_facts'][1 if write else 0]
        if (reg['access']!=('register_list_read'if write else'register_list_write')
                or set(reg['register_list'])!=all_regs or len(reg['register_list'])!=16
                or reg['width_bytes']!=4 or not reg['bulk_transfer']
                or not mem['memory']or mem['base_register']!='A7'or mem['indexed']
                or mem['access']!=('memory_write'if write else'memory_read')
                or mem['width_bytes']!=4 or not mem['bulk_transfer']
                or mem['ea_update']!=(2 if write else 1)):
            raise ValueError('draw return save frame differs')
    for pc,offset,address in [(0xE7BA,0,0x15E5A),(0xE7C0,2,0x15E5C),(0xE7C8,4,0x15E5E)]:
        memory(pc,0,offset);operand(at[pc],1,address=address)
    operand(at[0xE7D0],0,address=0x15E5E);operand(at[0xE7D0],1,register='D0')
    operand(at[0xE7D6],1,register='D0')
    if at[0xE7D6]['operand_facts'][0].get('immediate_value')!=0x4000:
        raise ValueError('draw return near threshold differs')
    # The near arm has no intervening call or write to the loaded A1. The
    # separately checked far arm is not folded into this value identity.
    near=window(rows,0xE7B6,0xE7DC)
    if any(p.get('direct_register')=='A1'and p.get('access')=='register_write'
           for r in near for p in r['operand_facts']):
        raise ValueError('draw return callback register was overwritten')
    call=at[0xE80E]['operand_facts'][0]
    if (not call['memory']or call['base_register']!='A1'or call['indexed']or call['ea_update']
            or not call['displacement_known']or call['displacement']):
        raise ValueError('draw return callback call differs')
    for pc,target in [(0xE792,0xE814),(0xE79C,0xE7A0),(0xE7A2,0xE7A6),
                       (0xE7A8,0xE814),(0xE7AE,0xE814),(0xE7DA,0xE80E),(0xE80A,0xE810)]:
        selected=[e for e in edges if e['source_offset']+0x800==pc]
        expected={('jump'if pc==0xE80A else'branch',target-0x800)}
        if pc!=0xE80A:expected.add(('fallthrough',pc+at[pc]['size']-0x800))
        if (len(selected)!=len(expected)or any(e['status']!='resolved'or e['target_section_index']!=0 for e in selected)
                or {(e['kind'],e['target_offset'])for e in selected}!=expected):
            raise ValueError('draw return branch differs')
    roots=[(0xE6F0,'A0',0xE816),(0xE6F4,'A1',0xEB16),(0xE706,'A0',0xE816),
           (0xE770,'A1',0xE816),(0xE774,'A0',0xEB16)]
    for pc,reg,address in roots:
        row=at.get(pc)
        if row is None or row.get('provenance')!='accepted_instruction':
            raise ValueError('draw return copy root missing')
        operation(row,'lea');operand(row,0,address=address,width=4);operand(row,1,register=reg,width=4)
    calls=[e for e in edges if e['source_offset']+0x800==0xE80E and e['kind']=='call']
    targets=sorted({e['target_offset']for e in calls if e['status']=='resolved'and e['target_section_index']==0})
    effects=[]
    for target in targets:
        selected=[s for s in summaries if s['callable_kind']=='direct'
                  and s['callable_section_index']==0 and s['entry_offset']==target]
        if len(selected)!=1:raise ValueError('draw return target needs its individual native summary')
        summary=selected[0]
        native=summary['effects'];registers=native['registers']
        compact={'state':registers['state']}
        for kind in ['preserved','clobbered','unknown']:
            group=[r['location']['register']for r in registers.get('locations',[])if r['effect']==kind]
            if group:compact[kind]=group
        effects.append({'runtime':target+0x800,'function_summary_id':summary['function_summary_id'],
                        'terminal_reason':summary['terminal_reason'],'registers':compact,
                        'memory_state':native['memory']['state'],'escape_state':native['escapes']['state'],
                        'native_effects_sha256':hashlib.sha256(json.dumps(native,sort_keys=True).encode()).hexdigest()})
    return {'view_pointer_byte_span':[6,10],'near_call_runtime':0xE80E,
            'near_call_A1_equals_current_row_LONG':True,'loaded_value_closed':False,
            'frame_runtime':0xE7B6,'restore_runtime':0xE810,'frame_bytes':64,
            'snapshot_overwritten_entry_registers':['D0.W','D1.W','D2.W','A1'],
            'restore_requires_ordinary_return_and_intact_frame':True,
            'unconditional_entry_register_preservation':False,
            'memory_restored_by_register_reload':False,
            'view_root_runtime':0xE816,'backup_root_runtime':0xEB16,
            'snapshot_bytes_per_input_count':16,'restore_bytes_per_reloaded_count':16,
            'byte_equality_count_bound':16,'copy_spans_disjoint_within_bound':0xE816+16*16<=0xEB16,
            'conditional_multi_row_return':{'conditions':['Ordinary initialized stack/row contracts',
                '2 <= input N <= 16 and 1 <= reloaded M <= 16; post-draw M bound is not proved',
                'All draws return normally with save frames intact','Positive reloaded count M',
                'No interfering writes during the restore copy'],
                'D7.W':65535,'A0':'backup + 16*M','A1':'view + 16*M',
                'restored_bytes_match_original_snapshot_only_if':'M=N and backup bytes unchanged'},
            'conditional_single_row_return':{'D7.W':0,'backup_restore_performed':False,
                'condition':'Draw helper returns normally with its save frame intact'},
            'global_count_or_record_preservation_proved':False,
            'target_effects':effects,'unresolved_call_edges':sum(e['status']=='unresolved'for e in calls),
            'individual_effects_close_dispatch':False}


def scenery_probe_crosswalk(count):
    """Byte-span algebra only, conditional on an unchanged 12-byte snapshot.

    This does not execute the probe, establish callback effects, or turn its
    overlapping reads into a second physical record owner.
    """
    if type(count) is not int or not 1 <= count <= 16:
        raise ValueError('scenery snapshot count must be in 1..16')
    fields = {0: 'x', 2: 'y', 4: 'z', 6: 'callbackHigh',
              8: 'callbackLow', 10: 'tail'}
    result = []
    for probe in range(count):
        reads = []
        for name, displacement in [('inputX', 0), ('inputY', 2),
                                    ('divisor', 4), ('actionGate', 10)]:
            offset = 10 * probe + displacement
            if offset + 2 > 12 * count:
                raise ValueError('scenery probe escapes conditional snapshot')
            reads.append({'consumer': name, 'byte_offset': offset,
                          'producer_row': offset // 12,
                          'producer_field': fields[offset % 12]})
        result.append({'probe': probe, 'phase': 10 * probe % 12, 'reads': reads})
    return result


def scenery_probe_contract(rows, edges=()):
    """Recheck the real overlapping reader, not just the arithmetic crosswalk."""
    at = {r['source_offset'] + 0x800: r for r in rows}
    def read(pc, displacement, dest=None, name='move'):
        r = at.get(pc)
        if r is None or r['provenance'] != 'accepted_instruction':
            raise ValueError('scenery probe instruction missing')
        operation(r, name)
        p = r['operand_facts'][0]
        if (not p['memory'] or p['base_register'] != 'A0' or p['indexed']
                or p['ea_update'] or not p['displacement_known']
                or p['displacement'] != displacement or p['width_bytes'] != 2
                or p['access'] != 'memory_read'):
            raise ValueError('scenery probe read differs')
        if dest is not None:
            operand(r, 1, register=dest)
    for pc, offset, reg in [(0x4AEC4, 0, 'D0'), (0x4AEC6, 2, 'D1'),
                             (0x4AECA, 4, 'D2')]:
        read(pc, offset, reg)
    root = at[0x4AEB2]; operation(root, 'lea')
    operand(root, 0, address=0xE816, width=4); operand(root, 1, register='A0', width=4)
    count = at[0x4AEB8]; operation(count, 'move')
    operand(count, 0, address=0x4E726); operand(count, 1, register='D7')
    adjust = at[0x4AEBE]; operation(adjust, 'subq'); operand(adjust, 1, register='D7')
    if adjust['operand_facts'][0].get('immediate_value') != 1:
        raise ValueError('scenery probe count adjustment differs')
    # Remaining anchors are checked by their accepted native operands in the
    # bounded reader; do not infer the layout from matching pointer values.
    block = window(rows, 0x4AEB2, 0x4AF62)
    divides = [r for r in block if r['mnemonic'] == 'divs']
    if len(divides) != 2:
        raise ValueError('scenery probe division count differs')
    for r, dest in zip(divides, ['D0', 'D1'], strict=True):
        operand(r, 0, register='D2'); operand(r, 1, register=dest)
    gates = [r for r in block if r['mnemonic'] == 'tst' and
             r['operand_facts'][0].get('base_register') == 'A0']
    if len(gates) != 1:
        raise ValueError('scenery probe gate count differs')
    read(gates[0]['source_offset'] + 0x800, 10, name='tst')
    advances = [r for r in block if r['mnemonic'] == 'lea' and
                r['operand_facts'][0].get('base_register') == 'A0']
    if len(advances) != 1:
        raise ValueError('scenery probe advance count differs')
    p = advances[0]['operand_facts'][0]
    if (not p['memory'] or p['indexed'] or p['ea_update']
            or not p['displacement_known'] or p['displacement'] != 10):
        raise ValueError('scenery probe advance differs')
    operand(advances[0], 1, register='A0', width=4)
    for pc, name, target in [(0x4AEC0, 'bmi', 0x4AF62),
            (0x4AEF0, 'bgt', 0x4AF5A), (0x4AF00, 'bgt', 0x4AF5A),
            (0x4AF12, 'beq', 0x4AF62), (0x4AF18, 'bne', 0x4AF62),
            (0x4AF56, 'bra', 0x4AF62), (0x4AF5E, 'dbf', 0x4AEC4)]:
        operation(at[pc], name)
        selected = [e for e in edges if e['source_offset']+0x800 == pc]
        expected = {('jump' if name == 'bra' else 'branch', target-0x800)}
        if name != 'bra':
            expected.add(('fallthrough', pc+at[pc]['size']-0x800))
        if (len(selected) != len(expected) or any(e['status'] != 'resolved'
                or e['target_section_index'] != 0 for e in selected)
                or {(e['kind'], e['target_offset']) for e in selected} != expected):
            raise ValueError('scenery probe control edges differ')
    operand(at[0x4AF5E], 0, register='D7')
    return {'producer_stride': 12, 'consumer_stride': 10,
            'post_return_count_source_runtime': 0x4E726,
            'crosswalk_requires_unchanged_snapshot_and_positive_count': True,
            'conditional_count_domain': [1, 16],
            'consumer_guard_proves_that_domain': False,
            'conditional_crosswalk': scenery_probe_crosswalk(16),
            'snapshot_or_count_preservation_proved': False,
            'live_execution_or_fault_observed': False}


def pending_system_damage_contract(rows):
    """Pin the source-backed state name and the two bounded selector lists."""
    at = {r['source_offset'] + 0x800: r for r in rows}
    block = window(rows, 0x2EE34, 0x2EE58)
    if [r['mnemonic'] for r in block] != [
            'movem', 'bsr', 'move', 'beq', 'add', 'bsr', 'clr', 'movem', 'rts']:
        raise ValueError('pending damage consumer framing differs')
    operand(at[0x2EE3C], 0, address=0x4E69C)
    operand(at[0x2EE3C], 1, register='D1')
    for i in [0, 1]:
        operand(at[0x2EE46], i, register='D1')
    operand(at[0x2EE4C], 0, address=0x4E69C)
    initializers = [(0x275AE, 10), (0x275C8, 10),
                    (0x284A2, 5), (0x284B6, 5)]
    for pc, value in initializers:
        r = at[pc]; operation(r, 'addi')
        operand(r, 1, address=0x4E69C)
        if r['operand_facts'][0].get('immediate_value') != value:
            raise ValueError('scenery pending damage amount differs')
    selectors = []
    for pc, doubles, load, mask, begin, end in [
            (0x2EE6C, [0x2EE70, 0x2EE72], 0x2EE74, 15, 0x2EF02, 0x2EF42),
            (0x2EEA8, [0x2EEB0, 0x2EEB2], 0x2EEB4, 3, 0x2EF42, 0x2EF52)]:
        r = at[pc]; operation(r, 'andi'); operand(r, 1, register='D0')
        if r['operand_facts'][0].get('immediate_value') != mask:
            raise ValueError('damage selector mask differs')
        for pc in doubles:
            r = at[pc]; operation(r, 'add')
            for i in [0, 1]:
                operand(r, i, register='D0')
        r = at[load]; operation(r, 'movea'); operand(r, 1, register='A0', width=4)
        p = r['operand_facts'][0]
        if (not p['memory'] or p['base_register'] != 'A0' or not p['indexed']
                or p['index_register'] != 'D0' or p['index_width_bytes'] != 2
                or p['index_scale'] != 1 or p['width_bytes'] != 4
                or p['ea_update'] or not p['displacement_known'] or p['displacement'] != 0):
            raise ValueError('damage selector load differs')
        lea = at[0x2EE62 if begin == 0x2EF02 else 0x2EEAC]
        operation(lea, 'lea'); operand(lea, 0, address=begin, width=4)
        operand(lea, 1, register='A0', width=4)
        selectors.append({'source_runtime_span': [begin, end], 'row_count': mask + 1,
                          'row_stride': 4, 'special_values_are_not_dereferences': True})
    for pc, value in [(0x2EE78, 0x2EF6E), (0x2EE9A, 0xffffffff)]:
        r = at[pc]; operation(r, 'cmpa'); operand(r, 1, register='A0', width=4)
        if r['operand_facts'][0].get('immediate_value') != value:
            raise ValueError('damage selector special comparison differs')
    uses = []
    for r in rows:
        for p in r['operand_facts']:
            if p.get('absolute_address') == 0x4E69C:
                if r['provenance'] != 'accepted_instruction' or p['width_bytes'] != 2:
                    raise ValueError('pending state use width/provenance differs')
                uses.append({'runtime': r['source_offset'] + 0x800,
                             'operation': r['mnemonic'], 'access': p['access']})
    return {'direct_absolute_uses': uses, 'selector_tables': selectors,
            'initial_callback_execution_proved': False,
            'complete_writer_alias_or_value_domain': False}


def panel_mask_inventory(rows):
    """Inventory explicit D6 effects; entry/branch dominance is source-reviewed."""
    block = window(rows, 0x1FA32, 0x1FC86)
    helper = window(rows, 0x1B436, 0x1B460)
    if block[0]['mnemonic'] != 'clr':
        raise ValueError('panel mask initial clear differs')
    operand(block[0], 0, register='D6')
    operation(block[-1], 'move')
    operand(block[-1], 0, register='D6')
    operand(block[-1], 1, address=0x1FD62)
    safe = {'nop', 'move', 'swap', 'eori', 'addq', 'subi', 'rol', 'add', 'ror', 'rts'}
    for row in helper:
        if row['mnemonic'] not in safe or any(
                p.get('direct_register') == 'D6' and p.get('access') != 'register_read'
                for p in row['operand_facts']):
            raise ValueError('panel mask helper has an unproved D6 effect')
    if helper[-1]['mnemonic'] != 'rts':
        raise ValueError('panel mask helper return differs')
    sets, clears, masks, calls = set(), set(), [], []
    for row in block:
        if row['mnemonic'] in {'jsr', 'bsr', 'jmp', 'movem', 'trap', 'rte', 'rtr', 'stop', 'illegal'}:
            if row['mnemonic'] != 'jsr':
                raise ValueError('panel mask has an unproved implicit effect')
            operand(row, 0, address=0x1B436, width=4)
            calls.append(row['source_offset'] + 0x800)
        if row is block[0]:
            continue
        effects = [p for p in row['operand_facts'] if p.get('direct_register') == 'D6'
                   and p.get('access') != 'register_read']
        if not effects:
            continue
        if len(effects) != 1 or row['mnemonic'] not in {'bset', 'bclr', 'andi'}:
            raise ValueError('panel mask has an unproved explicit D6 effect')
        value = row['operand_facts'][0].get('immediate_value')
        if row['mnemonic'] == 'andi':
            operand(row, 1, register='D6')
            if not isinstance(value, int) or not 0 <= value <= 0xFFFF:
                raise ValueError('panel mask WORD mask differs')
            masks.append(value)
        else:
            operand(row, 1, register='D6', width=4)
            if not isinstance(value, int) or not 0 <= value < 15:
                raise ValueError('panel mask bit operation exceeds the reviewed domain')
            (sets if row['mnemonic'] == 'bset' else clears).add(value)
    return {'bset_bits': sorted(sets), 'bclr_bits': sorted(clears), 'word_and_masks': masks,
            'direct_helper_calls': calls, 'helper_d6_preserved': True,
            'bit15_clear_on_reviewed_ordinary_producer': True,
            'entry_and_branch_dominance_review': 'foft-panel-flag-glyphs.md',
            'all_writers_or_runtime_visibility_proved': False}



def panel_text_receipt(payload, font):
    """Decode source offsets using the separately audited, pinned atlas slots."""
    expected = '8efc64f20c1e3956f0be348dd41867c94a254c2205a936ab1565aa3c7ac4c34a'
    if len(font) != 380 or hashlib.sha256(font).hexdigest() != expected:
        raise ValueError('panel font atlas identity differs')
    alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ -'
    if len(payload) < 0x1F0EE - 0x800:
        raise ValueError('panel text source bytes missing')
    phase_hashes = []
    words = [int.from_bytes(font[i:i+2], 'big') for i in range(0, 380, 2)]
    for phase, address in [(0, 0xBB2E), (1, 0xB9B2), (2, 0xB836), (3, 0xB6BA)]:
        data = payload[address-0x800:address-0x800+380]
        shifted = b''.join((word >> (4*phase)).to_bytes(2, 'big') for word in words)
        if data != shifted:
            raise ValueError('panel font phase view differs')
        phase_hashes.append({'phase': phase, 'runtime': address,
            'sha256': hashlib.sha256(data).hexdigest(), 'right_shift_bits': 4*phase})

    def text(pointer, count):
        start, end = pointer - 0x800, pointer - 0x800 + 2 * count
        if pointer % 2 or not 0 < count <= 0xFFFF or start < 0 or end > len(payload):
            raise ValueError('panel glyph text source extent differs')
        values = [int.from_bytes(payload[p:p+2], 'big') for p in range(start, end, 2)]
        if any(value % 5 or value // 5 >= len(alphabet) for value in values):
            raise ValueError('panel glyph offset is not an audited atlas slot')
        return ''.join(alphabet[value // 5] for value in values)

    if len(payload) < 0x1F0EE - 0x800:
        raise ValueError('panel text source bytes missing')
    labels, auxiliary = [], []
    for base, count, output in [(0x1ED96, 9, labels), (0x1EDF4, 2, auxiliary)]:
        for i in range(count):
            at = base-0x800 + 10*i
            pointer = int.from_bytes(payload[at:at+4], 'big')
            row = int.from_bytes(payload[at+6:at+8], 'big')
            words = int.from_bytes(payload[at+8:at+10], 'big')
            output.append({'display_row': row, 'text': text(pointer, words)})
    tables = {}
    for name, start, count in [('starport_type', 0x1F06A, 6), ('atmosphere', 0x1EEFE, 14),
                                ('flags', 0x1EB64, 16)]:
        options = []
        for i in range(count):
            at = start-0x800 + 8*i
            pointer = int.from_bytes(payload[at:at+4], 'big')
            words = int.from_bytes(payload[at+4:at+8], 'big')
            options.append(text(pointer, words))
        tables[name] = options
    return {'font_sha256': expected, 'font_slot_mapping': alphabet,
            'mapping_evidence': 'manual static five-WORD glyph-cell review; foft-panel-flag-glyphs.md',
            'phase_atlases': phase_hashes, 'labels': labels, 'auxiliary_labels': auxiliary,
            'initial_texts': tables, 'runtime_visibility': 'not observed'}


def collect(artifact, payload, *, full=False):
    rows = []
    for lo, hi in [(0xF16E, 0xF2EA), (0xFC24, 0xFC92)]:
        page = artifact.query_payload('instructions', section_index=0,
            source_offset=lo-0x800, end_offset=hi-0x800, limit=100)
        if page['has_more']:
            raise ValueError('instruction contract inventory incomplete')
        rows.extend(page['items'])
    for row in rows:
        refs = artifact.query_payload('references', section_index=0,
            source_offset=row['source_offset'], direction='outgoing', limit=100)
        if refs['has_more']:
            raise ValueError('reference inventory incomplete')
        row['resolved_reference_addresses'] = [
            {'operand_index': e['operand_index'], 'has_address': True,
             'address': e['target_offset']+0x800}
            for e in refs['items'] if e.get('target_section_index') == 0 and not e.get('comment_only')
            and e.get('operand_index') is not None]
    result = audit(payload, rows)
    if full:
        complete = []
        while True:
            page = artifact.query_payload('instructions', section_index=0,
                source_offset=0, end_offset=len(payload), offset=len(complete), limit=100)
            complete.extend(page['items'])
            if not page['has_more']:
                break
        # Authenticate every supplied native row too; no source bytes in output.
        for row in complete:
            at = row['source_offset']
            if payload[at:at+row['size']].hex() != row['bytes'].lower():
                raise ValueError('frame instruction bytes differ')
        result['frame_inventory'] = frame_inventory(complete)
        result['accepted_code_coordinates_and_bytes_sha256']=hashlib.sha256(json.dumps(
            [(r['source_offset'],r['size'],r['bytes'].lower())for r in complete],
            separators=(',',':')).encode()).hexdigest()
        result['body_work_chain'] = body_work_chain(complete)
        result['glyph_stream_inventory'] = glyph_stream_inventory(complete)
        result['fixed_point_receiver'] = fixed_point_receiver(complete)
        result['hit_record_contract'] = hit_record_contract(complete)
        result['flag_glyph_contract'] = flag_glyph_contract(payload, complete)
        result['indexed_panel_glyph_contract'] = indexed_panel_glyph_contract(payload, complete)
        result['scenery_bound_headers'] = scenery_bound_headers(payload, complete)
        append_edges = []
        for pc in [0x4AE28,0x4AE42,0x4AE52,0x4AE5E,0x4AE6A,0x4AE76,0x4AE7C,0x4AE90]:
            page = artifact.query_payload('edges',section_index=0,source_offset=pc-0x800,
                                          direction='outgoing',limit=100)
            if page['has_more']:
                raise ValueError('compacting edge query incomplete')
            append_edges.extend(page['items'])
        descriptor_load = next(r for r in complete if r['source_offset']+0x800==0x4AE22)
        refs = artifact.query_payload('references',section_index=0,source_offset=0x4AE22-0x800,
                                      direction='outgoing',limit=100)
        if refs['has_more']:
            raise ValueError('compacting descriptor reference query incomplete')
        descriptor_load['resolved_reference_addresses'] = [
            {'operand_index':e['operand_index'],'has_address':True,'address':e['target_offset']+0x800}
            for e in refs['items'] if e.get('target_section_index')==0 and not e.get('comment_only')
            and e.get('operand_index') is not None]
        result['scenery_compacting_append_contract'] = scenery_compacting_append_contract(complete,append_edges)
        copy_edges=[]
        for pc in [0xE6EA,0xE702,0xE70E,0xE788]:
            page=artifact.query_payload('edges',section_index=0,source_offset=pc-0x800,
                                         direction='outgoing',limit=100)
            if page['has_more']:
                raise ValueError('scenery copy edge query incomplete')
            copy_edges.extend(page['items'])
        result['scenery_record_copy_contract'] = scenery_record_copy_contract(complete,copy_edges)
        return_edges=list(copy_edges)
        for pc in [0xE792,0xE79C,0xE7A2,0xE7A8,0xE7AE,0xE7DA,0xE80A,0xE80E]:
            page=artifact.query_payload('edges',section_index=0,source_offset=pc-0x800,
                                        direction='outgoing',limit=100)
            if page['has_more']:raise ValueError('draw return edge query incomplete')
            return_edges.extend(page['items'])
        for pc in [0xE6F0,0xE6F4,0xE706,0xE770,0xE774]:
            row=next(r for r in complete if r['source_offset']+0x800==pc)
            page=artifact.query_payload('references',section_index=0,source_offset=pc-0x800,
                                        direction='outgoing',limit=100)
            if page['has_more']:raise ValueError('draw return root query incomplete')
            row['resolved_reference_addresses']=[{'operand_index':e['operand_index'],'has_address':True,
                'address':e['target_offset']+0x800}for e in page['items']
                if e.get('target_section_index')==0 and not e.get('comment_only')and e.get('operand_index')is not None]
        analysis=artifact.analysis_payload()[0]
        result['packed_draw_return_contract']=packed_draw_return_contract(complete,return_edges,
            analysis['sections'][0]['function_summaries'])
        for pc in [0x2EE62, 0x2EEAC]:
            row = next(r for r in complete if r['source_offset'] + 0x800 == pc)
            refs = artifact.query_payload('references', section_index=0,
                source_offset=pc-0x800, direction='outgoing', limit=100)
            if refs['has_more']:
                raise ValueError('damage selector reference query incomplete')
            row['resolved_reference_addresses'] = [
                {'operand_index': e['operand_index'], 'has_address': True,
                 'address': e['target_offset']+0x800}
                for e in refs['items'] if e.get('target_section_index') == 0
                and not e.get('comment_only') and e.get('operand_index') is not None]
        result['pending_system_damage_contract'] = pending_system_damage_contract(complete)
        probe_edges = []
        for pc in [0x4AEC0, 0x4AEF0, 0x4AF00, 0x4AF12, 0x4AF18, 0x4AF56, 0x4AF5E]:
            page = artifact.query_payload('edges', section_index=0, source_offset=pc-0x800,
                direction='outgoing', limit=100)
            if page['has_more']:
                raise ValueError('scenery probe edge query incomplete')
            probe_edges.extend(page['items'])
        result['scenery_probe_contract'] = scenery_probe_contract(complete, probe_edges)
        callback_cells = [int.from_bytes(payload[0x49802+4*i:0x49806+4*i], 'big')
                          for i in range(9)]
        result['scenery_probe_contract']['initialized_callback_half_properties'] = {
            'cells': len(callback_cells), 'unique_values': len(set(callback_cells)),
            'all_high_words_nonzero': all(value >> 16 != 0 for value in callback_cells),
            'all_low_words_nonzero': all(value & 0xffff != 0 for value in callback_cells),
            'preservation_at_consumer_proved': False}

        result['panel_mask_inventory'] = panel_mask_inventory(complete)
        result['panel_text_receipt'] = panel_text_receipt(payload,
            (Path(__file__).resolve().parents[1]/'targets/amiga_raw_foft/assets/dataGraphics380_1.bin').read_bytes())
    return result


def main():
    from amiga_reversing.disasm.disk_set import DiskSet
    from amiga_reversing.disasm.disk_set_state import _artifact
    from amiga_reversing.disasm.target_history import target_lock
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--member',type=Path,required=True)
    parser.add_argument('--full-frame-inventory',action='store_true')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]; target=root/'targets/amiga_raw_foft'
    with target_lock(target):
        owner=DiskSet.load(target,project_root=root)
        source,artifact=_artifact(owner,'main',{},input_body={'input_mode':'member','member_paths':{'main':str(args.member)}})
        try:
            result=collect(artifact,source.read_bytes(),full=args.full_frame_inventory);result['revision']=owner.revision
            print(json.dumps(result,indent=2))
        finally:
            artifact.close()
    return 0


if __name__=='__main__':
    raise SystemExit(main())

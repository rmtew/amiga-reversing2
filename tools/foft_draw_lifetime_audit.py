"""Pinned source contracts for draw return, snapshot and saved-offset lifetimes.

This consumes accepted native rows/edges and the authenticated complete member.
It neither executes the 68000 nor emits receiver, effect or code-admission facts.
"""
import argparse
import hashlib
import json
from pathlib import Path

from tools.foft_action_ownership_audit import intersects, signed_word
from tools.foft_irq_write_audit import reachable_write_inventory, require
from tools.foft_render_contract_audit import (
    MAIN_SHA256,
    operand,
    scenery_record_copy_contract,
    window,
)

COUNT = (0x4E726, 0x4E728)
BACKUP = (0xEB16, 0xEC16)
SAVED = (0x4E6A4, 0x4E6A6)


def no_explicit_memory_writes(rows):
    """A local source check, with faults/interrupts/implicit stack effects excluded."""
    allowed = {'clr', 'tst', 'bpl', 'bmi', 'neg', 'bgt', 'move', 'movea', 'bra', 'ext',
               'beq', 'ble', 'asl', 'divu', 'bvc', 'cmp', 'blt', 'lea', 'andi', 'addq',
               'sub', 'add', 'rts'}
    for row in rows:
        require(row['provenance'] == 'accepted_instruction', 'unaccepted instruction')
        require(row['mnemonic'] not in ('jsr', 'bsr', 'jmp', 'rte', 'trap'),
                'call or exceptional transfer needs separate effects')
        require(row['mnemonic'] in allowed, 'unsupported local operation or implicit effect')
        require(not any(p.get('memory') and 'write' in p.get('access', '')
                        for p in row['operand_facts']), 'explicit memory write')
    return {'explicit_memory_writes': [], 'ordinary_intact_return_required': True,
            'interrupts_faults_and_stack_alias_closed': False}


def activation_views(count):
    """Only the already-declared 64-slot source-window premise, not a live bound."""
    require(type(count) is int and 0 <= count < 64, 'requires conditional source slot 0..63')
    product = (20 * count) & 65535
    displacement = signed_word(product)
    state = (0x4E818 + displacement, 0x4E818 + displacement + 20)
    action = (0x4ED18 + displacement, 0x4ED18 + displacement + 16)
    orientation = (0x2B994 + (product >> 1), 0x2B994 + (product >> 1) + 10)
    require(not any(intersects(s, SAVED) for s in (state, action, orientation)),
            'activation writes overlap saved offset')
    return {'saved_word': product, 'signed_state_displacement': displacement,
            'state_write_view': list(state), 'action_write_view': list(action),
            'orientation_write_view': list(orientation),
            'later_state_receiver_if_saved_word_intact': state[0],
            'actual_entry_bound_or_intervening_preservation_proved': False}



def far_pixel_spans(bank):
    """Conditional software-store envelope; never a global bank or DMA fact."""
    require(type(bank) is int and bank in (0, 0x8000), 'requires preserved canonical draw bank')
    spans = [[0x70000 + bank + plane + 40*16 + (26 >> 3),
              0x70000 + bank + plane + 40*126 + (294 >> 3) + 1]
             for plane in (0, 0x2000, 0x4000, 0x6000)]
    require(not any(intersects(span, critical) for span in spans
                    for critical in (COUNT, BACKUP, SAVED, (0xE816, 0xE916))),
            'bounded pixel store intersects reviewed source state')
    return spans


def restricted_scenery_snapshot(count, attempts, bank=None):
    """Compose the checked paths under explicit caller/stack/async premises.

    This is span/count algebra, not an interpreter or a live-path assertion.
    A successful near callback is deliberately not an accepted premise.
    """
    require(type(count) is int and 2 <= count <= 14, 'requires fresh multi-row scenery N=2..14')
    require(len(attempts) == count and all(a in ('reject', 'far') for a in attempts),
            'every attempted row must use a checked rejecting or far path')
    if 'far' in attempts:
        far_pixel_spans(bank)
    saved = (BACKUP[0], BACKUP[0] + 16*count)
    view = (0xE816, 0xE816 + 16*count)
    require(saved[1] <= BACKUP[1] and not intersects(saved, view), 'snapshot domains overlap')
    return {'initial_N': count, 'reloaded_M_given_path_and_preservation_premises': count,
            'snapshot_bytes': 16*count, 'live_packed_bytes': 12*count,
            'backup_span': list(saved), 'view_snapshot_span': list(view),
            'restored_live_prefix_equals_original_given_premises': True,
            'premises': ['Scenery stores its positive post-cull count before drawing',
                         'Every draw attempt follows a rejection or the canonical-bank far path',
                         'Ordinary reads and returns; original frames and nonaliasing stack',
                         'No asynchronous/intervening writers'],
            'actual_path_or_unconditional_near_callback_preservation_proved': False}

def check_source(rows, analysis, data):
    require(len(data) == 489472 and hashlib.sha256(data).hexdigest() == MAIN_SHA256,
            'whole member bytes differ')
    require(len(rows) == 30616 and all(r['provenance'] == 'accepted_instruction' and
            data[r['source_offset']:r['source_offset'] + r['size']] == bytes.fromhex(r['bytes'])
            for r in rows), 'accepted rows do not match whole member')
    at = {r['source_offset'] + 2048: r for r in rows}
    edges = analysis['edges']
    links = {(e['source_offset'] + 2048, e['target_offset'] + 2048)
             for e in edges if e.get('target_offset', -1) >= 0}
    # This analysis payload is its single main-member section. Adapt only the
    # existing resolved local branch/fallthrough facts to the shared checker.
    # Enum values: src/m68k_ir.h M68K_CFG_EDGE_FALLTHROUGH/BRANCH.
    copy_edges = [{**e, 'kind': {1: 'fallthrough', 2: 'branch'}[e['kind']],
                   'status': 'resolved' if e['target_block_index'] >= 0 else 'unresolved',
                   'target_section_index': 0 if e['target_block_index'] >= 0 else -1}
                  for e in edges if e['kind'] in (1, 2)]
    copy = scenery_record_copy_contract(rows, copy_edges)
    require(copy['backup_chunk_bytes'] == 16, 'backup chunk differs')
    prefix = window(rows, 0xE78E, 0xE7B6)
    rejected = no_explicit_memory_writes(prefix)
    for pc, mnemonic in ((0xE792, 'bmi'), (0xE7A8, 'ble'), (0xE7AE, 'ble')):
        require(at[pc]['mnemonic'] == mnemonic and (pc, 0xE814) in links,
                'frustum rejection edge differs')
    require(at[0xE814]['mnemonic'] == 'rts' and not at[0xE814]['operand_facts'],
            'ordinary draw return differs')
    rejected.update(entry_runtime=0xE78E, rejection_sites=[0xE792, 0xE7A8, 0xE7AE],
                    return_runtime=0xE814, count_and_backup_explicitly_unchanged=True,
                    applies_to_successful_near_or_far_draw=False)
    draw = window(rows, 0xE7B6, 0xE80E)
    frame = at[0xE7B6]; restore = at[0xE810]
    registers = {f'{kind}{i}' for kind in ('D', 'A') for i in range(8)}
    require(frame['mnemonic'] == restore['mnemonic'] == 'movem' and
            set(frame['operand_facts'][0]['register_list']) == registers and
            len(frame['operand_facts'][0]['register_list']) == 16 and
            set(restore['operand_facts'][1]['register_list']) == registers and
            len(restore['operand_facts'][1]['register_list']) == 16,
            'draw register snapshot differs')
    memory = frame['operand_facts'][1]
    require(memory['memory'] and memory['base_register'] == 'A7' and
            memory['bulk_transfer'] and memory['width_bytes'] == 4 and memory['ea_update'] == 2,
            'draw save frame differs')
    memory = restore['operand_facts'][0]
    require(memory['memory'] and memory['base_register'] == 'A7' and
            memory['bulk_transfer'] and memory['width_bytes'] == 4 and memory['ea_update'] == 1,
            'draw restore frame differs')
    fixed = [(r['source_offset']+2048, p['absolute_address'], p['width_bytes'])
             for r in draw for p in r['operand_facts']
             if p.get('memory') and 'write' in p['access'] and not p.get('bulk_transfer')]
    require(fixed == [(0xE7BA, 0x15E5A, 2), (0xE7C0, 0x15E5C, 2), (0xE7C8, 0x15E5E, 2),
                      (0xE7DC, 0x15BD0, 2), (0xE7E2, 0x15BD2, 2), (0xE7EA, 0x15BD4, 2)],
            'far/common draw stores differ')
    require([r['source_offset']+2048 for r in draw if r['mnemonic'] in ('jsr', 'bsr', 'jmp')]
            == [0xE7F2, 0xE804] and (0xE80A, 0xE810) in links,
            'far return/callee sequence differs')
    # Far depth arm: zero is a last-record offset, hence a single projected row.
    operand(at[0xE7F0], 0, register='D0')
    require(at[0xE7F0]['mnemonic'] == 'clr' and (0xE7F2, 0xFD3E) in links
            and (0xE804, 0x197B2) in links, 'far draw helper chain differs')
    operand(at[0xE7D6], 0); operand(at[0xE7D6], 1, register='D0')
    require(at[0xE7D6]['operand_facts'][0]['immediate_value'] == 0x4000 and
            at[0xE7DA]['mnemonic'] == 'ble' and (0xE7DA, 0xE80E) in links,
            'far signed-depth selection differs')
    for pc, address in ((0xE7DC, 0x15BD0), (0xE7E2, 0x15BD2), (0xE7EA, 0x15BD4)):
        operand(at[pc], 1, address=address)
    projection = window(rows, 0xFD3E, 0xFD76)
    operand(at[0xFD3E], 0, address=0x15BD0, width=4)
    operand(at[0xFD3E], 1, register='A0', width=4)
    projection_writes = [(r['source_offset']+2048, p) for r in projection
                         for p in r['operand_facts'] if p.get('memory') and 'write' in p['access']]
    require([pc for pc, _ in projection_writes] == [0xFD56, 0xFD6A],
            'projection acquired another writer')
    for (_, p), offset in zip(projection_writes, (6, 8), strict=True):
        require(p['base_register'] == 'A0' and p['indexed'] and p['index_register'] == 'D0'
                and p['index_width_bytes'] == 2 and p['width_bytes'] == 2
                and p['displacement'] == offset and not p['ea_update'], 'projection store differs')
    for reg, expected in (('A0', [0xFD3E]), ('D0', [0xFD6E])):
        actual = [r['source_offset'] + 2048 for r in projection
                  if any(p.get('direct_register') == reg and not p.get('memory')
                         and 'write' in p.get('access', '') for p in r['operand_facts'])]
        require(actual == expected, 'single-row projection receiver/index clobbered')
    require(at[0xFD6E]['operand_facts'][0]['immediate_value'] == 10 and
            at[0xFD6E]['mnemonic'] == 'subi' and (0xFD72, 0xFD44) in links,
            'single-row projection exit differs')
    pixel = window(rows, 0x197B2, 0x197F8)
    for pc, value, branch in ((0x197B2, 127, 'bge'), (0x197B8, 15, 'ble'),
                              (0x197BE, 295, 'bge'), (0x197C4, 25, 'ble')):
        require(at[pc]['mnemonic'] == 'cmp' and at[pc]['operand_facts'][0]['immediate_value'] == value
                and at[pc+4]['mnemonic'] == branch and (pc+4, 0x197F6) in links,
                'pixel clip boundary differs')
    operand(at[0x197CA], 0, address=0x70000, width=4)
    operand(at[0x197D0], 0, address=0x16E2, width=4)
    require(at[0x197D0]['mnemonic'] == 'adda', 'pixel bank addition differs')
    for pc, name, value, register in ((0x197D6, 'mulu', 40, 'D1'),
                                      (0x197DE, 'lsr', 3, 'D0')):
        require(at[pc]['mnemonic'] == name and at[pc]['operand_facts'][0]['immediate_value'] == value,
                'pixel address arithmetic differs')
        operand(at[pc], 1, register=register)
    for pc, register in ((0x197DA, 'D1'), (0x197E0, 'D0')):
        require(at[pc]['mnemonic'] == 'adda', 'pixel offset addition differs')
        operand(at[pc], 0, register=register); operand(at[pc], 1, register='A0')
    pixel_writes = [(r['source_offset']+2048, p) for r in pixel for p in r['operand_facts']
                    if p.get('memory') and 'write' in p['access']]
    require([pc for pc, _ in pixel_writes] == [0x197E8, 0x197EA, 0x197EE, 0x197F2],
            'pixel acquired another writer')
    for (_, p), displacement in zip(pixel_writes, (0, 0x2000, 0x4000, 0x6000), strict=True):
        require(p['base_register'] == 'A0' and p['width_bytes'] == 1 and not p['indexed']
                and p['displacement'] == displacement and not p['ea_update'], 'pixel write domain differs')
    require(not any(r['mnemonic'] in ('jsr', 'bsr', 'jmp') for r in [*pixel, *projection]),
            'far helper acquired unreviewed callee')
    angle = window(rows, 0x1B780, 0x1B7E4)
    angle_effects = no_explicit_memory_writes(angle)
    allowed = {'clr', 'tst', 'bpl', 'neg', 'bgt', 'move', 'bra', 'ext', 'beq', 'asl',
               'divu', 'bvc', 'cmp', 'blt', 'lea', 'andi', 'addq', 'sub', 'add', 'rts'}
    require(all(r['mnemonic'] in allowed for r in angle), 'orientation operation differs')
    require(angle[-1]['mnemonic'] == 'rts', 'orientation return differs')
    # Every branch must stay in this complete body. No implicit external tail.
    for e in edges:
        if 0x1B780 <= e['source_offset'] + 2048 < 0x1B7E4 and e['kind'] != 5:
            require(e['target_block_index'] >= 0 and
                    0x1B780 <= e['target_offset'] + 2048 < 0x1B7E4,
                    'orientation transfer leaves body')
    for pc, name, value in ((0x1B7AA, 'asl', 6), (0x1B7BE, 'cmp', 0x50C),
                            (0x1B7D2, 'andi', 255)):
        require(at[pc]['mnemonic'] == name and
                at[pc]['operand_facts'][0]['immediate_value'] == value,
                'orientation arithmetic differs')
    require(at[0x1B7C2]['mnemonic'] == 'blt', 'signed ratio comparison differs')
    p = at[0x1B7CE]['operand_facts'][0]
    require(p['memory'] and p['access'] == 'memory_read' and p['width_bytes'] == 1
            and p['base_register'] == 'A0' and p['indexed'] and
            p['index_register'] == 'D0' and p['index_width_bytes'] == 2,
            'orientation table read differs')
    angle_effects.update(entry_runtime=0x1B780, end_runtime=0x1B7E4,
                         accepted_instructions=len(angle), table_index_unconditionally_bounded=False,
                         reason='WORD negation and signed BLT are retained; no zero-extension/index premise inferred')
    # Pin the concrete signed-WORD activation -> stored offset -> update receiver.
    for pc, name, reg, width in ((0x2DE7E, 'mulu', 'D1', 2),
                                (0x2DE88, 'adda', 'A6', 2),
                                (0x2E912, 'adda', 'A5', 2)):
        require(at[pc]['mnemonic'] == name, 'saved offset operation differs')
        operand(at[pc], 1, register=reg, width=width)
    require(at[0x2DE7E]['operand_facts'][0]['immediate_value'] == 20,
            'activation stride differs')
    operand(at[0x2DE88], 0, register='D1'); operand(at[0x2E912], 0, register='D0')
    operand(at[0x2DE8A], 0, register='D1'); operand(at[0x2DE8A], 1, address=SAVED[0])
    operand(at[0x2E90C], 0, address=SAVED[0]); operand(at[0x2E90C], 1, register='D0')
    for pc, reg, address in ((0x2DE82, 'A6', 0x4E818), (0x2DEE6, 'A6', 0x2B994),
                             (0x2DF08, 'A6', 0x4ED18), (0x2E8FC, 'A6', 0x4E818)):
        require(at[pc]['mnemonic'] == 'lea', 'saved offset receiver root differs')
        operand(at[pc], 0, address=address, width=4); operand(at[pc], 1, register=reg, width=4)
    require(at[0x2E902]['mnemonic'] == 'lea', 'update receiver copy differs')
    p = at[0x2E902]['operand_facts'][0]
    require(p['base_register'] == 'A6' and p['displacement'] == 0 and not p['indexed'],
            'update receiver no longer shares state root')
    operand(at[0x2E902], 1, register='A5', width=4)
    operand(at[0x2DE78], 0, address=0x4F218); operand(at[0x2DE78], 1, register='D1')
    operand(at[0x2DEEC], 0, register='D1'); operand(at[0x2DEEC], 1, register='D0')
    require(at[0x2DEEE]['mnemonic'] == 'lsr' and
            at[0x2DEEE]['operand_facts'][0]['immediate_value'] == 1,
            'orientation half-offset differs')
    operand(at[0x2DEEE], 1, register='D0')
    for pc, reg in ((0x2DEF0, 'D0'), (0x2DF0E, 'D1')):
        require(at[pc]['mnemonic'] == 'adda', 'activation index addition differs')
        operand(at[pc], 0, register=reg); operand(at[pc], 1, register='A6')
    activation = window(rows, 0x2DE78, 0x2DF30)
    require(not any(r['mnemonic'] in ('jsr', 'bsr', 'jmp') for r in activation),
            'activation prefix acquired callee effects')
    # Check all actual writes, including postincrements, before accepting view envelopes.
    expected = [(0x2DE8A, None, 0, 2, 0),
        *((pc, 'A6', off, width, 0) for pc, off, width in (
            (0x2DE90, 6, 2), (0x2DE98, 8, 2), (0x2DEA0, 10, 2),
            (0x2DEA8, 0, 2), (0x2DEAE, 4, 2), (0x2DECA, 8, 2),
            (0x2DED0, 2, 2), (0x2DED4, 16, 4), (0x2DEDC, 12, 2), (0x2DEE0, 14, 2),
            (0x2DEF2, 0, 2), (0x2DEF4, 2, 2), (0x2DEF8, 4, 2),
            (0x2DEFC, 6, 2), (0x2DF02, 8, 2))),
        (0x2DF10, 'A6', 0, 4, 1), (0x2DF12, 'A6', 0, 2, 1),
        (0x2DF14, 'A6', 0, 2, 1), (0x2DF18, 'A6', 0, 4, 1),
        (0x2DF1A, 'A6', 0, 4, 0), (0x2DF1C, None, 0, 2, 0),
        (0x2DF24, None, 0, 1, 0), (0x2DF2A, None, 0, 2, 0)]
    actual = [(r['source_offset'] + 2048, p['base_register'], p['displacement'],
               p['width_bytes'], p['ea_update']) for r in activation for p in r['operand_facts']
              if p.get('memory') and 'write' in p.get('access', '')]
    require(actual == expected, 'activation write widths or cursors differ')
    # No D1 write between its product and use as action displacement.
    require(not any(p.get('direct_register') == 'D1' and not p.get('memory')
                    and 'write' in p.get('access', '')
                    for r in window(rows, 0x2DE82, 0x2DF10) for p in r['operand_facts']),
            'saved product is clobbered')
    for pc, off in ((0x2DF1C, 0x4E6A2), (0x2DF24, 0x4E6A0), (0x2DF2A, 0x4F218)):
        operand(at[pc], len(at[pc]['operand_facts']) - 1, address=off,
                width=1 if pc == 0x2DF24 else 2)
    a6_writes = [r['source_offset'] + 2048 for r in activation
                 if any(p.get('direct_register') == 'A6' and not p.get('memory')
                        and 'write' in p.get('access', '') for p in r['operand_facts'])]
    require(a6_writes == [0x2DE82, 0x2DE88, 0x2DEE6, 0x2DEF0, 0x2DF08, 0x2DF0E],
            'activation receiver has another register writer')
    operand(at[0x4AEA6], 0, register='D7'); operand(at[0x4AEA6], 1, address=COUNT[0])
    require((0x4AEAC, 0xE6E8) in links, 'scenery count-to-draw call differs')
    direct_count = []
    for r in rows:
        for p in r['operand_facts']:
            if (p.get('absolute_address') is not None and p.get('memory') and
                    'write' in p.get('access', '') and not p.get('bulk_transfer') and
                    not p.get('indexed') and not p.get('base_register') and
                    intersects((p['absolute_address'], p['absolute_address'] + p['width_bytes']), COUNT)):
                require(r['mnemonic'] == 'move', 'count writer is not the original store')
                operand(r, 0, register='D7')
                direct_count.append({'runtime': r['source_offset'] + 2048,
                                     'width': p['width_bytes'], 'address': p['absolute_address']})
    require({x['runtime'] for x in direct_count} ==
            {0xF0E, 0xC646, 0x2C00A, 0x2C286, 0x47544, 0x49BCA, 0x49CAE, 0x4AEA6}
            and len(direct_count) == 8 and all(x['width'] == 2 for x in direct_count),
            'known count-writer protocol differs')
    roots = sorted({int.from_bytes(data[i-2048:i-2048+4], 'big') - 2048
                    for i in range(0x4A002, 0x4A026, 4)})
    callbacks = [{'runtime': root + 2048, **reachable_write_inventory(rows, analysis, [root], spans={
                     'count_word': COUNT, 'backup_prefix': BACKUP, 'saved_offset': SAVED,
                     'packed_prefix': (0xE816, 0xE8D6),
                     'scenery_callback_cells': (0x4A002, 0x4A026)})}
                 for root in roots]
    draw_roots = {r['offset'] for r in analysis['code_start_refs']
                  if r.get('source_offset') == 0xE80E - 2048}
    require(len(draw_roots) == 43, 'accepted draw target subset differs')
    accepted_union = reachable_write_inventory(rows, analysis, draw_roots, spans={
        'count_word': COUNT, 'backup_prefix': BACKUP, 'saved_offset': SAVED,
        'packed_prefix': (0xE816, 0xE8D6), 'scenery_callback_cells': (0x4A002, 0x4A026)})
    return {'main_sha256': MAIN_SHA256, 'runtime_executed': False,
            'frustum_rejection': rejected, 'word_ratio_orientation': angle_effects,
            'restricted_scenery_snapshot': {
                'source_count_store': 0x4AEA6, 'draw_call': 0x4AEAC,
                'case': restricted_scenery_snapshot(14, ['reject', 'far']*7, 0),
                'caller_bound_reference': 'foft-scenery-selector-lifetimes.json',
                'all_source_counts_checked': [restricted_scenery_snapshot(n, ['reject']*n)
                                              for n in range(2, 15)],
                'not_a_title_or_general_near_callback_contract': True},
            'far_draw': {'signed_depth': [0x4001, 0x7FFF], 'projection_rows': 1,
                'projection_output_word_addresses': [0x15BD6, 0x15BD8],
                'absolute_quotient_upper_bound': (32768*256)//0x4001,
                'screen_x': [26, 294], 'screen_y': [16, 126],
                'pixel_write_envelopes_by_bank': {str(b): far_pixel_spans(b) for b in (0, 0x8000)},
                'count_backup_saved_offset_excluded_by_explicit_stores': True,
                'conditions': ['Preserved bank offset 0 or 0x8000',
                    'Source reads and ordinary returns complete; stack/call frames do not alias reviewed cells',
                    'No asynchronous/intervening writes'],
                'unconditional_bank_or_full_callback_preservation_proved': False},
            'direct_count_writers': direct_count, 'initial_scenery_callback_paths': callbacks,
            'accepted_draw_target_union': accepted_union, 'writable_target_set_closed': False, 'whole_callback_count_or_backup_preservation': False,
            'backup_source_view': {'runtime': BACKUP[0], 'bytes': 256,
                                   'unit_bytes': 4, 'units': 64, 'allocation_proved': False, 'copy_protocol_rechecked': True},
            'saved_offset_transport': {'entry_runtime': 0x2DE78, 'before_first_call': 0x2DF32,
                'update_load': 0x2E90C, 'update_add': 0x2E912,
                'conditional_source_slots': [0, 63], 'cases_checked': 64,
                'own_prefix_preserves_saved_offset': all(activation_views(n) for n in range(64)),
                'saved_word_equals_original_activation_displacement_if_intact': True,
                'global_slot_bound_intervening_effects_or_regeneration_equality_proved': False}}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('rows', 'analysis', 'member', 'output'):
        p.add_argument('--' + key, type=Path, required=True)
    args = p.parse_args()
    result = check_source(json.loads(args.rows.read_text()), json.loads(args.analysis.read_text()),
                          args.member.read_bytes())
    args.output.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()

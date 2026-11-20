"""Source-checked scenery selector writes and fresh-record lifetime contracts.

Finite address/overwrite proofs only: no guest execution, callback admission,
new memory owner or assertion of asynchronous preservation.
"""
import argparse
import json
from pathlib import Path

from tools.foft_action_ownership_audit import (
    intersects,
    rng_effect_inventory,
    signed_word,
)
from tools.foft_frame_panel_audit import check_source as previous_contracts
from tools.foft_irq_write_audit import require
from tools.foft_render_contract_audit import operand, scenery_probe_crosswalk, window

PAGE_ROOTS = (0x4DBAC, 0x4DCAC, 0x4DDAC, 0x4DEAC)
CRITICAL = {'packed_views': (0xE816, 0xE8D6), 'draw_backup': (0xEB16, 0xEC16),
            'callback_cells': (0x4A002, 0x4A026), 'view_count': (0x4E726, 0x4E728),
            'saved_deployment_offset': (0x4E6A4, 0x4E6A6),
            'frozen_object_producer_count': (0x2F094, 0x2F096)}


def cell_offset(position):
    require(type(position) is int and 0 <= position <= 255, 'requires a position BYTE')
    return 32 * (position >> 4) + 2 * (position & 15)


def pattern_delta(incoming_word, key_byte):
    require(type(incoming_word) is int and 0 <= incoming_word <= 65535, 'requires incoming D6 WORD')
    require(type(key_byte) is int and 0 <= key_byte <= 255, 'requires loaded BYTE')
    return signed_word((((incoming_word & 0xFF00) | key_byte) * 8) & 65535)


def descriptor_row(source):
    require(len(source) == 16 and all(type(v) is int and 0 <= v <= 65535 for v in source),
            'requires sixteen source WORDs')
    return [0 if col in (0, 15) or value == 0 else ((value << 8) & 0xF00) | 10 * col
            for col, value in enumerate(source)]


def probe_write_lifetime(old_count, probe, new_count):
    require(type(old_count) is int and 1 <= old_count <= 14, 'requires fresh bounded old count')
    require(type(probe) is int and 0 <= probe < old_count, 'requires a bounded probe')
    require(type(new_count) is int and 0 <= new_count <= 14, 'requires fresh bounded new count')
    gate = scenery_probe_crosswalk(old_count)[probe]['reads'][-1]
    start = gate['byte_offset']
    return {'write_byte_offset': start, 'producer_row': gate['producer_row'],
            'producer_field': gate['producer_field'], 'overwritten_by_next_prefix': start + 2 <= 12 * new_count,
            'outside_next_prefix_is_cleared': False}


def check_source(rows, analysis, data):
    prior = previous_contracts(rows, analysis, data)
    at = {r['source_offset'] + 2048: r for r in rows}
    links = {(e['source_offset'] + 2048, e['target_offset'] + 2048)
             for e in analysis['edges'] if e.get('target_offset', -1) >= 0}
    rng = rng_effect_inventory(window(rows, 0x1B3CA, 0x1B420))
    require(rng['explicit_register_writes'] == ['D0', 'D1'], 'RNG preservation differs')
    # Exact reader widths: the BYTE load does not zero-extend the WORD index.
    operand(at[0x4A0A8], 1, register='D6', width=1)
    require(at[0x4A0A8]['mnemonic'] == 'move', 'pattern key load differs')
    operand(at[0x4A0A8], 0, width=1)
    for pc in (0x4A0E0, 0x4A0E2, 0x4A0E4):
        require(at[pc]['mnemonic'] == 'add', 'pattern scaling differs')
        operand(at[pc], 0, register='D6'); operand(at[pc], 1, register='D6')
    operand(at[0x4A0E6], 0, register='D6'); operand(at[0x4A0E6], 1, register='A1')
    require([r['mnemonic'] for r in window(rows, 0x4A0D4, 0x4A0E8)] ==
            ['lea', 'bsr', 'lea', 'lea', 'add', 'add', 'add', 'adda'], 'pattern path differs')
    require((0x4A0D6, 0x4A112) in links, 'page clear call differs')
    for pc, value in ((0x4A0F8, 15), (0x4A0FE, 15), (0x4A104, 240)):
        require(at[pc]['mnemonic'] == 'andi' and at[pc]['operand_facts'][0]['immediate_value'] == value,
                'placement masks differ')
        require(at[pc]['operand_facts'][0]['width_bytes'] == 2, 'placement mask width differs')
    store = at[0x4A10C]['operand_facts'][1]
    require(store['memory'] and store['base_register'] == 'A0' and store['indexed']
            and store['index_register'] == 'D5' and store['width_bytes'] == 2, 'cell store differs')
    operand(at[0x4A112], 1, register='D5', width=4)
    require(at[0x4A112]['operand_facts'][0]['immediate_value'] == 63, 'page clear count differs')
    require(at[0x4A114]['mnemonic'] == 'clr', 'page clear write differs')
    require(at[0x4A114]['operand_facts'][0]['width_bytes'] == 4, 'page clear width differs')
    page_body = window(rows, 0x4A096, 0x4A11C)
    writes = [(r['source_offset'] + 2048, p) for r in page_body for p in r['operand_facts']
              if p.get('memory') and 'write' in p.get('access', '')]
    require([pc for pc, _ in writes] == [0x4A10C, 0x4A114], 'selector acquired another explicit writer')
    require(writes[1][1]['base_register'] == 'A0' and writes[1][1]['ea_update'] == 1,
            'page clear cursor differs')
    ordered = {r['source_offset']: i for i, r in enumerate(rows)}
    roots = []
    for ref in analysis['code_start_refs']:
        if ref['offset'] != 0x4A096 - 2048 or ref.get('source_offset') not in ordered:
            continue
        index = ordered[ref['source_offset']]
        pre = rows[index-2:index]
        require(rows[index]['mnemonic'] == 'bsr' and
                sorted(r['mnemonic'] for r in pre) == ['lea', 'move'], 'page caller prefix differs')
        lea = next(r for r in pre if r['mnemonic'] == 'lea')
        move = next(r for r in pre if r['mnemonic'] == 'move')
        operand(lea, 1, register='A0', width=4); operand(move, 1, register='D0')
        matches = []
        for root in PAGE_ROOTS:
            field = lea['operand_facts'][0]
            if field.get('pc_relative'):
                if (field.get('width_bytes') == 4 and field.get('displacement_known')
                        and field['displacement'] == root - (lea['source_offset'] + 2048 + 2)):
                    matches.append(root)
            else:
                try:
                    operand(lea, 0, address=root, width=4)
                    matches.append(root)
                except ValueError:
                    pass
        require(len(matches) == 1, 'page caller lost its exact fixed root')
        roots.append({'call_runtime': ref['source_offset'] + 2048, 'page_root_runtime': matches[0]})
    require(len(roots) == 10, 'ordinary selector page caller set differs')
    # A BYTE key can inherit the completed height builder's DBF result.
    height = window(rows, 0x4BC4E, 0x4BFF4)
    d6_writes = [r for r in height if any(p.get('direct_register') == 'D6'
                 and not p.get('memory') and 'write' in p.get('access', '') for p in r['operand_facts'])]
    require(d6_writes and all(r['mnemonic'] in ('moveq', 'dbf') for r in d6_writes),
            'height D6 writers differ')
    require(all(r['operand_facts'][0].get('immediate_value') in (0, 15)
                for r in d6_writes if r['mnemonic'] == 'moveq'), 'height D6 initialization differs')
    require(at[0x4BCFA]['mnemonic'] == 'moveq' and
            at[0x4BCFA]['operand_facts'][0]['immediate_value'] == 0, 'zero-mask D6 result differs')
    transfer_pairs = [(0x4CDD8, 0x4CDE6), (0x4CF00, 0x4CF0E), (0x4D02A, 0x4D038)]
    for source, target in transfer_pairs:
        require((source, 0x4BC4E) in links and (target, 0x4A096) in links,
                'height-to-selector calls differ')
        middle = window(rows, source + at[source]['size'], target)
        require(sorted(r['mnemonic'] for r in middle) == ['lea', 'move'],
                'height-to-selector transfer acquired an effect')
        require(not any(p.get('direct_register') == 'D6' and 'write' in p.get('access', '')
                        for r in middle for p in r['operand_facts']), 'height D6 is not carried')
    # Positive producer bound and complete overwrite, not a global count cap.
    require(at[0x4DA4C]['mnemonic'] == 'clr', 'descriptor clear differs')
    for pc, target in ((0x4DA50, 0x4DA66), (0x4DA56, 0x4DA66), (0x4DA5A, 0x4DA66)):
        require((pc, target) in links, 'descriptor edge skip differs')
    require(at[0x4DA52]['operand_facts'][0]['immediate_value'] == 15 and
            at[0x4DA58]['mnemonic'] == 'tst', 'descriptor edge tests differ')
    require(at[0x4AE4A]['mnemonic'] == 'clr' and at[0x4AE4A]['operand_facts'][0]['width_bytes'] == 2,
            'fresh view tail clear differs')
    # No culler tail write: XYZ updates and whole-row movement preserve zero tails.
    culler = window(rows, 0xE564, 0xE6E4)
    for r in culler:
        require(r['mnemonic'] not in ('jsr', 'bsr', 'jmp'), 'culler acquired a call')
        for p in r['operand_facts']:
            if not p.get('memory') or 'write' not in p.get('access', '') or p.get('base_register') != 'A0':
                continue
            d = p.get('displacement'); w = p.get('width_bytes')
            require((w == 2 and d in (0, 2, 4)) or (w == 4 and d in (0, 4, 8)), 'culler row write differs')
    pattern_root = at[0x4A0DC]['operand_facts'][0]
    require(pattern_root.get('pc_relative') and pattern_root.get('displacement_known')
            and pattern_root['displacement'] == 0x4A066 - (0x4A0DC + 2), 'nominal pattern root differs')
    # Conditional same-cell page shifts, not a new data owner or live case.
    code_bytes = {r['source_offset'] + 2048 + i for r in rows for i in range(r['size'])}
    conditional_reads = []
    for kind in range(28, 32):
        control = data[0x4A026 + 2*kind - 2048:0x4A028 + 2*kind - 2048]
        shape = int.from_bytes(data[0x4C2F4 + 4*kind - 2048:0x4C2F6 + 4*kind - 2048], 'big', signed=True)
        require(control[0] == 255 and shape == -(kind - 23), 'conditional source controls differ')
        source = 0x4A066 + pattern_delta(0xFFFF, control[1])
        require(all(source + i in code_bytes for i in range(8)), 'conditional read lost its code ownership')
        pairs = [data[source + i - 2048:source + i + 2 - 2048] for i in range(0, 8, 2)]
        conditional_reads.append({'kind': kind, 'requires_completed_height_template_and_preserved_kind_cell': True,
            'source_runtime': source, 'source_remains_accepted_instruction_bytes': True,
            'cell_write_offsets': [cell_offset(pair[1]) for pair in pairs],
            'stored_selector_words': [pair[0] & 15 for pair in pairs],
            'following_D6_word': 2 * (pairs[-1][1] & 240), 'runtime_observed': False})
    # Initial source tables are bounded views, not promises about live contents.
    read = lambda lo, hi: data[lo-2048:hi-2048]
    variants = [read(i, i+6) for i in range(0x49F42, 0x4A002, 6)]
    require(len(variants) == 32 and max(v[0] for v in variants) == 4, 'initial variant records differ')
    require(all(v[0] <= 4 and all(x <= 31 for x in v[1:1+v[0]]) for v in variants), 'initial variant choice bounds differ')
    controls = [tuple(read(i, i+2)) for i in range(0x4A026, 0x4A066, 2)]
    require(len(controls) == 32 and max(p for c, p in controls if c == 255) == 5, 'nominal pattern keys differ')
    patterns = [tuple(read(i, i+2)) for i in range(0x4A066, 0x4A096, 2)]
    require(len(patterns) == 24 and max(c for c, _ in patterns) == 8, 'initial pattern records differ')
    positions = [p for c, p in controls if c not in (0, 255)] + [p for _, p in patterns]
    require(max(map(cell_offset, positions)) < 256, 'nominal intact position table leaves low page')
    envelopes = []
    for root in PAGE_ROOTS:
        span = (root, root + max(cell_offset(p) + 2 for p in range(256)))
        require(all(not intersects(span, region) for region in CRITICAL.values()), 'selector write intersects critical storage')
        envelopes.append({'root_runtime': root, 'clear_and_copy_bytes': 256, 'masked_cell_write_view': list(span),
                          'allocation_extent_inferred': False})
    windows = [(0x49D0A, 0x49F32), (0x4A096, 0x4A11C), (0x4D9F8, 0x4DAAA),
               (0x4ADC2, 0x4AF80), (0x4BC4E, 0x4BFF4), (0xE564, 0xE6E4), (0xE6E8, 0xE816)]
    return {'main_sha256': prior['main_sha256'], 'runtime_executed': False,
            'accepted_instructions_checked': sum(len(window(rows, lo, hi)) for lo, hi in windows),
            'windows': [{'start_runtime': lo, 'end_runtime': hi} for lo, hi in windows],
            'selector_page_envelopes': envelopes, 'ordinary_page_call_roots': roots,
            'height_to_selector_transfer_pairs': [list(p) for p in transfer_pairs],
            'nonintersection_scope': 'fixed page roots and explicit writes only; intact stack, normal RNG returns, no IRQ or unknown-caller closure', 'critical_regions_excluded': {k: list(v) for k, v in CRITICAL.items()},
            'pattern_key_load_width': 1, 'pattern_index_width': 2,
            'pattern_nominal_delta_requires_inherited_high_byte_multiple_of_32': True,
            'upper_byte_FF_delta_for_key_0_through_5': [pattern_delta(0xFFFF, k) for k in range(6)],
            'pattern_receiver_always_in_nominal_table': False,
            'conditional_original_instruction_byte_reads': conditional_reads,
            'source_views': {'variant_records': 32, 'variant_stride': 6, 'variant_trailing_gap_bytes': 32,
                             'control_records': 32, 'pattern_records': 24, 'placement_stride': 2,
                             'selector_pages': 4, 'cleared_words_per_page': 128, 'kind_pool_words': 8,
                             'view_bytes': 1344, 'typed_field_bytes': 1312, 'last_page_following_unknown_bytes': 256},
            'fresh_descriptor_row_max_nonempty': 14, 'conditional_backup_bytes_max': 224,
            'fresh_cull_marker_words_zero_under_preservation': True,
            'probe_write_is_not_back_projected_to_source_descriptors': True,
            'post_draw_count_buffer_callback_or_irq_preservation_proved': False,
            'new_native_receiver_or_code_admission': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('rows', 'analysis', 'member', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    result = check_source(json.loads(args.rows.read_text()), json.loads(args.analysis.read_text()), args.member.read_bytes())
    args.output.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()

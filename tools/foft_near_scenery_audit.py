"""Accepted-source store cover for the eight initial scenery callback bodies.

No guest execution, target admission, alternate CFG solver or native effect
fact is produced. CPU envelopes, programmed DMA rectangles and actual device
lifetime deliberately remain different claims.
"""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from amiga_reversing.disasm.projected_face_audit import audit_face_views
from tools.foft_action_ownership_audit import intersects
from tools.foft_draw_lifetime_audit import check_source as return_contract
from tools.foft_irq_write_audit import reachable_write_inventory, require
from tools.foft_render_contract_audit import operand, window

SPECS = ((2, 0x274F4, 0x27A48, 18, 230), (1, 0x27B20, 0x27D0A, 12, 120),
         (7, 0x27D9C, 0x28006, 10, 120), (3, 0x28080, 0x28352, 13, 170),
         (0, 0x283FC, 0x2895A, 16, 230), (4, 0x28A1E, 0x28CCC, 17, 200),
         (5, 0x28D9A, 0x29236, 18, 230), (6, 0x29318, 0x29656, 13, 190))
PROTECTED = {'count': (0x4E726, 0x4E728), 'view_snapshot': (0xE816, 0xE916),
             'draw_backup': (0xEB16, 0xEC16), 'work_backup': (0x4AF80, 0x4BC00),
             'descriptor_cursor': (0x4BC00, 0x4BC04),
             'descriptors': (0x4DAAC, 0x4DBAC), 'draw_bank': (0x16E2, 0x16E6),
             'glyph_cycle_word': (0x49B66, 0x49B68),
             'near_point_word':(0x4E2BA,0x4E2BC),
             'saved_deployment_offset':(0x4E6A4,0x4E6A6),
             'frozen_action_count':(0x2F094,0x2F096),
             'callback_cells': (0x4A002, 0x4A026), 'span_table': (0x186F4, 0x190F4)}


def chain_indices(ys, direction):
    """Bounded circular copy model for a stable 3..6-point source, not a CPU."""
    require(3 <= len(ys) <= 6 and all(type(y) is int and -32768 <= y <= 32767 for y in ys),
            'requires stable three-to-six WORD points')
    require(direction in (-1, 1), 'requires chain direction')
    start = max(i for i, y in enumerate(ys) if y == min(ys))
    indices = [start]
    current = (start + direction) % len(ys)
    while ys[current] != max(ys):
        indices.append(current)
        require(len(indices) < len(ys), 'chain has not reached computed maximum')
        current = (current + direction) % len(ys)
    indices.append(current)
    return indices


def edge_envelope(minimum, last, side):
    require(type(minimum) is int and type(last) is int and -32768 <= minimum <= last
            and 15 <= last <= 127 and minimum <= 127 and side in (0, 1),
            'requires admitted raster Y bounds and edge side')
    rows = max(1, last - max(15, minimum) + 1)
    return [0x16110 + 2*side, 0x16110 + 2*side + 4*(rows-1) + 2]


def mask_rectangle(left, right, top, bottom, bank):
    require(all(type(v) is int for v in (left, right, top, bottom, bank)) and
            25 <= left <= right <= 294 and 15 <= top <= bottom <= 127 and bank in (0, 0x8000),
            'requires clipped rectangle and preserved canonical bank')
    offset = 2*(left//16)
    width = 2*((right-left)//16+2)
    mask = [0x16458 + 40*top + offset, 0x16458 + 40*bottom + offset + width]
    planes = [[0x70000 + bank + p + 40*top + offset,
               0x70000 + bank + p + 40*bottom + offset + width]
              for p in (0, 0x2000, 0x4000, 0x6000)]
    return {'programmed_mask_and_cleanup': mask, 'programmed_planes': planes,
            'rows': bottom-top+1, 'words_per_row': width//2,
            'actual_dma_quiescence_or_visibility_proved': False}


def store_domain(site, geometry):
    """All nonconstant domains require the source witnesses checked below."""
    p = site['operand']; pc = site['runtime']; width = p['width_bytes']
    require(width in (1, 2, 4), 'unexpected write width')
    base, indexed = p.get('base_register'), p.get('indexed')
    if base == 'A7':
        require(not indexed and p.get('ea_update') == 2, 'unexpected stack destination')
        return 'nonaliasing_stack_premise', None
    address = p.get('absolute_address')
    if address is not None and not base and not indexed and not p.get('bulk_transfer'):
        return 'fixed_cpu_store', [address, address+width]
    require(not p.get('bulk_transfer'), 'uncovered bulk destination')
    if pc in geometry:
        require(base == 'A1' and not indexed and width == 2 and not p['ea_update'],
                'geometry destination differs')
        return 'fixed_projection_geometry', geometry[pc]
    classes = {
        'reverse_projection': ({0xB3F8, 0xB40E, 0xFD56, 0xFD6A}, 'A0', True, (0x15BD0, 0x15CC0), 2),
        'signed_scales': ({0xEEA2, 0xEEA6}, 'A0', True, (0xEEB0, 0xEFAC), 2),
        'raster_state': ({0x15E76, 0x15F20, 0x15F2E, 0x15F3C, 0x15F6E, 0x15F7C,
                          0x15FE8, 0x15FEC}, 'A5', False, (0x1857E, 0x1858C), None),
        'forward_chain': ({0x15EF0, 0x15EF2, 0x15F00, 0x15F02}, 'A0', False, (0x16090, 0x160A8), 2),
        'reverse_chain': ({0x15F08, 0x15F0A, 0x15F1C, 0x15F1E}, 'A0', False, (0x160D0, 0x160E8), 2),
        'paired_edges': ({0x15FFC, 0x16040, 0x16056, 0x16072, 0x1608A}, 'A1', False, (0x16110, 0x162D4), 2),
        'clipped_cpu_mask': ({0x15FC4, 0x15FC8, 0x15FD0, 0x15FD6}, 'A0', False, (0x166B2, 0x17856), 2),
        'face_points': ({0x1988E, 0x19894}, 'A2', True, (0x1858C, 0x185A4), 2),
        'optional_projection_input': ({0x27560, 0x27566, 0x2756E, 0x2844E, 0x28454, 0x2845C},
                                      'A0', False, (0x15BD0, 0x15BD6), 2),
        'audio_registers': ({0x4F362, 0x4F368}, 'A6', False, (0xDFF000, 0xE00000), 2),
        'audio_indexed_registers': ({0x4F374, 0x4F376, 0x4F37C, 0x4F388}, 'A2', False,
                                  (0xDFF000-32768, 0xDFF000+32767+10), None),
        'audio_software': ({0x4F382, 0x4F38E}, 'A1', False, (0x4F336, 0x4F356), 2),
    }
    for name, (sites, reg, index, domain, required_width) in classes.items():
        if pc in sites:
            require(base == reg and bool(indexed) == index and
                    (required_width is None or required_width == width), 'writer shape differs')
            if name == 'raster_state':
                require(p['displacement'] >= 0 and p['displacement']+width <= 14 and not p['ea_update'],
                        'raster state field escaped owner')
            elif name == 'audio_software':
                require(p['displacement'] in (6, 10) and not p['ea_update'], 'sound state field differs')
            elif name == 'optional_projection_input':
                require(p['displacement'] in (0, 2, 4) and not p['ea_update'], 'optional projection field differs')
            elif name == 'audio_indexed_registers':
                require((p['displacement'],width) in ((0,4),(4,2),(6,2),(8,2)) and not p['ea_update'],
                        'sound register field differs')
            elif name == 'audio_registers':
                require(p['displacement'] in (0x96, 0x9A), 'sound control register differs')
            elif name in ('face_points', 'signed_scales', 'reverse_projection'):
                expected = {'face_points': ('D6',(0,2)), 'signed_scales': ('D1',(0,14)),
                            'reverse_projection': ('D0',(0,2,6,8))}[name]
                require(p['index_register']==expected[0] and p['index_width_bytes']==2
                        and p['displacement'] in expected[1] and not p['ea_update'],
                        'indexed writer field differs')
            else:
                require(p['displacement']==0 and p['ea_update'] in (0,1), 'cursor writer field differs')
            return name, list(domain)
    raise ValueError(f'uncovered writer at ${pc:X}; no domain may be assumed')



def glyph_cycle(value):
    require(type(value) is int and 0 <= value <= 65535, 'requires glyph WORD')
    following = (value+2) & 65535
    signed = following-65536 if following & 32768 else following
    return 49 if signed > 55 else following


def cover_stores(sites, geometry, protected):
    require(len({(s['runtime'],s['operand_index'])for s in sites})==len(sites),
            'duplicate write-site identity')
    coverage=[];counts=Counter()
    for site in sites:
        require(site['operand'].get('memory'), 'write site is not a memory operand')
        name,span=store_domain(site,geometry)
        if span:
            require(not any(intersects(span,target)for target in protected.values()),
                    f'CPU domain {name} intersects protected state')
        counts[name]+=1
        coverage.append({'runtime':site['runtime'],'operand_index':site['operand_index'],
                         'domain':name,'byte_envelope':span})
    return coverage,dict(counts)


def exclude_accepted_code(coverage, code_spans):
    for site in coverage:
        span=site['byte_envelope']
        if span:
            require(not any(intersects(span,code)for code in code_spans),
                    'covered CPU store intersects accepted code')
    return True

def check_source(rows, analysis, data):
    previous = return_contract(rows, analysis, data)
    at = {r['source_offset']+2048: r for r in rows}
    order = {r['source_offset']+2048: i for i, r in enumerate(rows)}
    geometry = {}; faces = []; protocol_calls = []
    for index, entry, start, count, maximum in SPECS:
        body = window(rows, entry, start)
        tail=body[-5:]
        require([r['mnemonic']for r in tail] in
                (['move','jsr','moveq','lea','jmp'],['moveq','jsr','moveq','lea','jmp']),
                'model face-tail protocol differs')
        require(tail[0]['operand_facts'][0]['immediate_value']==maximum and
                tail[2]['operand_facts'][0]['immediate_value']==count-1,
                'model face/projection counts differ')
        operand(tail[1],0,address=0xFD3E,width=4)
        operand(tail[-1],0,address=0x19824,width=4)
        p=tail[3]['operand_facts'][0];pc=tail[3]['source_offset']+2048
        if p['pc_relative']:require(p['displacement']==start-pc-2,'face source root differs')
        else:operand(tail[3],0,address=start,width=4)
        operand(tail[3],1,register='A0',width=4)
        cursor = start
        for _ in range(count):
            vertices = int.from_bytes(data[cursor-2046:cursor-2044], 'big')
            require(vertices in (3, 4, 6), 'original face count differs')
            cursor += 4+2*vertices
        audit_face_views(data, load_address=2048, views=[{
            'start_runtime': start, 'end_runtime': cursor, 'face_count': count,
            'projection_max_byte_offset': maximum}], projection_stride=10, style_count=32)
        faces.append({'variant': index, 'span': [start, cursor], 'faces': count,
                      'last_projection_offset': maximum, 'source_points_at_most': 6})
        stores = [r for r in body if any(p.get('memory') and 'write' in p['access'] and
                                       p.get('base_register') == 'A1' for p in r['operand_facts'])]
        require(stores, 'model geometry is missing')
        roots = [r for r in body if r['mnemonic'] == 'lea' and
                 r['operand_facts'][1].get('direct_register') == 'A1' and
                 r['source_offset'] < stores[0]['source_offset']]
        require(roots, 'model geometry root is missing')
        root = roots[-1]; operand(root, 0, address=0x15BD0, width=4)
        segment = window(rows, root['source_offset']+2048+root['size'],
                         stores[-1]['source_offset']+2048+stores[-1]['size'])
        require(not any(r['mnemonic'] in ('jsr', 'bsr', 'jmp', 'bra') for r in segment),
                'geometry root crosses a call/transfer')
        require(not any(p.get('direct_register') == 'A1' and 'write' in p['access']
                        for r in segment for p in r['operand_facts']), 'geometry root is clobbered')
        for r in stores:
            for p in r['operand_facts']:
                if not (p.get('memory') and 'write' in p['access']): continue
                d = p['displacement']
                require(p['base_register'] == 'A1' and not p['indexed'] and not p['ea_update']
                        and p['width_bytes'] == 2 and 0 <= d <= maximum+4
                        and d % 10 in (0, 2, 4), 'geometry WORD view differs')
                geometry[r['source_offset']+2048] = [0x15BD0+d, 0x15BD2+d]
        for r in body:
            if r['mnemonic'] not in ('jsr', 'bsr'): continue
            target = r['operand_facts'][0].get('absolute_address')
            if target not in (0xFD3E, 0xB3E0): continue
            pre = rows[order[r['source_offset']+2048]-1]
            if pre['mnemonic'] == 'clr':
                operand(pre, 0, register='D0'); value = 0
            else:
                operand(pre, 1, register='D0', width=4 if pre['mnemonic']=='moveq' else 2)
                value = pre['operand_facts'][0]['immediate_value']
            require(value in (0, maximum) and value % 10 == 0 and value <= 230,
                    'projection/index caller premise differs')
            protocol_calls.append({'runtime': r['source_offset']+2048, 'target': target, 'last_offset': value})
    require(len(protocol_calls) == 18, 'model projection caller coverage differs')
    operand(at[0xB3E0],0,address=0x15BD0,width=4)
    require(at[0xB412]['mnemonic']=='subi' and
            at[0xB412]['operand_facts'][0]['immediate_value']==10,
            'reverse projection row step differs')
    for reg, expected in (('A0',[0xB3E0]),('D0',[0xB412])):
        require([r['source_offset']+2048 for r in window(rows,0xB3E0,0xB41A)
                 if any(p.get('direct_register')==reg and 'write'in p['access']
                        for p in r['operand_facts'])]==expected,'reverse projection cursor clobbered')
    for pc in (0x2755A,0x28448):operand(at[pc],0,address=0x15BD0,width=4)
    # Existing scaler writer: exactly seven WORD pairs per 28-byte block.
    scale = window(rows, 0xEE96, 0xEEB0)
    require(scale[0]['operand_facts'][0]['immediate_value'] == 12 and
            at[0xEEAA]['operand_facts'][0]['immediate_value'] == 2 and
            at[0xEEAC]['mnemonic'] == 'bpl', 'signed-scale counter differs')
    require(not any(p.get('direct_register') in ('A0', 'A2') and 'write' in p['access']
                    for r in scale for p in r['operand_facts']), 'scale writer changes root')
    operand(at[0xEE18], 0, address=0xEEB0, width=4)
    for pc, base, displacement in ((0xEE2A,'A0',84),(0xEE38,'A0',84),(0xEE46,'A2',28),
        (0xEE54,'A0',84),(0xEE62,'A0',84),(0xEE70,'A2',56),(0xEE7E,'A0',84),(0xEE8C,'A0',84)):
        p=at[pc]['operand_facts'][0]
        require(at[pc]['mnemonic']=='lea' and p['base_register']==base and not p['indexed']
                and p['displacement']==displacement,'scale block permutation differs')
        operand(at[pc],1,register='A0',width=4)
    operand(at[0xEE1E],1,register='A2',width=4)
    require(at[0xEE1E]['operand_facts'][0]['base_register']=='A0','scale root cache differs')
    init=window(rows,0x190F4,0x1912E)
    require(init[0]['operand_facts'][0]['immediate_value']==0 and
            at[0x19106]['operand_facts'][0]['immediate_value']==3 and
            at[0x19108]['operand_facts'][0]['immediate_value']==65534 and
            at[0x19126]['operand_facts'][0]['immediate_value']==320,
            'span-offset initializer formula differs')
    operand(at[0x190F6],0,address=0x186F4,width=4)
    for pc in (0x1910C,0x1910E,0x19110):
        p=at[pc]['operand_facts'][1]
        require(p['memory'] and p['base_register']=='A0' and p['ea_update']==1 and
                p['width_bytes']==2,'span initializer write cursor differs')
    require(at[0x19112]['operand_facts'][0]['immediate_value']==2,'span initializer gap differs')
    # Raster cached root is fixed; min/max source and clipping remain exact.
    for pc, reg, root in ((0x15E60, 'A4', 0x1858C), (0x15E64, 'A5', 0x1857E),
                           (0x1982A, 'A2', 0x1858C)):
        row = at[pc]; p = row['operand_facts'][0]
        if p.get('pc_relative'):
            require(p['width_bytes'] == 4 and not p['indexed'] and p['displacement_known']
                    and p['displacement'] == root-pc-2, 'PC-relative raster root differs')
        else: operand(row, 0, address=root, width=4)
        operand(row, 1, register=reg, width=4)
    for pc, value in ((0x15EB2, 127), (0x15EBA, 15), (0x15F24, 127),
                       (0x15F6A, 15), (0x15F32, 40), (0x15F36, 0x16458),
                       (0x15F72, 40), (0x15F76, 0x16458)):
        require(at[pc]['operand_facts'][0]['immediate_value'] == value, 'raster bound/root differs')
    require([r['source_offset']+2048 for r in window(rows,0x15E60,0x16090)
             if any(p.get('direct_register')=='A5' and 'write'in p['access']
                    for p in r['operand_facts'])]==[0x15E64], 'raster state root is clobbered')
    require(at[0x1986E]['mnemonic']=='moveq' and
            at[0x1986E]['operand_facts'][0]['immediate_value']==0 and
            at[0x1989A]['operand_facts'][0]['immediate_value']==4,
            'collected point cursor differs')
    # Initial and endpoint writes do not advance A1. Row writes step four and
    # test the incremented D2 against last<=127 before another endpoint store.
    edge = window(rows, 0x15FF4, 0x16090)
    d2 = [r['source_offset']+2048 for r in edge if any(
        p.get('direct_register') == 'D2' and 'write' in p['access'] for p in r['operand_facts'])]
    require(d2 == [0x15FF8, 0x16044, 0x16076], 'edge row counter writers differ')
    require(at[0x15FF4]['operand_facts'][0]['immediate_value'] == 15, 'edge top clip differs')
    for pc in (0x16044, 0x16076):
        require(at[pc]['mnemonic'] == 'addq' and at[pc]['operand_facts'][0]['immediate_value'] == 1,
                'edge row step differs')
    # Sound A1 roots and A2 custom-derived receiver; table values are read data.
    operand(at[0x4F356], 0, address=0xDFF000, width=4)
    operand(at[0x4F356], 1, register='A6', width=4)
    require(at[0x4F370]['operand_facts'][0]['base_register'] == 'A6' and
            at[0x4F370]['operand_facts'][0]['index_register'] == 'D0' and
            at[0x4F370]['operand_facts'][0]['index_width_bytes'] == 2, 'sound register root differs')
    for pc, offset, update in ((0x4F382, 10, 0), (0x4F38E, 6, 0)):
        p = at[pc]['operand_facts'][-1]
        require(p['displacement'] == offset and p['ea_update'] == update, 'sound software field differs')
    for pc, root in ((0x4F594,0x4F336),(0x4F5A4,0x4F346)):
        p=at[pc]['operand_facts'][0]
        require(at[pc]['mnemonic']=='lea' and p['pc_relative'] and p['displacement']==root-pc-2,
                'sound software root differs')
        operand(at[pc],1,register='A1',width=4)
    require(at[0x193F8]['mnemonic']=='rts','last line return differs')
    # Pin the decoded literal bus EA, not a symbolic/MMIO type resolution.
    # The native address-evidence conflict is retained below, not cleared or
    # promoted to an interpreted-reference/control fact.
    mmio_conflicts=[]
    for pc in (0x193F0,0x18462):
        p=at[pc]['operand_facts'][1]
        require(p['memory'] and p['access']=='memory_write' and p['absolute_address']==0xDFF058
                and p['width_bytes']==2 and not p['indexed'] and not p['base_register'],
                'literal blit-size store differs')
        if any(e.get('conflicted')for e in at[pc]['address_evidence']if e['operand_index']==1):
            mmio_conflicts.append(pc)
    require(not any(r['mnemonic']in('jsr','bsr')for r in window(rows,0x183A0,0x18468)),
            'first polygon submit gained a local call/wait')
    require(at[0x18468]['mnemonic']=='bsr' and at[0x184F2]['mnemonic']=='btst'
            and at[0x184EC]['mnemonic']=='move','polygon wait ordering differs')
    # Whole fixed-window save/restore and retained-row consumer, using widths,
    # not a new common record type for unrelated layouts.
    work_copies = []
    for r in rows:
        pc = r['source_offset']+2048
        if not (0x4AD80 <= pc < 0x4AF80): continue
        p = r['operand_facts']
        if (r['mnemonic']=='move' and len(p)==2 and all(q.get('memory') and q.get('ea_update')==1
                                                     and q.get('width_bytes')==4 for q in p)):
            work_copies.append(pc)
    require(work_copies == [0x4ADFE,0x4AE00,0x4AF74,0x4AF76], 'work-window LONG-copy coverage differs')
    for pc, value in ((0x4ADFA,399),(0x4AF70,399)):
        require(at[pc]['operand_facts'][0]['immediate_value']==value,'work-window count differs')
    for pc, reg, root in ((0x4ADF0,'A0',0x15BD0),(0x4ADF6,'A1',0x4AF80),
                           (0x4AF66,'A0',0x4AF80),(0x4AF6A,'A1',0x15BD0)):
        p=at[pc]['operand_facts'][0]
        if p['pc_relative']:
            require(p['displacement']==root-pc-2,'work-window relative root differs')
        else: operand(at[pc],0,address=root,width=4)
        operand(at[pc],1,register=reg,width=4)
    for pc, access in ((0x4AE06,'register_list_read'),(0x4AF62,'register_list_write')):
        require(at[pc]['mnemonic']=='movem' and any(p['access']==access and
                set(p['register_list'])=={*(f'D{i}'for i in range(8)),*(f'A{i}'for i in range(7))}
                for p in at[pc]['operand_facts']),'work-window register snapshot differs')
    for pc,address,width in ((0x27594,0x4E2B6,1),(0x28482,0x4E2B6,1),
                             (0x47556,0x4E2B6,2),(0x4759A,0x4E2B6,2)):
        operand(at[pc],0,address=address,width=width)
    operand(at[0x47560],1,address=0x49B66)
    require(at[0x47560]['operand_facts'][0]['immediate_value']==2 and
            at[0x47566]['operand_facts'][0]['immediate_value']==55 and
            at[0x47572]['operand_facts'][0]['immediate_value']==49,'glyph cycle contract differs')
    for pc, value in ((0x4A848, 39), (0x4A7DE, 6)):
        require(at[pc]['operand_facts'][0]['immediate_value'] == value, 'outer row schedule differs')
    roots = {int.from_bytes(data[i-2048:i-2048+4], 'big')-2048 for i in range(0x4A002,0x4A026,4)}
    inv = reachable_write_inventory(rows, analysis, roots, include_sites=True)
    require(inv['instructions'] == 2855 and len(inv['write_sites']) == 694,
            'callback source coverage differs')
    protected = {**PROTECTED, **{f"faces_{f['variant']}": tuple(f['span']) for f in faces}}
    coverage,counts=cover_stores(inv.pop('write_sites'),geometry,protected)
    code_preserved=exclude_accepted_code(coverage,[(b['start_offset']+2048,b['end_offset']+2048)
                                                  for b in analysis['blocks']])
    probe_stores=[]
    for r in window(rows,0x4AEB2,0x4AF62):
        for p in r['operand_facts']:
            if not (p.get('memory') and 'write'in p['access']):continue
            pc=r['source_offset']+2048
            if p['base_register']=='A7':
                require(p['ea_update']==2,'probe stack write differs')
                continue
            if pc==0x4AF50:
                require(p['base_register']=='A0' and not p['indexed'] and p['displacement']==10
                        and p['width_bytes']==2,'probe marker writer differs')
                span=[0xE816+10,0xE816+10*14+2]
                name='bounded_probe_marker_view'
            else:
                require(p['absolute_address'] is not None and not p['base_register'] and not p['indexed']
                        and not p['bulk_transfer'],'unknown probe writer')
                span=[p['absolute_address'],p['absolute_address']+p['width_bytes']]
                name='fixed_probe_effect'
            require(not any(intersects(span,protected[k])for k in
                            ('count','draw_backup','work_backup','descriptor_cursor','callback_cells','span_table')),
                    'probe writer intersects retained state')
            probe_stores.append({'runtime':pc,'width':p['width_bytes'],'domain':name,'span':span})
    latch=[s for s in coverage if s['byte_envelope'] and
           intersects(s['byte_envelope'],(0x4E2B6,0x4E2B8))]
    require([(s['runtime'],s['byte_envelope'])for s in latch]==
            [(0x27594,[0x4E2B6,0x4E2B7]),(0x28482,[0x4E2B6,0x4E2B7])],
            'callback latch writer protocol differs')
    return {'main_sha256': hashlib.sha256(data).hexdigest(), 'cpu':'68000', 'runtime_executed': False,
            'callback_roots': sorted(v+2048 for v in roots), 'native_target_set_closed': False,
            'source_coverage': inv, 'explicit_write_operands_covered': len(coverage),
            'domain_counts': dict(counts), 'write_cover': coverage,
            'geometry_word_stores': len(geometry), 'bounded_face_views': faces,
            'projection_caller_witnesses': protocol_calls,
            'protected_intervals': {k:list(v) for k,v in protected.items()},
            'cpu_count_backups_table_preservation_given_premises': True,
            'accepted_code_bytes_excluded_by_cpu_domains':code_preserved,
            'source_target_induction_if_entry_cells_rows_and_frames_intact':True,
            'premises': ['Entry callback cells/packed pointer lineage retain the eight original values; no competing code/cell/view writers',
                'Initial face grammar, span-offset table and fixed sound roots retain the checked contracts',
                'Original 68000 code and normal reads/returns/frames; stack aliases neither code nor protected data; no competing cache writers',
                'No unrelated device/IRQ or other writes to protected storage'],
            'cpu_preserves_entry_bank_value_without_assuming_it_canonical':True,
            'canonical_bank_needed_for_programmed_plane_rectangles':True,
            'callback_latch_setters':latch,
            'hardware_source_order':{'last_line_launch':0x193F0,'immediate_line_return':0x193F8,
                'first_polygon_setup':0x18414,'first_polygon_launch':0x18462,
                'first_polygon_wait':0x18468,'cleanup_launch':0x184EC,'cleanup_wait':0x184F2},
            'retained_symbolic_mmio_conflicts_at_literal_stores':mmio_conflicts,
            'hardware_first_submit_quiescence_proved': False, 'actual_memory_preservation_proved': False,
            'conditional_scenery_M_equals_N': 'N=2..14, preceding count store, covered CPU paths and noninterfering device/IRQ effects',
            'work_window': {'source':[0x15BD0,0x16850], 'backup':[0x4AF80,0x4BC00],
                'bytes':3200, 'longs':800, 'explicit_copy_sites':work_copies,
                'post_return_retained_copy_bytes':160, 'next_row_offset':160,
                'source_restoration_requires_unchanged_backup_and_no_late_device_writes':True},
            'probe_explicit_store_domains':probe_stores,
            'frame_consumer': {'latch':0x4E2B6, 'set_sites':[0x27594,0x28482],
                'read':0x47556,'glyph_word':0x49B66,'clear':0x4759A,
                'distinct_near_point_clear_once_per_scenery_draw':0x4A7AC,
                'event_counting':False,'visible_or_every_frame_execution_proved':False},
            'previous_return_contract_checked': previous['main_sha256']}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('rows','analysis','member','output'): p.add_argument('--'+key,type=Path,required=True)
    a=p.parse_args();result=check_source(json.loads(a.rows.read_text()),json.loads(a.analysis.read_text()),a.member.read_bytes())
    a.output.write_text(json.dumps(result,indent=2)+'\n')


if __name__ == '__main__': main()

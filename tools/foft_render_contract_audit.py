"""Recheck pinned FoFT matrix transport using accepted native operand facts.

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

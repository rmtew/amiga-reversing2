"""Deterministic label and disconnected-code inventory from native facts.

Raw terminal-decode candidates are kept separate from accepted CFG blocks.
No label text is interpreted as an address and no candidate is promoted.
"""
from bisect import bisect_right
from collections import Counter, defaultdict
import re

GENERIC = re.compile(r'(?:abs|loc|sub|data|table|string|unknown)_\d+_[0-9A-Fa-f]+\Z')


def source_inventory(analysis, *, section_index=0, entry_offset=0):
    section = next(s for s in analysis['sections'] if s['section_index'] == section_index)
    runs = sorted(section['accepted_code_runs'], key=lambda r:r['start_offset'])
    run_starts = [r['start_offset'] for r in runs]
    def is_code(offset):
        at = bisect_right(run_starts,offset)-1
        return at >= 0 and offset < runs[at]['end_offset']
    labels = {(r['symbol_name'],r['target_offset']) for r in section['rendered_symbol_accesses']
              if r['access_kind'] in ('label_statement','storage_label')
              and r.get('target_section_index') == section_index}
    references = defaultdict(set)
    for r in section['rendered_symbol_accesses']:
        if r['access_kind'] in ('operand','branch_target') and r.get('target_section_index') == section_index:
            references[r['target_offset']].add((r['offset'],r.get('operand_index')))
    incoming_kinds=defaultdict(set)
    for edge in section['edges']:
        if edge.get('kind') in (1,2,3,4):
            incoming_kinds[edge['target_offset']].add(edge['kind'])
    explicit_entries={r['offset'] for r in section['code_start_refs']
                      if r['evidence_kind'] in ('manual_action_log_entry_point','raw_image_entry')}
    roles={1:'fallthrough',2:'branch',3:'call',4:'jump'}
    rows=[]
    for name,offset in sorted(labels,key=lambda row:(row[1],row[0])):
        if not GENERIC.fullmatch(name):
            continue
        ownership = [r['kind_name'] for r in section['range_ownerships']
                     if r['start_offset'] <= offset < r['end_offset']]
        rows.append(dict(name=name,section_index=section_index,source_offset=offset,
                         ownership='code' if is_code(offset) else '|'.join(sorted(set(ownership))) or 'unclassified',
                         inbound_sources=sorted({r[0] for r in references[offset]}),
                         control_inbound_kinds=[roles[k]for k in sorted(incoming_kinds[offset])],
                         code_role=('called_entry' if 3 in incoming_kinds[offset] else
                                    'explicit_entry' if offset in explicit_entries else
                                    'jump_destination' if 4 in incoming_kinds[offset] else
                                    'branch_destination' if 2 in incoming_kinds[offset] else 'fallthrough_or_other')
                                   if is_code(offset) else None,
                         status='unresolved_purpose'))
    blocks=section['blocks'];starts=[b['start_offset']for b in blocks]
    def block_at(offset):
        i=bisect_right(starts,offset)-1
        return i if i>=0 and offset<blocks[i]['end_offset'] and is_code(blocks[i]['start_offset']) else None
    accepted={i for i,b in enumerate(blocks)if is_code(b['start_offset'])}
    adjacency=defaultdict(set);inbound=defaultdict(set)
    for edge in section['edges']:
        source,target=edge['source_block_index'],edge['target_block_index']
        if source in accepted and target in accepted:
            adjacency[source].add(target);inbound[target].add(source)
    # CFG serialization omits some accepted dispatch/vector edges. Add only
    # explicit native control evidence, never a seed's self-reference.
    evidence={'direct_control_target','runtime_control_target','dispatch_table_control_target','vector_store_control_target'}
    for ref in section['code_start_refs']:
        if ref['evidence_kind'] not in evidence or ref.get('source_section_index') != section_index:
            continue
        source,target=block_at(ref['source_offset']),block_at(ref['offset'])
        if source is not None and target is not None:
            adjacency[source].add(target);inbound[target].add(source)
    entry=block_at(entry_offset);reached=set();queue=[] if entry is None else[entry]
    while queue:
        at=queue.pop()
        if at in reached:continue
        reached.add(at);queue.extend(adjacency[at]-reached)
    disconnected=accepted-reached
    # Components use undirected connectivity only to group disconnected code;
    # they make no additional directed reachability claim.
    neighbours=defaultdict(set)
    for source,targets in adjacency.items():
        for target in targets:
            neighbours[source].add(target);neighbours[target].add(source)
    components=[];pending=set(disconnected)
    while pending:
        queue=[min(pending)];group=set()
        while queue:
            at=queue.pop()
            if at not in pending:continue
            pending.remove(at);group.add(at);queue.extend(neighbours[at]&pending)
        components.append(sorted(blocks[i]['start_offset']for i in group))
    signals=[{**r,'accepted_code':is_code(r['offset'])}for r in section['orphan_code_signals']]
    return dict(schema='native-source-inventory/v1',section_index=section_index,entry_offset=entry_offset,
        counts=dict(emitted_labels=len(labels),scoped_labels=sum('\\' in n for n,o in labels),generic_labels=len(rows),
                    generic_code_labels_by_role=dict(sorted(Counter(r['code_role']for r in rows if r['ownership']=='code').items())),
                    generic_labels_by_ownership=dict(sorted(Counter(r['ownership']for r in rows).items())),
                    accepted_cfg_blocks=len(accepted),entry_connected_blocks=len(reached),
                    disconnected_accepted_blocks=len(disconnected),disconnected_components=len(components),
                    blocks_without_inbound=sum(not inbound[i] for i in accepted if i!=entry),
                    raw_terminal_candidates=sum(not r['accepted_code']for r in signals)),
        generic_labels=rows,disconnected_components=components,
        blocks_without_inbound=[blocks[i]['start_offset']for i in sorted(accepted)if i!=entry and not inbound[i]],
        raw_candidates=signals)

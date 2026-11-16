"""Plan an explicit shared prefix after owner provenance has been reviewed.

This is a structural transformation, not an owner inference. The caller supplies
canonical source evidence for each independent root and applies the returned
normal catalogue commands as one revision-bound interpretation batch. Register
names, equal offsets and similar field names alone never authorize this plan.
"""
from __future__ import annotations

from copy import deepcopy
import re


def _signature(field):
    field = {k: v for k, v in field.items() if v is not None}
    # Untyped APTR storage has the same scalar contract as LONG. A pointee,
    # address domain or named base is deliberately not normalized this way.
    if (field.get('type') == 'APTR' and field.get('size') == 4
            and field.get('value_kind', 'scalar') == 'scalar'
            and not any(field.get(k) for k in ('pointer_struct', 'pointer_address_domain',
                                               'pointer_symbol_group', 'named_base', 'struct'))):
        field['type'] = 'LONG'
    return field


def plan_shared_prefix(structs, *, roots, offsets, name, owner_evidence):
    """Return existing catalogue commands; reject any conflicting descendant.

    Roots must be independent declared roots. Evidence is an explicit reviewed
    same-owner assertion at canonical source rows, not a value inferred here.
    Descendant sizes, register seeds, other fields and phase views are retained.
    No target files or Manual Action Log are written by this planner.
    """
    by_name = {s['name']: deepcopy(s) for s in structs}
    if len(by_name) != len(structs) or name in by_name or not roots or len(set(roots)) != len(roots):
        raise ValueError('new prefix and unique existing roots required')
    if set(owner_evidence) != set(roots):
        raise ValueError('reviewed owner evidence required for every root')
    for root in roots:
        if root not in by_name or by_name[root].get('base_struct'):
            raise ValueError('independent declared roots required')
        refs = owner_evidence[root]
        if not refs or any(not re.fullmatch(r's\d+:[0-9A-Fa-f]{8}:[a-z_]+', r) for r in refs):
            raise ValueError('canonical source owner evidence required')
    if not offsets or len(set(offsets)) != len(offsets) or any(type(o) is not int or o < 0 for o in offsets):
        raise ValueError('unique nonnegative field offsets required')
    descendants = []
    for st in by_name.values():
        current = st
        seen = set()
        while current['name'] not in roots:
            if current['name'] in seen:
                raise ValueError('cyclic inheritance')
            seen.add(current['name'])
            base = current.get('base_struct')
            if not base:
                break
            if base not in by_name:
                raise ValueError('unknown parent')
            current = by_name[base]
        if current['name'] in roots:
            descendants.append(st)
    selected = []
    for offset in sorted(offsets):
        matches = [(s, f) for s in descendants for f in s['fields'] if f['offset'] == offset]
        if len(matches) < 2:
            raise ValueError('each shared field requires at least two declarations')
        field = _signature(matches[0][1])
        if any(_signature(f) != field for _, f in matches):
            raise ValueError(f'conflicting field contracts at {offset}')
        end = offset + field['size']
        if field['size'] <= 0 or any(s['size'] < end for s in descendants):
            raise ValueError('shared field exceeds a descendant')
        for st in descendants:
            for other in st['fields']:
                if other['offset'] < end and offset < other['offset'] + other['size']:
                    if _signature(other) != field:
                        raise ValueError(f'phase-specific overlap at {offset} in {st["name"]}')
        if selected and selected[-1]['offset'] + selected[-1]['size'] > offset:
            raise ValueError('overlapping shared fields')
        selected.append(field)
    size = max(f['offset'] + f['size'] for f in selected)
    if any(by_name[r]['size'] < size for r in roots):
        raise ValueError('shared prefix exceeds a root')
    commands = [dict(command_id='target.custom_struct.add', context={'kind': 'target'},
                     parameters=dict(name=name, size=size, fields=selected))]
    for st in descendants:
        fields = [f for f in st['fields'] if f['offset'] not in offsets]
        if len(fields) == len(st['fields']) and st['name'] not in roots:
            continue
        parameters = {k: st[k] for k in ('name', 'size', 'base_struct', 'base_offset',
                                         'available_since', 'tag_offset', 'tag_value', 'tag_root_struct')
                      if st.get(k) is not None}
        parameters['fields'] = fields
        if st['name'] in roots:
            parameters.update(base_struct=name, base_offset=0)
        commands.append(dict(command_id='target.custom_struct.edit', context={'kind': 'target'},
                             parameters=parameters))
    return commands

"""Plan explicit imported-local bindings; never change old journal semantics."""

import re


def imported_local_family(original, current, *, owner_offset, member_start, member_end, name=None):
    """Identify one namespace by its immutable named source owner coordinate.

    This is a spelling/ownership plan, not a function-boundary or code-admission
    inference. Native code/row and member checks are applied by the caller.
    """
    if type(owner_offset) is not int or not member_start <= owner_offset < member_end:
        raise ValueError('source-local owner is outside the selected member')
    old = {r['name'] for r in original.get('seeded_code_labels', ())
           if r.get('hunk', 0) == 0 and r['addr'] == owner_offset and '\\' not in r['name']}
    live = {r['name'] for r in current.get('seeded_code_labels', ())
            if r.get('hunk', 0) == 0 and r['addr'] == owner_offset and '\\' not in r['name']}
    if len(old) != 1 or len(live) != 1:
        raise ValueError('source-local planning requires unique original and current source owners')
    old_name, current_name = old.pop(), live.pop()
    if any(r.get('type') == 'data' and r.get('hunk', 0) == 0 and r['addr'] == owner_offset
           and r.get('name') == old_name for r in original.get('seeded_entities', ())):
        raise ValueError('ambiguous source code/data owner')
    name = current_name if name is None else name
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name) or len(name.encode()) >= 64:
        raise ValueError('source-local owner requires a valid global source name')
    # A namespace repeated at another source address is not resolved by nearest
    # label order, even if only one of those addresses precedes this child.
    if {r['addr'] for r in original.get('seeded_code_labels', ())
        if r.get('hunk', 0) == 0 and r['name'] == old_name} != {owner_offset}:
        raise ValueError('ambiguous original source namespace')
    candidates, deferred, retained = [], [], []
    seen = set()
    for child in original.get('seeded_code_labels', ()):
        prefix, separator, local = child['name'].partition('\\')
        if child.get('hunk', 0) != 0 or prefix != old_name or not separator:
            continue
        at = child['addr']
        key = (at, child["name"])
        if key in seen:
            continue
        seen.add(key)
        reason = None
        current_rows = [r for r in current.get('seeded_code_labels', ())
                        if r.get('hunk', 0) == 0 and r['addr'] == at]
        current_names = {r["name"] for r in current_rows}
        current_row = next((r for r in current_rows if (r.get("source_locator") or "").endswith(f";scope_owner=s0:{owner_offset:08X}:label")), current_rows[0] if current_rows else {})
        if not owner_offset < at or not member_start <= at < member_end:
            reason = 'outside_member_or_not_after_owner'
        elif not re.fullmatch(r'\.[A-Za-z_][A-Za-z0-9_]*', local):
            reason = 'not_one_local_component'
        elif len((name+'\\'+local).encode()) >= 64:
            reason = 'qualified_name_limit'
        elif len(current_names) != 1:
            reason = 'ambiguous_current_source_identity'
        elif (current_row.get('source_locator') or '').endswith(f';scope_owner=s0:{owner_offset:08X}:label'):
            retained.append({'source_offset': at, 'name': current_row['name'], 'reason': 'already_bound'})
            continue
        elif current_row['name'] not in {child['name'], current_name+'\\'+local}:
            reason = 'authored_name_or_other_namespace'
        elif any(r['name'] == name+'\\'+local and (r.get('hunk', 0), r['addr']) != (0, at)
                 for r in current.get('seeded_code_labels', ())):
            reason = 'canonical_name_collision'
        item = {'source_offset': at, 'original_name': child['name'],
                'current_name': current_row['name'] if len(current_names) == 1 else None,
                'local_name': local}
        if reason:
            deferred.append({**item, 'reason': reason})
        else:
            candidates.append(item)
    return {'owner_offset': owner_offset, 'original_owner_name': old_name,
            'current_owner_name': current_name, 'owner_name': name,
            'candidates': candidates, 'deferred': deferred, 'retained': retained}

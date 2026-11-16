"""Audit and factor duplicate fields inside an explicitly reviewed owner family.

This operates on declared record ancestry, not CPU register names or inferred
physical ownership. Native access/provenance evidence must be reviewed by the
caller. Independent roots, rebased inheritance and differing phase contracts
are never silently unified.
"""
from collections import defaultdict
from copy import deepcopy
import json
import re
from .shared_record_fields import _signature


def audit_owner_family(structs, *, root):
    by_name = {s['name']:s for s in structs}
    if len(by_name)!=len(structs) or root not in by_name:
        raise ValueError('unique declarations and an existing owner root required')
    paths={}
    for name in by_name:
        chain=[];current=name
        while current:
            if current in chain:raise ValueError('cyclic inheritance')
            if current not in by_name:raise ValueError('unknown parent')
            chain.append(current);current=by_name[current].get('base_struct')
        if root in chain:paths[name]=chain[:chain.index(root)+1]
    members=[by_name[n]for n in sorted(paths)]
    rebased=[n for n in paths if any(by_name[a].get('base_offset',0) for a in paths[n][:-1])]
    if rebased:
        # A common numeric offset does not identify storage through a rebase.
        return dict(root=root,members=sorted(paths),rebased_views=sorted(rebased),duplicate_groups=[],blocked_reason='rebased inheritance requires a reviewed coordinate projection')
    declarations=defaultdict(list)
    for s in members:
        for field in s['fields']:
            declarations[json.dumps(_signature(field),sort_keys=True)].append(s['name'])
    groups=[]
    overlaps=[]
    signatures=sorted(declarations)
    for index,left_key in enumerate(signatures):
        left=json.loads(left_key)
        for right_key in signatures[index+1:]:
            right=json.loads(right_key)
            if left['offset']<right['offset']+right['size'] and right['offset']<left['offset']+left['size']:
                overlaps.append(dict(left_field=left,left_views=sorted(declarations[left_key]),
                                     right_field=right,right_views=sorted(declarations[right_key]),
                                     status='different_contracts_in_declared_views'))
    for signature,names in declarations.items():
        if len(names)<2:continue
        field=json.loads(signature);offset=field['offset'];end=offset+field['size']
        common=set(paths[names[0]])
        for name in names[1:]:common.intersection_update(paths[name])
        host=next(n for n in paths[names[0]]if n in common)
        descendants=[s for s in members if host in paths[s['name']]]
        conflicts=[]
        for s in descendants:
            if s['name']!=host and s['size']<end:
                conflicts.append(dict(view=s['name'],reason='field exceeds view extent'))
            for other in s['fields']:
                if other['offset']<end and offset<other['offset']+other['size'] and _signature(other)!=field:
                    conflicts.append(dict(view=s['name'],reason='overlapping different contract',field=deepcopy(other)))
        groups.append(dict(field=field,declarations=sorted(names),host=host,
                           affected_views=sorted(s['name']for s in descendants),
                           status='conflicting_view'if conflicts else'compatible_declared_owner',conflicts=conflicts))
    return dict(root=root,members=sorted(paths),rebased_views=[],
                overlapping_contracts=overlaps,
                duplicate_groups=sorted(groups,key=lambda g:(g['field']['offset'],g['field']['name'])))


def plan_owner_family_factoring(structs, *, root, owner_evidence):
    """Return one normal catalogue batch; keep every incompatible contract.

    Evidence asserts the existing family has the reviewed storage owner. It
    does not establish ownership for a separate root, nor new phase semantics.
    Hosting at the lowest common ancestor limits newly inherited fields. Host
    sizes may grow only within every affected descendant's existing bounds.
    """
    if not owner_evidence or any(not isinstance(r,str) or not re.fullmatch(r's\d+:[0-9A-Fa-f]{8}:[a-z_]+',r)for r in owner_evidence):
        raise ValueError('reviewed canonical owner evidence required')
    audit=audit_owner_family(structs,root=root)
    if audit.get('blocked_reason'):raise ValueError(audit['blocked_reason'])
    before={s['name']:deepcopy(s)for s in structs};after=deepcopy(before)
    for group in audit['duplicate_groups']:
        if group['status']!='compatible_declared_owner':continue
        field=group['field'];host=after[group['host']]
        for name in group['declarations']:
            after[name]['fields']=[f for f in after[name]['fields']if _signature(f)!=field]
        host['fields'].append(deepcopy(field));host['fields'].sort(key=lambda f:(f['offset'],f['name']))
        host['size']=max(host['size'],field['offset']+field['size'])
    commands=[]
    # Ancestors precede descendants; normal prospective batch validation still
    # validates the final entire hierarchy rather than temporary partial edits.
    def depth(name):
        n=0
        while after[name].get('base_struct'):
            n+=1;name=after[name]['base_struct']
        return n
    for name in sorted(after,key=lambda n:(depth(n),n)):
        st=after[name]
        if st==before[name]:continue
        p={k:st[k]for k in ('name','size','base_struct','base_offset','available_since','tag_offset','tag_value','tag_root_struct')if st.get(k)is not None}
        p['fields']=st['fields']
        commands.append(dict(command_id='target.custom_struct.edit',context=dict(kind='target'),parameters=p))
    return audit,commands

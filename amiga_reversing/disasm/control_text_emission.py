"""Conservative numeric-emission inventory for accepted native control text.

Reads a retained frozen source plan, never decodes bytes or classifies new text.
Only complete literal BYTE data statements with matching native source extents
prove numeric spelling. Quoted/mixed/expression or contradictory rows stay unknown.
"""
import bisect
import re

POLICY = 'accepted-control-text-numeric-emission/v1'
DATA_ROW_KIND = 10  # M68kRenderPlanRowKind, native source-plan wire contract.


def union(ranges):
    out=[]
    for a,b in sorted(set(ranges)):
        if b<=a:continue
        if out and a<=out[-1][1]:out[-1][1]=max(b,out[-1][1])
        else:out.append([a,b])
    return out


def numeric_values(line, size):
    statement=line.split(';',1)[0].strip()
    match=re.fullmatch(r'(dc|dcb)\.b\s+(.+)',statement,re.I)
    if not match:return None
    tokens=[t.strip()for t in match[2].split(',')]
    if any(not re.fullmatch(r'\$[0-9a-fA-F]+|[0-9]+',t)for t in tokens):return None
    values=[int(t[1:],16)if t.startswith('$')else int(t,10)for t in tokens]
    if match[1].lower()=='dcb':
        if len(values)!=2 or values[0]!=size or not 0<=values[1]<=255:return None
        return (values[1],)
    if len(values)!=size or any(v>255 for v in values):return None
    return tuple(values)


def control_text_emission(section, source_plan):
    """Return known numeric bytes and explicit unknowns in this owner domain."""
    if source_plan is None:return None
    section_index=section['section_index'];size=section['section_size']
    stored=[r['stored_size']for r in source_plan.get('sections',[])if r['section_index']==section_index]
    if len(stored)!=1 or type(stored[0])is not int or not 0<=stored[0]<=size:
        raise ValueError('Source plan must identify the selected stored section extent')
    size=stored[0]
    ranges=sorted({(max(0,r['start_offset']),min(size,r['end_offset']))for r in section.get('range_ownerships',[])
        if r.get('status_name')=='accepted'and r.get('kind_name')=='text'and r.get('role')=='string_control_stream'
        and r['start_offset']<size and r['end_offset']>0})
    ranges=[(a,b)for a,b in ranges if a<b];domain=union(ranges);starts=[a for a,b in domain]
    # Restrict byte identities to the accepted owner union before parsing rows.
    # Sets deduplicate exact rows and preserve numeric/unknown contradictions.
    evidence={};rows=set()
    for row in source_plan.get('rows',[]):
        if row.get('source_section_index')!=section_index:continue
        lines=row.get('text','').splitlines();mask=row.get('source_line_mask',0)
        spans=row.get('line_ranges',[])
        for index,line in enumerate(lines):
            if index<32 and mask&(1<<index)and index<len(spans):
                start,length=spans[index][:2]
            elif not mask and len(lines)==1 and row.get('has_source_range'):
                start,length=row['source_offset'],row['source_size']
            else:continue
            if type(start)is not int or type(length)is not int or length<=0 or start<0 or start+length>size:continue
            i=bisect.bisect_right(starts,start)-1
            if not ((i>=0 and domain[i][1]>start)or(i+1<len(domain)and domain[i+1][0]<start+length)):continue
            values=numeric_values(line,length)if row.get('kind')==DATA_ROW_KIND else None
            key=(start,length,line.split(';',1)[0].strip(),row.get('kind'))
            if key in rows:continue
            rows.add(key)
            for lo,hi in domain:
                for offset in range(max(start,lo),min(start+length,hi)):
                    evidence.setdefault(offset,set()).add(None if values is None else values[0]if len(values)==1 else values[offset-start])
    numeric={at for at,values in evidence.items()if len(values)==1 and None not in values}
    records=[]
    for start,end in ranges:
        known=sum(at in numeric for at in range(start,end))
        records.append(dict(start_offset=start,end_offset=end,numeric_bytes=known,
            unresolved_numeric_emission_bytes=end-start-known,wholly_numeric=known==end-start))
    total=sum(b-a for a,b in domain)
    return dict(policy=POLICY,section_index=section_index,stored_payload_bytes=size,
        domain='Union of accepted native text owners whose role is string_control_stream; no inferred or suspected text.',
        confirmed_ranges=len(ranges),confirmed_bytes=total,known_numeric_bytes=len(numeric),
        unresolved_numeric_emission_bytes=total-len(numeric),wholly_numeric_ranges=sum(r['wholly_numeric']for r in records),
        complete_numeric_emission_inventory=len(numeric)==total,ranges=records,
        limitations=['Only source-mapped literal dc.b/dcb.b statements are recognized; quoted/mixed/expression, missing or conflicting emission remains unresolved.',
                    'Numeric bytes can include ordinary characters, controls and terminators. This counts spelling, not byte semantics or newly discovered text.',
                    'This domain excludes other accepted text roles, unclassified payload, suspected text and asset eligibility.'])

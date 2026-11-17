"""Versioned progress measures over retained native facts, never a new analysis.

Counts describe evidence domains, not completion estimates. Missing eligibility
or emission facts stay unavailable. Addresses always come from native bindings.
"""
from collections import Counter, defaultdict
import json
import hashlib
from .source_inventory import source_inventory

POLICY = 'native-progress-evidence-v1'
ASSET_ROLES = ('bitmap', 'opaque_data', 'sound_sample')


def unique(rows):
    return [json.loads(s) for s in sorted({json.dumps(r, sort_keys=True) for r in rows})]


def intervals(ranges, size):
    """Union clipped half-open source ranges; adjacent owners do not create gaps."""
    result = []
    for start, end in sorted((max(0, a), min(size, b)) for a, b in ranges):
        if end <= start:
            continue
        if result and start <= result[-1][1]:
            result[-1][1] = max(result[-1][1], end)
        else:
            result.append([start, end])
    return result


def complement(ranges, size):
    result = []; end = 0
    for start, stop in intervals(ranges, size):
        if start > end:
            result.append([end, start])
        end = stop
    if end < size:
        result.append([end, size])
    return result


def byte_count(ranges):
    return sum(b-a for a, b in ranges)


def workspace_family(metadata, roots):
    if not roots:
        return None, 'No reviewed workspace root selector supplied.'
    if metadata is None or 'custom_structs' not in metadata:
        return None, 'Custom-struct ancestry metadata is unavailable.'
    structs = {r['name']: r for r in metadata['custom_structs']}
    if any(root not in structs for root in roots):
        return None, 'A selected workspace root is absent from the supplied metadata.'
    members = set(roots)
    while True:
        expanded = members | {name for name, row in structs.items() if row.get('base_struct') in members}
        if expanded == members:
            return sorted(members), None
        members = expanded


def typed_population(section, family=None):
    resolved_key = 'recovered_platform_typed_accesses'
    unresolved_key = 'recovered_platform_unresolved_typed_accesses'
    if resolved_key not in section or unresolved_key not in section:
        return None
    def select(key):
        return unique(r for r in section[key] if family is None or r.get('root_struct_name') in family)
    resolved, unresolved = select(resolved_key), select(unresolved_key)
    key = lambda r: (r['offset'], r['operand_index'])
    good = {key(r) for r in resolved}; bad = {key(r) for r in unresolved}
    conflicts = {key(r) for r in unresolved if 'conflict' in r.get('classification', '') or r.get('conflicted')}
    contracts = defaultdict(set)
    for r in resolved:
        contracts[key(r)].add((r.get('owner_struct_name'), r.get('field_name'), r.get('field_offset'), r.get('field_size')))
    causes = defaultdict(set)
    for r in unresolved:
        causes[r.get('classification', 'unknown')].add(key(r))
    return dict(resolved=len(good), unresolved=len(bad), operands=len(good | bad),
        both_resolved_and_unresolved=len(good & bad), reported_conflicts=len(conflicts),
        multiple_resolved_contracts=sum(len(v)>1 for v in contracts.values()),
        unresolved_by_classification={k:len(v) for k,v in sorted(causes.items())},
        resolved_records=resolved, unresolved_records=unresolved)


def build_scorecard(analysis, *, identity, metadata=None, package=None,
                    section_index=0, entry_offset=0, workspace_roots=(), detail=(), source_plan=None):
    section = next(s for s in analysis['sections'] if s['section_index'] == section_index)
    size = section['section_size']
    inventory = source_inventory(analysis, section_index=section_index, entry_offset=entry_offset)
    metrics = {}; details = {}
    base_domain = dict(section_index=section_index, source_start=0, source_end=size)
    def measure(name, value, unit, domain, *, denominator=None, cause=None, evidence='native accepted facts', level='native_fact'):
        metrics[name] = dict(status='unavailable' if cause else 'measured', value=None if cause else value,
            unit=unit, domain={**base_domain, 'selection':domain}, evidence=evidence,
            evidence_level='unavailable' if cause else level,
            denominator=denominator, unavailable_reason=cause)
    family, family_error = workspace_family(metadata, workspace_roots)
    for prefix, selected, error in [('typed', None, None), ('workspace', family, family_error)]:
        population = None if error else typed_population(section, selected)
        error = error or ('Native typed-access arrays are unavailable.' if population is None else None)
        domain = dict(kind='unique native source operand', workspace_members=selected) if prefix=='workspace' else 'unique native source operand'
        for name in ['resolved','unresolved','both_resolved_and_unresolved','reported_conflicts','multiple_resolved_contracts','unresolved_by_classification']:
            measure(prefix+'.'+name, None if population is None else population[name],
                'operands' if name!='unresolved_by_classification' else 'operands by native classification', domain,
                denominator=None if population is None else population['operands'], cause=error)
        details[prefix] = population
    owners = unique(section.get('range_ownerships', []))
    ownership_error = None if 'range_ownerships' in section else 'Native range ownership is unavailable.'
    if section.get('section_kind') == 3:
        ownership_error = 'The selected native section is BSS, not a stored payload-byte domain.'
    accepted = [r for r in owners if r.get('status_name')=='accepted']
    gaps = complement([(r['start_offset'],r['end_offset']) for r in accepted], size)
    for name,value,unit in [('bytes',byte_count(gaps),'bytes'),('intervals',len(gaps),'intervals')]:
        measure('payload.unclassified_'+name,value,unit,'complement of union of accepted ownership',denominator=size if name=='bytes' else None,cause=ownership_error)
    details['payload'] = dict(unclassified_intervals=gaps)
    for name,key in [('generic','generic_labels'),('generic_by_role','generic_code_labels_by_role'),
                     ('generic_by_ownership','generic_labels_by_ownership'),('semantic_locals','scoped_labels')]:
        value = inventory['counts'][key]
        measure('labels.'+name,value,'identities' if not isinstance(value,dict) else 'identities by role',
            'native source label/address bindings' if name!='semantic_locals' else 'canonical native scope identity/address',
            cause='Canonical native symbol origins are unavailable.' if value is None else None)
    details['labels'] = dict(generic=inventory['generic_labels'], semantic_locals=inventory['semantic_local_bindings'])
    control_keys = ['accepted_cfg_blocks','entry_connected_blocks','disconnected_accepted_blocks',
        'disconnected_components','blocks_without_inbound','raw_terminal_candidates','asynchronous_entry_blocks',
        'disconnected_asynchronous_blocks','disconnected_conditional_blocks','disconnected_only_asynchronous_blocks',
        'disconnected_only_conditional_blocks','disconnected_both_conditional_and_asynchronous_blocks','disconnected_unexplained_blocks']
    for key in control_keys:
        missing = None
        if key in ('disconnected_conditional_blocks','disconnected_only_asynchronous_blocks',
                   'disconnected_only_conditional_blocks','disconnected_both_conditional_and_asynchronous_blocks',
                   'disconnected_unexplained_blocks') and 'conditional_controls' not in section:
            missing = 'This snapshot does not export conditional-control evidence; absence is not zero.'
        measure('control.'+key, inventory['counts'][key], 'groups' if key=='disconnected_components' else
            'unaccepted candidates' if key=='raw_terminal_candidates' else 'blocks',
            inventory['counting_policy'], denominator=inventory['counts']['accepted_cfg_blocks'] if key not in ('raw_terminal_candidates','disconnected_components') else None,
            cause=missing, evidence='native terminal decode candidates' if key=='raw_terminal_candidates' else 'accepted CFG and explicit control evidence; installation is not execution',
            level='candidate' if key=='raw_terminal_candidates' else 'native_fact')
    details['control'] = {k:inventory[k] for k in ['disconnected_component_records','raw_candidates','blocks_without_inbound']}
    details['control']['conditional_refusals'] = [r for r in section.get('conditional_controls',[]) if not r['admitted']]
    confirmed_assets = [r for r in accepted if r.get('role') in ASSET_ROLES]
    asset_union = intervals([(r['start_offset'],r['end_offset']) for r in confirmed_assets], size)
    manifest = package.get('manifest',package) if package is not None else None
    packaged = unique(r for r in manifest.get('files',[]) if r['kind']=='asset' and r.get('source_section_index')==section_index) if manifest else []
    packaged_union = intervals([(r['source_offset'],r['source_offset']+r['size']) for r in packaged],size)
    package_error = None
    if manifest is None or 'files' not in manifest:
        package_error = 'A matching complete source-package manifest is unavailable.'
    elif not identity.get('payload_sha256') or manifest.get('target_identity_sha256') != identity['payload_sha256']:
        package_error = 'Source-package payload identity is missing or differs from this native snapshot.'
    measure('assets.packaged_ranges',len({(r['source_offset'],r['size'])for r in packaged}),'ranges','source-package asset records',cause=package_error,evidence='validated package metadata',level='package_record')
    measure('assets.incbin_bytes',byte_count(packaged_union),'bytes','union of source-package asset ranges',denominator=size,cause=package_error,evidence='validated package metadata',level='package_record')
    measure('assets.confirmed_ranges',len({(r['start_offset'],r['end_offset'],r['role'])for r in confirmed_assets}), 'ranges',dict(accepted_roles=list(ASSET_ROLES)),cause=ownership_error)
    measure('assets.confirmed_bytes',byte_count(asset_union),'bytes',dict(accepted_roles=list(ASSET_ROLES)),denominator=size,cause=ownership_error)
    overlap = intervals([(max(a,c),min(b,d))for a,b in asset_union for c,d in packaged_union if max(a,c)<min(b,d)],size)
    measure('assets.confirmed_bytes_not_packaged',byte_count(asset_union)-byte_count(overlap),'bytes',dict(accepted_roles=list(ASSET_ROLES)),
        denominator=byte_count(asset_union),cause=package_error or ownership_error,
        evidence='accepted asset-role ranges minus package coverage; not an eligibility claim')
    asset_gap = 'Native exporter row eligibility/refusal and inline-emission facts are not exported; accepted roles and package coverage alone do not establish other eligible inline assets or candidates.'
    for name,unit in [('confirmed_inline_assets','ranges'),('confirmed_inline_eligible_bytes','bytes'),('candidate_ranges','ranges')]:
        measure('assets.'+name,None,unit,'exporter eligibility and source-coordinate emission',cause=asset_gap)
    details['assets'] = dict(confirmed_ranges=confirmed_assets,packaged_ranges=packaged,eligibility_unavailable=asset_gap)
    text_ranges = [r for r in accepted if r['kind_name']=='text']
    text_union = intervals([(r['start_offset'],r['end_offset']) for r in text_ranges],size)
    measure('text.confirmed_ranges',len({(r['start_offset'],r['end_offset'],r.get('role'))for r in text_ranges}),'ranges','accepted text ownership',cause=ownership_error)
    measure('text.confirmed_bytes',byte_count(text_union),'bytes','union of accepted text ownership',denominator=size,cause=ownership_error)
    measure('text.confirmed_control_stream_ranges',len({(r['start_offset'],r['end_offset'])for r in text_ranges if r.get('role')=='string_control_stream'}),
        'ranges','accepted string_control_stream ownership',cause=ownership_error)
    emission_gap = 'No source-coordinate text-emission facts distinguish quoted, numeric control and wholly raw bytes.'
    measure('text.confirmed_raw_bytes',None,'bytes','accepted text joined to raw source emission',cause=emission_gap)
    suspicion_gap = 'No native suspected-text ranges with plain/control-coded classification and consumer evidence are exported; printable scans are insufficient.'
    for kind in ['plain','control_coded']:
        measure('text.suspected_'+kind+'_ranges',None,'ranges','native candidate bounds and consumer evidence',cause=suspicion_gap)
    from .control_text_emission import control_text_emission, POLICY as EMISSION_POLICY
    control_emission = None if ownership_error else control_text_emission(section,source_plan)
    control_error = ownership_error or ('No retained native source plan supplied for control-text emission.' if control_emission is None else None)
    control_domain = dict(policy=EMISSION_POLICY,owners='accepted string_control_stream union',
                          emission='source-mapped complete literal BYTE data statements; known numeric lower bound')
    for name,key,unit,denominator in [
        ('numeric_bytes','known_numeric_bytes','bytes','confirmed_bytes'),
        ('wholly_numeric_ranges','wholly_numeric_ranges','ranges','confirmed_ranges'),
        ('unresolved_numeric_emission_bytes','unresolved_numeric_emission_bytes','bytes','confirmed_bytes')]:
        measure('text.control_stream_'+name,None if control_emission is None else control_emission[key],unit,control_domain,
                denominator=None if control_emission is None else control_emission[denominator],cause=control_error,
                evidence='accepted native control-text ownership joined to the retained frozen source plan',level='native_source_plan')
    details['text'] = dict(confirmed_ranges=text_ranges,emission_unavailable=emission_gap,
                          suspected_unavailable=suspicion_gap,control_emission=control_emission)
    requested = set(detail)
    native_policy = analysis.get('analysis_policy')
    policy_identity = None if native_policy is None else dict(
        sha256=hashlib.sha256(json.dumps(native_policy,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        max_cpu=native_policy.get('max_cpu'),entry_point_count=native_policy.get('entry_point_count'),
        structured_data_item_count=native_policy.get('structured_data_item_count'))
    result = dict(schema='native-progress-scorecard/v1',identity=identity,
        native_policy=policy_identity,platform_backend_kind=analysis.get('platform_backend_kind'),
        counting_policy=dict(id=POLICY,section_index=section_index,payload_bytes=size,
            ordinary_roots=[dict(section_index=section_index,source_offset=entry_offset)],
            control_policy=inventory['counting_policy'],workspace_roots=sorted(set(workspace_roots)),
            workspace_members=family,workspace_evidence='reviewed declared ancestry subset, not persistent physical-owner proof',
            duplicate_policy='exact records deduplicated; typed operands keyed by section/offset/operand; byte measures union half-open ranges',
            unknown_policy='unavailable is distinct from measured zero'),
        roots=dict(asynchronous=inventory['asynchronous_roots'],conditional=inventory['conditional_roots'],
            analysis_seeds=[dict(source_offset=o,evidence=e)for o,e in sorted({(r['offset'],r['evidence_kind'])
                for r in section['code_start_refs']if r['evidence_kind']in ('manual_action_log_entry_point','raw_image_entry')})]),metrics=metrics)
    if requested:
        unknown = requested-{'all',*details}
        if unknown:
            raise ValueError('Unknown detail groups: '+', '.join(sorted(unknown)))
        result['detail'] = {k:v for k,v in details.items() if 'all' in requested or k in requested}
    return result


def compare_scorecards(before, after):
    reasons = []
    for label,card in [('before',before),('after',after)]:
        identity=card['identity']
        for key in ['source_version','analysis_sha256']:
            if not identity.get(key):
                reasons.append('Missing '+label+' '+key)
        analyzer=identity.get('analyzer') or {}
        if not isinstance(analyzer,dict) or not any(analyzer.get(k) for k in ['source_version','source_revision','native_backend_sha256']):
            reasons.append('Missing '+label+' analyzer identity')
    for key in ['target','payload_sha256']:
        if not before['identity'].get(key) or before['identity'].get(key)!=after['identity'].get(key):
            reasons.append('Missing or different '+key)
    for key in ['id','section_index','payload_bytes','ordinary_roots']:
        if before['counting_policy'].get(key)!=after['counting_policy'].get(key):
            reasons.append('Different counting policy '+key)
    changed=[]; availability=[]; excluded=[]
    for name in sorted(before['metrics'].keys() | after['metrics'].keys()):
        b=before['metrics'].get(name);a=after['metrics'].get(name)
        if b is None or a is None or b['status']!='measured' or a['status']!='measured':
            before_status=b['status']if b else'unavailable'
            after_status=a['status']if a else'unavailable'
            if before_status!=after_status:
                row=dict(measure=name,before=before_status,after=after_status)
                if b is None or a is None:row.update(before_recorded=b is not None,after_recorded=a is not None)
                availability.append(row)
            continue
        if reasons or b['domain']!=a['domain'] or b['unit']!=a['unit']:
            excluded.append(name);continue
        if b['value']!=a['value'] or b['denominator']!=a['denominator']:
            changed.append(dict(measure=name,before=b['value'],after=a['value'],unit=a['unit'],
                denominator_before=b['denominator'],denominator_after=a['denominator']))
    input_changes={key:dict(before=before['identity'].get(key),after=after['identity'].get(key))
        for key in ['source_version','analysis_sha256','analyzer','metadata_sha256','package_manifest_sha256','source_plan_sha256','control_text_emission_implementation_sha256']
        if before['identity'].get(key)!=after['identity'].get(key)}
    if before.get('native_policy')!=after.get('native_policy'):
        input_changes['native_policy']=dict(before=before.get('native_policy'),after=after.get('native_policy'))
    return dict(schema='native-progress-comparison/v1',comparable=not reasons,reasons=reasons,input_changes=input_changes,
        before=before['identity'],after=after['identity'],changed=changed,availability_changes=availability,excluded_measures=excluded)


# Compact commit-body measures; complete classifications remain in comparison JSON.
COMMIT_MEASURES = (
    'typed.unresolved','workspace.unresolved','payload.unclassified_bytes','payload.unclassified_intervals',
    'labels.generic','labels.semantic_locals','control.disconnected_accepted_blocks','control.disconnected_components',
    'control.disconnected_only_asynchronous_blocks','control.disconnected_only_conditional_blocks',
    'control.disconnected_both_conditional_and_asynchronous_blocks','control.disconnected_unexplained_blocks',
    'control.raw_terminal_candidates','assets.incbin_bytes','assets.confirmed_inline_assets',
    'assets.confirmed_inline_eligible_bytes','assets.candidate_ranges','text.confirmed_bytes','text.confirmed_ranges',
    'text.confirmed_control_stream_ranges','text.control_stream_numeric_bytes','text.control_stream_wholly_numeric_ranges',
    'text.control_stream_unresolved_numeric_emission_bytes','text.confirmed_raw_bytes',
    'text.suspected_plain_ranges','text.suspected_control_coded_ranges')


def commit_delta(comparison):
    if not comparison['comparable']:
        return 'Scorecard comparison unavailable: '+ '; '.join(comparison['reasons'])
    changed={r['measure']:r for r in comparison['changed']}
    availability={r['measure']:r for r in comparison['availability_changes']}
    lines=[]
    for name in COMMIT_MEASURES:
        row=changed.get(name)
        if row and row['before']!=row['after']:
            value=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'))
            suffix=''
            if name.startswith(('typed.','workspace.')):
                b,a=row['denominator_before'],row['denominator_after']
                suffix=f' (operands {b} -> {a})' if a!=b else f' (of {a} operands)'
            lines.append(f"{name}: {value(row['before'])} -> {value(row['after'])}{suffix}")
        elif name in availability:
            row=availability[name]
            lines.append(f"{name}: {row['before']} -> {row['after']} (availability)")
    return '\n'.join(lines) or 'No changed primary measured values in comparable domains; full comparison retains denominators and classifications.'

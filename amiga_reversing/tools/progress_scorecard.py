"""Report progress from an existing native analysis snapshot; never rebuild it."""
import argparse
import hashlib
import json
from pathlib import Path
from amiga_reversing.disasm.progress_scorecard import build_scorecard, compare_scorecards, commit_delta


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_bound(path, identity, key):
    if path is None:
        return None
    data = path.read_bytes()
    if not identity.get(key):
        raise ValueError('Provenance must bind the supplied input: '+key)
    if identity[key] != digest(data):
        raise ValueError('Input identity mismatch: '+key)
    identity[key] = digest(data)
    return json.loads(data)


def summary(card):
    def value(key):
        m=card['metrics'][key]
        if m['status']!='measured':
            return 'unavailable'
        text=json.dumps(m['value'],sort_keys=True,separators=(',',':'))
        return text+('/'+str(m['denominator']) if m['denominator'] is not None else '')
    lines=[
        'Typed unresolved: '+value('typed.unresolved')+'; workspace: '+value('workspace.unresolved'),
        'Unclassified payload: '+value('payload.unclassified_bytes')+' bytes; intervals: '+value('payload.unclassified_intervals'),
        'Generic labels: '+value('labels.generic')+'; code roles: '+value('labels.generic_by_role')+'; semantic locals: '+value('labels.semantic_locals'),
        'Disconnected accepted blocks: '+value('control.disconnected_accepted_blocks')+'; groups: '+value('control.disconnected_components')+'; raw candidates: '+value('control.raw_terminal_candidates'),
        'Disconnected explanations: async-only '+value('control.disconnected_only_asynchronous_blocks')+', conditional-only '+value('control.disconnected_only_conditional_blocks')+', both '+value('control.disconnected_both_conditional_and_asynchronous_blocks')+', unexplained '+value('control.disconnected_unexplained_blocks'),
        'INCBIN: '+value('assets.incbin_bytes')+' bytes; confirmed inline eligibility: '+value('assets.confirmed_inline_eligible_bytes')+'; candidates: '+value('assets.candidate_ranges'),
        'Confirmed text: '+value('text.confirmed_bytes')+' bytes; raw: '+value('text.confirmed_raw_bytes')+'; suspected plain/control-coded: '+value('text.suspected_plain_ranges')+'/'+value('text.suspected_control_coded_ranges'),
    ]
    if card['metrics']['text.control_stream_numeric_bytes']['status']=='measured':
        lines.append('Accepted control text numeric emission: '+value('text.control_stream_numeric_bytes')+' bytes; wholly numeric ranges: '+value('text.control_stream_wholly_numeric_ranges')+'; unresolved bytes: '+value('text.control_stream_unresolved_numeric_emission_bytes'))
    return '\n'.join(lines)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--analysis-json',required=True,type=Path)
    parser.add_argument('--provenance',required=True,type=Path,help='Snapshot identity receipt, containing target, payload/source/analyzer identities and analysis_sha256')
    parser.add_argument('--metadata',type=Path)
    parser.add_argument('--package-manifest',type=Path)
    parser.add_argument('--source-plan-json',type=Path,help='Retained frozen native plan, bound by source_plan_sha256 in provenance')
    parser.add_argument('--workspace-root',action='append',default=[])
    parser.add_argument('--section',type=int,default=0)
    parser.add_argument('--entry-offset',type=lambda s:int(s,0),default=0)
    parser.add_argument('--detail',action='append',choices=['all','typed','workspace','payload','labels','control','assets','text'],default=[])
    parser.add_argument('--compare',type=Path,help='Earlier scorecard generated under the same counting policy')
    parser.add_argument('--format',choices=['json','summary','delta'],default='json')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    try:
        provenance=json.loads(args.provenance.read_text())
        identity=dict(provenance.get('identity',provenance))
        required=['target','payload_sha256','source_version','analyzer','analysis_sha256']
        if any(not identity.get(k) for k in required):
            raise ValueError('Provenance requires '+', '.join(required)+'; unavailable analyzer build details may remain null inside analyzer')
        if args.format=='delta' and args.compare is None:
            raise ValueError('--format delta requires --compare')
        analysis=read_bound(args.analysis_json,identity,'analysis_sha256')
        metadata=read_bound(args.metadata,identity,'metadata_sha256')
        package=read_bound(args.package_manifest,identity,'package_manifest_sha256')
        if package and package.get('sha256'):
            canonical=(json.dumps(package['manifest'],sort_keys=True,indent=2,ensure_ascii=True)+'\n').encode()
            if digest(canonical)!=package['sha256']:
                raise ValueError('Source-package manifest content hash mismatch')
        if args.source_plan_json:
            identity['control_text_emission_implementation_sha256']=digest((Path(__file__).resolve().parents[1]/'disasm/control_text_emission.py').read_bytes())
        identity['scorecard_implementation_sha256']=digest((Path(__file__).resolve().parents[1]/'disasm/progress_scorecard.py').read_bytes())
        card=build_scorecard(analysis,identity=identity,metadata=metadata,package=package,section_index=args.section,
            entry_offset=args.entry_offset,workspace_roots=args.workspace_root,detail=args.detail,source_plan=read_bound(args.source_plan_json,identity,'source_plan_sha256'))
        if args.compare:
            card['comparison']=compare_scorecards(json.loads(args.compare.read_text()),card)
        if args.format=='json':
            text=json.dumps(card,sort_keys=True,indent=2)+'\n'
        elif args.format=='delta':
            text=commit_delta(card['comparison'])+'\n'
        else:
            text=summary(card)+'\n'
        if args.output:
            args.output.write_text(text)
        else:
            print(text,end='')
    except (ValueError,KeyError) as error:
        parser.error(str(error))


if __name__=='__main__':
    main()

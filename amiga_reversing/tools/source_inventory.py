"""Inventory native generic labels, disconnected accepted code and raw candidates."""
from __future__ import annotations
import argparse
import json
import hashlib
from pathlib import Path
from amiga_reversing.disasm.binary_source import resolve_target_binary_source
from amiga_reversing.disasm.c_backend import build_listing_artifact_profile_from_binary_source
from amiga_reversing.disasm.effective_metadata import effective_metadata_file
from amiga_reversing.disasm.project_paths import PROJECT_ROOT
from amiga_reversing.disasm.source_inventory import source_inventory


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target',required=True)
    parser.add_argument('--section',type=int,default=0)
    parser.add_argument('--entry-offset',type=lambda s:int(s,0),default=0)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--analysis-json',type=Path,help='Reuse exported native analysis without rebuilding a listing')
    parser.add_argument('--check-bindings',action='store_true',
        help='Exit nonzero for native memory/control operand binding gaps or conflicts; leaves the report for review')
    args=parser.parse_args()
    target=(PROJECT_ROOT/'targets'/args.target).resolve()
    if target.parent!=(PROJECT_ROOT/'targets').resolve():
        parser.error('target must be a target directory name')
    if args.analysis_json:
        snapshot=args.analysis_json.read_bytes()
        analysis=json.loads(snapshot)
        provenance=dict(kind='provided_native_analysis_json',sha256=hashlib.sha256(snapshot).hexdigest(),
            target_identity='caller-supplied target name; verify snapshot receipt separately',
            analyzer_identity=None,metadata_identity=None)
    else:
        source=resolve_target_binary_source(target,PROJECT_ROOT)
        with effective_metadata_file(target) as metadata:
            metadata_digest=hashlib.sha256(metadata.read_bytes()).hexdigest()
            artifact=build_listing_artifact_profile_from_binary_source(source,metadata_path=metadata)[2]
        try:
            analysis=artifact.analysis_payload()[0]
        finally:
            artifact.close()
        provenance=dict(kind='built_native_listing',metadata_sha256=metadata_digest)
    payload=source_inventory(analysis,section_index=args.section,entry_offset=args.entry_offset)
    payload['snapshot_provenance']=provenance
    payload['target']=args.target
    text=json.dumps(payload,indent=2,sort_keys=True)+'\n'
    if args.output:
        args.output.write_text(text)
        print(json.dumps(payload['counts'],sort_keys=True))
    else:
        print(text,end='')
    if args.check_bindings and (
            payload['control_reference_audit']['operand_binding_gaps'] or
            any(status != 'symbolic_operand' and count for status,count in
                payload['memory_operand_bindings']['counts'].items())):
        raise SystemExit(1)


if __name__=='__main__':main()

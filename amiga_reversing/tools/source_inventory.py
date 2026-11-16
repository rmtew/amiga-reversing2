"""Inventory native generic labels, disconnected accepted code and raw candidates."""
from __future__ import annotations
import argparse
import json
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
    args=parser.parse_args()
    target=(PROJECT_ROOT/'targets'/args.target).resolve()
    if target.parent!=(PROJECT_ROOT/'targets').resolve():
        parser.error('target must be a target directory name')
    source=resolve_target_binary_source(target,PROJECT_ROOT)
    with effective_metadata_file(target) as metadata:
        artifact=build_listing_artifact_profile_from_binary_source(source,metadata_path=metadata)[2]
    try:
        payload=source_inventory(artifact.analysis_payload()[0],section_index=args.section,entry_offset=args.entry_offset)
    finally:
        artifact.close()
    payload['target']=args.target
    text=json.dumps(payload,indent=2,sort_keys=True)+'\n'
    if args.output:
        args.output.write_text(text)
        print(json.dumps(payload['counts'],sort_keys=True))
    else:
        print(text,end='')


if __name__=='__main__':main()

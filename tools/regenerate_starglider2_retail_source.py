"""Regenerate the committed shared assembly through the normal native exporter.

Private original input and a built native backend are needed only for this
step. Normal assembly uses build_starglider2_retail_pair and needs neither.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import tempfile
from tools.build_starglider2_retail_pair import ROOT,EXPECTED,load_shared_program,shared_source,build_packaged

def require_saved_annotations(target):
    """Retain action history while refusing dependencies absent from the snapshot."""
    pending=target/'manual_actions.jsonl'
    if not pending.exists() or not pending.read_text().strip():
        return
    from amiga_reversing.disasm.target_metadata import load_target_metadata,target_metadata_json_payload
    from amiga_reversing.disasm.effective_metadata import effective_target_metadata
    saved=load_target_metadata(target)
    effective=effective_target_metadata(target)
    def canonical(metadata):
        payload=target_metadata_json_payload(metadata)
        # MAL projection sorts these independent declarations even when no
        # entity changed. Compare complete records, retaining multiplicity.
        payload['seeded_entities']=sorted(payload['seeded_entities'],key=lambda row:json.dumps(row,sort_keys=True))
        return payload
    if saved is None or effective is None or canonical(saved)!=canonical(effective):
        raise ValueError('save checked annotations to target_metadata.json before regenerating committed source')


def generate_package(root=ROOT):
    from amiga_reversing.disasm.binary_source import resolve_target_binary_source
    from amiga_reversing.disasm.effective_metadata import effective_metadata_file
    from amiga_reversing.disasm.c_backend import CListingArtifact,_source_file_for_c_backend,_platform_include_dir_for_listing
    from amiga_reversing.disasm.source_package import build_source_package,collect_native_package_includes,extend_source_package
    target=root/'targets/starglider2_retail'
    require_saved_annotations(target)
    load_shared_program(root)
    source=resolve_target_binary_source(target,root)
    with effective_metadata_file(target) as metadata:
        with _source_file_for_c_backend(source,project_root=root) as native:
            artifact=CListingArtifact.create(native,metadata_text=str(metadata),
                include_dir=str(_platform_include_dir_for_listing(native.platform_name,root)),project_root=root)
        try:payload=artifact.source_package_payload(256,platform_symbol_profiles=('cpu','amiga-custom','atari-st-mfp'))
        finally:artifact.close()
    text=shared_source(payload['source_text'])
    references=set(re.findall(r'(?im)^\s*INCBIN\s+"([^"]+)"',text))
    if references!={a['path'] for a in payload['assets']}:
        raise ValueError('native includes and required asset inventory differ')
    if '/workspace/' in text or '/home/' in text:
        raise ValueError('local path in generated source')
    includes=collect_native_package_includes({**payload,'source_text':text},root/'ext/atarist_includes/devpac_3_10/include')
    package=build_source_package(dict(filename='retail-shared.s',source_text=text,target='starglider2_retail',
        assembler_profile='vasm',metadata_hash=hashlib.sha256((target/'target_metadata.json').read_bytes()).hexdigest(),
        target_identity_sha256=EXPECTED['st']),payload['assets'],256,includes=includes)
    records=[]
    for name,high in [('st',0),('amiga',128)]:
        data=(f'; Shared retail payload; platform flag high BYTE only.\n'
              f'SGII_RETAIL_PLATFORM_HIGH EQU ${high:02X}\n INCLUDE "retail-shared.s"\n').encode()
        records.append(dict(path=f'retail-{name}.s',kind='source',size=len(data),data_hex=data.hex()))
    return extend_source_package(package,records,application=dict(profile='starglider2-retail-pair-v1',
        wrappers=dict(st='retail-st.s',amiga='retail-amiga.s'),payload_bytes=419308,expected_sha256=EXPECTED))

def regenerate(vasm: Path,*,root=ROOT,check=False):
    from amiga_reversing.disasm.source_package import materialize_source_package,validate_source_package
    from amiga_reversing.disasm.source_package_publish import publish_source_package,PUBLISH_MANIFEST
    package=generate_package(root);files=validate_source_package(package)
    with tempfile.TemporaryDirectory(prefix='sgii-source-verify-') as temp:
        temporary=Path(temp);target=temporary/'targets/starglider2_retail';target.mkdir(parents=True)
        (target/'target_metadata.json').write_bytes((root/'targets/starglider2_retail/target_metadata.json').read_bytes())
        materialize_source_package(package,target/'rendered')
        # Materialization uses manifest.json for archives; normal source
        # publication owns source-package-manifest.json beside the listing.
        (target/'rendered'/'manifest.json').unlink()
        (target/'rendered'/PUBLISH_MANIFEST).write_text(json.dumps(dict(manifest=package['manifest'],sha256=package['sha256']),sort_keys=True,indent=2)+'\n')
        result=build_packaged(vasm,temporary/'built',project_root=temporary)
    destination=root/'targets/starglider2_retail/rendered'
    if check:
        expected={**files,PUBLISH_MANIFEST:(json.dumps(dict(manifest=package['manifest'],sha256=package['sha256']),sort_keys=True,indent=2)+'\n').encode()}
        if any(not (destination/p).is_file() or (destination/p).read_bytes()!=b for p,b in expected.items()):
            raise ValueError('committed retail source differs from native regeneration')
    else:
        destination.mkdir(parents=True,exist_ok=True)
        publish_source_package(package,destination)
    return dict(package_sha256=package['sha256'],files=len(files),asset_bytes=sum(r['size'] for r in package['manifest']['files'] if r['kind']=='asset'),builds=result,checked=check)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vasm',type=Path,required=True)
    parser.add_argument('--check',action='store_true',help='Regenerate and compare without changing committed files')
    args=parser.parse_args()
    print(json.dumps(regenerate(args.vasm,check=args.check),indent=2))
if __name__=='__main__':main()

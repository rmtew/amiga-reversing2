"""Build both original retail handoffs from one native rendered source export.

The proven same-disk difference is the high BYTE of the entry flag at $1002.
The checked-in package builds without original media or the native backend.
Explicit native exports remain supported for analysis verification.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import shutil

ROOT=Path(__file__).resolve().parents[1]
EXPECTED={
 'st':'20c19400180d7e846b78aa615b68446293f8ca54015c4f4a42a77f03b24e8260',
 'amiga':'334f83ec3bdb30e36b2e5c741b7788e4a3489ee15811d11e1e52ef83bd28a938',
}


def shared_source(source: str) -> str:
    pattern=r'(?m)^(platform_entry_flags:\r?\n)[ \t]*dc\.b \$00(?=\r?$)'
    matches=list(re.finditer(pattern,source))
    if len(matches)!=1:
        raise ValueError('expected one native entry-flag high BYTE; refuse another source layout')
    return re.sub(pattern,r'\1\tdc.b SGII_RETAIL_PLATFORM_HIGH',source)


def load_shared_program(root=ROOT):
    from amiga_reversing.disasm.game_catalog import load_family,object_keys
    manifest=json.loads((root/'targets/starglider2_retail/shared_program.json').read_text())
    object_keys(manifest,'schema_version id family analysis_target bindings')
    if manifest['schema_version']!=1 or manifest['id']!='starglider2_retail' or manifest['analysis_target']!=manifest['id']:
        raise ValueError('invalid shared retail project')
    if set(manifest['bindings'])!={'amiga','atari_st'}:raise ValueError('both platform bindings are required')
    family=load_family(root,manifest['family']);analysis=family['targets'][manifest['analysis_target']]
    for key,flags in [('amiga',32769),('atari_st',1)]:
        binding=manifest['bindings'][key];object_keys(binding,'target platform platform_flags monitors')
        target=family['targets'][binding['target']]
        if binding['platform_flags']!=flags or family['releases'][target['release']]['platform']!=binding['platform']:
            raise ValueError('platform binding differs from shared program')
        if family['artifacts'][target['artifact']]['size']!=419308 or target['context']!=analysis['context']:
            raise ValueError('platform load contexts differ')
        expected=EXPECTED['st' if key=='atari_st' else key]
        if target['artifact']!=expected:raise ValueError('unexpected retail binding identity')
    return manifest


def render_shared(root=ROOT):
    from amiga_reversing.disasm.binary_source import resolve_target_binary_source
    from amiga_reversing.disasm.effective_metadata import effective_metadata_file
    from amiga_reversing.disasm.c_backend import render_project_source_with_c_backend
    manifest=load_shared_program(root);target=root/'targets'/manifest['analysis_target']
    source=resolve_target_binary_source(target,root)
    if source.read_bytes()[2:4]!=b'\x00\x01':raise ValueError('unexpected analysis handoff flags')
    with effective_metadata_file(target) as metadata:
        return render_project_source_with_c_backend(source,metadata_path=metadata)


def package_files(root=ROOT):
    """Validate the committed, manifest-owned assembly input set."""
    directory=(root/'targets/starglider2_retail/rendered').resolve()
    envelope=json.loads((directory/'source-package-manifest.json').read_text())
    manifest=envelope['manifest'];application=manifest.get('application',{})
    if application.get('profile')!='starglider2-retail-pair-v1':
        raise ValueError('unsupported retail source package')
    if set(application.get('wrappers',{}))!=set(EXPECTED):
        raise ValueError('both platform wrappers are required')
    expected_manifest=hashlib.sha256((json.dumps(manifest,sort_keys=True,indent=2,ensure_ascii=True)+'\n').encode()).hexdigest()
    if envelope['sha256']!=expected_manifest:
        raise ValueError('source-package manifest integrity mismatch')
    metadata=root/'targets/starglider2_retail/target_metadata.json'
    if hashlib.sha256(metadata.read_bytes()).hexdigest()!=manifest['metadata_hash']:
        raise ValueError('annotations changed; regenerate the committed retail source')
    if application['expected_sha256']!=EXPECTED or application['payload_bytes']!=419308:
        raise ValueError('retail identity differs from the platform bindings')
    files={}
    for record in manifest['files']:
        relative=record['path'];parts=PurePosixPath(relative)
        if parts.is_absolute() or '..' in parts.parts or '\\' in relative or relative in files:
            raise ValueError('invalid package path')
        path=(directory/relative).resolve()
        if not path.is_relative_to(directory):
            raise ValueError('package path escapes its directory')
        data=path.read_bytes()
        if len(data)!=record['size'] or hashlib.sha256(data).hexdigest()!=record['sha256']:
            raise ValueError('changed generated source or include: '+relative)
        files[relative]=data
    required={manifest['source'],*application['wrappers'].values()}
    if not required<=files.keys():
        raise ValueError('shared listing or platform wrapper missing')
    return directory,manifest,files


def build_packaged(vasm: Path, output: Path, *, project_root=ROOT) -> dict:
    directory,manifest,_files=package_files(project_root)
    output=output.resolve();output.mkdir(parents=True,exist_ok=False)
    executable=shutil.which(str(vasm)) or str(vasm.resolve())
    results={}
    for platform,wrapper in manifest['application']['wrappers'].items():
        raw=output/f'retail-{platform}.raw'
        subprocess.run([executable,'-m68000','-no-opt','-Fbin','-quiet',
                        '-o',str(raw),wrapper],cwd=directory,check=True)
        data=raw.read_bytes();digest=hashlib.sha256(data).hexdigest()
        if len(data)!=419308 or digest!=EXPECTED[platform]:
            raise ValueError(f'{platform} output differs from the original retail handoff')
        results[platform]=dict(size=len(data),sha256=digest)
    return results


def build(vasm: Path, output: Path, source: Path | None=None, *, project_root=ROOT) -> dict:
    if source is None:return build_packaged(vasm,output,project_root=project_root)
    text=source.read_text()
    output.mkdir(parents=True,exist_ok=False)
    (output/'retail-original-st.s').write_text(text)
    common=output/'retail-shared.s';common.write_text(shared_source(text))
    results={}
    for platform,high in [('st',0),('amiga',128)]:
        wrapper=output/f'retail-{platform}.s'
        wrapper.write_text(f'SGII_RETAIL_PLATFORM_HIGH EQU ${high:02X}\n INCLUDE "retail-shared.s"\n')
        raw=output/f'retail-{platform}.raw'
        subprocess.run([str(vasm.resolve()),'-m68000','-no-opt','-Fbin','-quiet','-o',raw.name,wrapper.name],cwd=output,check=True)
        data=raw.read_bytes();digest=hashlib.sha256(data).hexdigest()
        if len(data)!=419308 or digest!=EXPECTED[platform]:
            raise ValueError(f'{platform} output is not the original retail handoff: {len(data)} bytes, {digest}')
        results[platform]=dict(size=len(data),sha256=digest)
    return results


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vasm',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True,help='Fresh output directory for the two raw payloads')
    parser.add_argument('--source',type=Path,help='Optional inline native source for analysis checks; default uses the committed package')
    args=parser.parse_args()
    import json
    print(json.dumps(build(args.vasm,args.output.resolve(),args.source),indent=2))


if __name__=='__main__':main()

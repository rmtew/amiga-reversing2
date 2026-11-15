"""Build both original retail handoffs from one native rendered source export.

The proven same-disk difference is the high BYTE of the entry flag at $1002.
The exported source stays unchanged. Private output contains a derived common
source, two flag wrappers and independently hash-checked raw binaries.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

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


def build(vasm: Path, output: Path, source: Path | None=None, *, project_root=ROOT) -> dict:
    text=source.read_text() if source is not None else render_shared(project_root)
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
    parser.add_argument('--output',type=Path,required=True,help='Fresh private output directory; contains game binaries')
    parser.add_argument('--source',type=Path,help='Optional already-rendered private source; default renders the shared target from verified local input')
    args=parser.parse_args()
    import json
    print(json.dumps(build(args.vasm,args.output.resolve(),args.source),indent=2))


if __name__=='__main__':main()

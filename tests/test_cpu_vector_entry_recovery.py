"""Generated CPU vector kinds recover installs independently of platform backend."""
import json
from pathlib import Path
import pytest
from amiga_reversing.disasm import c_backend
from amiga_reversing.disasm.c_backend import CListingArtifact,_CBackendSourceFile
ROOT=Path(__file__).resolve().parents[1]

def vector_artifact(tmp_path,platform,store):
 source=' SECTION code,code\n ORG $1000\n '+store+'\n rts\nhandler:\n moveq #42,d1\n rte\n'
 raw,_=c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',source);binary=tmp_path/'vector.raw';binary.write_bytes(raw)
 meta=tmp_path/'metadata.json';meta.write_text('{}')
 a=CListingArtifact.create(_CBackendSourceFile(binary,platform,0,0x1000),metadata_text=str(meta),include_dir=str(ROOT/'ext/amiga_includes/ndk_2.0/include'),project_root=ROOT)
 return a,raw,raw.index(bytes.fromhex('722a4e73'))

@pytest.mark.parametrize('platform',('amiga-raw','atari-st-raw'))
@pytest.mark.parametrize('store',('move.l #handler,$6c.w','move.l #handler,$8.l','move.l #handler,$80.w','lea handler(pc),a0\n move.l a0,$6c.w'))
def test_known_cpu_exception_interrupt_and_trap_slots_admit_mapped_handlers(tmp_path,platform,store):
 a,raw,target=vector_artifact(tmp_path,platform,store)
 try:
  section=a.analysis_payload()[0]['sections'][0];assert any(r['start_offset']<=target<r['end_offset']for r in section['accepted_code_runs'])
  text=a.inline_source_text_with_profile()[0];rebuilt,_=c_backend.assemble_platform_source_text_with_c_backend(platform,text);assert rebuilt==raw
 finally:a.close()

@pytest.mark.parametrize('store',('move.l #handler,$0.w','move.l #handler,$4.w','move.l #handler,$6d.w','move.l #handler,$200.w','move.w #handler,$6c.w','move.b #42,$6c.w','move.l #handler+1,$6c.w','move.l #$90000,$6c.w'))
def test_noncallback_partial_misaligned_or_external_stores_do_not_admit_handler(tmp_path,store):
 a,raw,target=vector_artifact(tmp_path,'atari-st-raw',store)
 try:
  section=a.analysis_payload()[0]['sections'][0];assert not any(r['start_offset']<=target<r['end_offset']for r in section['accepted_code_runs'])
 finally:a.close()

@pytest.mark.parametrize('platform',('amiga-raw','atari-st-raw'))
@pytest.mark.parametrize('store',('move.l #handler,$6c.w','lea handler(pc),a1\n move.l a1,$6c.w'))
def test_async_handler_does_not_inherit_installers_computed_jump_register(tmp_path,platform,store):
 source=' SECTION code,code\n ORG $1000\n lea unrelated(pc),a0\n '+store+'\n rts\nhandler:\n jmp (a0)\nunrelated:\n moveq #42,d1\n rte\n'
 raw,_=c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',source);binary=tmp_path/'async.raw';binary.write_bytes(raw);meta=tmp_path/'metadata.json';meta.write_text('{}')
 a=CListingArtifact.create(_CBackendSourceFile(binary,platform,0,0x1000),metadata_text=str(meta),include_dir=str(ROOT/'ext/amiga_includes/ndk_2.0/include'),project_root=ROOT)
 try:
  target=raw.index(bytes.fromhex('722a4e73'));handler=raw.index(bytes.fromhex('4ed0'));runs=a.analysis_payload()[0]['sections'][0]['accepted_code_runs']
  assert any(r['start_offset']<=handler<r['end_offset']for r in runs)
  assert not any(r['start_offset']<=target<r['end_offset']for r in runs)
 finally:a.close()

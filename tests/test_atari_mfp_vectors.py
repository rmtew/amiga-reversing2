"""MFP slot identity is platform/configuration conditioned asynchronous evidence."""
import json
import subprocess
from pathlib import Path
import pytest
from amiga_reversing.disasm import c_backend
from amiga_reversing.disasm.binary_source import RawBinarySource,RawAddressModel,BinarySourceKind
from tests.test_custom_record_flow_platforms import STRaw
from tests.test_conditional_control_installation import verify
ROOT=Path(__file__).resolve().parents[1]

def fixture(tmp_path,installer,handler='rte',platform='st',extra=None):
    prefix=installer+'\n rts\n'
    encoded,_=c_backend.assemble_platform_source_text_with_c_backend('amiga-raw','handler EQU $1040\nsection code,code\norg $1000\n'+prefix)
    assert len(encoded)<64
    text='section code,code\norg $1000\n'+prefix+f'dcb.b {64-len(encoded)},0\nhandler:\n'+handler+'\n'
    raw,_=c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',text)
    binary=tmp_path/'input.bin';binary.write_bytes(raw)
    cls=STRaw if platform=='st' else RawBinarySource
    source=cls(kind=BinarySourceKind.RAW_BINARY,path=binary,address_model=RawAddressModel.RUNTIME_ABSOLUTE,
        load_address=4096,entrypoint=4096,code_start_offset=0,display_path=str(binary),analysis_cache_path=tmp_path/'cache')
    metadata=tmp_path/'metadata.json';metadata.write_text(json.dumps(extra or {}))
    return c_backend.build_listing_artifact_profile_from_binary_source(source,metadata_path=metadata)[2],raw

def accepted(section,at):
    return any(r['start_offset']<=at<r['end_offset']for r in section['accepted_code_runs'])

@pytest.mark.parametrize('installer',[
    'move.l #$1040,$118.w',
    'move.b #$58,$FFFFFA17.w\n move.l #$1040,$158.w',
    'moveq #$58,d0\n move.b d0,$FFFFFA17.w\n move.l #$1040,$158.w',
    'lea handler(pc),a0\n move.l a0,$118.w',
    'lea handler(pc),a1\n move.l a1,$134.l',
    'lea handler(pc),a0\n move.l a0,d0\n move.l d0,$118.w',
])
def test_initial_and_register_installations_are_async_not_cfg_calls(tmp_path,installer):
    artifact,raw=fixture(tmp_path,installer)
    try:
        section=artifact.analysis_payload()[0]['sections'][0]
        assert accepted(section,64)
        refs=[r for r in section['code_start_refs']if r['offset']==64]
        assert any(r['evidence_kind']=='vector_store_control_target'for r in refs)
        assert all(r.get('entry_kind')=='asynchronous_vector' and not r['execution_proven'] and not r['installer_state_propagated']for r in refs if r['evidence_kind']=='vector_store_control_target')
        assert not any(e['target_offset']==64 for e in section['edges'])
        verify(artifact,raw,tmp_path)
    finally:artifact.close()

@pytest.mark.parametrize('installer,platform',[
    ('move.l #$1040,$118.w','amiga'),
    ('move.b #$58,$FFFFFA17.w\n move.l #$1040,$118.w','st'),
    ('move.b #$58,$FFFFFA17.w\n move.l #$1040,$158.w','amiga'),
    ('move.l #$1040,$119.w','st'),
    ('move.l #$1040,$140.w','st'),
    ('move.l #$1040,$FC.w','st'),
    ('move.w #$1040,$118.w','st'),
    ('move.l a0,$118.w','st'),
    ('move.l $1040.l,$118.w','st'),
    ('move.l $0040.l,$118.w','st'),
    ('move.l $0040.l,d0\n move.l d0,$118.w','st'),
    ('move.l $1040.l,d0\n move.l d0,$118.w','st'),
    ('move.l #$1041,$118.w','st'),
])
def test_platform_slot_width_unknown_and_memory_values_do_not_guess(tmp_path,installer,platform):
    artifact,raw=fixture(tmp_path,installer,platform=platform)
    try:
        section=artifact.analysis_payload()[0]['sections'][0]
        assert not accepted(section,64)
        assert not any(r['offset']==64 and r['evidence_kind']=='vector_store_control_target'for r in section['code_start_refs'])
        verify(artifact,raw,tmp_path)
    finally:artifact.close()

def test_chained_handler_discovery_has_independent_entry_state(tmp_path):
    # A1 points to a valid raw decoy in the installer; asynchronous entry must
    # not use that value to resolve the handler's JMP (A1).
    artifact,raw=fixture(tmp_path,'lea.l $1080.l,a1\n move.l #$1040,$118.w',
        'lea second(pc),a0\n move.l a0,$118.w\n jmp (a1)\n dcb.b 54,0\nsecond:\n rte')
    try:
        section=artifact.analysis_payload()[0]['sections'][0]
        assert accepted(section,64)
        assert not any(e['kind'] in (3,4) and e['target_offset']==128 for e in section['edges'])
        second=len(raw)-2
        assert accepted(section,second)
        assert any(r['offset']==second and r['evidence_kind']=='vector_store_control_target'for r in section['code_start_refs'])
        assert not any(e['target_offset']==second for e in section['edges'])
        verify(artifact,raw,tmp_path)
    finally:artifact.close()

@pytest.mark.parametrize('extra',[
    {'seeded_entities':[dict(type='data',hunk=0,addr=64,end=66,unit='byte',name='owned_payload')]},
    {'execution_views':[dict(source_start=0,source_end=66,base_addr=0x1000,name='identity'),dict(source_start=64,source_end=66,base_addr=0x2040,name='competing')]},
])
def test_data_ownership_and_competing_views_refuse(tmp_path,extra):
    artifact,raw=fixture(tmp_path,'move.l #$1040,$118.w',extra=extra)
    try:
        section=artifact.analysis_payload()[0]['sections'][0]
        assert not accepted(section,64)
        verify(artifact,raw,tmp_path)
    finally:artifact.close()

def test_generated_controller_metadata_is_deterministic_and_base_selected(tmp_path):
    from src.scripts.generate_atari_st_vector_runtime import generate
    assert generate()==(ROOT/'src/generated/atari_st_vector_runtime.h').read_text()
    source=tmp_path/'slots.c';source.write_text('''#include "generated/atari_st_vector_runtime.h"
#include <assert.h>
int main(void) {
  assert(atari_st_mfp_vector_slot(0x118,0x48));
  assert(atari_st_mfp_vector_slot(0x134,0x40));
  assert(!atari_st_mfp_vector_slot(0x118,0x58));
  assert(atari_st_mfp_vector_slot(0x158,0x58));
  assert(!atari_st_mfp_vector_slot(0x119,0x48));
  assert(!atari_st_mfp_vector_slot(0x140,0x48));
  assert(!atari_st_mfp_vector_slot(0x00,0x08));
  return 0;
}''')
    out=tmp_path/'slots';subprocess.run(['cc','-Isrc',str(source),'-o',str(out)],cwd=ROOT,check=True)
    subprocess.run([str(out)],check=True)


def test_instruction_interior_is_not_a_new_entry(tmp_path):
    artifact,raw=fixture(tmp_path,'move.l #$1042,$118.w','move.l #$12345678,d0\n rte',extra={
        'seeded_code_entrypoints':[dict(hunk=0,addr=64,name='established_handler')]})
    try:
        section=artifact.analysis_payload()[0]['sections'][0]
        assert not any(b['start_offset']==66 for b in section['blocks'])
        assert 'move.l #$12345678,d0' in artifact.inline_source_text_with_profile()[0]
        verify(artifact,raw,tmp_path)
    finally:artifact.close()

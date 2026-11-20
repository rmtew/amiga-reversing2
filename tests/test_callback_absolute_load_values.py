"""An absolute memory operand supplies contents, never its own address value."""
import json
from contextlib import contextmanager

import pytest

from amiga_reversing.disasm import c_backend
from amiga_reversing.disasm.binary_source import (
    BinarySourceKind,
    RawAddressModel,
    RawBinarySource,
)
from tests.test_typed_index_symbol_compensation import exact


@contextmanager
def fixture(tmp_path, transfer):
    # Runtime scalar address equals the SOURCE offset of phantom. Confusing
    # address/contents or runtime/source coordinates therefore invents code.
    text=(' SECTION code,code\n ORG $800\n lea.l owner(pc),a0\n'+transfer+'''
 movea.l 6(a0),a1
 jsr (a1)
 rts
carrier: dcb.b 16,0
owner: dcb.b 16,0
scalar: dc.l 0
 dcb.b 2044,0
phantom: moveq #7,d0
 rts
''')
    path=tmp_path/'input.bin'
    raw,_=c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',text,output_path=path)
    source=RawBinarySource(kind=BinarySourceKind.RAW_BINARY,path=path,
        address_model=RawAddressModel.RUNTIME_ABSOLUTE,load_address=0x800,
        entrypoint=0x800,code_start_offset=0,display_path='synthetic',analysis_cache_path=tmp_path/'analysis')
    metadata=tmp_path/'metadata.json';metadata.write_text(json.dumps({'target_type':'program','entry_register_seeds':[]}))
    artifact=c_backend.build_listing_artifact_profile_from_binary_source(source,metadata_path=metadata)[2]
    try:yield artifact,raw
    finally:artifact.close()


@pytest.mark.parametrize('transfer',[
    ' move.l scalar.l,6(a0)\n',
    ' movea.l scalar.l,a2\n move.l a2,6(a0)\n',
    ' move.l scalar.l,d2\n move.l d2,6(a0)\n',
    ' move.l scalar.w,6(a0)\n',
    ' move.w scalar.l,d2\n move.l d2,6(a0)\n',
    ' lea.l carrier(pc),a2\n move.l scalar.l,6(a2)\n'
    ' lea.l carrier(pc),a1\n move.l 0(a1,d0.w),6(a0)\n',
])
def test_unknown_absolute_load_never_becomes_the_memory_address_callback(tmp_path,transfer):
    with fixture(tmp_path,transfer)as(a,raw):
        refs=a.analysis_payload()[0]['sections'][0]['code_start_refs']
        assert not [r for r in refs if r['evidence_kind']=='callback_field_control_target']
        assert not [e for e in a.query_payload('edges',limit=100)['items']
                    if e['kind']=='call'and e['status']=='resolved']
        exact(a,raw,tmp_path)


@pytest.mark.parametrize('transfer',[
    ' lea.l phantom.l,a2\n move.l a2,6(a0)\n',
    ' move.l #phantom,scalar.l\n move.l scalar.l,6(a0)\n',
    ' move.l #phantom,scalar.l\n movea.l scalar.l,a2\n move.l a2,6(a0)\n',
])
def test_effective_address_and_proven_absolute_slot_contents_still_flow(tmp_path,transfer):
    with fixture(tmp_path,transfer)as(a,raw):
        calls=[e for e in a.query_payload('edges',limit=100)['items']if e['kind']=='call'and e['status']=='resolved']
        assert len(calls)==1 and calls[0]['target_offset']==len(raw)-4
        site=next(x for x in a.analysis_payload()[0]['sections'][0]['recovered_indirect_sites']
                  if x['source_offset']==calls[0]['source_offset'])
        assert not site['runtime_target_set_closed']
        exact(a,raw,tmp_path)

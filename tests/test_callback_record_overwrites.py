"""A definite local byte overwrite cannot revive a stale record callback."""
import json
from contextlib import contextmanager

import pytest

from amiga_reversing.disasm import c_backend
from amiga_reversing.disasm.binary_source import (
    BinarySourceKind,
    RawAddressModel,
    RawBinarySource,
)
from tests.test_callback_fragment_transport import resolved_calls
from tests.test_typed_index_symbol_compensation import exact


@contextmanager
def fixture(tmp_path, *, before='', after='', load=0x800, prefix='', direct=False):
    code=f' SECTION code,code\n ORG ${load:X}\n'+''' lea.l state(pc),a0
 lea.l view(pc),a1
 lea.l callback(pc),a2
'''+(' move.l a2,6(a1)\n'if direct else' move.l a2,16(a0)\n')+prefix+before
    if not direct: code+=' move.l 16(a0),6(a1)\n'
    code+=after+'''read: movea.l 6(a1),a2
 jsr (a2)
 rts
callback: moveq #7,d0
 rts
state: dcb.b 20,0
view: dcb.b 12,0
helper: rts
'''
    path=tmp_path/'input.bin'
    raw,_=c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',code,output_path=path)
    source=RawBinarySource(kind=BinarySourceKind.RAW_BINARY,path=path,
        address_model=RawAddressModel.RUNTIME_ABSOLUTE,load_address=load,entrypoint=load,
        code_start_offset=0,display_path='synthetic',analysis_cache_path=tmp_path/'analysis')
    m=tmp_path/'metadata.json';m.write_text(json.dumps({'target_type':'program','entry_register_seeds':[]}))
    a=c_backend.build_listing_artifact_profile_from_binary_source(source,metadata_path=m)[2]
    try:yield a,raw
    finally:a.close()


@pytest.mark.parametrize('updates',[
    {'before':' clr.l 16(a0)\n'},
    {'before':' clr.w 18(a0)\n'},
    {'before':' move.w #$ffff,18(a0)\n'},
    {'before':' move.b #$ff,19(a0)\n'},
    {'after':' clr.l 6(a1)\n'},
    {'after':' clr.w 8(a1)\n'},
    {'after':' clr.l 6(a1)\n','direct':True},
    {'before':' move.l d0,(a3)\n clr.l 16(a0)\n'},
    {'before':' clr.w 16(a0)\n','load':0x20000},
])
def test_definite_conflicting_byte_before_copy_or_reload_rejects_stale_value(tmp_path,updates):
    with fixture(tmp_path,**updates)as(a,raw):
        assert not resolved_calls(a)
        assert any(e['kind']=='call'and e['status']=='unresolved'
                   for e in a.query_payload('edges',limit=100)['items'])
        exact(a,raw,tmp_path)


@pytest.mark.parametrize('updates',[
    {},
    {'before':' clr.l 12(a0)\n'},
    {'before':' clr.w 16(a0)\n'},  # Same two high bytes at runtime $800.
    {'before':' move.w #2,16(a0)\n','load':0x20000},
    {'before':' move.w #1,16(a0)\n clr.w 16(a0)\n'},
    {'before':' clr.l 16(a0)\n move.l #callback,16(a0)\n'},
    {'before':' clr.l 16(a0)\n move.l d0,(a3)\n'},
    {'before':' clr.l 16(a0)\n bsr.w helper\n'},
    {'before':' clr.l 16(a0)\n pea.l callback(pc)\n'},
    {'before':' clr.l 16(a0)\n link.w a4,#-8\n'},
    {'before':' tst.w d4\n beq.w copy\n clr.l 16(a0)\ncopy:\n'},
    {'after':' tst.w d4\n beq.w read\n clr.l 6(a1)\n'},
])
def test_matching_bytes_disjoint_stores_and_unproved_paths_keep_may_value(tmp_path,updates):
    with fixture(tmp_path,**updates)as(a,raw):
        assert len(resolved_calls(a))==1
        sites=a.analysis_payload()[0]['sections'][0]['recovered_indirect_sites']
        assert all(not s['runtime_target_set_closed']for s in sites)
        exact(a,raw,tmp_path)

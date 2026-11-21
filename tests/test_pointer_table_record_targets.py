"""Checked list roots retain source extent without changing pointer domains."""
from contextlib import nullcontext
from copy import deepcopy

import pytest

from amiga_reversing.disasm import record_lists
from tests.test_disk_set_state import data_request, editable
from tests.test_scoped_record_arrays import metadata

TYPES=[{'name': 'Header','size': 2,'fields': [{'name': 'countMinusOne','type': 'UWORD','offset': 0,'size': 2}]},
       {'name': 'Pair','size': 4,'fields': [{'name': 'a','type': 'WORD','offset': 0,'size': 2},{'name': 'b','type': 'WORD','offset': 2,'size': 2}]}]
RUNS=[{'record_type': 'Header','count': 1},{'record_type': 'Pair','count': 1},{'record_type': 'Header','count': 1},{'record_type': 'Pair','count': 2}]
FLAG='record_list_preserve_source_owner'


def setup(tmp_path,monkeypatch):
    pointers=[0x1020,0x1026,0x1026,0,0xDEADBEEF,0x1022]
    payload=b''.join(p.to_bytes(4,'big')for p in pointers)+bytes.fromhex('cafe123400000001000200010003000400050006')
    _,target,_,call=editable(tmp_path,monkeypatch,record_data=payload,
                           record_scalar_label=(28,'adjacentScalar',4),record_imports=({'hunk':0,'addr':34,'end':36,'name':'retainedA','type':'data','unit':'word','seed_origin':'manual_analysis','review_status':'seeded','citation':'Independent interior scalar'},))
    def edit(lo,hi,command,params):
        ins=call('inspect',source_offset=lo,**({'end_offset':hi}if hi else{}),row_kind='data')
        return call('interpret',**data_request(ins,command,params))
    edit(4,28,'range.data_block.layout.create',{'name': 'profilePointers','default_unit': 'long'})
    edit(32,48,'range.data_block.layout.create',{'name': 'profiles','default_unit': 'word'})
    edit(32,48,'range.data_block.element.set',{'kind': 'array','width': 16,'array_count': 8,'array_stride': 2})
    edit(4,None,'row.data_block.layout.pointer_table',{'row_count': 6,'row_stride': 4,'pointer_offsets': [0],'encoding': 'abs32','target_kind': 'data','address_domain': 'mapped_source'})
    def declare():return edit(32,48,'range.data_block.record_list.declare',{'record_types': TYPES,'runs': RUNS})
    return target,call,declare


def layout(target):
    return next(l for l in metadata(target)['data_block_layouts']if l['name']=='profiles')


def assert_symbolic(target):
    text=(target/'main.s').read_text()
    assert 'dc.l profiles'in text and text.count('dc.l profiles+$6')==2
    assert 'dc.l retainedA'in text and 'retainedA:'in text
    assert 'dc.l $00001020'not in text and 'dc.l $00001026'not in text
    assert 'dc.l $00000000'in text and 'dc.l $DEADBEEF'in text
    assert 'adjacentScalar:'in text and '$CAFE1234'in text
    assert text.count('; countMinusOne')==2 and text.count('; a')==3
    projected=metadata(target)
    root=next(e for e in projected['seeded_entities']if e.get('name')=='profiles')
    assert (root['addr'],root['end'],root['source_owner_start'],root['source_owner_size'])==(32,34,32,16)
    assert not projected['manual_runtime_address_refs']


@pytest.mark.parametrize('legacy',[False,True])
def test_table_to_list_preserves_aliases_interior_null_unmapped_and_journal_upgrade(tmp_path,monkeypatch,legacy):
    target,call,declare=setup(tmp_path,monkeypatch)
    before=(target/'main.s').read_bytes()
    normal=record_lists.validate_record_list
    def historical(payload,owner):
        for e in payload['data_block_elements']:e['type_binding'].pop(FLAG,None)
        return normal(payload,owner)
    with monkeypatch.context()if legacy else nullcontext() as patch:
        if legacy:patch.setattr(record_lists,'validate_record_list',historical)
        saved=declare()
    structured=(target/'main.s').read_bytes()
    if legacy:
        assert b'dc.l $00001026'in structured
        call('regenerate',expected_revision=saved['revision'])
        assert (target/'main.s').read_bytes()==structured
        upgrade=declare();assert_symbolic(target)
        call('rollback',expected_revision=upgrade['revision'],action_id=upgrade['actions'][0]['action_id'])
        assert (target/'main.s').read_bytes()==structured
        # Re-declaration is the ordinary checked upgrade; old source witnesses stay.
        declare()
    assert_symbolic(target)
    assert all(e['type_binding'][FLAG]is True for e in layout(target)['elements'])
    if not legacy:
        undone=call('rollback',expected_revision=saved['revision'],action_id=saved['actions'][0]['action_id'])
        assert (target/'main.s').read_bytes()==before
        call('rollback',expected_revision=undone['revision'],action_id=saved['actions'][0]['action_id'],redo=True)
        assert_symbolic(target)


@pytest.mark.parametrize('change',['mixed','false','source_width','source_offset','run_width','provenance','missing_provenance','contract'])
def test_source_extent_requires_complete_checked_partition(tmp_path,monkeypatch,change):
    target,_,declare=setup(tmp_path,monkeypatch);declare()
    owner=deepcopy(layout(target));elements=owner['elements']
    if change=='mixed':elements[1]['type_binding'].pop(FLAG)
    if change=='false':
        for e in elements:e['type_binding'][FLAG]=False
    if change=='source_width':elements[0]['provenance']['record_list_source_array']['width']+=2
    if change=='source_offset':elements[0]['provenance']['record_list_source_array']['offset']=2
    if change=='run_width':elements[1]['width']+=2
    if change=='provenance':elements[1]['provenance']['record_list_id']='different'
    if change=='missing_provenance':elements[1]['provenance']=None
    if change=='contract':elements[0]['type_binding'].pop('record_contract')
    with pytest.raises(ValueError,match='record list'):
        record_lists.preserved_list_owner_span(owner)


def test_legacy_or_unrelated_records_do_not_acquire_a_wider_owner(tmp_path,monkeypatch):
    target,_,declare=setup(tmp_path,monkeypatch);declare()
    owner=deepcopy(layout(target))
    for e in owner['elements']:e['type_binding'].pop(FLAG)
    assert record_lists.preserved_list_owner_span(owner)is None


def test_mixed_public_source_extent_is_not_a_uniform_header_array(tmp_path,monkeypatch,capfd):
    monkeypatch.setenv('AMIGA_REVERSING_PROFILE_TYPED_SOURCE_ARRAYS','1')
    _,_,declare=setup(tmp_path,monkeypatch);declare()
    lines=[line for line in capfd.readouterr().err.splitlines()
           if 'typed_source_array 'in line and 'offset=32 size=16 type=Header label=profiles 'in line]
    assert lines
    assert all('admitted=0 reason=member_contract_mismatch'in line for line in lines)

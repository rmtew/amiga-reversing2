"""A fixed BYTE field keeps its established custom-type span semantics."""
import pytest
from amiga_reversing.disasm.record_arrays import record_shape


def keyword_fields():
    return [dict(name='keyword', type='BYTE', offset=0, size=8),
            dict(name='implementation',type='LONG',offset=8,size=4,
                 value_kind='target_pointer',pointer_address_domain='mapped_source')]


def test_keyword_byte_span_reproduces_existing_type_shape():
    assert record_shape(dict(name='Keyword',size=12,fields=keyword_fields()))['fields']==keyword_fields()


@pytest.mark.parametrize('bad', [
    dict(name='empty',type='BYTE',offset=0,size=0),
    dict(name='outside',type='BYTE',offset=1,size=12),
    dict(name='wordArray',type='WORD',offset=0,size=4),
    dict(name='longArray',type='LONG',offset=0,size=8),
    dict(name='bytePointer',type='BYTE',offset=0,size=4,value_kind='target_pointer',pointer_address_domain='mapped_source'),
    dict(name='oddWord',type='WORD',offset=1,size=2),
])
def test_byte_spans_do_not_widen_other_field_contracts(bad):
    with pytest.raises(ValueError):record_shape(dict(name='Bad',size=12,fields=[bad]))


def test_byte_span_overlap_and_odd_byte_only_record():
    assert record_shape(dict(name='Bytes',size=5,fields=[dict(name='bytes',type='UBYTE',offset=1,size=3)]))['fields'][0]['size']==3
    with pytest.raises(ValueError,match='overlap'):
        record_shape(dict(name='Overlap',size=12,fields=keyword_fields()+[dict(name='inside',type='BYTE',offset=7,size=1)]))


def test_scoped_byte_span_record_roundtrip_history_and_known_code_refs(tmp_path,monkeypatch):
    from tests.test_disk_set_state import editable,data_request
    from tests.test_scoped_record_arrays import metadata
    from amiga_reversing.disasm.disk_set import DiskSet
    from amiga_reversing.disasm.disk_set_state import _artifact
    values=[0x1002,0,0xDEADBEEF,0x1002]
    content=b''.join(word.ljust(8,b'\0')+v.to_bytes(4,'big')for word,v in zip([b'go',b'stop',b'other',b'again'],values))
    project,target,paths,call=editable(tmp_path,monkeypatch,record_data=content+b'\xa5\x5a')
    before_import=(target/'analysis/main.target_metadata.json').read_bytes()
    selected=call('inspect',source_offset=4,end_offset=52,row_kind='data')
    call('interpret',**data_request(selected,'range.data_block.layout.create',dict(name='keywords',default_unit='byte')))
    selected=call('inspect',source_offset=4,end_offset=52,row_kind='data')
    request=data_request(selected,'range.data_block.records.declare',dict(record_type='Keyword',record_size=12,record_stride=12,record_count=4,fields=keyword_fields()))
    before=(target/'main.s').read_bytes();sibling=(target/'overlay.s').read_bytes()
    saved=call('interpret',**request);assert saved['verification']['media_exact']and saved['verification']['all_placement_coverage']
    text=(target/'main.s').read_text();assert text.count('dc.l finish')==2 and '$DEADBEEF'in text and 'dc.l $00000000'in text
    declared=next(t for t in metadata(target)['custom_structs']if t['name']=='Keyword');assert declared['fields'][0]['size']==8 and declared['fields'][0]['type']=='BYTE'
    owner=DiskSet.load(target,project_root=project);_,a=_artifact(owner,'main',paths)
    try:assert [x['source_offset']for x in a.query_payload('instructions',limit=100)['items']]==[0,2]
    finally:a.close()
    with pytest.raises(ValueError,match='revision'):call('interpret',**request)
    action=saved['actions'][0]['action_id'];assert any(x['action_id']==action for x in call('history')['items'])
    undone=call('rollback',expected_revision=saved['revision'],action_id=action);assert (target/'main.s').read_bytes()==before
    redone=call('rollback',expected_revision=undone['revision'],action_id=action,redo=True);assert (target/'main.s').read_text()==text and redone['verification']['media_exact']
    assert (target/'overlay.s').read_bytes()==sibling and (target/'analysis/main.target_metadata.json').read_bytes()==before_import


def test_scoped_odd_byte_span_and_atomic_extent_rejection(tmp_path,monkeypatch):
    from tests.test_disk_set_state import editable,data_request
    from tests.test_scoped_scalar_arrays import snapshot
    _,target,_,call=editable(tmp_path,monkeypatch,record_data=b'abcdefghij!')
    selected=call('inspect',source_offset=5,end_offset=15,row_kind='data')
    call('interpret',**data_request(selected,'range.data_block.layout.create',dict(name='byteRecords',default_unit='byte')))
    selected=call('inspect',source_offset=5,end_offset=15,row_kind='data');fields=[dict(name='span',type='UBYTE',offset=1,size=3)]
    req=data_request(selected,'range.data_block.records.declare',dict(record_type='ByteOnly',record_size=5,record_stride=5,record_count=2,fields=fields))
    saved=call('interpret',**req);assert saved['verification']['media_exact']
    selected=call('inspect',source_offset=5,end_offset=15,row_kind='data');bad=data_request(selected,'range.data_block.records.declare',dict(record_type='ByteOnly',record_size=5,record_stride=5,record_count=3,fields=fields));before=snapshot(target)
    with pytest.raises(ValueError,match='count|extent'):call('interpret',**bad)
    assert snapshot(target)==before

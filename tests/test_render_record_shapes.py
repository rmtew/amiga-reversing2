"""Packed address fields and sparse shared-action views use ordinary scoped records."""

from amiga_reversing.disasm.disk_set import DiskSet
from amiga_reversing.disasm.disk_set_state import _artifact
from tests.test_disk_set_state import data_request, editable
from tests.test_scoped_record_arrays import metadata


def declare(call, end, name, size, fields):
    selected = call('inspect', source_offset=4, end_offset=end, row_kind='data')
    call('interpret', **data_request(selected, 'range.data_block.layout.create',
        {'name': 'renderRecords', 'default_unit': 'word'}))
    selected = call('inspect', source_offset=4, end_offset=end, row_kind='data')
    return call('interpret', **data_request(selected, 'range.data_block.records.declare',
        {'record_type': name, 'record_size': size, 'record_count': (end-4)//size,
         'record_stride': size, 'fields': fields}))


def test_packed_twelve_byte_record_retains_even_long_address_and_sentinel_words(tmp_path, monkeypatch):
    fields = [{'name': n, 'type': 'WORD', 'offset': i*2, 'size': 2}
              for i, n in enumerate(('x', 'y', 'z'))] + [
        {'name': 'drawAddress', 'type': 'APTR', 'offset': 6, 'size': 4,
         'value_kind': 'target_pointer', 'pointer_address_domain': 'mapped_source'},
        {'name': 'stateOffsetOrMarker', 'type': 'UWORD', 'offset': 10, 'size': 2}]
    payload = b''.join(bytes.fromhex('000100020003') + pointer.to_bytes(4, 'big') + marker.to_bytes(2, 'big')
                       for pointer, marker in [(0, 0xF0F0), (0x1028, 20), (0xDEADBEEF, 40)])
    project, target, paths, call = editable(tmp_path, monkeypatch,
        record_data=payload+bytes.fromhex('c0deface'), record_label=(40, 'knownRenderData'))
    saved = declare(call, 40, 'PackedRenderRecord', 12, fields)
    assert saved['verification']['media_exact'] and saved['verification']['all_placement_coverage']
    data = metadata(target)
    record = next(t for t in data['custom_structs'] if t['name'] == 'PackedRenderRecord')
    assert record['fields'][3]['offset'] == 6 and record['size'] == 12
    text = (target/'main.s').read_text()
    assert 'PackedRenderRecord_drawAddress RS.L 1' in text
    assert 'dc.l knownRenderData' in text and '$DEADBEEF' in text and '$F0F0' in text
    owner = DiskSet.load(target, project_root=project)
    source, artifact = _artifact(owner, 'main', paths)
    try:
        assert [r['source_offset'] for r in artifact.query_payload('instructions', limit=100)['items']] == [0, 2]
        refs = artifact.query_payload('references', source_offset=22, direction='outgoing')['items']
        assert len(refs) == 1 and refs[0]['target_offset'] == 40
        assert refs[0]['provenance'] == 'typed_data_pointer'
        assert not artifact.query_payload('references', source_offset=10, direction='outgoing')['items']
        assert not artifact.query_payload('references', source_offset=34, direction='outgoing')['items']
    finally:
        artifact.close()


def test_sparse_twenty_byte_record_preserves_unknown_bytes_and_alias_on_replay(tmp_path, monkeypatch):
    fields = [{'name': 'gateWord12', 'type': 'WORD', 'offset': 12, 'size': 2},
              {'name': 'packedActionWord', 'type': 'UWORD', 'offset': 14, 'size': 2}]
    one = bytes.fromhex('4e75deadbeef112233445566ffff4020778899aa')
    assert len(one) == 20
    _, target, _, call = editable(tmp_path, monkeypatch,
        record_data=one+one, record_label=(6, 'keptUnknownBytes'))
    selected = call('inspect', source_offset=4, end_offset=44, row_kind='data')
    call('interpret', **data_request(selected, 'range.data_block.layout.create',
        {'name': 'renderRecords', 'default_unit': 'word'}))
    before = (target/'main.s').read_bytes()
    selected = call('inspect', source_offset=4, end_offset=44, row_kind='data')
    saved = call('interpret', **data_request(selected, 'range.data_block.records.declare',
        {'record_type': 'SparseActionRecord', 'record_size': 20, 'record_count': 2,
         'record_stride': 20, 'fields': fields}))
    after = (target/'main.s').read_bytes()
    assert b'keptUnknownBytes:' in after and b'dc.b' in after and b'dc.w' in after
    assert saved['verification']['media_exact'] and saved['verification']['all_placement_coverage']
    undone = call('rollback', expected_revision=saved['revision'], action_id=saved['actions'][0]['action_id'])
    assert (target/'main.s').read_bytes() == before
    redone = call('rollback', expected_revision=undone['revision'], action_id=saved['actions'][0]['action_id'], redo=True)
    assert (target/'main.s').read_bytes() == after
    generated = call('regenerate', expected_revision=redone['revision'])
    assert generated['verification']['member_sources_exact']
    assert any(t['name'] == 'SparseActionRecord' for t in metadata(target)['custom_structs'])

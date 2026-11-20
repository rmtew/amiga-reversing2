"""An inspected source layout root carries its owner through label rename."""
from dataclasses import replace

import pytest

from amiga_reversing.disasm.effective_metadata import _rename_manual_layout_owner
from amiga_reversing.disasm.target_metadata import DataBlockLayoutMetadata
from tests.test_disk_set_state import data_request, editable


def test_scoped_typed_root_rename_history_undo_and_exact_rebuild(tmp_path, monkeypatch):
    _, target, _, call = editable(tmp_path, monkeypatch,
        record_data=bytes.fromhex('00010002'), record_label=(4, 'oldRecord'))
    selected = call('inspect', source_offset=4, end_offset=8, row_kind='data')
    call('interpret', **data_request(selected, 'range.data_block.layout.create',
                                   {'name': 'oldRecord', 'default_unit': 'word'}))
    selected = call('inspect', source_offset=4, end_offset=8, row_kind='data')
    call('interpret', **data_request(selected, 'range.data_block.records.declare', {
        'record_type': 'Pair', 'record_size': 4, 'record_stride': 4, 'record_count': 1,
        'field_presentation': True, 'fields': [
            {'name': 'first', 'type': 'WORD', 'offset': 0, 'size': 2},
            {'name': 'second', 'type': 'WORD', 'offset': 2, 'size': 2}]}))
    before = (target/'main.s').read_bytes()
    prefix = (target/'analysis/main.manual_actions.jsonl').read_bytes()
    selected = call('inspect', source_offset=4, row_kind='label')
    assert selected['row']['source_label_layout_id']
    result = call('interpret', **data_request(selected, 'label.rename', {'name': 'newRecord'}))
    assert result['verification']['media_exact']
    assert 'newRecord:' in (target/'main.s').read_text()
    assert 'oldRecord:' not in (target/'main.s').read_text()
    assert (target/'analysis/main.manual_actions.jsonl').read_bytes().startswith(prefix)
    action = result['actions'][0]
    assert action['label']['data_block_layout_id'] == selected['row']['source_label_layout_id']
    undone = call('rollback', expected_revision=result['revision'], action_id=action['action_id'])
    assert (target/'main.s').read_bytes() == before
    assert undone['verification']['media_exact']


def test_layout_root_rename_requires_the_exact_source_identity():
    layout = DataBlockLayoutMetadata.from_dict({'layout_id': 'owner', 'hunk': 0,
        'source_start': 4, 'source_end': 8, 'name': 'old', 'default_unit': 'word',
        'seed_origin': 'manual_analysis', 'review_status': 'seeded', 'citation': 'Synthetic owner'})
    label = {'data_block_layout_id': 'owner', 'hunk': 0, 'addr': 4,
                 'previous_name': 'old', 'name': 'new', 'address_domain': 'source'}
    renamed, = _rename_manual_layout_owner([layout], label)
    assert renamed == replace(layout, name='new')
    assert _rename_manual_layout_owner([renamed], label) == [renamed]
    historical = dict(label); historical.pop('data_block_layout_id')
    assert _rename_manual_layout_owner([layout], historical) == [layout]
    for change in [{'addr': 5}, {'hunk': 1}, {'previous_name': 'foreign'},
                   {'data_block_layout_id': 'other'}, {'address_domain': 'runtime'},
                   {'previous_name': None}, {'name': None}, {'addr': None}]:
        with pytest.raises(ValueError, match='source|owner'):
            _rename_manual_layout_owner([layout], {**label, **change})
    with pytest.raises(ValueError, match='unique'):
        _rename_manual_layout_owner([layout, layout], label)

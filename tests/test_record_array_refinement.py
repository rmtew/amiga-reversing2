"""Checked record regrouping preserves a complete primitive grid and history."""

import copy

import pytest

from tests.test_disk_set_state import data_request, editable
from tests.test_scoped_record_arrays import create, metadata
from tests.test_scoped_scalar_arrays import array_request, snapshot

FIELDS = [dict(name=n, type='WORD', offset=i*2, size=2)
          for i, n in enumerate(('x', 'y', 'z', 'screenX', 'screenY'))]


def request(call, **updates):
    selected = call('inspect', source_offset=4, end_offset=24, row_kind='data')
    params = dict(record_type='ProjectedPoint', record_size=10, record_count=2,
                  record_stride=10, fields=copy.deepcopy(FIELDS))
    params.update(updates)
    return data_request(selected, 'range.data_block.records.declare', params)


def test_complete_word_grid_refinement_retains_annotation_replay_and_undo(tmp_path, monkeypatch):
    _, target, _, call = editable(tmp_path, monkeypatch, scalar_array=True)
    create(call, 24)
    call('interpret', **array_request(call, end=24, stride=2, count=10, name='inputWords'))
    prior = metadata(target)['data_block_layouts'][-1]['elements'][0]
    before = (target/'main.s').read_bytes()
    saved = call('interpret', **request(call))
    element = metadata(target)['data_block_layouts'][-1]['elements'][0]
    assert element['provenance']['primitive_array_refinement'] == prior
    assert element['name'] == 'inputWords'
    assert saved['verification']['media_exact'] and saved['verification']['all_placement_coverage']
    after = (target/'main.s').read_bytes()
    assert b'existingArrayWord:' in after and b'ProjectedPoint_screenX' in after
    action = saved['actions'][0]['action_id']
    undone = call('rollback', expected_revision=saved['revision'], action_id=action)
    assert (target/'main.s').read_bytes() == before
    redone = call('rollback', expected_revision=undone['revision'], action_id=action, redo=True)
    assert (target/'main.s').read_bytes() == after
    call('regenerate', expected_revision=redone['revision'])
    assert metadata(target)['data_block_layouts'][-1]['elements'][0]['provenance'] == element['provenance']
    call('interpret', **request(call))
    assert (target/'main.s').read_bytes() == after
    assert metadata(target)['data_block_layouts'][-1]['elements'][0]['provenance'] == element['provenance']


@pytest.mark.parametrize('fields', [
    FIELDS[:-1],  # a gap would discard a primitive footprint
    [dict(name='wide', type='LONG', offset=0, size=4)] + FIELDS[2:],
    [dict(name='address', type='APTR', offset=0, size=4,
          value_kind='target_pointer', pointer_address_domain='mapped_source')] + FIELDS[2:],
])
def test_refinement_rejects_changed_leaf_grid_atomically(tmp_path, monkeypatch, fields):
    _, target, _, call = editable(tmp_path, monkeypatch, scalar_array=True)
    create(call, 24)
    call('interpret', **array_request(call, end=24, stride=2, count=10))
    before = snapshot(target)
    with pytest.raises(ValueError, match='primitive array grid'):
        call('interpret', **request(call, fields=fields))
    assert snapshot(target) == before


def test_refinement_rejects_partial_array_even_when_fields_fit(tmp_path, monkeypatch):
    _, target, _, call = editable(tmp_path, monkeypatch, scalar_array=True)
    create(call, 24)
    call('interpret', **array_request(call, end=24, stride=2, count=10))
    selected = call('inspect', source_offset=4, end_offset=14, row_kind='data')
    body = data_request(selected, 'range.data_block.records.declare', dict(
        record_type='ProjectedPoint', record_size=10, record_count=1,
        record_stride=10, fields=FIELDS))
    before = snapshot(target)
    with pytest.raises(ValueError, match='primitive array grid'):
        call('interpret', **body)
    assert snapshot(target) == before


def test_refinement_provenance_is_rechecked_against_actual_prior_grid():
    from amiga_reversing.disasm.record_arrays import validate_record_array

    shape = dict(name='Pair', size=4, fields=FIELDS[:2])
    prior = dict(layout_id='owner', offset=0, width=8, kind='array',
                 array_count=4, array_stride=2, type_binding=None)
    binding = dict(binding_kind='custom_struct', bound_type_id='Pair',
                   record_contract=shape, array_count=2, element_offset=0,
                   element_width=8, layout_id='owner')
    element = dict(layout_id='owner', offset=0, width=8, kind='array',
                   array_count=2, array_stride=4, type_binding=binding)
    layout = dict(source_start=4, source_end=12, elements=[prior])
    validate_record_array(element, shape, layout)
    element['provenance']['primitive_array_refinement']['array_stride'] = 4
    with pytest.raises(ValueError, match='provenance differs'):
        validate_record_array(element, shape, layout)


def test_refinement_does_not_silently_drop_array_display_representation(tmp_path, monkeypatch):
    _, target, _, call = editable(tmp_path, monkeypatch, scalar_array=True)
    create(call, 24)
    call('interpret', **array_request(call, end=24, stride=2, count=10,
                                    representation='decimal'))
    before = snapshot(target)
    with pytest.raises(ValueError, match='primitive array grid'):
        call('interpret', **request(call))
    assert snapshot(target) == before

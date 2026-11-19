"""Explicit record fields retain checked ownership without legacy byte packing."""
import copy
import re
import pytest

from tests.test_disk_set_state import editable, data_request
from tests.test_scoped_record_arrays import metadata
from tests.test_scoped_scalar_arrays import snapshot

FIELDS = [dict(name=n, type='WORD', offset=i * 2, size=2)
          for i, n in enumerate(('x', 'y'))]


def setup(tmp_path, monkeypatch, *, legacy_text=False):
    project, target, paths, call = editable(
        tmp_path, monkeypatch, record_data=bytes.fromhex('000a005a') + b'Hello\0\xa5\x5a',
        record_scalar_label=(6, 'initialY', 2),
        record_legacy_text=legacy_text,
        entry_comments=[dict(hunk=0, addr=6, comment='Keep this independent field comment',
            seed_origin='manual_analysis', review_status='seeded', citation='Synthetic imported comment')])
    selected = call('inspect', source_offset=4, end_offset=8, row_kind='data')
    call('interpret', **data_request(selected, 'range.data_block.layout.create',
                                    dict(name='coordinates', default_unit='byte')))
    call('interpret', **request(call))
    if legacy_text:
        selected = call('inspect', source_offset=8, end_offset=14, row_kind='data')
        call('interpret', **data_request(selected, 'range.seed.data.string', {}))
    return project, target, paths, call


def request(call, **updates):
    selected = call('inspect', source_offset=4, end_offset=8, row_kind='data')
    params = dict(record_type='Point', record_size=4, record_count=1,
                  record_stride=4, fields=copy.deepcopy(FIELDS))
    params.update(updates)
    return data_request(selected, 'range.data_block.records.declare', params)


@pytest.mark.parametrize('legacy_text', [False, True])
def test_explicit_fields_upgrade_same_record_roundtrip_history_and_names(tmp_path, monkeypatch, legacy_text):
    project, target, paths, call = setup(tmp_path, monkeypatch, legacy_text=legacy_text)
    compact = (target / 'main.s').read_bytes()
    sibling = (target / 'overlay.s').read_bytes()
    imported = (target / 'analysis/main.target_metadata.json').read_bytes()
    previous = metadata(target)['data_block_layouts'][-1]['elements'][0]
    stale = request(call, field_presentation=True)
    saved = call('interpret', **stale)
    text = (target / 'main.s').read_text()
    assert re.search(r'dc\.w\s+\$000A\b', text)
    assert re.search(r'dc\.w\s+\$005A\b', text)
    assert 'coordinates:' in text and 'initialY:' in text
    assert 'Keep this independent field comment' in text
    if legacy_text:
        assert '"Hello",$00' in text and '"ZHello"' not in text
    element = metadata(target)['data_block_layouts'][-1]['elements'][0]
    binding = element['type_binding']
    assert binding['record_field_presentation'] is True
    assert binding['record_preserve_scalar_names'] is True
    assert binding['record_contract'] == previous['type_binding']['record_contract']
    assert binding['type_binding_id'] == previous['type_binding']['type_binding_id']
    assert binding['owner_action_id'] == saved['actions'][0]['action_id']
    assert element['provenance'] == previous['provenance']
    assert saved['verification']['media_exact'] and saved['verification']['all_placement_coverage']
    with pytest.raises(ValueError, match='revision'):
        call('interpret', **stale)
    undone = call('rollback', expected_revision=saved['revision'],
                  action_id=saved['actions'][0]['action_id'])
    assert (target / 'main.s').read_bytes() == compact
    redone = call('rollback', expected_revision=undone['revision'],
                  action_id=saved['actions'][0]['action_id'], redo=True)
    assert (target / 'main.s').read_text() == text
    call('regenerate', expected_revision=redone['revision'])
    call('interpret', **request(call, field_presentation=True))
    assert (target / 'main.s').read_text() == text
    # Legacy reauthoring cannot silently erase the explicit field contract.
    call('interpret', **request(call))
    assert (target / 'main.s').read_text() == text
    assert (target / 'overlay.s').read_bytes() == sibling
    assert (target / 'analysis/main.target_metadata.json').read_bytes() == imported
    from amiga_reversing.disasm.disk_set import DiskSet
    from amiga_reversing.disasm.disk_set_state import _artifact
    owner = DiskSet.load(target, project_root=project)
    _, artifact = _artifact(owner, 'main', paths)
    try:
        assert [r['source_offset'] for r in artifact.query_payload('instructions', limit=100)['items']] == [0, 2]
    finally:
        artifact.close()


@pytest.mark.parametrize('changes', [dict(field_presentation=False),
    dict(field_presentation=1), dict(field_presentation='fields'),
    dict(field_presentation=True, record_count=2)])
def test_field_presentation_does_not_relax_shape_or_parameter_checks(tmp_path, monkeypatch, changes):
    _, target, _, call = setup(tmp_path, monkeypatch)
    before = snapshot(target)
    with pytest.raises(ValueError):
        call('interpret', **request(call, **changes))
    assert snapshot(target) == before


def test_field_presentation_cannot_reinterpret_existing_primitive_grid(tmp_path, monkeypatch):
    from tests.test_scoped_record_arrays import create
    from tests.test_scoped_scalar_arrays import array_request
    _, target, _, call = editable(tmp_path, monkeypatch, scalar_array=True)
    create(call, 24)
    call('interpret', **array_request(call, end=24, stride=2, count=10))
    selected = call('inspect', source_offset=4, end_offset=24, row_kind='data')
    req = data_request(selected, 'range.data_block.records.declare', dict(
        record_type='Wide', record_size=4, record_count=5, record_stride=4,
        fields=[dict(name='value', type='LONG', offset=0, size=4)], field_presentation=True))
    before = snapshot(target)
    with pytest.raises(ValueError, match='primitive array grid'):
        call('interpret', **req)
    assert snapshot(target) == before

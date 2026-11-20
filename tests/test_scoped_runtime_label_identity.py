"""Renaming a declared runtime identity must not silently add a source alias."""

from tests.test_disk_set_state import data_request, editable
from tests.test_scoped_record_arrays import metadata as effective_metadata


def test_repeated_scoped_runtime_rename_preserves_domain_history_and_undo(tmp_path, monkeypatch):
    _, target, _, call = editable(tmp_path, monkeypatch, owner_scope=True)
    selected = call('inspect', source_offset=4, row_kind='label')
    first = call('interpret', **data_request(selected, 'label.rename', {'name': 'oldName'}))
    before = (target/'main.s').read_bytes()
    prefix = (target/'analysis/main.manual_actions.jsonl').read_bytes()
    selected = call('inspect', source_offset=4, row_kind='label')
    result = call('interpret', **data_request(selected, 'label.rename', {'name': 'newName'}))
    metadata = effective_metadata(target)
    labels = [r for r in metadata['absolute_code_labels'] if r['addr'] == 0x1004]
    assert [r['name'] for r in labels] == ['newName']
    assert not [r for r in metadata['seeded_code_labels'] if r['addr'] == 4]
    assert 'oldName:' not in (target/'main.s').read_text()
    assert (target/'analysis/main.manual_actions.jsonl').read_bytes().startswith(prefix)
    action, = result['actions']
    assert action['label']['address_domain'] == 'runtime'
    assert action['label']['addr'] == 0x1004
    assert action['label']['label_id'] == first['actions'][0]['label']['label_id']
    undone = call('rollback', expected_revision=result['revision'], action_id=action['action_id'])
    assert (target/'main.s').read_bytes() == before
    redone = call('rollback', expected_revision=undone['revision'], action_id=action['action_id'], redo=True)
    checked = call('verify', expected_revision=redone['revision'], output=str(tmp_path/'verified'))
    assert checked['verification']['exact'] and checked['coverage']['complete']


def test_declared_runtime_rename_cannot_silently_become_a_source_local(tmp_path, monkeypatch):
    import pytest

    from tests.test_scoped_scalar_arrays import snapshot

    _, target, _, call = editable(tmp_path, monkeypatch, owner_scope=True)
    selected = call('inspect', source_offset=4, row_kind='label')
    call('interpret', **data_request(selected, 'label.rename', {'name': 'runtimeName'}))
    selected = call('inspect', source_offset=4, row_kind='label')
    before = snapshot(target)
    with pytest.raises(ValueError, match='runtime label rename preserves its address domain'):
        call('interpret', **data_request(selected, 'label.rename',
            {'name': '.local', 'scope': 'local', 'owner_offset': 0}))
    assert snapshot(target) == before


def test_identity_uses_native_runtime_coordinate_and_keeps_comments():
    from amiga_reversing.disasm.listing_context import (
        annotate_source_label_identity,
        listing_element_contexts,
    )

    row = {'kind': 'label', 'label': 'runtimeName', 'section_index': 2,
           'start_offset': 4, 'runtime_address': 0x9000}
    annotate_source_label_identity(row, [], [
        {'name': 'runtimeName', 'addr': 0x9000, 'comment': 'Original comment'}])
    context, = listing_element_contexts(row)
    assert context['canonical_symbol_address_domain'] == 'runtime'
    assert context['canonical_symbol_address'] == 0x9000
    assert context['canonical_symbol_hunk'] == 2
    assert context['source_label_comment'] == 'Original comment'


def test_source_identity_wins_only_at_its_exact_coordinate():
    from amiga_reversing.disasm.listing_context import annotate_source_label_identity

    row = {'kind': 'label', 'label': 'abs_0_00001004', 'section_index': 0,
           'start_offset': 4, 'runtime_address': 0x1004}
    annotate_source_label_identity(row, [{'hunk': 0, 'addr': 4, 'name': row['label']}])
    assert row['canonical_label_address_domain'] == 'source'
    assert row['canonical_label_address'] == 4


def test_coincident_source_and_runtime_identities_fail_closed():
    from amiga_reversing.disasm.listing_context import annotate_source_label_identity

    row = {'kind': 'label', 'label': 'same', 'section_index': 0,
           'start_offset': 4, 'runtime_address': 0x1004}
    annotate_source_label_identity(row, [{'hunk': 0, 'addr': 4, 'name': 'same'}],
                                   [{'addr': 0x1004, 'name': 'same'}])
    assert row['canonical_label_ambiguous']
    assert 'canonical_label_address_domain' not in row


def test_missing_or_wrong_native_runtime_coordinate_is_not_guessed():
    from amiga_reversing.disasm.listing_context import annotate_source_label_identity

    for coordinate in [None, 0x2004]:
        row = {'kind': 'label', 'label': 'runtimeName', 'section_index': 0,
               'start_offset': 4, 'runtime_address': coordinate}
        annotate_source_label_identity(row, [], [{'addr': 0x1004, 'name': 'runtimeName'}])
        assert row['canonical_label_ambiguous']
        assert 'canonical_label_address_domain' not in row


def test_imported_data_name_resembling_generated_runtime_symbol_keeps_source_domain(tmp_path, monkeypatch):
    _, target, _, call = editable(tmp_path, monkeypatch, record_data=bytes(16),
                                  record_label=(4, 'abs_0_00001004'))
    selected = call('inspect', source_offset=4, row_kind='label')
    saved = call('interpret', **data_request(selected, 'label.rename', {'name': 'dataName'}))
    current = effective_metadata(target)
    assert saved['actions'][0]['label']['address_domain'] == 'source'
    named = [e for e in current['seeded_entities'] if e.get('name') == 'dataName']
    assert len(named) == 1 and named[0]['addr'] == 4 and named[0]['end'] == 8
    assert named[0]['unit'] == 'byte' and named[0]['subtype'] == 'opaque_data'
    assert 'pre-existing data anchor' in named[0]['citation']
    assert not [e for e in current['absolute_code_labels'] if e['addr'] == 0x1004]


def test_imported_runtime_label_is_replaced_without_rewriting_immutable_state(tmp_path, monkeypatch):
    from amiga_reversing.disasm.disk_set import DiskSet

    _, target, _, call = editable(tmp_path, monkeypatch, owner_scope=True, runtime_labels=[
        {'addr': 0x1004, 'name': 'importedRuntime', 'seed_origin': 'manual_analysis',
         'review_status': 'seeded', 'citation': 'Immutable imported runtime identity'}])
    owner = DiskSet.load(target, project_root=target.parent.parent)
    baseline = target/owner.members['main']['analysis']['state']['target_metadata.json']['path']
    original = baseline.read_bytes()
    selected = call('inspect', source_offset=4, row_kind='label')
    saved = call('interpret', **data_request(selected, 'label.rename', {'name': 'correctRuntime'}))
    current = effective_metadata(target)
    assert [d['name'] for d in current['absolute_code_labels'] if d['addr'] == 0x1004] == ['correctRuntime']
    assert not [d for d in current['seeded_code_labels'] if d['addr'] == 4]
    assert baseline.read_bytes() == original
    assert saved['verification']['media_exact']

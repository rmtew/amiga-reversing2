"""Correct a merged legacy opaque view only against its exact frozen import."""
import copy
import json

import pytest

from amiga_reversing.disasm.disk_set import DiskSet
from tests.test_disk_set_state import data_request, editable

COMMAND = 'correction.suppress_seeded_item.seeded_entity'


def prepared(tmp_path, monkeypatch):
    seed = {'hunk': 0, 'addr': 4, 'end': 20, 'type': 'data', 'unit': 'byte',
            'subtype': 'opaque_data', 'seed_origin': 'manual_analysis', 'review_status': 'seeded',
            'source_id': 'fixture-import', 'citation': 'Imported uninterpreted bytes'}
    project, target, _, call = editable(tmp_path, monkeypatch, record_data=bytes(16), record_imports=[seed])
    selected = call('inspect', source_offset=4, end_offset=20, row_kind='data')
    call('interpret', **data_request(selected, 'range.data_block.layout.create',
                                   {'name': 'wordChoices', 'default_unit': 'word'}))
    selected = call('inspect', source_offset=4, end_offset=20, row_kind='data')
    call('interpret', **data_request(selected, 'range.data_block.element.set',
                                   {'kind': 'array', 'width': 16, 'array_count': 8, 'array_stride': 2}))
    return project, target, call


def test_merged_opaque_array_correction_replays_and_undoes_exactly(tmp_path, monkeypatch):
    _, target, call = prepared(tmp_path, monkeypatch)
    before = (target/'main.s').read_bytes()
    assert b'opaque_data' in before
    original = (target/'analysis/main.target_metadata.json').read_bytes()
    selected = call('inspect', source_offset=4, row_kind='data')
    assert COMMAND in {r['command_id'] for r in selected['commands']}
    saved = call('interpret', **data_request(selected, COMMAND, {}))
    assert saved['verification']['media_exact']
    after = (target/'main.s').read_bytes()
    assert b'opaque_data' not in after and b'wordChoices:' in after and b'dcb.w $8' in after
    assert (target/'analysis/main.target_metadata.json').read_bytes() == original
    action = saved['actions'][0]['action_id']
    undone = call('rollback', expected_revision=saved['revision'], action_id=action)
    assert (target/'main.s').read_bytes() == before
    call('rollback', expected_revision=undone['revision'], action_id=action, redo=True)
    assert (target/'main.s').read_bytes() == after


@pytest.mark.parametrize('change', ['original_name', 'original_comment', 'original_type',
    'original_owner', 'original_manual', 'current_comment', 'current_pointer',
    'current_other_name', 'current_provenance', 'duplicate_original', 'partial', 'array_stride',
    'unknown_metadata', 'runtime_view'])
def test_opaque_refinement_does_not_erase_independent_or_partial_facts(tmp_path, monkeypatch, change):
    from amiga_reversing.disasm.disk_set_state import _conflicting_array_opaque_seed

    project, target, _ = prepared(tmp_path, monkeypatch)
    owner = DiskSet.load(target, project_root=project)
    a = owner.members['main']['analysis']
    current = json.loads((target/a['metadata']['path']).read_bytes())
    baseline = json.loads((target/a['state']['target_metadata.json']['path']).read_bytes())
    layout = current['data_block_layouts'][0]
    old = next(e for e in baseline['seeded_entities'] if e['addr'] == 4)
    new = next(e for e in current['seeded_entities'] if e['addr'] == 4)
    row = {'start_offset': 4, 'end_offset': 20}
    if change == 'original_name': old['name'] = 'independent'
    if change == 'original_comment': old['comment'] = 'Authored meaning'
    if change == 'original_type': old['c_type'] = 'BYTE'
    if change == 'original_owner': old['source_owner_start'] = 0
    if change == 'original_manual': old['source_id'] = 'manual_action_log'
    if change == 'current_comment': new['comment'] = 'Authored meaning'
    if change == 'current_pointer': new['value_kind'] = 'target_pointer'
    if change == 'current_other_name': new['name'] = 'independent'
    if change == 'current_provenance': new['citation'] = 'Authored meaning'
    if change == 'duplicate_original': baseline['seeded_entities'].append(copy.deepcopy(old))
    if change == 'partial': row['end_offset'] = 18
    if change == 'array_stride': layout['elements'][0]['array_stride'] = 4
    if change == 'unknown_metadata': old['future_semantic_fact'] = 'independent'
    if change == 'runtime_view': layout['runtime_start'] = 0x1000
    assert _conflicting_array_opaque_seed(row, layout, current, baseline) is None


def test_exact_fingerprint_keeps_same_span_authored_replacement_and_old_wire_shape():
    from dataclasses import replace

    from amiga_reversing.disasm.target_metadata import (
        SeededEntityMetadata,
        SuppressedSeededItemMetadata,
        TargetMetadata,
        apply_suppressed_seeded_items,
        seeded_entity_fingerprint,
        target_metadata_json_payload,
    )
    original = SeededEntityMetadata.from_dict({'hunk': 0, 'addr': 4, 'end': 20,
        'type': 'data', 'unit': 'byte', 'subtype': 'opaque_data', 'seed_origin': 'manual_analysis',
        'review_status': 'seeded', 'citation': 'Imported bytes', 'source_id': 'fixture-import'})
    replacement = replace(original, unit='word', subtype=None, name='newArray',
                          source_id='manual_action_log', citation='manual_action_log:array')
    identity = {'kind': 'seeded_entity', 'hunk': 0, 'addr': 4, 'end': 20}
    legacy = SuppressedSeededItemMetadata.from_dict(identity)
    exact = SuppressedSeededItemMetadata.from_dict({**identity, 'source_fingerprint': seeded_entity_fingerprint(original)})
    metadata = TargetMetadata(target_type='program', entry_register_seeds=(),
                              seeded_entities=(original, replacement))
    assert apply_suppressed_seeded_items(metadata, (exact,)).seeded_entities == (replacement,)
    assert not apply_suppressed_seeded_items(metadata, (legacy,)).seeded_entities
    payload = target_metadata_json_payload(replace(metadata, suppressed_seeded_items=(legacy,)))
    assert json.loads(json.dumps(payload))['suppressed_seeded_items'] == [identity]


def test_correction_does_not_accept_a_forged_fingerprint(tmp_path, monkeypatch):
    _, target, call = prepared(tmp_path, monkeypatch)
    selected = call('inspect', source_offset=4, row_kind='data')
    prefix = (target/'analysis/main.manual_actions.jsonl').read_bytes()
    with pytest.raises(ValueError, match='suppressible seeded item'):
        call('interpret', **data_request(selected, COMMAND, {'source_fingerprint': '0'*64}))
    assert (target/'analysis/main.manual_actions.jsonl').read_bytes() == prefix

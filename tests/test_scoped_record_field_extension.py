"""Explicit gap-field extension preserves old record witnesses and history."""

import copy

import pytest

from tests.test_disk_set_state import editable
from tests.test_scoped_record_arrays import FIELDS, create, metadata, request
from tests.test_scoped_scalar_arrays import snapshot


def initial(tmp_path, monkeypatch):
    project, target, paths, call = editable(tmp_path, monkeypatch, scalar_array=True)
    create(call)
    saved = call('interpret', **request(call, fields=copy.deepcopy(FIELDS[:1])))
    return project, target, paths, call, saved


def test_extend_only_unknown_gap_keeps_identity_bytes_history_and_undo(tmp_path, monkeypatch):
    _, target, _, call, first = initial(tmp_path, monkeypatch)
    prior = metadata(target)['data_block_layouts'][-1]['elements'][0]
    prefix = (target/'analysis/main.manual_actions.jsonl').read_bytes()
    before = (target/'main.s').read_bytes()
    sibling = (target/'overlay.s').read_bytes()
    result = call('interpret', **request(call, extend_fields=True))
    action, = result['actions']
    assert action['kind'] == 'extend_manual_record_array'
    current = metadata(target)['data_block_layouts'][-1]['elements'][0]
    assert current['type_binding']['type_binding_id'] == prior['type_binding']['type_binding_id']
    assert current['type_binding']['owner_action_id'] == prior['type_binding']['owner_action_id']
    extension, = current['type_binding']['record_field_extensions']
    assert extension['prior_record_contract'] == prior['type_binding']['record_contract']
    assert extension['action_id'] == action['action_id']
    assert current['type_binding']['record_contract']['fields'] == FIELDS
    assert (target/'analysis/main.manual_actions.jsonl').read_bytes().startswith(prefix)
    assert (target/'overlay.s').read_bytes() == sibling
    assert result['verification']['media_exact']
    rendered = (target/'main.s').read_bytes()
    undone = call('rollback', expected_revision=result['revision'], action_id=action['action_id'])
    assert (target/'main.s').read_bytes() == before
    redone = call('rollback', expected_revision=undone['revision'], action_id=action['action_id'], redo=True)
    assert (target/'main.s').read_bytes() == rendered
    assert call('regenerate', expected_revision=redone['revision'])['verification']['media_exact']
    assert first['actions'][0]['action_id'] == prior['type_binding']['owner_action_id']


@pytest.mark.parametrize('change', ['ordinary_declare', 'rename_old', 'reinterpret_old',
                                   'size', 'count', 'stride', 'no_new_field', 'overlap'])
def test_extension_cannot_reinterpret_resize_or_replace_existing_facts(tmp_path, monkeypatch, change):
    _, target, _, call, _ = initial(tmp_path, monkeypatch)
    params = {'extend_fields': True}
    if change == 'ordinary_declare':
        params = {}
    elif change == 'rename_old':
        params['fields'] = [{**FIELDS[0], 'name': 'other'}, FIELDS[1]]
    elif change == 'reinterpret_old':
        params['fields'] = [{**FIELDS[0], 'type': 'WORD'}, FIELDS[1]]
    elif change in {'size', 'count', 'stride'}:
        params['record_'+change] = {'size': 8, 'count': 6, 'stride': 2}[change]
    elif change == 'no_new_field':
        params['fields'] = FIELDS[:1]
    elif change == 'overlap':
        params['fields'] = [FIELDS[0], {**FIELDS[1], 'offset': 0}]
    selected = request(call, **params)
    before = snapshot(target)
    with pytest.raises(ValueError, match='record|array'):
        call('interpret', **selected)
    assert snapshot(target) == before


def test_type_shared_by_another_binding_is_not_changed_from_one_selection(tmp_path, monkeypatch):
    from tests.test_disk_set_state import data_request

    _, target, _, call = editable(tmp_path, monkeypatch, scalar_array=True)
    create(call, end=16)
    call('interpret', **request(call, end=16, fields=FIELDS[:1]))
    selected = call('inspect', source_offset=16, end_offset=32, row_kind='data')
    call('interpret', **data_request(selected, 'range.data_block.layout.create',
                                    {'name': 'otherRecords', 'default_unit': 'word'}))
    selected = call('inspect', source_offset=16, end_offset=32, row_kind='data')
    call('interpret', **data_request(selected, 'range.data_block.records.declare',
        {'record_type': 'Pair', 'record_size': 4, 'record_count': 4, 'record_stride': 4,
         'fields': FIELDS[:1]}))
    selected = request(call, end=16, extend_fields=True)
    before = snapshot(target)
    with pytest.raises(ValueError, match='exclusive array binding'):
        call('interpret', **selected)
    assert snapshot(target) == before


@pytest.mark.parametrize('change', ['prior', 'new_name', 'new_provenance'])
def test_normal_replay_refuses_tampered_prior_or_replacement_witness(tmp_path, monkeypatch, change):
    from amiga_reversing.disasm.disk_set import DiskSet
    from amiga_reversing.disasm.disk_set_state import (
        _artifact,
        _prepare_member_interpretation,
        state_context,
    )
    from amiga_reversing.disasm.manual_actions import (
        ManualActionKind,
        append_manual_actions,
    )

    project, target, paths, call, _ = initial(tmp_path, monkeypatch)
    selected = request(call, extend_fields=True)
    owner = DiskSet.load(target, project_root=project)
    source, artifact = _artifact(owner, 'main', paths)
    try:
        actions = _prepare_member_interpretation(owner, 'main', selected, artifact=artifact, source=source)
    finally:
        artifact.close()
    kind, payload = copy.deepcopy(actions[0])
    if change == 'prior':
        payload['prior_binding']['type_binding']['record_contract']['fields'][0]['name'] = 'forged'
    elif change == 'new_name':
        payload['data_block_element']['name'] = 'forged'
    else:
        payload['data_block_element']['provenance'] = {'forged': True}
    before = snapshot(target)
    with state_context(owner, 'main'), pytest.raises(ValueError, match='binding witness'):
        append_manual_actions(target, binary_source=source,
                              actions=[(ManualActionKind(kind), payload)])
    assert snapshot(target) == before


def test_member_only_extension_rehashes_bytes_and_cannot_claim_disk_proof(tmp_path, monkeypatch):
    from pathlib import Path

    from amiga_reversing.disasm import restoration
    from amiga_reversing.disasm.disk_set import DiskSet

    project, target, paths, _, _ = initial(tmp_path, monkeypatch)
    owner = DiskSet.load(target, project_root=project)
    member = tmp_path/'main.bin'
    member.write_bytes(owner.recover(paths)[0]['main'])
    for path in paths.values():
        Path(path).unlink()

    def call(operation, **body):
        return restoration.execute(target.name, {'operation': operation, 'member_id': 'main',
            'input_mode': 'member', 'member_paths': {'main': str(member)}, **body})

    selected = request(call, extend_fields=True)
    before = snapshot(target)
    original = member.read_bytes()
    member.write_bytes(bytes([original[0] ^ 1]) + original[1:])
    with pytest.raises(ValueError, match='SHA-256|member'):
        call('interpret', **selected)
    assert snapshot(target) == before
    member.write_bytes(original)
    saved = call('interpret', **selected)
    assert saved['verification']['verification_scope'] == 'member'
    assert saved['verification']['media_exact'] is None
    assert saved['verification']['all_placement_coverage'] is None
    assert call('verify_member', expected_revision=saved['revision'],
                output=str(tmp_path/'proof'))['verification']['media_verification'] == 'not_performed'


@pytest.mark.parametrize('flag', [False, 0, 1, 'true', None])
def test_extension_requires_explicit_true(tmp_path, monkeypatch, flag):
    _, target, _, call, _ = initial(tmp_path, monkeypatch)
    selected = request(call, extend_fields=flag)
    before = snapshot(target)
    with pytest.raises(ValueError, match='explicit true'):
        call('interpret', **selected)
    assert snapshot(target) == before


def test_repeated_extension_retains_chain_and_refuses_out_of_order_undo(tmp_path, monkeypatch):
    _, target, _, call = editable(tmp_path, monkeypatch, scalar_array=True)
    create(call, end=28)
    shape = {'record_type': 'Wider', 'record_size': 8, 'record_stride': 8, 'record_count': 3}
    call('interpret', **request(call, end=28, fields=FIELDS[:1], **shape))
    first = call('interpret', **request(call, end=28, fields=FIELDS,
                                       extend_fields=True, **shape))
    pointer = {'name': 'dataAddress', 'type': 'APTR', 'offset': 4, 'size': 4,
               'value_kind': 'target_pointer', 'pointer_address_domain': 'mapped_source'}
    second = call('interpret', **request(call, end=28, fields=[*FIELDS, pointer],
                                        extend_fields=True, **shape))
    first_id, second_id = first['actions'][0]['action_id'], second['actions'][0]['action_id']
    current = metadata(target)['data_block_layouts'][-1]['elements'][0]
    assert [e['action_id'] for e in current['type_binding']['record_field_extensions']] == [first_id, second_id]
    assert current['type_binding']['record_contract']['fields'][-1] == pointer
    text, before = (target/'main.s').read_bytes(), snapshot(target)
    with pytest.raises(ValueError, match='prior binding witness'):
        call('rollback', expected_revision=second['revision'], action_id=first_id)
    assert snapshot(target) == before
    undone = call('rollback', expected_revision=second['revision'], action_id=second_id)
    undone = call('rollback', expected_revision=undone['revision'], action_id=first_id)
    redone = call('rollback', expected_revision=undone['revision'], action_id=first_id, redo=True)
    call('rollback', expected_revision=redone['revision'], action_id=second_id, redo=True)
    assert (target/'main.s').read_bytes() == text

"""Heterogeneous lists reuse the checked record renderer and atomic history."""
import copy
import pytest

from tests.test_disk_set_state import editable, data_request
from tests.test_scoped_record_arrays import create, metadata
from tests.test_scoped_scalar_arrays import array_request, snapshot

TYPES = [dict(name='Pair', size=4, fields=[dict(name='x',type='WORD',offset=0,size=2),dict(name='y',type='WORD',offset=2,size=2)]),
         dict(name='Triple', size=6, fields=[dict(name=n,type='WORD',offset=i*2,size=2)for i,n in enumerate(['a','b','c'])])]
RUNS = [dict(record_type='Pair',count=1),dict(record_type='Triple',count=1),dict(record_type='Pair',count=1)]


def setup(tmp_path, monkeypatch):
    _, target, _, call = editable(tmp_path,monkeypatch,
        record_data=bytes.fromhex('0001000200030004000500060007'),record_label=(10,'sharedInteriorWord'))
    create(call,18)
    call('interpret',**array_request(call,end=18,stride=2,count=7,name='keptWordOwner'))
    return target,call


def request(call,types=None,runs=None,end=18):
    i=call('inspect',source_offset=4,end_offset=end,row_kind='data')
    return data_request(i,'range.data_block.record_list.declare',dict(record_types=copy.deepcopy(TYPES if types is None else types),runs=copy.deepcopy(RUNS if runs is None else runs)))


def test_mixed_list_alias_provenance_exact_replay_undo_and_idempotence(tmp_path,monkeypatch):
    target,call=setup(tmp_path,monkeypatch)
    prior=metadata(target)['data_block_layouts'][-1]['elements'][0]
    before=(target/'main.s').read_bytes()
    saved=call('interpret',**request(call));after=(target/'main.s').read_bytes()
    assert saved['verification']['media_exact']and saved['verification']['all_placement_coverage']
    assert b'sharedInteriorWord:'in after and b'Pair_x'in after and b'Triple_b'in after
    assert b'dc.b' not in after
    assert b'keptWordOwner:' in after
    assert b'; x' in after and b'; y' in after and b'; a' in after and b'; c' in after
    elements=metadata(target)['data_block_layouts'][-1]['elements']
    assert [e['offset']for e in elements]==[0,4,10]
    assert all(e['provenance']['record_list_source_array']==prior for e in elements)
    assert elements[0]['name']=='keptWordOwner'
    action=saved['actions'][0]['action_id']
    undone=call('rollback',expected_revision=saved['revision'],action_id=action)
    assert (target/'main.s').read_bytes()==before
    redone=call('rollback',expected_revision=undone['revision'],action_id=action,redo=True)
    assert (target/'main.s').read_bytes()==after
    call('regenerate',expected_revision=redone['revision'])
    assert (target/'main.s').read_bytes()==after
    proof=call('verify',expected_revision=redone['revision'],output=str(tmp_path/'proof'))['verification']
    call('review',expected_revision=redone['revision'],action_id=action,
         decision='accept',reason='Independent exact synthetic list reconstruction.',
         verification_id=proof['receipt_id'])
    call('interpret',**request(call))
    assert (target/'main.s').read_bytes()==after
    with pytest.raises(ValueError,match='stale_revision'):
        call('interpret',**request_stale(saved,call))


def request_stale(saved,call):
    r=request(call);r['expected_revision']=saved['revision'];return r


@pytest.mark.parametrize('runs',[
    [],[dict(record_type='Missing',count=1)],
    [dict(record_type='Pair',count=True)],
    [dict(record_type='Pair',count=0)],
    [dict(record_type='Pair',count=-1)],
    [dict(record_type='Pair',count=2**32)],
    [dict(record_type='Pair',count=1)],
    [dict(record_type='Pair',count=4)],
    [dict(record_type='Pair',count=1,offset=0)],
])
def test_bad_partition_is_atomic(tmp_path,monkeypatch,runs):
    target,call=setup(tmp_path,monkeypatch);before=snapshot(target)
    with pytest.raises((ValueError,RuntimeError)):
        call('interpret',**request(call,runs=runs))
    assert snapshot(target)==before


def test_partial_owner_and_changed_leaf_grid_are_rejected(tmp_path,monkeypatch):
    target,call=setup(tmp_path,monkeypatch);before=snapshot(target)
    inspected=call('inspect',source_offset=4,end_offset=14,row_kind='data')
    command=next(c for c in inspected['commands']if c['command_id']=='range.data_block.record_list.declare')
    assert command['enabled'] is False and command['range_availability']=='unavailable'
    with pytest.raises(ValueError):
        call('interpret',**request(call,end=14))
    types=copy.deepcopy(TYPES);types[0]['fields']=[dict(name='wide',type='LONG',offset=0,size=4)]
    with pytest.raises(ValueError,match='primitive leaf'):
        call('interpret',**request(call,types=types))
    assert snapshot(target)==before


def test_normalization_keeps_equivalent_run_and_type_orders_identical():
    from amiga_reversing.disasm.record_lists import record_list_plan
    layout=dict(layout_id='owner',source_start=4,source_end=18)
    a=record_list_plan(TYPES,[dict(record_type='Pair',count=1),dict(record_type='Pair',count=1),dict(record_type='Triple',count=1)],layout)
    b=record_list_plan(list(reversed(TYPES)),[dict(record_type='Pair',count=2),dict(record_type='Triple',count=1)],layout)
    assert a==b


def test_shared_member_list_uses_owner_scope_and_rejects_outside_extent(tmp_path,monkeypatch):
    import json
    from amiga_reversing.disasm.disk_codecs import digest
    from amiga_reversing.disasm.disk_set import compose_source_package
    from amiga_reversing.disasm.source_package_publish import publish_source_package
    from tests.test_disk_set import packages_for
    target,call=setup(tmp_path,monkeypatch)
    path=target/'manifest.json';manifest=json.loads(path.read_bytes())
    manifest['members'].append(dict(id='list_view',kind='data',size=14,
        sha256=digest(bytes.fromhex('0001000200030004000500060007')),
        context=dict(address_model='runtime_absolute',load_address=0x1004,entrypoint=None,
                     code_start_offset=None,phase='decoded_resource'),source=None,analysis=None))
    manifest['relationships'].append(dict(kind='embedded',member='list_view',owner='main',offset=4,size=14,evidence='Independent exact synthetic owner slice.'))
    package=compose_source_package(manifest,packages_for(target,manifest));publish_source_package(package,target)
    manifest['package_sha256']=package['sha256'];path.write_text(json.dumps(manifest))
    selected=call('inspect',member='list_view',source_offset=0,end_offset=14,row_kind='data')
    saved=call('interpret',member='list_view',**data_request(selected,'range.data_block.record_list.declare',dict(record_types=TYPES,runs=RUNS)))
    assert saved['verification']['all_placement_coverage']
    assert saved['actions'][0]['interpretation']['member_subject']['analysis_member_id']=='main'
    assert metadata(target)['data_block_layouts'][-1]['source_start']==4
    assert call('history',member='list_view')['items'][0]['kind']=='declare_manual_record_list'
    before=snapshot(target)
    with pytest.raises(ValueError,match='bounded data range'):
        call('inspect',member='list_view',source_offset=0,end_offset=16,row_kind='data')
    assert snapshot(target)==before


def test_changed_type_and_forged_partition_fail_before_journal_append(tmp_path,monkeypatch):
    target,call=setup(tmp_path,monkeypatch)
    saved=call('interpret',**request(call));before=snapshot(target)
    types=copy.deepcopy(TYPES);types[0]['fields'][0]['name']='changed'
    with pytest.raises(ValueError):call('interpret',**request(call,types=types))
    assert snapshot(target)==before
    # The ordinary replay validator independently checks its actual prior grid.
    from amiga_reversing.disasm.record_lists import validate_record_list
    data=metadata(target);layout=data['data_block_layouts'][-1]
    elements=copy.deepcopy(layout['elements'])
    payload=dict(custom_structs=TYPES,runs=RUNS,data_block_elements=elements,
                 source_array=copy.deepcopy(elements[0]['provenance']['record_list_source_array']))
    payload['source_array']['array_stride']=4
    with pytest.raises(ValueError):validate_record_list(payload,layout)
    assert snapshot(target)==before


def test_legacy_projection_snapshot_upgrades_through_normal_journal(tmp_path,monkeypatch):
    from amiga_reversing.disasm import record_lists
    target,call=setup(tmp_path,monkeypatch)
    normal=record_lists.validate_record_list
    def legacy(payload,layout):
        for element in payload['data_block_elements']:
            element['type_binding'].pop('record_list_field_presentation',None)
        return normal(payload,layout)
    # Model the historical catalog payload, without changing any validation.
    with monkeypatch.context() as patch:
        patch.setattr(record_lists,'validate_record_list',legacy)
        old=call('interpret',**request(call))
    compact=(target/'main.s').read_bytes()
    call('regenerate',expected_revision=old['revision'])
    assert (target/'main.s').read_bytes()==compact
    upgraded=call('interpret',**request(call))
    structured=(target/'main.s').read_bytes()
    assert b'; x'in structured and b'; a'in structured and structured!=compact
    assert upgraded['verification']['all_placement_coverage']
    elements=metadata(target)['data_block_layouts'][-1]['elements']
    assert all(e['type_binding']['record_list_field_presentation'] is True for e in elements)
    call('rollback',expected_revision=upgraded['revision'],action_id=upgraded['actions'][0]['action_id'])
    assert (target/'main.s').read_bytes()==compact

"""New declarations preserve matching typed scalar names without replay drift."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from amiga_reversing.disasm.effective_metadata import _record_list_scalar_names
from amiga_reversing.disasm.target_metadata import (
    SeededEntityMetadata,
    TargetMetadataReviewStatus,
    TargetMetadataSeedOrigin,
)
from tests.test_disk_set_state import data_request, editable
from tests.test_scoped_record_arrays import metadata


def leaves():
    field = SeededEntityMetadata(addr=8,end=10,hunk=0,type='data',unit='word',
        seed_origin=TargetMetadataSeedOrigin.MANUAL_ANALYSIS,
        review_status=TargetMetadataReviewStatus.SEEDED,citation='Synthetic declared field',
        name='generated',struct_name='Point',field_name='x',field_type='word',
        c_type='word',value_kind='scalar')
    old = replace(field,name='secondPoint',c_type='/word',value_kind=None,
                  citation='Synthetic imported field',source_id='imported')
    return field, old


def test_compatible_typed_name_changes_only_spelling_and_requires_new_contract():
    field, old = leaves()
    layout = SimpleNamespace(source_start=4)
    # Persisted declarations without the new presentation contract retain their
    # old projection; the ordinary before-snapshot guard must remain usable.
    assert _record_list_scalar_names((field,),[old],layout) == (field,)
    renamed = _record_list_scalar_names((field,),[old],layout,compatible_typed=True)[0]
    assert renamed == replace(field,name='secondPoint')
    assert old.name == 'secondPoint' and old.source_id == 'imported'


@pytest.mark.parametrize('changes',[
    {'addr': 6},{'end': 12},{'hunk': 1},{'unit': 'long'},{'struct_name': 'Other'},
    {'field_name': 'y'},{'field_type': 'uword'},{'c_type': '/long'},
    {'value_kind': 'target_pointer'},{'pointer_struct': 'Point'},{'value_domain': 'flags'},
    {'subtype': 'pointer_table'},
])
def test_typed_name_needs_exact_shape_type_and_scalar_semantics(changes):
    field, old = leaves()
    assert _record_list_scalar_names((field,),[replace(old,**changes)],
        SimpleNamespace(source_start=4),compatible_typed=True) == (field,)


def test_competing_compatible_names_still_require_explicit_reconciliation():
    field, old = leaves()
    with pytest.raises(ValueError,match='ambiguous independent scalar names'):
        _record_list_scalar_names((field,),[old,replace(old,name='another')],
                                  SimpleNamespace(source_start=4),compatible_typed=True)


def test_scoped_typed_name_upgrade_preserves_history_type_and_exact_members(tmp_path, monkeypatch):
    imported = {'hunk': 0,'addr': 8,'end': 10,'name': 'secondPoint','type': 'data','unit': 'word',
        'struct_name': 'Point','field_name': 'x','field_type': 'word','c_type': '/word',
        'seed_origin': 'manual_analysis','review_status': 'seeded','citation': 'Synthetic imported typed field'}
    _, target, _, call = editable(tmp_path,monkeypatch,
        record_data=bytes.fromhex('0001000200030004'),record_imports=[imported])
    baseline = (target/'analysis/main.target_metadata.json').read_bytes()
    selected = call('inspect',source_offset=4,end_offset=12,row_kind='data')
    call('interpret',**data_request(selected,'range.data_block.layout.create',
                                   {'name': 'points','default_unit': 'word'}))
    def request(**updates):
        selected = call('inspect',source_offset=4,end_offset=12,row_kind='data')
        return data_request(selected,'range.data_block.records.declare',dict(
            record_type='Point',record_size=4,record_count=2,record_stride=4,
            fields=[{'name': n,'type': 'WORD','offset': i*2,'size': 2}for i,n in enumerate(['x','y'])],
            **updates))
    call('interpret',**request())
    compact = (target/'main.s').read_bytes()
    previous = metadata(target)['data_block_layouts'][-1]['elements'][0]
    saved = call('interpret',**request(field_presentation=True))
    after = (target/'main.s').read_text()
    assert 'secondPoint:' in after and 'points_x_1:' not in after
    current = metadata(target)['data_block_layouts'][-1]['elements'][0]
    assert current['type_binding']['record_preserve_compatible_scalar_names'] is True
    assert current['type_binding']['record_contract'] == previous['type_binding']['record_contract']
    assert current['type_binding']['type_binding_id'] == previous['type_binding']['type_binding_id']
    assert current['provenance'] == previous['provenance']
    assert saved['verification']['member_sources_exact'] and saved['verification']['media_exact']
    assert (target/'analysis/main.target_metadata.json').read_bytes() == baseline
    undone = call('rollback',expected_revision=saved['revision'],action_id=saved['actions'][0]['action_id'])
    assert (target/'main.s').read_bytes() == compact
    redone = call('rollback',expected_revision=undone['revision'],action_id=saved['actions'][0]['action_id'],redo=True)
    assert (target/'main.s').read_text() == after
    call('regenerate',expected_revision=redone['revision'])
    call('interpret',**request())
    assert (target/'main.s').read_text() == after


def test_typed_pointer_identity_does_not_supply_a_scalar_field_name():
    field, old = leaves()
    field = replace(field,end=12,unit='long',field_type='long',c_type='long')
    old = replace(old,end=12,unit='long',field_type='long',c_type='/long',
                  value_kind='target_pointer',pointer_address_domain='mapped_source')
    assert _record_list_scalar_names((field,),[old],SimpleNamespace(source_start=4),
                                     compatible_typed=True) == (field,)


@pytest.mark.parametrize('value',[False,1,'true'])
def test_compatible_name_contract_requires_explicit_true_and_field_presentation(value):
    from amiga_reversing.disasm.record_arrays import validate_record_array
    record = {'name':'Point','size':2,'fields':[{'name':'x','type':'WORD','offset':0,'size':2}]}
    binding = {'record_field_presentation':True,'record_preserve_scalar_names':True,
               'record_preserve_compatible_scalar_names':value}
    element = {'kind':'array','offset':0,'width':2,'array_count':1,'array_stride':2,'type_binding':binding}
    with pytest.raises(ValueError,match='compatible scalar names'):
        validate_record_array(element,record,{'source_start':0,'source_end':2})

"""The FoFT receipt checker consumes native witnesses; it cannot invent one."""

from copy import deepcopy

import pytest

from tools.foft_render_contract_audit import fixed_point_receiver


def rows():
    return [{'source_offset': 0x1A312 + i * 2, 'provenance': 'accepted_instruction',
             'typed_accesses': [{'root_struct_name': 'ProjectedPointInput',
                 'operand_index': 0, 'base_register': 'A6', 'field_name': name,
                 'field_offset': i * 2, 'struct_size': 8, 'field_size': 2,
                 'record_cursor_loop': {'header_offset': 0x1A312, 'tail_offset': 0x1A41A,
                     'iteration_count': 150, 'iteration_stride': 8, 'access_width': 2,
                     'counter_register': 5, 'access_kind': 1, 'first_offset': i * 2,
                     'record_count': 150, 'base_record_index': 0, 'body_only': True}}]}
            for i, name in enumerate(['position0', 'position1', 'position2', 'planeFlagWord'])]


def test_complete_native_witnesses_have_exact_last_extent_without_value_claim():
    result = fixed_point_receiver(rows())
    assert [f['last_access_end'] for f in result['fields']] == [1194, 1196, 1198, 1200]
    assert result['body_only'] and not result['pointee_or_value_closure']


@pytest.mark.parametrize('change', ['missing', 'duplicate', 'unaccepted', 'root',
                                    'count', 'stride', 'field', 'body_only'])
def test_missing_ambiguous_or_different_native_proof_cannot_certify_target(change):
    data = deepcopy(rows())
    field = data[0]['typed_accesses'][0]
    if change == 'missing':
        data[0]['typed_accesses'] = []
    elif change == 'duplicate':
        data[0]['typed_accesses'].append(deepcopy(field))
    elif change == 'unaccepted':
        data[0]['provenance'] = 'candidate'
    elif change == 'root':
        field['root_struct_name'] = 'Other'
    elif change == 'field':
        field['field_offset'] = 2
    else:
        key = {'count': 'iteration_count', 'stride': 'iteration_stride',
               'body_only': 'body_only'}[change]
        field['record_cursor_loop'][key] = {'count': 151, 'stride': 6,
                                          'body_only': False}[change]
    with pytest.raises(ValueError, match='point receiver'):
        fixed_point_receiver(data)

"""Host source-contract tests; these never execute game code or supply guest input."""
import pytest

from tools.foft_draw_lifetime_audit import (
    SAVED,
    activation_views,
    no_explicit_memory_writes,
)


def row(name, *fields, provenance='accepted_instruction'):
    return {'mnemonic': name, 'operand_facts': list(fields), 'provenance': provenance}


def test_no_write_contract_is_local_not_a_callback_or_async_certificate():
    result = no_explicit_memory_writes([
        row('move', {'memory': True, 'access': 'memory_read', 'width_bytes': 2}),
        row('cmp', {'memory': False, 'access': 'register_read'}), row('ble'), row('rts')])
    assert result['explicit_memory_writes'] == []
    assert result['ordinary_intact_return_required']
    assert not result['interrupts_faults_and_stack_alias_closed']


@pytest.mark.parametrize('access', ['memory_write', 'memory_read_write'])
@pytest.mark.parametrize('width', [1, 2, 4])
def test_no_write_contract_rejects_any_explicit_width_and_read_modify_write(access, width):
    with pytest.raises(ValueError, match='explicit memory write'):
        no_explicit_memory_writes([row('move', {'memory': True, 'access': access, 'width_bytes': width})])


@pytest.mark.parametrize('mnemonic', ['jsr', 'bsr', 'jmp', 'rte', 'trap'])
def test_no_write_contract_does_not_hide_callee_or_exception_effects(mnemonic):
    with pytest.raises(ValueError, match='separate effects'):
        no_explicit_memory_writes([row(mnemonic)])


def test_no_write_contract_rejects_unaccepted_source():
    with pytest.raises(ValueError, match='unaccepted'):
        no_explicit_memory_writes([row('rts', provenance='candidate_instruction')])


def test_all_conditional_source_slots_reconstruct_the_original_state_receiver():
    for n in range(64):
        v = activation_views(n)
        assert v['saved_word'] == 20*n
        assert v['state_write_view'] == [0x4E818 + 20*n, 0x4E818 + 20*(n+1)]
        assert v['action_write_view'] == [0x4ED18 + 20*n, 0x4ED18 + 20*n+16]
        assert v['orientation_write_view'] == [0x2B994 + 10*n, 0x2B994 + 10*(n+1)]
        assert v['later_state_receiver_if_saved_word_intact'] == v['state_write_view'][0]
        assert not v['actual_entry_bound_or_intervening_preservation_proved']
        for key in ('state_write_view', 'action_write_view', 'orientation_write_view'):
            lo, hi = v[key]
            assert hi <= SAVED[0] or SAVED[1] <= lo


def test_live_count_change_is_not_a_new_offset_or_recreation_equality():
    # Address algebra under the explicit source-slot premise, not a generated guest case.
    activation = activation_views(3)
    after_count_increment = activation_views(4)
    assert activation['later_state_receiver_if_saved_word_intact'] != after_count_increment['state_write_view'][0]
    assert activation['saved_word'] == 60


@pytest.mark.parametrize('count', [-1, 64, 65, 65535, True, 1.0, None])
def test_conditional_slot_certificate_does_not_promote_an_unproved_global_domain(count):
    with pytest.raises(ValueError, match='conditional source slot'):
        activation_views(count)


@pytest.mark.parametrize('mnemonic', ['link', 'pea', 'trapv', 'unknown'])
def test_no_write_contract_rejects_unmodeled_implicit_effects(mnemonic):
    with pytest.raises(ValueError, match='unsupported local operation'):
        no_explicit_memory_writes([row(mnemonic)])


def test_reviewed_domains_keep_partial_write_widths_and_unknown_aliases():
    from tools.foft_irq_write_audit import direct_write_inventory
    rows = [
        {'source_offset': 0, 'operand_facts': [
            {'access': 'memory_read_write', 'width_bytes': 4, 'absolute_address': SAVED[0]-2}]},
        {'source_offset': 4, 'operand_facts': [
            {'access': 'memory_write', 'width_bytes': 2, 'absolute_address': SAVED[1]}]},
        {'source_offset': 6, 'operand_facts': [
            {'access': 'memory_write', 'width_bytes': 2, 'base_register': 'A6'}]}]
    proof = direct_write_inventory(rows, spans={'saved': SAVED})
    assert proof['direct_intersections']['saved'] == [
        {'runtime': 0x800, 'address': SAVED[0]-2, 'width': 4}]
    assert proof['other_write_operands'] == 1
    assert not proof['whole_memory_alias_closure']


@pytest.mark.parametrize('span', [(5, 5), (6, 5), (-1, 1), (0, 2**32+1), (True, 3)])
def test_reviewed_domain_rejects_invalid_extent(span):
    from tools.foft_irq_write_audit import direct_write_inventory
    with pytest.raises(ValueError, match='reviewed write span'):
        direct_write_inventory([], spans={'saved': span})


@pytest.mark.parametrize('bank', [0, 0x8000])
def test_all_clipped_pixel_bytes_fit_the_conditional_plane_envelopes(bank):
    from tools.foft_draw_lifetime_audit import BACKUP, COUNT, far_pixel_spans
    spans = far_pixel_spans(bank)
    for x in range(26, 295):
        for y in range(16, 127):
            for i, plane in enumerate((0, 0x2000, 0x4000, 0x6000)):
                address = 0x70000 + bank + plane + 40*y + (x >> 3)
                assert spans[i][0] <= address < spans[i][1]
                assert all(not (lo <= address < hi) for lo, hi in (COUNT, BACKUP, SAVED))


@pytest.mark.parametrize('bank', [-0x8000, 1, 0x10000, True, None])
def test_far_pixel_certificate_requires_the_separate_bank_premise(bank):
    from tools.foft_draw_lifetime_audit import far_pixel_spans
    with pytest.raises(ValueError, match='preserved canonical draw bank'):
        far_pixel_spans(bank)


def test_far_projection_divisor_is_positive_and_quotient_fits_without_normalizing_input():
    # Every signed WORD coordinate has magnitude <=32768; source scales by 256.
    # Far arm admits only signed positive depths 16385..32767. This interval
    # inequality covers the complete domain without running or inventing game states.
    numerator_bound = 32768*256
    for depth in range(0x4001, 0x8000):
        assert numerator_bound//depth <= 511 < 32768


@pytest.mark.parametrize('data', [b'', bytes(489472)])
def test_source_audit_requires_actual_complete_pinned_member_bytes(data):
    from tools.foft_draw_lifetime_audit import check_source
    with pytest.raises(ValueError, match='whole member bytes differ'):
        check_source([], {}, data)


def test_restricted_scenery_composition_derives_count_equality_not_a_live_claim():
    from tools.foft_draw_lifetime_audit import restricted_scenery_snapshot
    for n in range(2, 15):
        for kinds, bank in ((['reject']*n, None), (['far']*n, 0),
                            (['far']+['reject']*(n-1), 0x8000)):
            p = restricted_scenery_snapshot(n, kinds, bank)
            assert p['initial_N'] == p['reloaded_M_given_path_and_preservation_premises'] == n
            assert p['snapshot_bytes'] == 16*n and p['live_packed_bytes'] == 12*n
            assert p['backup_span'][0] >= p['view_snapshot_span'][1]
            assert p['restored_live_prefix_equals_original_given_premises']
            assert not p['actual_path_or_unconditional_near_callback_preservation_proved']


@pytest.mark.parametrize(('count', 'attempts', 'bank'), [
    (1, ['reject'], None), (15, ['reject']*15, None),
    (2, ['reject', 'near'], None), (2, ['reject'], None),
    (2, ['far', 'reject'], None), (2, ['far', 'reject'], 1)])
def test_restricted_snapshot_does_not_borrow_singleton_title_or_unknown_near_effects(count, attempts, bank):
    from tools.foft_draw_lifetime_audit import restricted_scenery_snapshot
    with pytest.raises(ValueError, match="requires|every attempted"):
        restricted_scenery_snapshot(count, attempts, bank)

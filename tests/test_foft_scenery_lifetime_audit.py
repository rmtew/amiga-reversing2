"""Finite address/lifetime properties; no FoFT bytes or guest execution."""
import pytest

from tools.foft_scenery_lifetime_audit import (
    CRITICAL,
    PAGE_ROOTS,
    cell_offset,
    descriptor_row,
    pattern_delta,
    probe_write_lifetime,
)


def test_position_mask_has_512_byte_write_view_not_256_byte_page_bound():
    offsets = {cell_offset(p) for p in range(256)}
    assert offsets == set(range(0, 512, 2))
    assert cell_offset(0x7F) == 254 and cell_offset(0x80) == 256
    for root in PAGE_ROOTS:
        for lo, hi in CRITICAL.values():
            assert root + 512 <= lo or hi <= root


@pytest.mark.parametrize('high', range(32))
def test_byte_load_word_scale_retains_five_effective_upper_bits(high):
    for alias in range(8):
        incoming = ((high + 32 * alias) << 8) | 0xA5
        for key in range(6):
            delta = pattern_delta(incoming, key)
            assert (0 <= delta < 48) == (high == 0)
            assert delta - pattern_delta(incoming, 0) == 8 * key
            assert delta == pattern_delta(incoming ^ 0xFF, key)


def test_ff_upper_byte_is_not_silently_zero_extended():
    assert [pattern_delta(0xFFFF, k) for k in range(6)] == [-2048, -2040, -2032, -2024, -2016, -2008]


def test_all_descriptor_enable_masks_leave_both_edge_columns_clear():
    for mask in range(1 << 14):
        source = [0xFFFF, *((1 if mask & (1 << i) else 0) for i in range(14)), 0xFFFF]
        row = descriptor_row(source)
        assert row[0] == row[15] == 0
        assert sum(v != 0 for v in row) == mask.bit_count() <= 14
        for i in range(1, 15):
            if row[i]:
                assert row[i] & 255 == 10 * i
    assert 12 * 14 == 168 and 16 * 14 == 224


@pytest.mark.parametrize('value', [1, 8, 15, 16, 256, 65535])
def test_nonzero_source_with_zero_selector_nibble_still_uses_column_offset(value):
    row = descriptor_row([value] * 16)
    assert sum(v != 0 for v in row) == 14
    assert all(row[i] == ((value << 8) & 0xF00) | 10 * i for i in range(1, 15))


def test_next_complete_prefix_replaces_probe_write_in_every_interpreted_field():
    seen = set()
    for old_count in range(1, 15):
        for probe in range(old_count):
            for new_count in range(15):
                result = probe_write_lifetime(old_count, probe, new_count)
                seen.add(result['producer_field'])
                # A fully written new prefix replaces words regardless of their
                # old field kind. Outside it, no cleared or retained value is promised.
                assert result['overwritten_by_next_prefix'] == (result['producer_row'] < new_count)
                assert result['outside_next_prefix_is_cleared'] is False
    assert seen == {'x', 'y', 'z', 'callbackHigh', 'callbackLow', 'tail'}


@pytest.mark.parametrize(('fn', 'args'), [
    (cell_offset, (True,)), (cell_offset, (256,)),
    (pattern_delta, (65536, 0)), (pattern_delta, (0, 256)),
    (descriptor_row, ([0] * 15,)), (descriptor_row, ([True] * 16,)),
    (probe_write_lifetime, (0, 0, 1)), (probe_write_lifetime, (15, 0, 1)),
    (probe_write_lifetime, (1, 1, 1)), (probe_write_lifetime, (1, 0, 15)),
])
def test_contracts_refuse_unsupported_host_assertions(fn, args):
    with pytest.raises(ValueError, match='requires'):
        fn(*args)

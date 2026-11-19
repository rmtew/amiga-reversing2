"""Storage directives can retain complete scalar partitions without retyping them."""

import pytest

from tests.test_structural_record_views import fixture


def check(tmp_path, raw, *, properties=None):
    code = " lea.l TABLE(pc),a6\n andi.w #1,d0\n mulu.w #18,d0\n move.w 2(a6,d0.w),d1\n rts"
    return fixture(
        tmp_path, record_size=18, raw=raw, raw_properties=properties, code=code
    )


@pytest.mark.parametrize("raw", [(128, 12, "long"), (124, 12, "long")])
def test_long_storage_cells_preserve_complete_word_field_partitions(tmp_path, raw):
    text, rows = check(tmp_path, raw)
    uses = [a for r in rows for a in r["typed_accesses"]]
    assert len(uses) == 1 and uses[0]["field_name"] == "y"
    assert uses[0]["word_index"]["record_count"] == 3
    assert "Point_y" in text


@pytest.mark.parametrize(
    ("raw", "properties"),
    [
        ((130, 12, "long"), None),
        ((128, 16, "long"), None),
        ((128, 12, "long"), {"c_type": "LONG"}),
    ],
)
def test_partial_cells_or_explicit_value_types_are_not_discarded(
    tmp_path, raw, properties
):
    _, rows = check(tmp_path, raw, properties=properties)
    assert not [a for r in rows for a in r["typed_accesses"]]


def test_scalar_long_view_cannot_establish_a_pointer_array(tmp_path):
    code = (
        " lea.l TABLE(pc),a6\n andi.w #1,d0\n lsl.w #2,d0\n movea.l (a6,d0.w),a1\n rts"
    )
    _, rows = fixture(tmp_path, record_size=4, raw=(124, 16, "long"), code=code)
    assert not [a for r in rows for a in r["typed_accesses"]]

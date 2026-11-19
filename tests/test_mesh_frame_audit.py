"""Conditional arithmetic and exact native operand accounting, not guest runs."""

import pytest

from tools.foft_mesh_frame_audit import (
    conditional_induction,
    instruction_digest,
    write_inventory,
)


def row(offset, operand, *, evidence=(), extras=()):
    return {
        "source_offset": offset,
        "operand_facts": [operand, *extras],
        "address_evidence": list(evidence),
    }


def operand(**changes):
    return {
        "operand_index": 0,
        "memory": True,
        "access": "memory_write",
        "width_bytes": 2,
        "absolute_address": 0x2000,
        "bulk_transfer": False,
        **changes,
    }


def test_register_writes_and_operand_aliases_are_not_dynamic_write_counts():
    rows = [
        row(0, operand()),
        row(2, operand(memory=False, access="register_write")),
        row(4, operand(absolute_address=None)),
    ]
    r = write_inventory(rows, 0x2000, 2)
    assert r["counts"] == {
        "explicit_memory_write_operands": 2,
        "absolute": 1,
        "indirect_exact": 0,
        "indirect_without_exact_address": 1,
    }
    assert len(r["frame_write_sites"]) == 1 and not r["global_alias_closure"]


def test_wide_absolute_write_crossing_the_word_is_not_missed():
    r = write_inventory(
        [row(0, operand(absolute_address=0x1FFE, width_bytes=4))], 0x2000, 2
    )
    assert r["frame_write_sites"][0]["bytes"] == 4


def test_bulk_store_uses_the_native_register_list_from_its_other_operand():
    r = write_inventory(
        [
            row(
                0,
                operand(absolute_address=0x1FFC, width_bytes=4, bulk_transfer=True),
                extras=[
                    {
                        "memory": False,
                        "access": "register_list_read",
                        "register_list": ["D0", "D1"],
                    }
                ],
            )
        ],
        0x2000,
        2,
    )
    assert r["frame_write_sites"][0]["bytes"] == 8


def test_conflicted_symbolic_evidence_does_not_erase_a_literal_physical_address():
    r = write_inventory(
        [
            row(
                0,
                operand(),
                evidence=[
                    {
                        "operand_index": 0,
                        "has_address": True,
                        "conflicted": True,
                        "address": 0x2000,
                        "width_bytes": 2,
                    }
                ],
            )
        ],
        0x2000,
        2,
    )
    assert len(r["frame_write_sites"]) == 1


def test_clear_hold_and_increment_close_only_a_conditional_old_index_invariant():
    r = conditional_induction(0, list(range(0, 1080, 90)), 90, 1080)
    assert r["conditional_stored_range"] == [0, 12] and r[
        "conditional_selected_range"
    ] == [0, 11]
    assert r["transition_cases"] == 24 and r["selection_uses_old_value"]
    assert (
        r["requires_other_writers_to_preserve_word"]
        and not r["unconditional_receiver_fact"]
    )


@pytest.mark.parametrize(
    "arguments", [(1, [0, 90], 90, 180), (0, [0, 91], 90, 180), (0, [0, 90], 90, 179)]
)
def test_a_changed_initial_or_table_extent_is_not_a_proof(arguments):
    with pytest.raises(ValueError, match="initial|offsets|extent"):
        conditional_induction(*arguments)


def test_repeated_opcodes_at_different_coordinates_are_distinct_witnesses():
    assert instruction_digest(
        [{"source_offset": 0, "bytes": "4e75"}]
    ) != instruction_digest([{"source_offset": 2, "bytes": "4e75"}])


def test_offset_extent_alone_does_not_prove_signed_word_addressing():
    with pytest.raises(ValueError, match="signed WORD"):
        conditional_induction(0, [90 * i for i in range(400)], 90, 36000)

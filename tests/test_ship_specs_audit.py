"""Read-only data contract checks, not game execution or pointer discovery."""

import copy

import pytest

from tools.foft_ship_specs_audit import audit, digest


def fixture():
    words = lambda values: b"".join(v.to_bytes(4, "big") for v in values)
    payload = words([0x1008, 0x1014, 0x1020, 0x1026, 0, 0x1020, 0x102C, 0])
    payload += bytes.fromhex("00010002") + b"A\0"
    payload += bytes.fromhex("00010002") + b"A\0"
    payload += bytes.fromhex("00030004") + b"B\0"
    lists = [
        {
            "start_runtime": lo,
            "end_runtime": lo + 12,
            "nonnull_count": 2,
            "sha256": digest(payload[lo - 0x1000 : lo - 0x1000 + 12]),
        }
        for lo in [0x1008, 0x1014]
    ]
    records = [
        {
            "start_runtime": lo,
            "text_start_runtime": lo + 4,
            "end_runtime": lo + 6,
            "x": 1 if i < 2 else 3,
            "y": 2 if i < 2 else 4,
            "references": 2 if i == 0 else 1,
            "sha256": digest(payload[lo - 0x1000 : lo - 0x1000 + 6]),
        }
        for i, lo in enumerate([0x1020, 0x1026, 0x102C])
    ]
    mapping = {
        "revision": "fixture",
        "size": len(payload),
        "sha256": digest(payload),
        "load_address": 0x1000,
        "outer": {
            "start_runtime": 0x1000,
            "end_runtime": 0x1008,
            "sha256": digest(payload[:8]),
        },
        "lists": lists,
        "records": records,
        "readers": [],
        "expected_counts": {
            "lists": 2,
            "pointer_cells": 6,
            "nonnull_references": 4,
            "zero_sentinels": 2,
        },
    }
    return payload, mapping


def test_shared_prefixes_and_equal_bodies_at_distinct_addresses_are_preserved():
    payload, mapping = fixture()
    original = copy.deepcopy(mapping)
    result = audit(payload, mapping)
    assert mapping == original
    assert result["distinct_display_records"] == 3
    assert result["shared_records"] == [{"runtime": 0x1020, "references": 2}]
    assert result["identical_record_groups_at_distinct_addresses"] == [[0x1020, 0x1026]]
    assert not result["ownership_or_code_inferred"] and not result["guest_execution"]


@pytest.mark.parametrize("value", [0, 0xDEADBEEF, 0x1024])
def test_first_pointer_must_be_valid_and_point_to_prefix_not_text(value):
    payload, mapping = fixture()
    payload = payload[:8] + value.to_bytes(4, "big") + payload[12:]
    mapping["sha256"] = digest(payload)
    mapping["lists"][0]["sha256"] = digest(payload[8:20])
    with pytest.raises(ValueError, match="prefix addresses"):
        audit(payload, mapping)


def test_zero_sentinel_is_checked_and_never_reinterpreted_as_a_target():
    payload, mapping = fixture()
    payload = payload[:16] + (0x1020).to_bytes(4, "big") + payload[20:]
    mapping["sha256"] = digest(payload)
    mapping["lists"][0]["sha256"] = digest(payload[8:20])
    with pytest.raises(ValueError, match="sentinel"):
        audit(payload, mapping)


@pytest.mark.parametrize(
    "change",
    ["empty", "duplicate_prefix", "shared_count", "padded_string", "aggregate"],
)
def test_inconsistent_pinned_tool_facts_are_rejected(change):
    payload, mapping = fixture()
    if change == "empty":
        mapping["lists"][0]["nonnull_count"] = 0
    elif change == "duplicate_prefix":
        mapping["records"].append(copy.deepcopy(mapping["records"][0]))
    elif change == "shared_count":
        mapping["records"][0]["references"] = 1
    elif change == "padded_string":
        mapping["records"][0]["end_runtime"] += 1
    else:
        mapping["expected_counts"]["pointer_cells"] += 1
    with pytest.raises(ValueError, match="list|display|inventory|aggregate"):
        audit(payload, mapping)

"""Synthetic source records and alias windows; never guest execution."""

import copy

import pytest

from tools.foft_burst_audit import digest
from tools.foft_display_provenance_audit import audit


def fixture():
    base = 0x1000
    payload = bytearray(256)
    sources = []
    for i, lo in enumerate([0, 24]):
        data = (
            (0x0B20 + i).to_bytes(2, "big")
            + bytes.fromhex("0e00")
            + bytes.fromhex("f000f000") * 4
            + bytes(4)
        )
        payload[lo : lo + 24] = data
        sources.append(
            {
                "name": "source" + str(i),
                "start_runtime": base + lo,
                "end_runtime": base + lo + 24,
                "sha256": digest(data),
                "position_word": 0x0B20 + i,
                "control_word": 0x0E00,
                "body_pairs": 4,
                "body_pair_words": [0xF000, 0xF000],
                "conditional_offsets": [0, 1],
                "header_base": 12,
            }
        )
    payload = bytes(payload)
    region = lambda lo, hi: {
        "start_runtime": base + lo,
        "end_runtime": base + hi,
        "sha256": digest(payload[lo:hi]),
    }
    mapping = {
        "size": len(payload),
        "sha256": digest(payload),
        "load_address": base,
        "revision": "synthetic",
        "sprites": sources,
        "scratch": {
            "bytes": 16,
            "source": region(144, 160),
            "backup": region(192, 208),
            "surviving_stores": [region(48, 54), region(54, 68), region(80, 128)],
        },
        "scenery_scan": {
            "view_start_runtime": base + 80,
            "view_end_runtime": base + 128,
            "producer_stride": 12,
            "reader_stride": 10,
            "conditional_max_count": 4,
            "last_word_offset": 10,
            "producer_byte_residues": [0, 10, 8, 6, 4, 2],
            "conditional_read_end": 42,
        },
    }
    return payload, mapping


def test_distinct_headers_and_overlapping_views_are_checked_without_new_owners():
    payload, m = fixture()
    before = copy.deepcopy(m)
    result = audit(payload, m)
    assert result["scan_residues"] == [0, 10, 8, 6, 4, 2]
    assert result["conditional_scan_end"] == 42 and result["surviving_stores"] == 3
    assert [r["first_rows_min"] for r in result["sprite_sources"]] == [2, 2]
    assert [r["first_rows_max"] for r in result["sprite_sources"]] == [3, 3]
    assert all(
        r["remaining_pairs_zero_height"] and not r["live_fetch_or_termination_proved"]
        for r in result["sprite_sources"]
    )
    assert (
        not result["guest_execution"] and not result["new_ownership_or_code_inferred"]
    )
    assert m == before


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ("range", "first segment"),
        ("stride", "scan relation"),
        ("scratch", "scratch view"),
        ("survivor", "inside the restored"),
        ("view", "scan extent"),
        ("fingerprint", "store fingerprint"),
    ],
)
def test_invalid_reviewed_relations_are_rejected(change, match):
    payload, m = fixture()
    if change == "range":
        m["sprites"][0]["conditional_offsets"] = [0, 10]
    if change == "stride":
        m["scenery_scan"]["reader_stride"] = 12
    if change == "scratch":
        m["scratch"]["bytes"] = 8
    if change == "survivor":
        m["scratch"]["surviving_stores"][0].update(
            start_runtime=0x1090, end_runtime=0x1096
        )
    if change == "fingerprint":
        m["scratch"]["surviving_stores"][0]["sha256"] = "0" * 64
    if change == "view":
        m["scenery_scan"]["view_end_runtime"] = 0x105A
    with pytest.raises(ValueError, match=match):
        audit(payload, m)


def test_same_body_bytes_do_not_allow_two_headers_to_become_one_store():
    payload, m = fixture()
    m["sprites"][1] = {**m["sprites"][0], "name": "other"}
    with pytest.raises(ValueError, match="distinct sprite sources"):
        audit(payload, m)


def test_nonzero_height_following_controls_do_not_gain_chain_closure():
    payload, m = fixture()
    payload = payload[:4] + bytes.fromhex("01000200") * 4 + payload[20:]
    m["sha256"] = digest(payload)
    m["sprites"][0]["sha256"] = digest(payload[:24])
    m["sprites"][0]["body_pair_words"] = [0x100, 0x200]
    with pytest.raises(ValueError, match="zero-height"):
        audit(payload, m)

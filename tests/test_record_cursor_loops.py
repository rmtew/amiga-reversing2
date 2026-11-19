"""DBF count and affine cursor translation jointly prove body-only fields."""

import pytest

from tests.test_structural_record_views import fixture


def check(
    tmp_path, *, trips="99", advance="lea.l 18(a0),a0", body="", entry="", prefix=""
):
    code = (
        prefix + " lea.l TABLE(pc),a0\n" + entry + f" move.w #{trips},d7\n"
        "again:\n move.w 2(a0),d0\n subq.w #1,4(a0)\n tst.w d1\n beq.w join\n"
        " move.l 14(a0),d2\njoin:\n" + body + " " + advance + "\n dbf.w d7,again\n"
        " move.w 2(a0),d4\n rts\n"
    )
    text, rows = fixture(tmp_path, record_size=18, count=100, code=code)
    fields = [
        (r, a) for r in rows for a in r["typed_accesses"] if a.get("record_cursor_loop")
    ]
    return text, rows, fields


def test_hundred_record_count_stride_and_branch_merge_prove_only_body(tmp_path):
    text, rows, fields = check(tmp_path)
    assert len(fields) == 3
    assert "move.w Point_y(a0),d0" in text
    assert "subq.w #1,Point_z(a0)" in text
    assert "move.l Point_relative(a0),d2" in text
    for _, a in fields:
        d = a["record_cursor_loop"]
        assert (d["iteration_count"], d["iteration_stride"], d["record_count"]) == (
            100,
            18,
            100,
        )
        assert d["body_only"] and "word_index" not in a
    exit_row = next(r for r in rows if r["text"].endswith(",d4"))
    assert not exit_row["typed_accesses"]
    assert exit_row["text"] == "move.w $0002(a0),d4"


@pytest.mark.parametrize(
    "options",
    [
        {"trips": "100"},
        {"advance": "lea.l 16(a0),a0"},
        {"body": " addq.w #1,d7\n"},
        {"body": " movea.l a1,a0\n"},
        {"body": " tst.w d2\n beq.w keep\n lea.l 18(a0),a0\nkeep:\n"},
        {"entry": " move.w d3,d7\n", "trips": "1"},
    ],
)
def test_unproved_counter_cursor_or_merge_does_not_get_body_contract(tmp_path, options):
    # The unknown-count case uses a register load instead of an immediate.
    if "entry" in options:
        text, rows = fixture(
            tmp_path,
            record_size=18,
            count=100,
            code=" lea.l TABLE(pc),a0\n move.w d3,d7\nagain:\n move.w 2(a0),d0\n lea.l 18(a0),a0\n dbf.w d7,again\n rts\n",
        )
        assert not [
            a for r in rows for a in r["typed_accesses"] if a.get("record_cursor_loop")
        ]
    else:
        _, _, fields = check(tmp_path, **options)
        assert not fields


def test_two_equal_ordinary_entry_paths_preserve_the_same_root(tmp_path):
    _, _, fields = check(
        tmp_path, entry=" tst.w d3\n beq.w ready\n lea.l TABLE(pc),a0\nready:\n"
    )
    assert len(fields) == 3


def test_different_entry_cursors_cannot_borrow_one_incoming_extent(tmp_path):
    _, _, fields = check(
        tmp_path, entry=" tst.w d3\n beq.w ready\n lea.l TABLE+18(pc),a0\nready:\n"
    )
    assert not fields


def test_backwards_hundred_record_cursor_keeps_exit_untyped(tmp_path):
    text, rows, fields = check(
        tmp_path, entry=" lea.l TABLE+1782(pc),a0\n", advance="lea.l -18(a0),a0"
    )
    assert len(fields) == 3
    assert all(a["record_cursor_loop"]["iteration_stride"] == -18 for _, a in fields)
    exit_row = next(r for r in rows if r["text"].endswith(",d4"))
    assert not exit_row["typed_accesses"]


def test_static_memory_to_memory_operands_share_the_unchanged_cursor(tmp_path):
    _, _, fields = check(tmp_path, body=" move.w 8(a0),2(a0)\n")
    copied = [(r, a) for r, a in fields if r["text"].startswith("move.w Point_w4")]
    assert len(copied) == 2
    assert {a["operand_index"] for _, a in copied} == {0, 1}


def test_repeated_updating_base_does_not_acquire_two_static_field_contracts(tmp_path):
    _, _, fields = check(
        tmp_path, body=" move.w (a0)+,2(a0)\n", advance="lea.l 16(a0),a0"
    )
    assert not [(r, a) for r, a in fields if r["text"].startswith("move.w (a0)+")]


def test_incomplete_flow_cannot_supply_a_record_cursor_proof(tmp_path, monkeypatch):
    monkeypatch.setenv("AMIGA_REVERSING_TYPED_FLOW_MAX_NODE_VISITS", "1")
    _, _, fields = check(tmp_path)
    assert not fields

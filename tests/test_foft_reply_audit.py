import pytest

from tools.foft_reply_audit import reply_shape


def test_guard_and_outer_flags_and_capture_preserve_byte_roles():
    shape = reply_shape(b"?h+h-fHello %1?\0")
    assert shape["guard"]["flag_index"] == ord("h")
    assert [op["kind"] for op in shape["operations"]] == [
        "set_flag",
        "clear_flag",
        "literal",
        "capture",
        "literal",
    ]
    assert shape["capture_output_bound_known"] is False
    assert shape["literal_output_upper_bound_excluding_nul"] == 7


def test_random_branches_use_original_plus_only_control_semantics():
    shape = reply_shape(b"%r2(+1yes/-1no)\0")
    random = shape["operations"][0]
    assert random["header_end"] == 4
    assert random["divisor"] == 2
    assert random["branches"][0]["set_flags"][0]["flag_index"] == ord("1")
    assert random["branches"][1]["set_flags"] == []
    assert random["branches"][1]["literal_bytes"] == 4
    assert shape["literal_output_upper_bound_excluding_nul"] == 4


@pytest.mark.parametrize(
    ("record", "reason"),
    [
        (b"no NUL", "NUL-terminated"),
        (b"a\0b\0", "NUL-terminated"),
        (b"?\0", "guard flag"),
        (b"?\x80x\0", "guard flag"),
        (b"+\x80\0", "flag operand"),
        (b"%0\0", "selector"),
        (b"%r0(a)\0", "random count"),
        (b"%r2(a)\0", "fewer alternatives"),
        (b"%r1(a\0", "unterminated"),
        (b"%\0", "percent operand"),
        (b"+\0", "flag operand"),
        (b"%r1(+)\0", "set operand"),
    ],
)
def test_unproved_or_out_of_bounds_shapes_refuse(record, reason):
    with pytest.raises(ValueError, match=reason):
        reply_shape(record)


def _fixture_audit(body):
    import hashlib

    from tools.foft_reply_audit import audit

    payload = bytes.fromhex("00001008 ffffffff") + b"x\0" + body
    manifest = {
        "members": [
            {
                "id": "main",
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "context": {"load_address": 0x1000},
            }
        ]
    }
    prior = {"source_extent": {"start": 0, "end": 8}}
    return audit, payload, manifest, prior


def test_audit_follows_guard_records_only_through_first_unconditional_reply():
    audit, payload, manifest, prior = _fixture_audit(b"?hagain\0+hhello\0unknown bytes")
    result = audit(payload, manifest, prior)
    assert result["reply_record_count"] == 2
    assert result["chains"][0]["source_end"] == 26
    assert result["chains"][0]["records"][0]["guard"]["next_record_if_clear"]
    with pytest.raises(ValueError, match="payload identity"):
        audit(payload + b"x", manifest, prior)


def test_audit_refuses_missing_guard_fallback_or_record_terminator():
    for body, reason in [(b"?honly\0", "fallback"), (b"unterminated", "crosses")]:
        audit, payload, manifest, prior = _fixture_audit(body)
        with pytest.raises(ValueError, match=reason):
            audit(payload, manifest, prior)


def test_selected_choice_keeps_original_distinct_flag_operand_checks():
    # The choice handler rejects zero, not negative bytes. This is a shape
    # contract, not permission to treat that index as inside the 128-byte array.
    shape = reply_shape(b"%r1(+\x80text)\0")
    branch = shape["operations"][0]["branches"][0]
    assert branch["set_flags"][0]["flag_index"] == 128
    assert branch["literal_bytes"] == 4

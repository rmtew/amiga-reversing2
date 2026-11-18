"""Pure host-side record validation, without guest execution or code inference."""

import pytest

from amiga_reversing.disasm.projected_face_audit import (
    audit_face_views,
    check_immediate_operand,
)


def face(style=1, offsets=(0, 10, 20)):
    return b"".join(v.to_bytes(2, "big") for v in (style, len(offsets), *offsets))


def view(start=0x1000, end=0x100A, count=1, maximum=20):
    return {
        "start_runtime": start,
        "end_runtime": end,
        "face_count": count,
        "projection_max_byte_offset": maximum,
    }


def audit(data, views):
    return audit_face_views(
        data, load_address=0x1000, views=views, projection_stride=10, style_count=32
    )


def test_variable_records_and_true_address_sharing_preserve_gap():
    data = face() + face(2, (0, 10, 20, 30)) + b"??" + face()
    result = audit(
        data,
        [
            view(end=0x1016, count=2, maximum=30),
            view(start=0x100A, end=0x1016, maximum=30),
            view(start=0x1018, end=0x1022),
        ],
    )
    assert result["unique_physical_records"] == 3
    assert result["covered_bytes"] == 32
    assert result["shared_record_starts"] == [0x100A]
    assert result["covered_spans"] == [
        {"start_runtime": 0x1000, "end_runtime": 0x1016},
        {"start_runtime": 0x1018, "end_runtime": 0x1022},
    ]
    assert result["views"][0]["vertex_count_histogram"] == {"3": 1, "4": 1}
    assert not result["control_flow_or_ownership_inferred"]


def test_identical_record_bytes_at_distinct_addresses_are_not_aliased():
    result = audit(face() * 2, [view(), view(start=0x100A, end=0x1014)])
    assert result["unique_physical_records"] == 2
    assert result["shared_record_starts"] == []


@pytest.mark.parametrize(
    "change",
    [
        {"face_count": 0},
        {"face_count": True},
        {"face_count": 2},
        {"end_runtime": 0x1008},
        {"end_runtime": 0x100C},
        {"start_runtime": 0x1001},
        {"start_runtime": 0xFFE},
        {"projection_max_byte_offset": 19},
        {"projection_max_byte_offset": 10},
        {"sha256": "wrong"},
    ],
)
def test_bad_tool_contract_is_rejected_without_changing_input(change):
    data = face()
    v = {**view(), **change}
    with pytest.raises(ValueError, match="face|extent|fingerprint"):
        audit(data, [v])
    assert data == face()


@pytest.mark.parametrize("data", [face(32), face(1, (0, 10)), face(1, (0, 10, 21))])
def test_out_of_contract_record_is_rejected(data):
    with pytest.raises(ValueError, match="face"):
        audit(data, [view(end=0x1000 + len(data))])


def test_native_operand_witness_does_not_guess_a_value():
    row = {
        "operand_facts": [
            {"immediate_value": 5},
            {"direct_register": "D0", "access": "register_write"},
        ]
    }
    check_immediate_operand(row, value=5, register="D0")
    with pytest.raises(ValueError, match="operand"):
        check_immediate_operand(row, value=6, register="D0")
    row["operand_facts"][1]["access"] = "register_read"
    with pytest.raises(ValueError, match="operand"):
        check_immediate_operand(row, value=5, register="D0")


def test_views_cannot_reinterpret_the_interior_of_another_face():
    data = face(1, (0, 10, *([0] * 10)))
    with pytest.raises(ValueError, match="overlap"):
        audit(data, [view(end=0x101C), view(start=0x1004, end=0x101C)])


def test_recipe_rechecks_native_operands_and_does_not_mutate_callbacks():
    import copy
    import hashlib

    from tools.foft_model_audit import audit_native

    data = bytes(8) + face()
    body_hash = hashlib.sha256(data[:8]).hexdigest()
    mapping = {
        "main_payload_sha256": hashlib.sha256(data).hexdigest(),
        "load_address": 0x1000,
        "revision": "fixture",
        "entries": [
            {
                "index": 0,
                "symbol": "example",
                "body_protocol_traced": True,
                "recognized_body": {
                    "runtime_start": 0x1000,
                    "runtime_end": 0x1008,
                    "sha256": body_hash,
                    "projection_max_byte_offset": 20,
                },
                "routine_operands": {
                    "projection_argument_runtime": 0x1000,
                    "face_count_argument_runtime": 0x1002,
                    "projection_call_runtime": 0x1006,
                    "projection_reader_runtime": 0x2000,
                    "face_reader_runtime": 0x2000,
                },
                "geometry": {
                    "start_runtime": 0x1008,
                    "end_runtime": 0x1012,
                    "unique_face_records": 1,
                    "shared_face_record_runtimes": [],
                    "views": [
                        {
                            **view(start=0x1008, end=0x1012),
                            "load_runtime": 0x1004,
                            "call_runtime": 0x1006,
                        }
                    ],
                },
            }
        ],
    }

    def assignment(value):
        return {
            "operand_facts": [
                {"immediate_value": value},
                {"direct_register": "D0", "access": "register_write"},
            ]
        }

    rows = {
        0x1000: assignment(20),
        0x1002: assignment(0),
        0x1006: {
            "operand_facts": [{"access": "branch_target", "absolute_address": 0x2000}]
        },
    }
    refs = [{"source_offset": 4, "operand_index": 0, "target_offset": 8}]
    before = copy.deepcopy((mapping, rows, refs))
    result = audit_native(
        data, mapping, instruction=rows.__getitem__, references=lambda _: refs
    )
    assert result["physical_face_records"] == 1 and not result["inference_or_mutation"]
    assert (mapping, rows, refs) == before
    refs[0]["target_offset"] = 9
    with pytest.raises(ValueError, match="reference"):
        audit_native(
            data, mapping, instruction=rows.__getitem__, references=lambda _: refs
        )
    refs[0]["target_offset"] = 8
    rows[0x1002] = assignment(1)
    with pytest.raises(ValueError, match="operand"):
        audit_native(
            data, mapping, instruction=rows.__getitem__, references=lambda _: refs
        )

    rows[0x1002] = assignment(0)
    mapping["coverage"] = {
        "body_protocols_traced": 1,
        "geometry_unique_faces": 1,
        "geometry_union_bytes": 11,
    }
    with pytest.raises(ValueError, match="aggregate"):
        audit_native(
            data, mapping, instruction=rows.__getitem__, references=lambda _: refs
        )

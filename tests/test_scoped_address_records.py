"""Record address fields compose existing ABS32 semantics without pointee claims."""

import pytest

from amiga_reversing.disasm.disk_set import DiskSet
from amiga_reversing.disasm.disk_set_state import _artifact, state_context
from amiga_reversing.disasm.effective_metadata import effective_target_metadata
from tests.test_disk_set_state import data_request, editable
from tests.test_scoped_record_arrays import metadata
from tests.test_scoped_scalar_arrays import snapshot


def fields():
    return [
        {"name": f"word{i}", "type": "UWORD", "offset": 2 * i, "size": 2}
        for i in range(8)
    ] + [
        {
            "name": "address",
            "type": "APTR",
            "offset": 16,
            "size": 4,
            "value_kind": "target_pointer",
            "pointer_address_domain": "mapped_source",
        }
    ]


def fixture(tmp_path, monkeypatch, *, values=None):
    target_offset = 4 + 64 * 20
    values = (
        values
        or [0, 0x1000 + target_offset, 0xDEADBEEF, 0x1001, 0x1000 + target_offset]
        + [0] * 59
    )
    payload = b"".join(
        b"".join((i + j).to_bytes(2, "big") for j in range(8))
        + value.to_bytes(4, "big")
        for i, value in enumerate(values)
    ) + bytes.fromhex("4e75a5a5")
    project, target, paths, call = editable(
        tmp_path,
        monkeypatch,
        record_data=payload,
        record_label=(target_offset, "knownTarget"),
    )
    selected = call(
        "inspect", source_offset=4, end_offset=target_offset, row_kind="data"
    )
    call(
        "interpret",
        **data_request(
            selected,
            "range.data_block.layout.create",
            {"name": "states", "default_unit": "word"},
        ),
    )
    return project, target, paths, call, target_offset


def request(call, end, fs=None):
    selected = call("inspect", source_offset=4, end_offset=end, row_kind="data")
    return data_request(
        selected,
        "range.data_block.records.declare",
        {
            "record_type": "State",
            "record_size": 20,
            "record_count": 64,
            "record_stride": 20,
            "fields": fs or fields(),
        },
    )


def test_mixed_address_records_keep_aliases_history_and_code_boundary(
    tmp_path, monkeypatch
):
    project, target, paths, call, end = fixture(tmp_path, monkeypatch)
    before = (target / "main.s").read_bytes()
    sibling = (target / "overlay.s").read_bytes()
    saved = call("interpret", **request(call, end))
    assert (
        saved["verification"]["media_exact"]
        and saved["verification"]["all_placement_coverage"]
    )
    record = next(t for t in metadata(target)["custom_structs"] if t["name"] == "State")
    pointer = record["fields"][-1]
    assert (
        pointer["value_kind"] == "target_pointer"
        and pointer["pointer_address_domain"] == "mapped_source"
    )
    assert pointer["pointer_struct"] is None
    owner = DiskSet.load(target, project_root=project)
    source, a = _artifact(owner, "main", paths)
    try:
        instructions = a.query_payload("instructions", limit=100)["items"]
        assert [r["source_offset"] for r in instructions] == [0, 2]
        assert (
            a.row_for_source_offset(section_index=0, offset=end)["kind"]
            != "instruction"
        )
        text = a.inline_source_text_with_profile()[0]
        assert "dc.l $00000000" in text and "$DEADBEEF" in text
        assert "State_address RS.L 1" in text
        assert text.count("dc.l knownTarget") == 2
        assert text.count("knownTarget:") == 1
        assert "dc.l $00001001" in text  # instruction interior stays literal
        assert "dc.w $0007" in text  # neighboring scalar retains its width
    finally:
        a.close()
    assert (target / "overlay.s").read_bytes() == sibling
    current = (target / "main.s").read_bytes()
    undone = call(
        "rollback",
        expected_revision=saved["revision"],
        action_id=saved["actions"][0]["action_id"],
    )
    assert (target / "main.s").read_bytes() == before
    redone = call(
        "rollback",
        expected_revision=undone["revision"],
        action_id=saved["actions"][0]["action_id"],
        redo=True,
    )
    assert (target / "main.s").read_bytes() == current
    regenerated = call("regenerate", expected_revision=redone["revision"])
    assert regenerated["verification"]["member_sources_exact"]
    proof = call(
        "verify",
        expected_revision=regenerated["revision"],
        output=str(tmp_path / "proof"),
    )["verification"]
    call(
        "review",
        expected_revision=regenerated["revision"],
        action_id=saved["actions"][0]["action_id"],
        decision="accept",
        reason="Address-field encoding and preserved code boundary verified.",
        verification_id=proof["receipt_id"],
    )
    with state_context(DiskSet.load(target, project_root=project), "main"):
        effective = effective_target_metadata(target, binary_source=source)
    address_leaves = [x for x in effective.seeded_entities if x.field_name == "address"]
    assert len(address_leaves) == 64 and all(
        x.pointer_struct is None for x in address_leaves
    )
    assert len(effective.seeded_code_entrypoints) == 0


@pytest.mark.parametrize(
    "change",
    [
        {"size": 2, "type": "UWORD"},
        {"pointer_address_domain": None},
        {"pointer_address_domain": "legacy"},
        {"pointer_address_domain": "other"},
        {"pointer_address_domain": {}},
        {"value_kind": {}},
        {"value_kind": "struct_pointer", "pointer_struct": "Target"},
        {"struct": "Nested"},
        {"value_kind": "scalar"},
        {"pointer_symbol_group": "wrong"},
        {"pointer_address_domain": "runtime_only"},
        {"pointer_address_domain": "runtime_only", "pointer_symbol_group": ""},
        {"pointer_address_domain": "runtime_only", "pointer_symbol_group": "x" * 64},
        {"type": "BPTR"},
        {"type": "APTR", "offset": 15},
        {"encoding": "relative"},
        {"pointee_type": "Unknown"},
        {"const": True},
        {"targets": [0x1000]},
    ],
)
def test_address_contract_rejections_are_atomic(tmp_path, monkeypatch, change):
    _, target, _, call, end = fixture(tmp_path, monkeypatch)
    fs = fields()
    fs[-1].update(change)
    body = request(call, end, fs)
    before = snapshot(target)
    with pytest.raises(
        ValueError, match="record|ABS32|pointer|field|flat|width|richer"
    ):
        call("interpret", **body)
    assert snapshot(target) == before


def test_explicit_runtime_domain_keeps_unregistered_values_literal(
    tmp_path, monkeypatch
):
    _, target, _, call, end = fixture(tmp_path, monkeypatch)
    fs = fields()
    fs[-1].update(
        type="ULONG",
        pointer_address_domain="runtime_only",
        pointer_symbol_group="scratch",
    )
    saved = call("interpret", **request(call, end, fs))
    assert saved["verification"]["media_exact"]
    ptr = next(t for t in metadata(target)["custom_structs"] if t["name"] == "State")[
        "fields"
    ][-1]
    assert ptr["pointer_symbol_group"] == "scratch"
    assert "$DEADBEEF" in (target / "main.s").read_text()


def test_shape_reuse_and_domain_change_do_not_drop_provenance(tmp_path, monkeypatch):
    _, target, _, call, end = fixture(tmp_path, monkeypatch)
    call("interpret", **request(call, end))
    record = next(t for t in metadata(target)["custom_structs"] if t["name"] == "State")
    call("interpret", **request(call, end))
    assert (
        next(t for t in metadata(target)["custom_structs"] if t["name"] == "State")
        == record
    )
    fs = fields()
    fs[-1].update(pointer_address_domain="runtime_only", pointer_symbol_group="scratch")
    before = snapshot(target)
    with pytest.raises(ValueError, match="conflict|contract"):
        call("interpret", **request(call, end, fs))
    assert snapshot(target) == before


@pytest.mark.parametrize("write", ["", " move.l #$12345678,(a2)\n"])
def test_address_field_access_has_no_implied_pointee_or_constness(tmp_path, write):
    from amiga_reversing.disasm import c_backend
    from tests.test_base_candidates import candidate_artifact
    from tests.test_typed_pointer_cursor_read import metadata as pointer_metadata

    extra = pointer_metadata()
    field = extra["custom_structs"][0]["fields"][0]
    field["value_kind"] = "target_pointer"
    del field["pointer_struct"]
    field["pointer_address_domain"] = "mapped_source"
    with candidate_artifact(
        tmp_path,
        write + " move.l (a2)+,d3\n movea.l d3,a0\n move.w (a0),d0\n rts",
        [],
        extra,
    ) as (a, original):
        accesses = a.analysis_payload()[0]["sections"][0][
            "recovered_platform_typed_accesses"
        ]
        assert any(r["root_struct_name"] == "Record" for r in accesses), accesses
        assert not any(r["root_struct_name"] == "Header" for r in accesses)
        text = a.inline_source_text_with_profile()[0]
        if write:
            assert "$12345678" in text
        assert (
            c_backend.assemble_platform_source_text_with_c_backend("amiga-raw", text)[0]
            == original
        )

"""Explicit imported scalar correction retains scoped ownership and history."""

import json

import pytest

from amiga_reversing.disasm.disk_set import DiskSet
from tests.test_disk_set_state import data_request, editable

COMMAND = "correction.suppress_seeded_item.seeded_entity"


def prepared(tmp_path, monkeypatch, unit="word"):
    _, target, _, call = editable(
        tmp_path,
        monkeypatch,
        scalar_array=True,
        scalar_tail="long",
        absolute_alias=True,
    )
    selected = call("inspect", source_offset=4, end_offset=1032, row_kind="data")
    call(
        "interpret",
        **data_request(
            selected,
            "range.data_block.layout.create",
            {"name": "wordValues", "default_unit": unit},
        ),
    )
    selected = call("inspect", source_offset=4, end_offset=1032, row_kind="data")
    call(
        "interpret",
        **data_request(
            selected,
            "range.data_block.element.set",
            {
                "kind": "array",
                "width": 1028,
                "array_count": 1028 if unit == "byte" else 514,
                "array_stride": 1 if unit == "byte" else 2,
            },
        ),
    )
    return target, call


def test_explicit_imported_correction_roundtrip_undo_and_redo(tmp_path, monkeypatch):
    target, call = prepared(tmp_path, monkeypatch)
    original = (target / "analysis/main.target_metadata.json").read_bytes()
    selected = call("inspect", source_offset=1028, row_kind="data")
    assert COMMAND in {c["command_id"] for c in selected["commands"]}
    saved = call("interpret", **data_request(selected, COMMAND, {}))
    assert (
        saved["verification"]["media_exact"]
        and saved["verification"]["all_placement_coverage"]
    )
    text = (target / "main.s").read_text()
    assert "$0200" in text and "dc.w $0201" in text
    assert "dc.l $02000201" not in text
    assert "syntheticRuntimeEntry:" in text
    assert (target / "analysis/main.target_metadata.json").read_bytes() == original
    assert any(
        e.get("unit") == "long" and e["addr"] == 1028
        for e in json.loads(original)["seeded_entities"]
    )
    action = saved["actions"][0]["action_id"]
    undone = call("rollback", expected_revision=saved["revision"], action_id=action)
    assert "dc.l $02000201" in (target / "main.s").read_text()
    redone = call(
        "rollback", expected_revision=undone["revision"], action_id=action, redo=True
    )
    assert redone["verification"]["media_exact"]
    assert (target / "main.s").read_text() == text
    assert (target / "analysis/main.target_metadata.json").read_bytes() == original


@pytest.mark.parametrize(
    "protection",
    [
        "comment",
        "named",
        "manual",
        "validated",
        "typed",
        "pointer",
        "evidence",
        "partial",
        "same_unit",
        "owner",
        "zero_owner",
    ],
)
def test_protected_or_partial_imports_do_not_offer_correction(
    tmp_path, monkeypatch, protection
):
    from amiga_reversing.disasm.disk_set_state import _conflicting_array_scalar_seed

    target, call = prepared(tmp_path, monkeypatch)
    # Simulate an authoritative prior import, not an application mutation.
    owner = DiskSet.load(target, project_root=target.parent.parent)
    path = target / owner.members["main"]["analysis"]["metadata"]["path"]
    meta = json.loads(path.read_bytes())
    seed = next(
        e
        for e in meta["seeded_entities"]
        if e.get("addr") == 1028 and e.get("unit") == "long"
    )
    updates = {
        "comment": {"comment": "Independent interpretation"},
        "named": {"name": "ownedLong"},
        "manual": {"source_id": "manual_action_log"},
        "validated": {"review_status": "validated"},
        "typed": {"field_type": "long"},
        "pointer": {"value_kind": "target_pointer"},
        "evidence": {"source_evidence_id": "prior-proof"},
        "partial": {"end": 1034},
        "same_unit": {"unit": "word"},
        "owner": {"owner_action_id": "independent"},
        "zero_owner": {"source_owner_start": 0},
    }
    seed.update(updates[protection])
    layout = next(x for x in meta["data_block_layouts"] if x["source_start"] == 4)
    row = {"start_offset": 1028, "end_offset": 1032}
    before = json.dumps(meta, sort_keys=True)
    assert _conflicting_array_scalar_seed(row, layout, meta) is None
    assert json.dumps(meta, sort_keys=True) == before


def test_correction_keeps_revision_and_member_scope(tmp_path, monkeypatch):
    target, call = prepared(tmp_path, monkeypatch)
    selected = call("inspect", source_offset=1028, row_kind="data")
    stale = data_request(selected, COMMAND, {})
    stale["expected_revision"] = "0" * 64
    before = (target / "manifest.json").read_bytes()
    with pytest.raises(ValueError, match="revision"):
        call("interpret", **stale)
    for params in (
        {"hunk": 1},
        {"kind": "seeded_code_entrypoint"},
        {"addr": 2},
        {"end": 1030},
    ):
        with pytest.raises(ValueError, match="suppressible seeded item"):
            call("interpret", **data_request(selected, COMMAND, params))
        assert (target / "manifest.json").read_bytes() == before
    forged = data_request(selected, COMMAND, {})
    forged["context"]["locator"]["member_id"] = "boot"
    with pytest.raises(ValueError, match="subject|revision|member|locator"):
        call("interpret", **forged)
    assert (target / "manifest.json").read_bytes() == before
    instruction = call("inspect", source_offset=0, row_kind="instruction")
    assert COMMAND not in {c["command_id"] for c in instruction["commands"]}


@pytest.mark.parametrize(
    "conflict",
    ["partial", "typed_array", "pointer_table", "unproven_array", "overlap", "phase"],
)
def test_array_or_identity_conflicts_stay_closed(tmp_path, monkeypatch, conflict):
    from amiga_reversing.disasm.disk_set_state import _conflicting_array_scalar_seed

    target, _ = prepared(tmp_path, monkeypatch)
    owner = DiskSet.load(target, project_root=target.parent.parent)
    meta = json.loads(
        (target / owner.members["main"]["analysis"]["metadata"]["path"]).read_bytes()
    )
    layout = next(x for x in meta["data_block_layouts"] if x["source_start"] == 4)
    row = {"start_offset": 1028, "end_offset": 1032}
    if conflict == "partial":
        row["start_offset"] = 1030
    if conflict == "typed_array":
        layout["elements"][0]["type_binding"] = {"kind": "custom", "type_id": "proven"}
    if conflict == "pointer_table":
        layout["pointer_table"] = {"row_count": 257}
    if conflict == "unproven_array":
        layout["elements"][0]["citation"] = "Imported assumption"
    if conflict == "overlap":
        meta["seeded_entities"].append(
            {
                "hunk": 0,
                "addr": 1030,
                "end": 1032,
                "type": "data",
                "unit": "word",
                "name": "independent",
            }
        )
    if conflict == "phase":
        row["start_offset"] = 1029
    assert _conflicting_array_scalar_seed(row, layout, meta) is None


@pytest.mark.parametrize("unit", ["word", "long"])
def test_same_general_predicate_handles_both_scalar_array_widths(
    tmp_path, monkeypatch, unit
):
    from amiga_reversing.disasm.disk_set_state import _conflicting_array_scalar_seed

    target, _ = prepared(tmp_path, monkeypatch)
    owner = DiskSet.load(target, project_root=target.parent.parent)
    meta = json.loads(
        (target / owner.members["main"]["analysis"]["metadata"]["path"]).read_bytes()
    )
    layout = next(x for x in meta["data_block_layouts"] if x["source_start"] == 4)
    layout["default_unit"] = unit
    layout["elements"][0].update(
        array_stride=2 if unit == "word" else 4,
        array_count=514 if unit == "word" else 257,
    )
    for seed in meta["seeded_entities"]:
        if seed.get("addr") == 4 and seed.get("end") == 1032:
            seed["unit"] = unit
        if seed.get("addr") == 1028 and seed.get("end") == 1032:
            seed["unit"] = "long" if unit == "word" else "word"
    assert _conflicting_array_scalar_seed(
        {"start_offset": 1028, "end_offset": 1032}, layout, meta
    ) == {"kind": "seeded_entity", "hunk": 0, "addr": 1028, "end": 1032}


def test_explicit_scalar_correction_in_a_byte_array_keeps_aliases_and_exact_bytes(
    tmp_path, monkeypatch
):
    target, call = prepared(tmp_path, monkeypatch, unit="byte")
    selected = call("inspect", source_offset=1028, row_kind="data")
    assert COMMAND in {c["command_id"] for c in selected["commands"]}
    saved = call("interpret", **data_request(selected, COMMAND, {}))
    assert (
        saved["verification"]["media_exact"]
        and saved["verification"]["all_placement_coverage"]
    )
    text = (target / "main.s").read_text()
    assert "syntheticRuntimeEntry:" in text
    assert "dc.l $02000201" not in text
    undone = call(
        "rollback",
        expected_revision=saved["revision"],
        action_id=saved["actions"][0]["action_id"],
    )
    assert undone["verification"]["media_exact"]
    assert "dc.l $02000201" in (target / "main.s").read_text()

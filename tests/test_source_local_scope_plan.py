"""Explicit source-scope plans use normal revision, journal and byte checks."""

import copy

import pytest

from amiga_reversing.disasm.disk_set import DiskSet
from amiga_reversing.disasm.source_local_scopes import imported_local_family
from tests.test_disk_set_state import data_request, editable
from tests.test_scoped_scalar_arrays import snapshot


def source_labels(*, raw=False, owner=0, child=2):
    return [
        {
            "hunk": 0,
            "addr": at,
            "name": name,
            "seed_origin": "manual_analysis",
            "review_status": "seeded",
            "citation": "Original imported namespace",
        }
        for at, name in [(owner, "Original"), (child, "Original\\.done")]
        + ([(child + 2, "Original\\.payload")] if raw else [])
    ]


def test_family_uses_unique_original_source_owner_and_retains_authored_names():
    original = {"seeded_code_labels": source_labels()}
    current = copy.deepcopy(original)
    current["seeded_code_labels"][0]["name"] = "Renamed"
    family = imported_local_family(
        original, current, owner_offset=0, member_start=0, member_end=4
    )
    assert (
        family["original_owner_name"] == "Original"
        and family["owner_name"] == "Renamed"
    )
    assert family["candidates"][0]["local_name"] == ".done"
    current["seeded_code_labels"][1]["name"] = "public_return"
    assert (
        imported_local_family(
            original, current, owner_offset=0, member_start=0, member_end=4
        )["deferred"][0]["reason"]
        == "authored_name_or_other_namespace"
    )


@pytest.mark.parametrize(
    "case", ["missing", "ambiguous", "duplicate", "data", "outside"]
)
def test_missing_ambiguous_or_outside_source_owners_refuse(case):
    original = {"seeded_code_labels": source_labels()}
    current = copy.deepcopy(original)
    offset = 0
    if case == "missing":
        original["seeded_code_labels"].pop(0)
    if case == "ambiguous":
        original["seeded_code_labels"].append({**source_labels()[0], "name": "alias"})
    if case == "duplicate":
        original["seeded_code_labels"].append({**source_labels()[0], "addr": 6})
    if case == "data":
        original["seeded_entities"] = [
            {"hunk": 0, "addr": 0, "name": "Original", "type": "data"}
        ]
    if case == "outside":
        offset = 4
    with pytest.raises(ValueError, match="owner|namespace|outside"):
        imported_local_family(
            original, current, owner_offset=offset, member_start=0, member_end=4
        )


def test_plan_does_not_claim_outside_children_or_truncate_names():
    original = {"seeded_code_labels": source_labels(raw=True)}
    result = imported_local_family(
        original, original, owner_offset=0, member_start=0, member_end=4
    )
    assert (
        len(result["candidates"]) == 1 and result["deferred"][0]["source_offset"] == 4
    )
    result = imported_local_family(
        original, original, owner_offset=0, member_start=0, member_end=8, name="N" * 60
    )
    assert not result["candidates"] and all(
        r["reason"] == "qualified_name_limit" for r in result["deferred"]
    )


def test_normal_plan_apply_replay_future_owner_rename_and_undo(tmp_path, monkeypatch):
    project, target, _, call = editable(
        tmp_path,
        monkeypatch,
        owner_scope=True,
        source_labels=source_labels(owner=4, child=6),
    )
    owner = DiskSet.load(target, project_root=project)
    call("state")
    before = snapshot(target)
    plan = call(
        "plan_local_scopes",
        expected_revision=owner.revision,
        source_offset=4,
        name="Restored",
    )
    assert (
        plan["complete"]
        and not plan["writes_performed"]
        and not plan["code_admission_changed"]
    )
    assert len(plan["entries"]) == 2 and snapshot(target) == before
    saved = call(
        "interpret_batch",
        expected_revision=plan["expected_revision"],
        entries=plan["entries"],
    )
    assert saved["verification"]["media_exact"]
    current = DiskSet.load(target, project_root=project)
    labels = current.manifest["members"][0]["analysis"]["metadata"]["path"]
    import json

    metadata = json.loads((target / labels).read_bytes())
    assert (
        next(r["name"] for r in metadata["seeded_code_labels"] if r["addr"] == 6)
        == "Restored\\.done"
    )
    again = call(
        "plan_local_scopes", expected_revision=saved["revision"], source_offset=4
    )
    assert not again["entries"] and again["retained"][0]["reason"] == "already_bound"
    inspected = call("inspect", source_offset=4, row_kind="label")
    renamed = call(
        "interpret", **data_request(inspected, "label.rename", {"name": "Final"})
    )
    current = DiskSet.load(target, project_root=project)
    metadata = json.loads(
        (target / current.members["main"]["analysis"]["metadata"]["path"]).read_bytes()
    )
    assert (
        next(r["name"] for r in metadata["seeded_code_labels"] if r["addr"] == 6)
        == "Final\\.done"
    )
    assert call("regenerate", expected_revision=renamed["revision"])["verification"][
        "media_exact"
    ]
    action = renamed["actions"][0]["action_id"]
    undone = call("rollback", expected_revision=renamed["revision"], action_id=action)
    assert undone["verification"]["media_exact"]
    call("rollback", expected_revision=undone["revision"], action_id=action, redo=True)


def test_raw_rts_candidate_is_deferred_and_planning_never_admits_code(
    tmp_path, monkeypatch
):
    project, target, _, call = editable(
        tmp_path,
        monkeypatch,
        owner_scope=True,
        owner_tail=bytes.fromhex("4e75a55a"),
        source_labels=source_labels(raw=True, owner=4, child=6),
    )
    owner = DiskSet.load(target, project_root=project)
    call("state")
    before = snapshot(target)
    plan = call("plan_local_scopes", expected_revision=owner.revision, source_offset=4)
    assert not plan["complete"] and len(plan["entries"]) == 1
    assert plan["deferred"][0]["reason"] == "not_an_accepted_instruction_boundary"
    assert snapshot(target) == before


def test_stale_plan_and_wrong_member_are_refused_before_any_write(
    tmp_path, monkeypatch
):
    project, target, _, call = editable(
        tmp_path,
        monkeypatch,
        owner_scope=True,
        source_labels=source_labels(owner=4, child=6),
    )
    owner = DiskSet.load(target, project_root=project)
    call("state")
    before = snapshot(target)
    with pytest.raises(ValueError, match="stale_revision"):
        call("plan_local_scopes", expected_revision="0" * 64, source_offset=4)
    with pytest.raises(ValueError, match="owner|source_offset"):
        call(
            "plan_local_scopes",
            member="return_view",
            expected_revision=owner.revision,
            source_offset=2,
        )
    assert snapshot(target) == before


def test_bare_display_keeps_canonical_identity_and_ambiguous_sources_refuse():
    from amiga_reversing.disasm.listing_context import (
        annotate_source_label_identity,
        listing_element_contexts,
    )
    from amiga_reversing.disasm.manual_action_catalog import (
        _label_validation_metadata,
        _row_label_payload,
    )

    row = {
        "kind": "label",
        "section_index": 0,
        "start_offset": 2,
        "end_offset": 2,
        "label": ".done",
        "stable_key": "s0:00000002:label",
    }
    annotate_source_label_identity(row, source_labels())
    element = next(
        e for e in listing_element_contexts(row) if e["element_kind"] == "label"
    )
    assert (
        element["symbol"] == ".done"
        and element["canonical_symbol"] == "Original\\.done"
    )
    assert element["element_id"].endswith("label:.done")
    payload = _row_label_payload(
        row, element, {"name": ".finish", "scope": "local", "owner_offset": 0}
    )
    assert payload["previous_name"] == "Original\\.done"
    assert _label_validation_metadata(element)["current_scope"] == "local"
    ambiguous = {k: v for k, v in row.items() if not k.startswith("canonical_")}
    annotate_source_label_identity(
        ambiguous, source_labels() + [{"hunk": 0, "addr": 2, "name": "Other\\.done"}]
    )
    element = next(
        e for e in listing_element_contexts(ambiguous) if e["element_kind"] == "label"
    )
    with pytest.raises(ValueError, match="ambiguous canonical"):
        _row_label_payload(
            ambiguous, element, {"name": ".finish", "scope": "local", "owner_offset": 0}
        )


def test_existing_named_entry_can_bind_scopes_without_renaming_an_alias(
    tmp_path, monkeypatch
):
    project, target, _, call = editable(
        tmp_path, monkeypatch, source_labels=source_labels()
    )
    owner = DiskSet.load(target, project_root=project)
    plan = call("plan_local_scopes", expected_revision=owner.revision, source_offset=0)
    assert plan["complete"] and len(plan["entries"]) == 1
    assert plan["verification_scope"] == "planning_only" and plan["media_exact"] is None
    saved = call(
        "interpret_batch", expected_revision=plan["revision"], entries=plan["entries"]
    )
    assert saved["verification"]["media_exact"]


def test_member_plan_rehashes_owner_bytes_and_apply_cannot_use_stale_inputs(
    tmp_path, monkeypatch
):
    project, target, paths, call = editable(
        tmp_path,
        monkeypatch,
        owner_scope=True,
        source_labels=source_labels(owner=4, child=6),
    )
    owner = DiskSet.load(target, project_root=project)
    values, _, _ = owner.recover(paths)
    pinned = tmp_path / "main.bin"
    pinned.write_bytes(values["main"])
    inputs = {
        "input_mode": "member",
        "media_paths": {},
        "member_paths": {"main": str(pinned)},
    }
    call("state")
    before = snapshot(target)
    plan = call(
        "plan_local_scopes", expected_revision=owner.revision, source_offset=4, **inputs
    )
    assert (
        plan["entries"]
        and plan["media_exact"] is None
        and plan["all_placement_coverage"] is None
    )
    assert plan["verification_scope"] == "planning_only" and "receipt_id" not in plan
    pinned.write_bytes(bytes(len(values["main"])))
    with pytest.raises(ValueError, match="identity|hash|SHA|sha|pinned|match"):
        call(
            "interpret_batch",
            expected_revision=plan["revision"],
            entries=plan["entries"],
            **inputs,
        )
    with pytest.raises(ValueError, match="identity|hash|SHA|sha|pinned|match"):
        call(
            "plan_local_scopes",
            expected_revision=owner.revision,
            source_offset=4,
            **inputs,
        )
    assert snapshot(target) == before


def test_normal_bind_preserves_imported_label_comment(tmp_path, monkeypatch):
    labels = source_labels(owner=4, child=6)
    labels[1]["comment"] = "Original return-point note"
    project, target, _, call = editable(
        tmp_path, monkeypatch, owner_scope=True, source_labels=labels
    )
    owner = DiskSet.load(target, project_root=project)
    plan = call(
        "plan_local_scopes",
        expected_revision=owner.revision,
        source_offset=4,
        name="Restored",
    )
    saved = call(
        "interpret_batch", expected_revision=plan["revision"], entries=plan["entries"]
    )
    current = DiskSet.load(target, project_root=project)
    import json

    projected = json.loads(
        (target / current.members["main"]["analysis"]["metadata"]["path"]).read_bytes()
    )
    child = next(r for r in projected["seeded_code_labels"] if r["addr"] == 6)
    assert (
        child["name"] == "Restored\\.done"
        and child["comment"] == "Original return-point note"
    )
    assert saved["verification"]["media_exact"]


def test_identical_imported_scope_identities_are_not_duplicate_actions():
    original = {"seeded_code_labels": source_labels() * 2}
    family = imported_local_family(
        original, original, owner_offset=0, member_start=0, member_end=4
    )
    assert len(family["candidates"]) == 1 and not family["deferred"]

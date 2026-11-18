"""Catalog ID changes cannot duplicate an authored source owner or strand edits."""

import json
from copy import deepcopy
from types import SimpleNamespace

import pytest

from amiga_reversing.disasm.disk_codecs import digest
from amiga_reversing.disasm.disk_set import DiskSet, compose_source_package
from amiga_reversing.disasm.disk_set_state import (
    _apply_member_change,
    _member_packages,
    state_context,
)
from amiga_reversing.disasm.effective_metadata import effective_metadata_text
from amiga_reversing.disasm.manual_action_catalog import target_catalog_manual_payload
from amiga_reversing.disasm.manual_actions import (
    append_manual_actions,
    manual_action_kind,
)
from amiga_reversing.disasm.source_label_identity import (
    exact_duplicate_source_owner_undo,
    reuse_source_global_point_actions,
)
from amiga_reversing.disasm.source_package_publish import publish_source_package
from tests.test_disk_set_state import editable


def seed_owner(project, target, paths):
    owner = DiskSet.load(target, project_root=project)
    kind, payload = target_catalog_manual_payload(
        "target.code_label.add", {"hunk": 0, "addr": 4, "name": "rootFunction"}
    )

    def append(root, source):
        return {
            "actions": append_manual_actions(
                root,
                binary_source=source,
                actions=[(manual_action_kind(kind), payload)],
            )
        }

    result = _apply_member_change(owner, "main", {"media_paths": paths}, append)
    return result, payload["label"]["label_id"]


def rename(inspected, name, **params):
    row = inspected["row"]
    return {
        "expected_revision": inspected["revision"],
        "command_id": "label.rename",
        "context": inspected["context"],
        "parameters": dict(name=name, **params),
        "evidence": {
            "reason": "Reuse this independently proved existing source point.",
            "evidence_refs": [row.get("stable_key") or row["row_key"]],
        },
    }


def files(target):
    return {
        str(p.relative_to(target)): p.read_bytes()
        for p in target.rglob("*")
        if p.is_file() and p.name != ".target-history.lock"
    }


def test_scoped_restatement_reuses_catalog_owner_and_locals_survive_undo_redo(
    tmp_path, monkeypatch
):
    project, target, paths, call = editable(tmp_path, monkeypatch, owner_scope=True)
    _, identity = seed_owner(project, target, paths)
    metadata_path = (
        target
        / DiskSet.load(target, project_root=project).members["main"]["analysis"][
            "metadata"
        ]["path"]
    )
    original_owner = next(
        p
        for p in json.loads(metadata_path.read_bytes())["seeded_code_labels"]
        if p["name"] == "rootFunction"
    )
    journal = target / "analysis/main.manual_actions.jsonl"
    prefix = journal.read_bytes()
    for _ in range(2):
        inspected = call("inspect", source_offset=4, row_kind="label")
        saved = call("interpret", **rename(inspected, "rootFunction", scope="global"))
        last = json.loads(journal.read_text().splitlines()[-1])
        assert last["label"]["label_id"] == identity
        assert (
            next(
                p
                for p in json.loads(metadata_path.read_bytes())["seeded_code_labels"]
                if p["name"] == "rootFunction"
            )
            == original_owner
        )
    restatement = last["action_id"]
    inspected = call("inspect", source_offset=6, row_kind="label")
    saved = call(
        "interpret", **rename(inspected, ".done", scope="local", owner_offset=4)
    )
    for redo in (False, True):
        saved = call(
            "rollback",
            expected_revision=saved["revision"],
            action_id=restatement,
            redo=redo,
        )
        assert "rootFunction:" in (target / "main.s").read_text()
        assert ".done:" in (target / "main.s").read_text()
    checked = call(
        "verify", expected_revision=saved["revision"], output=str(tmp_path / "verified")
    )
    assert (
        checked["coverage"]["complete"] and checked["coverage"]["independent_redecode"]
    )
    assert (
        checked["members"]["main"]["native_exact"]
        and checked["members"]["main"]["vasm_exact"]
    )
    assert journal.read_bytes().startswith(prefix)


def test_different_source_point_collision_is_atomic(tmp_path, monkeypatch):
    project, target, paths, call = editable(tmp_path, monkeypatch, owner_scope=True)
    seed_owner(project, target, paths)
    inspected = call("inspect", source_offset=6, row_kind="label")
    before = files(target)
    with pytest.raises(ValueError, match="replay blocked after edit"):
        call("interpret", **rename(inspected, "rootFunction", scope="global"))
    assert files(target) == before


def legacy_duplicate(project, target, paths):
    """Test-only reproduction of a snapshot published by the old transaction."""
    owner = DiskSet.load(target, project_root=project)
    values, _, _ = owner.recover(paths)
    source, _ = owner._analysis_input("main", values)
    member = owner.members["main"]
    analysis = member["analysis"]
    with state_context(owner, "main"):
        action = append_manual_actions(
            target,
            binary_source=source,
            actions=[
                (
                    manual_action_kind("create_manual_label"),
                    {
                        "label": {
                            "label_id": "legacy-row-owner",
                            "hunk": 0,
                            "addr": 4,
                            "end": 5,
                            "name": "rootFunction",
                            "scope": "global",
                            "address_domain": "source",
                        }
                    },
                )
            ],
        )[0]
        metadata = effective_metadata_text(target, binary_source=source).encode()
    (target / analysis["metadata"]["path"]).write_bytes(metadata)
    analysis["metadata"]["sha256"] = digest(metadata)
    for ref in analysis["state"].values():
        p = target / ref["path"]
        ref["sha256"] = digest(p.read_bytes()) if p.exists() else None
    package = compose_source_package(
        owner.manifest, _member_packages(owner, "main", source)
    )
    publish_source_package(package, target)
    owner.manifest["package_sha256"] = package["sha256"]
    (target / "manifest.json").write_text(json.dumps(owner.manifest))
    return action


def test_exact_legacy_duplicate_has_checked_undo_but_redo_cannot_reintroduce_it(
    tmp_path, monkeypatch
):
    project, target, paths, call = editable(tmp_path, monkeypatch, owner_scope=True)
    seed_owner(project, target, paths)
    duplicate = legacy_duplicate(project, target, paths)
    journal = target / "analysis/main.manual_actions.jsonl"
    prefix = journal.read_bytes()
    revision = DiskSet.load(target, project_root=project).revision
    saved = call(
        "rollback", expected_revision=revision, action_id=duplicate["action_id"]
    )
    assert "rootFunction:" in (target / "main.s").read_text()
    assert journal.read_bytes().startswith(prefix)
    assert (
        json.loads(journal.read_text().splitlines()[-1])["undoes_action_id"]
        == duplicate["action_id"]
    )
    checked = call(
        "verify", expected_revision=saved["revision"], output=str(tmp_path / "verified")
    )
    assert (
        checked["coverage"]["complete"] and checked["coverage"]["independent_redecode"]
    )
    before = files(target)
    with pytest.raises(ValueError, match="replay blocked after edit"):
        call(
            "rollback",
            expected_revision=saved["revision"],
            action_id=duplicate["action_id"],
            redo=True,
        )
    assert files(target) == before


@pytest.mark.parametrize(
    "changes",
    [
        {"addr": 5},
        {"hunk": 1},
        {"name": "other"},
        {"address_domain": "runtime"},
        {"scope": "local", "owner_offset": 0},
        {"end": 8},
    ],
)
def test_identity_reuse_never_merges_different_contexts(changes):
    prior = {
        "label_id": "original",
        "hunk": 0,
        "addr": 4,
        "name": "root",
        "scope": "global",
        "address_domain": "source",
        "comment": "Retain original annotation",
    }
    new = {**prior, **changes, "label_id": "row"}
    result = reuse_source_global_point_actions(
        [("create_manual_label", {"label": new})], [prior]
    )
    assert result[0][1]["label"]["label_id"] == "row"
    assert prior["label_id"] == "original"


def test_reuse_retains_provenance_attributes_and_duplicate_existing_ids_remain_ambiguous():
    prior = {
        "label_id": "original",
        "hunk": 0,
        "addr": 4,
        "name": "root",
        "comment": "Keep",
        "scope": "global",
    }
    new = {"label_id": "row", "hunk": 0, "addr": 4, "name": "root", "scope": "global"}
    result = reuse_source_global_point_actions(
        [("create_manual_label", {"label": new})], [prior]
    )
    assert result[0][1]["label"]["label_id"] == "original"
    assert result[0][1]["label"]["comment"] == "Keep"
    result = reuse_source_global_point_actions(
        [("create_manual_label", {"label": new})],
        [prior, {**prior, "label_id": "second"}],
    )
    assert result[0][1]["label"]["label_id"] == "row"


@pytest.mark.parametrize(
    "change",
    [
        "inactive",
        "redo_kind",
        "other_blocker",
        "other_point",
        "runtime",
        "non_point",
        "local",
        "unrelated",
    ],
)
def test_blocked_recovery_requires_only_the_exact_attributed_duplicate(change):
    label = {
        "label_id": "new",
        "hunk": 0,
        "addr": 4,
        "name": "root",
        "scope": "global",
        "address_domain": "source",
    }
    old = {**label, "label_id": "old"}
    record = {
        "kind": "create_manual_label",
        "action_id": "action",
        "label": deepcopy(label),
    }
    item = {
        "kind": "label_scope_conflict",
        "review_blocker": True,
        "label_ids": ["old", "new"],
    }
    projection = SimpleNamespace(
        active_action_ids=["action"], labels=[old, label], review_items=[item]
    )
    assert exact_duplicate_source_owner_undo(projection, record)
    if change == "inactive":
        projection.active_action_ids = []
    if change == "redo_kind":
        record["kind"] = "redo_action"
    if change == "other_blocker":
        projection.review_items.append({"kind": "other", "review_blocker": True})
    if change == "other_point":
        old["addr"] = 6
    if change == "runtime":
        old["address_domain"] = "runtime"
    if change == "non_point":
        record["label"]["end"] = 8
    if change == "local":
        record["label"].update(scope="local", owner_offset=0)
    if change == "unrelated":
        record["label"]["label_id"] = "unrelated"
    assert not exact_duplicate_source_owner_undo(projection, record)

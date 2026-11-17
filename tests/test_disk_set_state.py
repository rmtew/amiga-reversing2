"""Existing catalog/MAL editing through a single scoped disk-set owner."""

import json

import pytest

from amiga_reversing.disasm.analysis_state_paths import STATE_FILES
from amiga_reversing.disasm.disk_codecs import digest
from amiga_reversing.disasm.disk_set import DiskSet, compose_source_package
from amiga_reversing.disasm.source_package_publish import publish_source_package
from tests.test_disk_set import ROOT, fixture, packages_for


def editable(tmp_path, monkeypatch):
    from amiga_reversing.disasm import restoration, server

    project, target, paths, manifest = fixture(tmp_path)
    metadata_path = target / manifest["members"][0]["analysis"]["metadata"]["path"]
    metadata = json.loads(metadata_path.read_bytes())
    metadata["seeded_code_labels"] = [
        {
            "hunk": 0,
            "addr": 2,
            "name": "finish",
            "seed_origin": "manual_analysis",
            "review_status": "seeded",
            "citation": "Synthetic RTS boundary",
        }
    ]
    data = json.dumps(metadata).encode()
    metadata_path.write_bytes(data)
    manifest["members"][0]["analysis"]["metadata"]["sha256"] = digest(data)
    (project / "tools").mkdir()
    (project / "tools/vasmm68k_mot.exe").symlink_to(ROOT / "tools/vasmm68k_mot.exe")
    for member in manifest["members"]:
        if not member["analysis"]:
            continue
        state = {}
        for name in STATE_FILES:
            path = "analysis/" + member["id"] + "." + name
            data = (
                (target / member["analysis"]["metadata"]["path"]).read_bytes()
                if name == "target_metadata.json"
                else None
            )
            if data is not None:
                (target / path).write_bytes(data)
            state[name] = {
                "path": path,
                "sha256": digest(data) if data is not None else None,
            }
        member["analysis"]["state"] = state
    package = compose_source_package(manifest, packages_for(target, manifest))
    publish_source_package(package, target)
    manifest["package_sha256"] = package["sha256"]
    (target / "manifest.json").write_text(json.dumps(manifest))
    # Begin from the same native-rendered baseline as an imported real owner.
    from amiga_reversing.disasm.disk_set_state import _member_packages

    owner = DiskSet.load(target, project_root=project)
    values, _, _ = owner.recover(paths)
    packages = packages_for(target, manifest)
    for member in ("main", "overlay"):
        source, _ = owner._analysis_input(member, values)
        from amiga_reversing.disasm.disk_set_state import state_context
        from amiga_reversing.disasm.effective_metadata import effective_metadata_text

        with state_context(owner, member):
            snapshot = effective_metadata_text(target, binary_source=source).encode()
        ref = manifest["members"][0 if member == "main" else 1]["analysis"]["metadata"]
        (target / ref["path"]).write_bytes(snapshot)
        ref["sha256"] = digest(snapshot)
        owner.members[member]["analysis"]["metadata"]["sha256"] = digest(snapshot)
        packages[member] = _member_packages(owner, member, source)[member]
    package = compose_source_package(manifest, packages)
    publish_source_package(package, target)
    manifest["package_sha256"] = package["sha256"]
    (target / "manifest.json").write_text(json.dumps(manifest))
    monkeypatch.setattr(server, "PROJECT_ROOT", project)

    def call(operation, member="main", **body):
        return restoration.execute(
            target.name,
            {"operation": operation, "member_id": member, "media_paths": paths, **body},
        )

    return project, target, paths, call


def request(inspected, text="Seeds the observed constant seven in D0."):
    row = inspected["row"]
    return {
        "expected_revision": inspected["revision"],
        "command_id": "comment.edit",
        "context": inspected["context"],
        "parameters": {"text": text},
        "evidence": {
            "reason": "The original MOVEQ instruction encodes the constant directly.",
            "evidence_refs": [row.get("stable_key") or row.get("row_key")],
        },
    }


def test_catalog_edit_replays_existing_mal_and_preserves_other_member_scope(
    tmp_path, monkeypatch
):
    project, target, paths, call = editable(tmp_path, monkeypatch)
    initial = call("state")
    from amiga_reversing.disasm.projects import list_projects

    assert len(list_projects(project)) == 1 and initial["member_mutation_supported"]
    assert next(m for m in initial["members"] if m["id"] == "main")["editable"]
    inspected = call("inspect", source_offset=0)
    assert any(c["command_id"] == "comment.edit" for c in inspected["commands"])
    other_before = (target / "overlay.s").read_bytes()
    result = call("interpret", **request(inspected))
    assert result["verification"]["all_placement_coverage"]
    assert result["revision"] != initial["revision"]
    assert b"Seeds the observed constant seven" in (target / "main.s").read_bytes()
    assert (target / "overlay.s").read_bytes() == other_before
    owner = DiskSet.load(target, project_root=project)
    log = (
        target
        / owner.members["main"]["analysis"]["state"]["manual_actions.jsonl"]["path"]
    )
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert records[0]["record"] == "manual_action_log_header"
    assert (
        records[1]["interpretation"]["member_subject"]["analysis_member_id"] == "main"
    )
    assert owner.regenerate(paths)["main"]["whole_source_package_exact"]
    with pytest.raises(ValueError, match="stale_revision"):
        call("interpret", **request(inspected))


def test_equal_address_member_cannot_reuse_another_members_locator(
    tmp_path, monkeypatch
):
    _, target, _, call = editable(tmp_path, monkeypatch)
    inspected = call("inspect", source_offset=0)
    before = (target / "manifest.json").read_bytes()
    with pytest.raises(ValueError, match="subject or revision mismatch"):
        call("interpret", member="overlay", **request(inspected))
    assert (target / "manifest.json").read_bytes() == before


def test_failed_candidate_build_leaves_original_annotations_and_package_intact(
    tmp_path, monkeypatch
):
    _, target, _, call = editable(tmp_path, monkeypatch)
    inspected = call("inspect", source_offset=0)
    before = {
        p.relative_to(target): p.read_bytes()
        for p in target.rglob("*")
        if p.is_file() and p.name != ".target-history.lock"
    }

    def refuse(*args, **kwargs):
        raise ValueError("candidate proof refused")

    monkeypatch.setattr(DiskSet, "build", refuse)
    with pytest.raises(ValueError, match="candidate proof refused"):
        call("interpret", **request(inspected))
    after = {
        p.relative_to(target): p.read_bytes()
        for p in target.rglob("*")
        if p.is_file() and p.name != ".target-history.lock"
    }
    assert before == after


def test_embedded_view_edits_the_one_owner_journal_and_history(tmp_path, monkeypatch):
    project, target, paths, call = editable(tmp_path, monkeypatch)
    inspected = call("inspect", member="return_view", source_offset=0)
    parameters = request(inspected, "Return from the synthetic constant routine.")
    parameters["evidence"]["reason"] = "The original word is the routine's RTS."
    result = call("interpret", member="return_view", **parameters)
    assert result["scope"]["analysis_member_id"] == "main"
    assert not any("return_view" in p.name for p in (target / "analysis").iterdir())
    history = call(
        "history", member="return_view", expected_revision=result["revision"]
    )
    assert len(history["items"]) == 1 and history["items"][0]["active"]
    assert history["scope"]["analysis_member_id"] == "main"
    assert DiskSet.load(target, project_root=project).regenerate(paths)["main"][
        "whole_source_package_exact"
    ]


def test_label_catalog_uses_existing_payload_and_native_name_resolution(
    tmp_path, monkeypatch
):
    _, target, _, call = editable(tmp_path, monkeypatch)
    inspected = call("inspect", source_offset=2, row_kind="label")
    parameters = request(inspected)
    parameters.update(command_id="label.rename", parameters={"name": "returnSeven"})
    result = call("interpret", **parameters)
    assert result["verification"]["media_exact"]
    assert "returnSeven:" in (target / "main.s").read_text()


def test_ambiguous_native_label_is_not_chosen_for_an_edit(tmp_path, monkeypatch):
    _, _, _, call = editable(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="ambiguous member source identity"):
        call("inspect", source_offset=0, row_kind="label")


def test_new_journal_subject_cannot_be_copied_to_another_member(tmp_path, monkeypatch):
    project, target, _, call = editable(tmp_path, monkeypatch)
    inspected = call("inspect", source_offset=0)
    call("interpret", **request(inspected))
    manifest = json.loads((target / "manifest.json").read_bytes())
    main = manifest["members"][0]["analysis"]["state"]["manual_actions.jsonl"]
    overlay = manifest["members"][1]["analysis"]["state"]["manual_actions.jsonl"]
    data = (target / main["path"]).read_bytes()
    (target / overlay["path"]).write_bytes(data)
    overlay["sha256"] = digest(data)
    (target / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="journal subject mismatch"):
        DiskSet.load(target, project_root=project)


def test_publication_failure_rolls_back_journal_metadata_and_source(
    tmp_path, monkeypatch
):
    import amiga_reversing.disasm.disk_set_state as state

    _, target, _, call = editable(tmp_path, monkeypatch)
    inspected = call("inspect", source_offset=0)
    before = {
        p.relative_to(target): p.read_bytes()
        for p in target.rglob("*")
        if p.is_file() and p.name != ".target-history.lock"
    }
    replace = state.os.replace
    failed = False

    def refuse_once(source, destination):
        nonlocal failed
        if destination == target / "manifest.json" and not failed:
            failed = True
            raise OSError("publication interrupted")
        return replace(source, destination)

    monkeypatch.setattr(state.os, "replace", refuse_once)
    with pytest.raises(OSError, match="publication interrupted"):
        call("interpret", **request(inspected))
    after = {
        p.relative_to(target): p.read_bytes()
        for p in target.rglob("*")
        if p.is_file() and p.name != ".target-history.lock"
    }
    assert failed and before == after


def test_member_import_keeps_action_bytes_when_rebinding_artifact_header():
    from amiga_reversing.disasm.disk_set_state import import_state

    member = {
        "id": "bank",
        "sha256": "a" * 64,
        "size": 4,
        "context": {
            "address_model": "runtime_absolute",
            "load_address": 0x1000,
            "entrypoint": 0x1000,
            "code_start_offset": 0,
        },
    }
    header = {
        "record": "manual_action_log_header",
        "version": 1,
        "target_identity": {
            "schema_version": 1,
            "source_kind": "artifact",
            "target_format": "raw_binary",
            "original_sha256": member["sha256"],
            "original_size": 4,
            "parent_disk_id": None,
            "artifact_id": member["sha256"],
            "platform": "amiga",
            "game_family": "synthetic",
            "binding_revision": "b" * 64,
            **member["context"],
        },
    }
    suffix = b'{ "unknown_historical_field": true, "record": "manual_action" }\n'
    original = dict.fromkeys(STATE_FILES)
    original.update(
        {
            "target_metadata.json": b"{}",
            "manual_actions.jsonl": json.dumps(header).encode() + b"\n" + suffix,
        }
    )
    bindings, files, receipt = import_state(member, original, platform="amiga")
    migrated = files[bindings["manual_actions.jsonl"]["path"]]
    assert (
        migrated.partition(b"\n")[2] == suffix and receipt["artifact_header_normalized"]
    )
    member["context"]["entrypoint"] += 2
    with pytest.raises(ValueError, match="identity or address context"):
        import_state(member, original, platform="amiga")


@pytest.mark.parametrize("mismatch", [False, True])
def test_generic_creation_requires_journal_snapshot_continuity(
    tmp_path, monkeypatch, mismatch
):
    from amiga_reversing.disasm.disk_set import create_disk_set

    _, source, paths, _ = editable(tmp_path, monkeypatch)
    manifest = json.loads((source / "manifest.json").read_bytes())
    refs = [m["recipe"] for m in manifest["media"]]
    for m in manifest["members"]:
        if m["analysis"]:
            refs += [
                m["analysis"]["metadata"],
                *m["analysis"]["state_files"],
                *[
                    r
                    for r in m["analysis"]["state"].values()
                    if r["sha256"] is not None
                ],
            ]
    files = {r["path"]: (source / r["path"]).read_bytes() for r in refs}
    if mismatch:
        ref = manifest["members"][0]["analysis"]["state"]["target_metadata.json"]
        data = json.loads(files[ref["path"]])
        data["seeded_code_labels"] = []
        files[ref["path"]] = json.dumps(data).encode()
        ref["sha256"] = digest(files[ref["path"]])
    project = tmp_path / "imported-project"
    target = project / "targets" / manifest["id"]
    if mismatch:
        with pytest.raises(ValueError, match="journal projection does not match"):
            create_disk_set(
                target,
                manifest,
                packages_for(source, manifest),
                files,
                paths,
                project_root=project,
            )
        assert not target.exists()
    else:
        owner = create_disk_set(
            target,
            manifest,
            packages_for(source, manifest),
            files,
            paths,
            project_root=project,
        )
        assert owner.members["main"]["analysis"]["state"]


def test_review_and_undo_use_the_shared_owner_journals(tmp_path, monkeypatch):
    _, target, _, call = editable(tmp_path, monkeypatch)
    inspected = call("inspect", member="return_view", source_offset=0)
    edited = call("interpret", member="return_view", **request(inspected))
    action = edited["actions"][0]["action_id"]
    review = {"action_id": action, "decision": "defer", "reason": "Needs more context."}
    with pytest.raises(ValueError, match="this analysis member"):
        call("review", member="overlay", expected_revision=edited["revision"], **review)
    deferred = call("review", expected_revision=edited["revision"], **review)
    assert deferred["decision"]["scope"]["analysis_member_id"] == "main"
    rejected = call(
        "review",
        member="return_view",
        expected_revision=deferred["revision"],
        **{**review, "decision": "reject"},
    )
    history = call("history")
    assert history["preserved_decision_records"] == 3
    assert history["items"][0]["decision"]["action"] == "reject_fact"
    with pytest.raises(ValueError, match="stale_revision"):
        call("rollback", action_id=action, expected_revision=deferred["revision"])
    with pytest.raises(ValueError, match="this analysis member"):
        call(
            "rollback",
            member="overlay",
            action_id=action,
            expected_revision=rejected["revision"],
        )
    undone = call(
        "rollback",
        member="return_view",
        action_id=action,
        expected_revision=rejected["revision"],
    )
    assert undone["verification"]["all_placement_coverage"]
    assert "Seeds the observed" not in (target / "main.s").read_text()
    redone = call(
        "rollback", action_id=action, redo=True, expected_revision=undone["revision"]
    )
    assert redone["verification"]["media_exact"]
    assert "Seeds the observed" in (target / "main.s").read_text()
    assert next(i for i in call("history")["items"] if i["action_id"] == action)[
        "active"
    ]


def test_decision_journal_cannot_be_rebound_to_another_member(tmp_path, monkeypatch):
    project, target, _, call = editable(tmp_path, monkeypatch)
    inspected = call("inspect", source_offset=0)
    edited = call("interpret", **request(inspected))
    call(
        "review",
        expected_revision=edited["revision"],
        action_id=edited["actions"][0]["action_id"],
        decision="defer",
        reason="Needs more context.",
    )
    path = target / "manifest.json"
    manifest = json.loads(path.read_bytes())
    main, overlay = manifest["members"][:2]
    source = main["analysis"]["state"]["decision_journal.jsonl"]
    destination = overlay["analysis"]["state"]["decision_journal.jsonl"]
    (target / destination["path"]).write_bytes((target / source["path"]).read_bytes())
    destination["sha256"] = source["sha256"]
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="member decision subject mismatch"):
        DiskSet.load(target, project_root=project)

"""Existing catalog/MAL editing through a single scoped disk-set owner."""

import json

import pytest

from amiga_reversing.disasm.analysis_state_paths import STATE_FILES
from amiga_reversing.disasm.disk_codecs import digest
from amiga_reversing.disasm.disk_set import DiskSet, compose_source_package
from amiga_reversing.disasm.source_package_publish import publish_source_package
from tests.test_disk_set import ROOT, fixture, packages_for


def editable(
    tmp_path,
    monkeypatch,
    *,
    table=False,
    string=False,
    interior=False,
    owner_scope=False,
    opaque_prefix=False,
    pointer_rows=False,
    legacy_prefix=False,
):
    from amiga_reversing.disasm import restoration, server

    extra = (
        {
            "main_data": bytes.fromhex("70074e75000200001002"),
            "main_text": " SECTION code,code\n ORG $1000\n moveq #7,d0\n rts\n dc.w $0002\n dc.l $00001002\n",
        }
        if table
        else {
            "main_data": bytes.fromhex(
                "60024e7541fa00084e753f68" if interior else "70074e753f68"
            )
            + b"Hello\0",
            "main_text": ' SECTION code,code\n ORG $1000\n bra.b useSuffix\n rts\n useSuffix:\n lea.l stringSuffix(pc),a0\n rts\n dc.b $3f,$68,"He"\n stringSuffix:\n dc.b "llo",0\n'
            if interior
            else ' SECTION code,code\n ORG $1000\n moveq #7,d0\n rts\n dc.b $3f,$68,"Hello",0\n',
        }
        if string
        else {}
    )
    if opaque_prefix:
        assert not table and not string and not interior and not owner_scope
        extra = {
            "main_data": bytes.fromhex("70074e75") + b"\xa5" * 1024 + bytes(4),
            "main_text": " SECTION code,code\n ORG $1000\n moveq #7,d0\n rts\n dcb.b 1024,$a5\n dc.l 0\n",
        }
    if owner_scope:
        assert not table and not string and not interior
        extra = {
            "main_data": bytes.fromhex("60024e7570074e75"),
            "main_text": " SECTION code,code\n ORG $1000\n bra.b helper\n rts\nhelper:\n moveq #7,d0\nending:\n rts\n",
        }
    if pointer_rows:
        values = [0x1020, 0x1020, 0x1028, 0, 0x1020, 0xDEADBEEF, 0x1020]
        data = bytes.fromhex("70074e75") + b"".join(value.to_bytes(4, "big") for value in values)
        data += bytes.fromhex("4e75123456789abc11112222")
        extra = {"main_data": data, "main_text": " SECTION code,code\n ORG $1000\n moveq #7,d0\n rts\n dc.l "
                 + ",".join(f"${value:08X}" for value in values) + "\n dc.b "
                 + ",".join(f"${value:02X}" for value in data[32:]) + "\n"}
    project, target, paths, manifest = fixture(tmp_path, **extra)
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
    if opaque_prefix:
        metadata["source_output_policy"] = {
            "mode": "binary_assets",
            "minimum_asset_size": 256,
        }
        metadata.setdefault("seeded_entities", []).append(
            {
                "hunk": 0,
                "addr": 4,
                "end": 1032,
                "name": "opaquePrefix",
                "type": "data",
                "unit": "byte",
                "subtype": "opaque_data",
                "seed_origin": "manual_analysis",
                "review_status": "seeded",
                "citation": "Synthetic pre-existing opaque record with a later typed tail",
            }
        )
    if owner_scope:
        metadata["seeded_code_labels"].append(
            {
                "hunk": 0,
                "addr": 6,
                "name": "ending",
                "seed_origin": "manual_analysis",
                "review_status": "seeded",
                "citation": "Synthetic helper's final RTS source point",
            }
        )
    if interior:
        assert string and not table
        metadata["seeded_code_labels"].append(
            {
                "hunk": 0,
                "addr": 14,
                "name": "stringSuffix",
                "seed_origin": "manual_analysis",
                "review_status": "seeded",
                "citation": "Synthetic alternate entry into the same normal text bytes",
            }
        )
    if legacy_prefix:
        assert string
        metadata.setdefault("seeded_entities", []).append({
            "hunk": 0, "addr": 5, "end": 12, "type": "data", "subtype": "string", "unit": "byte",
            "encoding": "ascii", "source_id": "fixture-import", "source_locator": "legacy-prefix",
            "seed_origin": "manual_analysis", "review_status": "seeded", "citation": "Preliminary imported string"})
    if pointer_rows:
        metadata.setdefault("seeded_entities", []).append({
            "hunk": 0, "addr": 32, "end": 40, "type": "data", "unit": "long", "name": "existingRecord",
            "seed_origin": "manual_analysis", "review_status": "seeded", "citation": "Independent fixture record"})
        metadata["seeded_entities"].append({
            "hunk": 0, "addr": 28, "end": 32, "type": "data", "unit": "long",
            "seed_origin": "manual_analysis", "review_status": "seeded", "citation": "Independent scalar"})
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


def test_member_verify_accepts_only_current_canonical_owner_receipts(
    tmp_path, monkeypatch
):
    _, _, _, call = editable(tmp_path, monkeypatch)
    inspected = call("inspect", member="return_view", source_offset=0)
    edited = call("interpret", member="return_view", **request(inspected))
    revision = edited["revision"]
    review = {
        "action_id": edited["actions"][0]["action_id"],
        "decision": "accept",
        "reason": "The instruction and exact rebuild support the interpretation.",
    }
    with pytest.raises(ValueError, match="persisted receipt identity"):
        call("review", expected_revision=revision, **review)
    wrong = call(
        "verify",
        member="overlay",
        expected_revision=revision,
        output=str(tmp_path / "overlay-proof"),
    )["verification"]
    with pytest.raises(ValueError, match="does not match this member"):
        call(
            "review",
            expected_revision=revision,
            verification_id=wrong["receipt_id"],
            **review,
        )
    verified = call(
        "verify",
        member="return_view",
        expected_revision=revision,
        output=str(tmp_path / "main-proof"),
    )
    proof = verified["verification"]
    assert (
        verified["coverage"]["complete"]
        and verified["coverage"]["independent_redecode"]
    )
    assert proof["member_subject"]["analysis_member_id"] == "main"
    assert proof["member_build"]["native_exact"] and proof["member_build"]["vasm_exact"]
    accepted = call(
        "review",
        expected_revision=revision,
        verification_id=proof["receipt_id"],
        **review,
    )
    assert accepted["decision"]["verification_id"] == proof["receipt_id"]
    assert accepted["decision"]["action"] == "accept_fact"
    assert (
        call("history", member="return_view")["items"][0]["decision"]
        == accepted["decision"]
    )
    with pytest.raises(ValueError, match="does not match this member and revision"):
        call(
            "review",
            expected_revision=accepted["revision"],
            verification_id=proof["receipt_id"],
            **review,
        )


def test_scoped_batch_prepares_all_entries_before_one_atomic_append(
    tmp_path, monkeypatch
):
    _, target, _, call = editable(tmp_path, monkeypatch)
    first = call("inspect", source_offset=0)
    second = call("inspect", source_offset=2, row_kind="label")
    foreign = request(call("inspect", member="overlay", source_offset=0))
    foreign.pop("expected_revision")
    one = request(first)
    two = request(second)
    two.update(command_id="label.rename", parameters={"name": "finishBatch"})
    revision = one.pop("expected_revision")
    two.pop("expected_revision")
    from amiga_reversing.disasm import disk_set_state

    original_artifact = disk_set_state._artifact
    calls = []

    def counted_artifact(*args, **kwargs):
        calls.append(args[1])
        return original_artifact(*args, **kwargs)

    monkeypatch.setattr(disk_set_state, "_artifact", counted_artifact)
    before = (target / "manifest.json").read_bytes()
    with pytest.raises(ValueError, match="not available"):
        call(
            "interpret_batch",
            expected_revision=revision,
            entries=[one, {**two, "command_id": "unsupported"}],
        )
    assert (target / "manifest.json").read_bytes() == before
    assert calls == ["main"]
    calls.clear()
    with pytest.raises(ValueError, match="subject or revision mismatch"):
        call("interpret_batch", expected_revision=revision, entries=[one, foreign])
    assert (target / "manifest.json").read_bytes() == before
    assert calls == ["main"]
    calls.clear()
    saved = call("interpret_batch", expected_revision=revision, entries=[one, two])
    assert calls == ["main"]
    assert len(saved["actions"]) == 2
    assert saved["verification"]["media_exact"]
    assert "finishBatch:" in (target / "main.s").read_text()
    assert "Seeds the observed" in (target / "main.s").read_text()
    with pytest.raises(ValueError, match="outer member"):
        call(
            "interpret_batch",
            expected_revision=saved["revision"],
            entries=[{**one, "member_id": "overlay"}],
        )


def data_request(inspected, command, parameters):
    rows = inspected.get("rows") or [inspected["row"]]
    return {
        "expected_revision": inspected["revision"],
        "command_id": command,
        "context": inspected["context"],
        "parameters": parameters,
        "evidence": {
            "reason": "Synthetic bounded scalar record and absolute pointer.",
            "evidence_refs": [r.get("stable_key") or r["row_key"] for r in rows],
        },
    }


def test_scoped_data_range_scalar_pointer_and_conservative_bounds(
    tmp_path, monkeypatch
):
    _, target, _, call = editable(tmp_path, monkeypatch, table=True)
    with pytest.raises(ValueError, match="contiguous native data"):
        call("inspect", source_offset=0, end_offset=4, row_kind="data")
    with pytest.raises(ValueError, match="bounded data range"):
        call("inspect", source_offset=4, end_offset=11, row_kind="data")
    inspected = call("inspect", source_offset=4, end_offset=10, row_kind="data")
    assert all(
        c["target_context"] == inspected["context"] for c in inspected["commands"]
    )
    import copy

    forged = data_request(inspected, "range.data_block.layout.create", {})
    forged["context"] = copy.deepcopy(forged["context"])
    forged["context"]["locators"][0]["member_id"] = "overlay"
    with pytest.raises(ValueError, match="subject or revision mismatch"):
        call("interpret", **forged)
    created = call(
        "interpret",
        **data_request(
            inspected,
            "range.data_block.layout.create",
            {
                "name": "syntheticCommand",
                "role": "WORD keyboard offset and LONG handler",
                "default_unit": "word",
            },
        ),
    )
    overlap = call("inspect", source_offset=4, end_offset=6, row_kind="data")
    with pytest.raises(ValueError, match="overlaps an existing layout"):
        call("interpret", **data_request(overlap, "range.data_block.layout.create", {}))
    ptr = call("inspect", source_offset=6, end_offset=10, row_kind="data")
    assert ptr["context"]["source_span"] == {
        "section_index": 0,
        "start_offset": 6,
        "end_offset": 10,
    }
    assert ptr["context"]["locators"][0]["start_offset"] == 4
    before = (target / "manifest.json").read_bytes()
    with pytest.raises(ValueError, match="exact span"):
        call(
            "interpret",
            **data_request(
                ptr, "range.data_block.element.set", {"kind": "scalar", "width": 2}
            ),
        )
    assert (target / "manifest.json").read_bytes() == before
    scalar = call(
        "interpret",
        **data_request(
            ptr,
            "range.data_block.element.set",
            {"kind": "scalar", "name": "commandHandler"},
        ),
    )
    assert scalar["verification"]["media_exact"]
    inspected = call("inspect", source_offset=6, row_kind="data")
    params = {
        "reference_kind": "absolute",
        "source_value": 0x1002,
        "runtime_address": 0x1002,
        "target_hunk": 0,
        "target_offset": 2,
    }
    before = (target / "manifest.json").read_bytes()
    with pytest.raises(ValueError, match="resolve uniquely"):
        call(
            "interpret",
            **data_request(
                inspected,
                "row.data_block.element.interpret_ref",
                {**params, "target_offset": 0},
            ),
        )
    with pytest.raises(ValueError, match="selected source bytes"):
        call(
            "interpret",
            **data_request(
                inspected,
                "row.data_block.element.interpret_ref",
                {**params, "runtime_address": 0x1000},
            ),
        )
    with pytest.raises(ValueError, match="exact span"):
        call(
            "interpret",
            **data_request(
                inspected,
                "row.data_block.element.interpret_ref",
                {**params, "layout_id": "foreign"},
            ),
        )
    assert (target / "manifest.json").read_bytes() == before
    linked = call(
        "interpret",
        **data_request(inspected, "row.data_block.element.interpret_ref", params),
    )
    assert linked["verification"]["media_exact"]
    assert "dc.l finish" in (target / "main.s").read_text()
    described = call("inspect", source_offset=6, row_kind="data")
    with pytest.raises(ValueError, match="inspected member layout"):
        call(
            "interpret",
            **data_request(
                described,
                "row.data_block.layout.describe",
                {"layout_id": "foreign", "role": ""},
            ),
        )
    cleared = call(
        "interpret",
        **data_request(described, "row.data_block.layout.describe", {"role": ""}),
    )
    assert cleared["verification"]["media_exact"]
    assert (
        "WORD keyboard offset and LONG handler" not in (target / "main.s").read_text()
    )
    assert "dc.l finish" in (target / "main.s").read_text()
    assert created["revision"] != linked["revision"]


def test_legacy_row_range_does_not_silently_ignore_member_span():
    from amiga_reversing.disasm import server

    with pytest.raises(server.CommandContractError, match="scoped disk-set member"):
        server._command_context_from_body(
            "unopened",
            {
                "kind": "range",
                "locators": [],
                "source_span": {"section_index": 0, "start_offset": 2, "end_offset": 4},
            },
        )


def test_regenerate_refreshes_all_owned_sources_without_annotations(
    tmp_path, monkeypatch
):
    from amiga_reversing.disasm import disk_set_state

    _, target, _, call = editable(tmp_path, monkeypatch)
    state = call("state")
    before = {p.name: p.read_bytes() for p in (target / "analysis").iterdir()}
    original = disk_set_state._member_packages
    visits = []

    def render(owner, changed, sources):
        visits.append((changed, set(sources)))
        return original(owner, changed, sources)

    monkeypatch.setattr(disk_set_state, "_member_packages", render)
    result = call("regenerate", expected_revision=state["revision"])
    assert visits == [("*", {"main", "overlay"})]
    assert result["verification"]["media_exact"]
    assert {p.name: p.read_bytes() for p in (target / "analysis").iterdir()} == before
    with pytest.raises(ValueError, match="stale_revision"):
        call("regenerate", expected_revision="old")


def test_scoped_string_body_preserves_typed_prefix_and_exact_source(
    tmp_path, monkeypatch
):
    _, target, _, call = editable(tmp_path, monkeypatch, string=True)
    header = call("inspect", source_offset=4, end_offset=6, row_kind="data")
    call(
        "interpret",
        **data_request(
            header,
            "range.data_block.layout.create",
            {"name": "replyGuard", "default_unit": "byte"},
        ),
    )
    for start in (4, 5):
        selected = call(
            "inspect", source_offset=start, end_offset=start + 1, row_kind="data"
        )
        call(
            "interpret",
            **data_request(
                selected, "range.data_block.element.set", {"kind": "scalar", "width": 1}
            ),
        )
    before = (target / "analysis/main.manual_actions.jsonl").read_bytes()
    selected = call("inspect", source_offset=6, end_offset=12, row_kind="data")
    saved = call("interpret", **data_request(selected, "range.seed.data.string", {}))
    assert saved["verification"]["media_exact"]
    assert '\tdc.b "Hello",$00' in (target / "main.s").read_text()
    assert (
        (target / "analysis/main.manual_actions.jsonl").read_bytes().startswith(before)
    )
    for start, end, reason in [(4, 12, "typed layout"), (6, 11, "NUL-terminated")]:
        selected = call("inspect", source_offset=start, end_offset=end, row_kind="data")
        manifest = (target / "manifest.json").read_bytes()
        with pytest.raises(ValueError, match=reason):
            call("interpret", **data_request(selected, "range.seed.data.string", {}))
        assert (target / "manifest.json").read_bytes() == manifest


def test_scoped_string_seed_preserves_a_proven_interior_text_entry(
    tmp_path, monkeypatch
):
    _, target, _, call = editable(tmp_path, monkeypatch, string=True, interior=True)
    selected = call("inspect", source_offset=12, end_offset=18, row_kind="data")
    saved = call("interpret", **data_request(selected, "range.seed.data.string", {}))
    assert saved["verification"]["media_exact"]
    text = (target / "main.s").read_text()
    assert 'stringSuffix:\n\tdc.b "llo",$00' in text
    assert '\tdc.b "He"' in text


def test_member_local_owner_is_explicit_source_declaration_beside_runtime_alias(
    tmp_path, monkeypatch
):
    _, target, _, call = editable(tmp_path, monkeypatch, owner_scope=True)

    def rename(selected, name, **scope):
        result = request(selected)
        result.update(command_id="label.rename", parameters={"name": name, **scope})
        result["evidence"]["reason"] = (
            "The existing helper entry and sequential RTS establish these source identities."
        )
        return result

    owner = call("inspect", source_offset=4, row_kind="label")
    call("interpret", **rename(owner, "begin"))
    owner = call("inspect", source_offset=4, row_kind="label")
    child = call("inspect", source_offset=6, row_kind="label")
    source_owner = rename(owner, "begin", scope="global")
    local = rename(child, ".done", scope="local", owner_offset=4)
    before = (target / "manifest.json").read_bytes()
    with pytest.raises(ValueError, match="unique named global owner"):
        call("interpret", **local)
    assert (target / "manifest.json").read_bytes() == before
    entries = [
        {k: v for k, v in r.items() if k != "expected_revision"}
        for r in (source_owner, local)
    ]
    saved = call(
        "interpret_batch", expected_revision=owner["revision"], entries=entries
    )
    assert saved["verification"]["media_exact"]
    text = (target / "main.s").read_text()
    assert "begin:\n" in text and ".done:\n\trts" in text


def test_scoped_word_offset_binds_two_source_points_and_builds_exactly(
    tmp_path, monkeypatch
):
    _, target, _, call = editable(tmp_path, monkeypatch, table=True)
    selected = call("inspect", source_offset=4, end_offset=10, row_kind="data")
    call(
        "interpret",
        **data_request(
            selected,
            "range.data_block.layout.create",
            {"name": "relativeRecord", "default_unit": "word"},
        ),
    )
    for start, end, name in ((4, 6, "fieldOffset"), (6, 10, "payloadField")):
        selected = call("inspect", source_offset=start, end_offset=end, row_kind="data")
        call(
            "interpret",
            **data_request(
                selected,
                "range.data_block.element.set",
                {"kind": "scalar", "width": end - start, "name": name},
            ),
        )
    selected = call("inspect", source_offset=4, row_kind="data")
    saved = call(
        "interpret",
        **data_request(
            selected,
            "row.data_block.element.interpret_ref",
            {
                "reference_kind": "base_displacement",
                "target_hunk": 0,
                "target_offset": 6,
                "base_locator": {"hunk": 0, "offset": 4},
                "signed": True,
                "scale": 1,
            },
        ),
    )
    assert saved["verification"]["media_exact"]
    text = (target / "main.s").read_text()
    assert "dc.w payloadField-fieldOffset" in text
    assert "dc.w $0002" not in text
    selected = call("inspect", source_offset=4, row_kind="data")
    before = (target / "manifest.json").read_bytes()
    for target_offset, base_offset, scale, reason in (
        (8, 4, 1, "target|base"),
        (8, 4, 2, "scale 1"),
        (12, 10, 1, "outside the analysis owner"),
    ):
        with pytest.raises(ValueError, match=reason):
            call(
                "interpret",
                **data_request(
                    selected,
                    "row.data_block.element.interpret_ref",
                    {
                        "reference_kind": "base_displacement",
                        "target_hunk": 0,
                        "target_offset": target_offset,
                        "base_locator": {"hunk": 0, "offset": base_offset},
                        "signed": True,
                        "scale": scale,
                    },
                ),
            )
        assert (target / "manifest.json").read_bytes() == before


def test_scoped_opaque_prefix_remains_an_asset_beside_typed_fields(
    tmp_path, monkeypatch
):
    _, target, _, call = editable(tmp_path, monkeypatch, opaque_prefix=True)
    selected = call("inspect", source_offset=4, end_offset=1028, row_kind="data")
    saved = call(
        "interpret",
        **data_request(selected, "range.seed.data.opaque_data", {}),
    )
    assert saved["verification"]["media_exact"]
    text = (target / "main.s").read_text()
    assert "INCBIN" in text
    manifest = json.loads((target / "source-package-manifest.json").read_bytes())
    before_assets = [x for x in manifest["manifest"]["files"] if x["kind"] == "asset"]
    assert len(before_assets) == 1 and before_assets[0]["size"] == 1024
    selected = call("inspect", source_offset=1028, end_offset=1032, row_kind="data")
    call(
        "interpret",
        **data_request(
            selected, "range.data_block.layout.create", {"name": "recordTail"}
        ),
    )
    selected = call("inspect", source_offset=1028, end_offset=1032, row_kind="data")
    call(
        "interpret",
        **data_request(
            selected,
            "range.data_block.element.set",
            {"kind": "scalar", "width": 4, "name": "tailValue"},
        ),
    )
    manifest = json.loads((target / "source-package-manifest.json").read_bytes())
    after_assets = [x for x in manifest["manifest"]["files"] if x["kind"] == "asset"]
    assert [(x["asset_id"], x["sha256"], x["size"]) for x in before_assets] == [
        (x["asset_id"], x["sha256"], x["size"]) for x in after_assets
    ]
    assert "INCBIN" in (target / "main.s").read_text()
    selected = call("inspect", source_offset=1028, end_offset=1032, row_kind="data")
    before = (target / "manifest.json").read_bytes()
    with pytest.raises(ValueError, match="overlaps an existing typed layout"):
        call("interpret", **data_request(selected, "range.seed.data.opaque_data", {}))
    assert (target / "manifest.json").read_bytes() == before


@pytest.mark.parametrize("count", [127, 257])
def test_large_scoped_batch_validates_late_entry_before_atomic_exact_publish(tmp_path, monkeypatch, count):
    from copy import deepcopy

    from amiga_reversing.disasm import disk_set_state

    _, target, _, call = editable(tmp_path, monkeypatch)
    selected = call("inspect", source_offset=0)
    revision = selected["revision"]
    entries = []
    for index in range(count):
        body = request(selected, text=f"Independent scoped batch evidence {index}.")
        body.pop("expected_revision")
        entries.append(body)
    original = disk_set_state._artifact
    visits = []
    def artifact(*args, **kwargs):
        visits.append(args[1])
        return original(*args, **kwargs)
    monkeypatch.setattr(disk_set_state, "_artifact", artifact)
    manifest = (target / "manifest.json").read_bytes()
    source = (target / "main.s").read_bytes()
    invalid = deepcopy(entries)
    invalid[-1]["command_id"] = "unsupported"
    with pytest.raises(ValueError, match="not available"):
        call("interpret_batch", expected_revision=revision, entries=invalid)
    assert visits == ["main"]
    assert (target / "manifest.json").read_bytes() == manifest
    assert (target / "main.s").read_bytes() == source
    assert not list((target / "analysis").glob("*.manual_actions.jsonl"))
    visits.clear()
    saved = call("interpret_batch", expected_revision=revision, entries=entries)
    assert visits == ["main"]
    assert len(saved["actions"]) == count
    assert saved["verification"]["media_exact"]
    assert saved["verification"]["all_placement_coverage"]
    assert f"Independent scoped batch evidence {count - 1}." in (target / "main.s").read_text()
    with pytest.raises(ValueError, match="stale_revision"):
        call("interpret_batch", expected_revision=revision, entries=entries)


def test_scoped_pointer_table_declaration_roundtrips_and_undo_keeps_shape_and_history(tmp_path, monkeypatch):
    from tests.test_declared_data_pointer_table import declaration

    _, target, _, call = editable(tmp_path, monkeypatch, pointer_rows=True)
    selected = call("inspect", source_offset=4, end_offset=28, row_kind="data")
    call("interpret", **data_request(selected, "range.data_block.layout.create",
                                    {"name": "pointerRows", "default_unit": "long"}))
    for offset in (8, 20):
        scalar = call("inspect", source_offset=offset, end_offset=offset + 4, row_kind="data")
        call("interpret", **data_request(scalar, "range.data_block.element.set", {"kind": "scalar", "width": 4}))
    selected = call("inspect", source_offset=4, row_kind="data")
    assert "row.data_block.layout.pointer_table" in {a["command_id"] for a in selected["commands"]}
    bad = declaration(count=3)
    before = (target / "analysis/main.manual_actions.jsonl").read_bytes()
    with pytest.raises(ValueError, match="exactly cover"):
        call("interpret", **data_request(selected, "row.data_block.layout.pointer_table", bad))
    assert (target / "analysis/main.manual_actions.jsonl").read_bytes() == before
    saved = call("interpret", **data_request(selected, "row.data_block.layout.pointer_table", declaration()))
    assert saved["verification"]["media_exact"] and saved["verification"]["all_placement_coverage"]
    text = (target / "main.s").read_text()
    assert "dc.l existingRecord" in text
    assert "dc.l $00001020" in text  # Scalar columns/adjacent scalar stay numeric.
    metadata = json.loads((target / DiskSet.load(target, project_root=target.parent.parent).members["main"]["analysis"]["metadata"]["path"]).read_bytes())
    table = metadata["data_block_layouts"][0]["pointer_table"]
    assert {k: v for k, v in table.items() if k != "citation"} == declaration()
    assert not metadata["manual_runtime_address_refs"]
    assert len(saved["actions"]) == 1
    identity = saved["actions"][0]["action_id"]
    undone = call("rollback", expected_revision=saved["revision"], action_id=identity)
    metadata = json.loads((target / DiskSet.load(target, project_root=target.parent.parent).members["main"]["analysis"]["metadata"]["path"]).read_bytes())
    assert metadata["data_block_layouts"][0].get("pointer_table") is None
    redone = call("rollback", expected_revision=undone["revision"], action_id=identity, redo=True)
    assert redone["verification"]["media_exact"]
    assert (target / "main.s").read_text() == text
    assert (target / "analysis/main.manual_actions.jsonl").read_bytes().startswith(before)


def test_prefix_native_precedence_keeps_authoritative_snapshot_guard_and_journals(tmp_path, monkeypatch):
    _, target, _, call = editable(tmp_path, monkeypatch, string=True, legacy_prefix=True)
    prefix = call("inspect", source_offset=4, end_offset=6, row_kind="data")
    call("interpret", **data_request(prefix, "range.data_block.layout.create", {"default_unit": "word"}))
    prefix = call("inspect", source_offset=4, end_offset=6, row_kind="data")
    call("interpret", **data_request(prefix, "range.data_block.element.set", {"kind": "scalar", "width": 2}))
    text = call("inspect", source_offset=6, end_offset=12, row_kind="data")
    saved = call("interpret", **data_request(text, "range.seed.data.string", {}))
    owner = DiskSet.load(target, project_root=target.parent.parent)
    snapshot = target / owner.members["main"]["analysis"]["metadata"]["path"]
    facts = json.loads(snapshot.read_bytes())
    assert any(e["addr"] == 5 and e["end"] == 12 and e["source_id"] == "fixture-import"
               for e in facts["seeded_entities"])
    assert '\tdc.w $3F68\n\tdc.b "Hello",$00' in (target / "main.s").read_text()
    journals = {p: p.read_bytes() for p in (target / "analysis").glob("*.jsonl")}
    snapshot_before = snapshot.read_bytes()
    regenerated = call("regenerate", expected_revision=saved["revision"])
    assert regenerated["verification"]["media_exact"] and regenerated["verification"]["all_placement_coverage"]
    assert snapshot.read_bytes() == snapshot_before
    assert all(p.read_bytes() == value for p, value in journals.items())

"""Content-bound member analysis stays distinct from authentic disk verification."""

import json
from pathlib import Path

import pytest

from amiga_reversing.disasm import restoration
from amiga_reversing.disasm.disk_set import DiskSet
from tests.test_disk_set_state import editable, request
from tests.test_scoped_scalar_arrays import snapshot


def member_fixture(tmp_path, monkeypatch):
    project, target, paths, full_call = editable(tmp_path, monkeypatch)
    owner = DiskSet.load(target, project_root=project)
    values = owner.recover(paths)[0]
    member = tmp_path / "extracted-main.bin"
    member.write_bytes(values["main"])
    for path in paths.values():
        Path(path).unlink()

    def call(operation, **body):
        return restoration.execute(target.name, {
            "operation": operation, "member_id": "main",
            "input_mode": "member", "member_paths": {"main": str(member)}, **body,
        })

    call("state")  # Establish the ordinary target lock before atomic snapshots.
    return project, target, member, call, full_call


def test_real_member_edit_history_verify_review_undo_without_media(tmp_path, monkeypatch):
    project, target, member, call, _ = member_fixture(tmp_path, monkeypatch)
    sibling = (target / "overlay.s").read_bytes()
    inspected = call("inspect", source_offset=0)
    edited = call("interpret", **request(inspected))
    proof = edited["verification"]
    assert proof["verification_scope"] == "member"
    assert proof["media_exact"] is None and proof["all_placement_coverage"] is None
    assert set(proof["members"]) == {"main", "return_view"}
    assert proof["members"]["main"]["native_exact"]
    assert proof["members"]["main"]["vasm_exact"]
    assert (target / "overlay.s").read_bytes() == sibling
    assert call("history")["items"][0]["action_id"] == edited["actions"][0]["action_id"]
    checked = call("verify_member", expected_revision=edited["revision"],
                   output=str(tmp_path / "verified"))
    receipt = checked["verification"]
    assert receipt["kind"] == "disk_set_member_source_verification"
    assert receipt["media_verification"] == "not_performed"
    assert checked["regeneration"]["main"]["whole_source_package_exact"]
    assert str(member) not in json.dumps(receipt)
    action = edited["actions"][0]["action_id"]
    reviewed = call("review", expected_revision=edited["revision"], action_id=action,
                    verification_id=receipt["receipt_id"], decision="accept",
                    reason="Native and independent assembly preserve the verified member.")
    assert reviewed["verification"]["media_exact"] is None
    undone = call("rollback", expected_revision=reviewed["revision"], action_id=action)
    assert b"Seeds the observed" not in (target / "main.s").read_bytes()
    redone = call("rollback", expected_revision=undone["revision"], action_id=action, redo=True)
    assert redone["verification"]["media_exact"] is None
    assert (target / "overlay.s").read_bytes() == sibling


@pytest.mark.parametrize("change", ["wrong_bytes", "short", "long", "missing", "digest_only", "wrong_owner"])
def test_member_input_requires_the_actual_selected_content(tmp_path, monkeypatch, change):
    _, target, member, call, _ = member_fixture(tmp_path, monkeypatch)
    before = snapshot(target)
    extra = {}
    if change == "wrong_bytes":
        data = bytearray(member.read_bytes()); data[0] ^= 1; member.write_bytes(data)
    elif change == "short":
        member.write_bytes(member.read_bytes()[:-1])
    elif change == "long":
        member.write_bytes(member.read_bytes() + b"\0")
    elif change == "missing":
        member.unlink()
    elif change == "digest_only":
        extra = {"member_paths": {"main": {"sha256": "0" * 64}}}
    else:
        extra = {"member_paths": {"overlay": str(member)}}
    with pytest.raises(ValueError, match="member|owner"):
        call("inspect", source_offset=0, **extra)
    assert snapshot(target) == before


def test_wrong_member_context_revision_and_source_window_remain_closed(tmp_path, monkeypatch):
    _, target, member, call, _ = member_fixture(tmp_path, monkeypatch)
    inspected = call("inspect", source_offset=0)
    before = snapshot(target)
    with pytest.raises(ValueError, match="owner"):
        call("inspect", member_id="overlay", source_offset=0)
    with pytest.raises(ValueError, match="unknown disk-set member"):
        call("inspect", member_id="missing", source_offset=0)
    with pytest.raises(ValueError, match="stale_revision"):
        call("interpret", **{**request(inspected), "expected_revision": "0" * 64})
    forged = request(inspected)
    forged["context"]["locator"]["end_offset"] += 2
    with pytest.raises(ValueError, match="locator subject or revision mismatch"):
        call("interpret", **forged)
    assert snapshot(target) == before
    assert member.is_file()


@pytest.mark.parametrize("operation", ["build", "verify"])
def test_disk_proof_cannot_be_downgraded_to_member_mode(tmp_path, monkeypatch, operation):
    _, target, _, call, full_call = member_fixture(tmp_path, monkeypatch)
    revision = call("state")["revision"]
    with pytest.raises(ValueError, match="original media"):
        call(operation, expected_revision=revision, output=str(tmp_path / "out"))
    with pytest.raises((ValueError, FileNotFoundError)):
        full_call(operation, expected_revision=revision, output=str(tmp_path / "disk"))
    assert not (tmp_path / "out").exists()


def test_member_mode_does_not_bless_a_stale_effective_metadata_snapshot(tmp_path, monkeypatch):
    from amiga_reversing.disasm.disk_codecs import digest

    _, target, _, call, _ = member_fixture(tmp_path, monkeypatch)
    manifest_path = target / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    m = next(m for m in manifest["members"] if m["id"] == "main")
    ref = m["analysis"]["metadata"]
    metadata_path = target / ref["path"]
    data = json.loads(metadata_path.read_bytes())
    data["seeded_code_labels"] = []
    metadata_path.write_text(json.dumps(data))
    ref["sha256"] = digest(metadata_path.read_bytes())
    from amiga_reversing.disasm.disk_set import compose_source_package
    from amiga_reversing.disasm.source_package_publish import publish_source_package
    from tests.test_disk_set import packages_for
    package = compose_source_package(manifest, packages_for(target, manifest))
    publish_source_package(package, target)
    manifest["package_sha256"] = package["sha256"]
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="snapshot"):
        call("inspect", source_offset=0)
    with pytest.raises(ValueError, match="snapshot"):
        call("query", kind="summary")


def test_changed_input_during_candidate_build_prevents_publication(tmp_path, monkeypatch):
    _, target, member, call, _ = member_fixture(tmp_path, monkeypatch)
    inspected = call("inspect", source_offset=0)
    before = snapshot(target)
    original = DiskSet._assemble_members
    def changing(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        member.write_bytes(bytes(len(member.read_bytes())))
        return result
    monkeypatch.setattr(DiskSet, "_assemble_members", changing)
    with pytest.raises(ValueError, match="SHA-256"):
        call("interpret", **request(inspected))
    assert snapshot(target) == before

def test_linked_member_keeps_its_owner_and_bounded_source_context(tmp_path, monkeypatch):
    _, target, _, call, _ = member_fixture(tmp_path, monkeypatch)
    inspected = call("inspect", member_id="return_view", source_offset=0)
    assert inspected["scope"]["analysis_member_id"] == "main"
    changed = call("interpret", member_id="return_view", **request(inspected,
        text="This linked member retains the owner's original RTS."))
    assert changed["scope"]["analysis_member_id"] == "main"
    assert changed["verification"]["verified_analysis_members"] == ["main"]
    assert b"linked member" in (target / "main.s").read_bytes()


def test_source_receipt_is_revision_bound_and_cannot_certify_disk_review(tmp_path, monkeypatch):
    _, _, _, call, full_call = member_fixture(tmp_path, monkeypatch)
    edited = call("interpret", **request(call("inspect", source_offset=0)))
    receipt = call("verify_member", expected_revision=edited["revision"],
                   output=str(tmp_path / "member-proof"))["verification"]
    with pytest.raises(ValueError, match="does not match"):
        full_call("review", expected_revision=edited["revision"],
                  action_id=edited["actions"][0]["action_id"], decision="accept",
                  reason="Disk review cannot use a source-only receipt.",
                  verification_id=receipt["receipt_id"])
    newer = call("interpret", **request(call("inspect", source_offset=2), text="Original RTS."))
    with pytest.raises(ValueError, match="does not match"):
        call("review", expected_revision=newer["revision"],
             action_id=edited["actions"][0]["action_id"], decision="accept",
             reason="The older proof cannot certify this revision.",
             verification_id=receipt["receipt_id"])


@pytest.mark.parametrize("fields", [
    {"input_mode": "other"},
    {"media_paths": {"unused": "ignored.img"}},
    {"input_mode": "media"},
])
def test_explicit_modes_do_not_silently_ignore_supplied_bindings(tmp_path, monkeypatch, fields):
    _, _, _, call, _ = member_fixture(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="input_mode"):
        call("inspect", source_offset=0, **fields)

def test_existing_full_media_receipt_can_review_the_same_member_revision(tmp_path, monkeypatch):
    project, target, paths, full = editable(tmp_path, monkeypatch)
    changed = full("interpret", **request(full("inspect", source_offset=0)))
    proof = full("verify", expected_revision=changed["revision"],
                 output=str(tmp_path / "disk-proof"))["verification"]
    owner = DiskSet.load(target, project_root=project)
    member = tmp_path / "main.bin"
    member.write_bytes(owner.recover(paths)[0]["main"])
    for path in paths.values():
        Path(path).unlink()
    result = restoration.execute(target.name, {
        "operation": "review", "member_id": "main", "input_mode": "member",
        "member_paths": {"main": str(member)}, "expected_revision": changed["revision"],
        "action_id": changed["actions"][0]["action_id"], "decision": "accept",
        "reason": "The matching original full-media proof also verifies member source.",
        "verification_id": proof["receipt_id"],
    })
    assert result["review_verification"]["kind"] == "disk_set_member_verification"
    assert result["verification"]["media_exact"] is None

def test_member_query_and_regenerate_preserve_other_owners_and_history(tmp_path, monkeypatch):
    project, target, _, call, _ = member_fixture(tmp_path, monkeypatch)
    owner = DiskSet.load(target, project_root=project)
    other = {
        r["path"]: (target / r["path"]).read_bytes()
        for r in owner.package["manifest"]["files"] if "main" not in r["members"]
    }
    journals = {p: p.read_bytes() for p in (target / "analysis").glob("*.jsonl")}
    found = call("query", kind="instructions", source_offset=0, end_offset=4)
    assert found["scope"]["analysis_member_id"] == "main" and found["items"]
    regenerated = call("regenerate", expected_revision=found["revision"])
    assert regenerated["verification"]["media_exact"] is None
    assert all((target / name).read_bytes() == data for name, data in other.items())
    assert all(p.read_bytes() == data for p, data in journals.items())

def test_correctly_hashed_standalone_child_is_not_a_substitute_for_its_owner(tmp_path, monkeypatch):
    from amiga_reversing.disasm.disk_codecs import digest

    project, target, member, call, _ = member_fixture(tmp_path, monkeypatch)
    owner = DiskSet.load(target, project_root=project)
    owner_id, offset = owner.owner("return_view")
    child = owner.members["return_view"]
    child_file = tmp_path / "correct-child.bin"
    data = member.read_bytes()[offset:offset + child["size"]]
    assert len(data) == child["size"] and digest(data) == child["sha256"]
    child_file.write_bytes(data)
    for bindings, reason in [
        ({"return_view": str(child_file)}, "owner"),
        ({owner_id: str(child_file)}, "length or SHA-256"),
    ]:
        with pytest.raises(ValueError, match=reason):
            call("inspect", member_id="return_view", source_offset=0, member_paths=bindings)
    assert call("inspect", member_id="return_view", source_offset=0)["scope"]["analysis_member_id"] == owner_id

"""Bounded records reuse custom types, scoped ownership and atomic history."""

import copy
import json

import pytest

from amiga_reversing.disasm.disk_set import DiskSet
from tests.test_disk_set_state import data_request, editable
from tests.test_scoped_scalar_arrays import snapshot

FIELDS = [
    {"name": "category", "type": "UWORD", "offset": 0, "size": 2},
    {"name": "actionWord14", "type": "UWORD", "offset": 2, "size": 2},
]


def create(call, end=32):
    inspected = call("inspect", source_offset=4, end_offset=end, row_kind="data")
    return call(
        "interpret",
        **data_request(
            inspected,
            "range.data_block.layout.create",
            {"name": "records", "default_unit": "word"},
        ),
    )


def request(call, *, end=32, **updates):
    inspected = call("inspect", source_offset=4, end_offset=end, row_kind="data")
    params = {
        "record_type": "Pair",
        "record_size": 4,
        "record_count": (end - 4) // 4,
        "record_stride": 4,
        "fields": copy.deepcopy(FIELDS),
    }
    params.update(updates)
    return data_request(inspected, "range.data_block.records.declare", params)


def metadata(target):
    owner = DiskSet.load(target, project_root=target.parent.parent)
    return json.loads(
        (target / owner.members["main"]["analysis"]["metadata"]["path"]).read_bytes()
    )


def test_record_declaration_replay_review_undo_and_sibling_preservation(
    tmp_path, monkeypatch
):
    _, target, _, call = editable(tmp_path, monkeypatch, scalar_array=True)
    create(call)
    before, sibling = (
        (target / "main.s").read_bytes(),
        (target / "overlay.s").read_bytes(),
    )
    saved = call("interpret", **request(call))
    assert len(saved["actions"]) == 1
    assert (
        saved["verification"]["media_exact"]
        and saved["verification"]["all_placement_coverage"]
    )
    action = saved["actions"][0]
    assert action["kind"] == "declare_manual_record_array"
    assert action["interpretation"]["member_subject"]["analysis_member_id"] == "main"
    data = metadata(target)
    record = next(t for t in data["custom_structs"] if t["name"] == "Pair")
    assert [(f["name"], f["offset"], f["size"]) for f in record["fields"]] == [
        ("category", 0, 2),
        ("actionWord14", 2, 2),
    ]
    element = data["data_block_layouts"][-1]["elements"][0]
    assert element["array_count"] == 7 and element["array_stride"] == 4
    assert element["type_binding"]["record_contract"]["fields"] == FIELDS
    assert element["type_binding"]["owner_action_id"] == action["action_id"]
    text = (target / "main.s").read_bytes()
    assert b"dc.w" in text and b"existingArrayWord:" in text
    assert (target / "overlay.s").read_bytes() == sibling
    undone = call(
        "rollback", expected_revision=saved["revision"], action_id=action["action_id"]
    )
    assert (target / "main.s").read_bytes() == before
    assert not any(t["name"] == "Pair" for t in metadata(target)["custom_structs"])
    redone = call(
        "rollback",
        expected_revision=undone["revision"],
        action_id=action["action_id"],
        redo=True,
    )
    assert (target / "main.s").read_bytes() == text
    regenerated = call("regenerate", expected_revision=redone["revision"])
    assert regenerated["verification"]["media_exact"]
    proof = call(
        "verify",
        expected_revision=regenerated["revision"],
        output=str(tmp_path / "proof"),
    )["verification"]
    call(
        "review",
        expected_revision=regenerated["revision"],
        action_id=action["action_id"],
        decision="accept",
        reason="Exact synthetic record reconstruction.",
        verification_id=proof["receipt_id"],
    )
    assert (
        next(
            r for r in call("history")["items"] if r["action_id"] == action["action_id"]
        )["decision"]["action"]
        == "accept_fact"
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"record_count": 0},
        {"record_count": True},
        {"record_count": -1},
        {"record_count": 8},
        {"record_count": 2**32},
        {"record_stride": 2},
        {"record_stride": 0},
        {"record_stride": 2**32},
        {"record_size": True},
        {"record_size": 0},
        {"record_type": "bad.name"},
        {"width": 24},
        {"fields": []},
        {"fields": [{"name": "tooWide", "type": "UWORD", "offset": 0, "size": 4}]},
        {
            "fields": [
                FIELDS[0],
                {"name": "overlap", "type": "UWORD", "offset": 0, "size": 2},
            ]
        },
        {
            "fields": [
                FIELDS[0],
                {"name": "category", "type": "UWORD", "offset": 2, "size": 2},
            ]
        },
        {"fields": [{"name": "outside", "type": "UWORD", "offset": 4, "size": 2}]},
        {
            "fields": [
                {
                    "name": "pointer",
                    "type": "ULONG",
                    "offset": 0,
                    "size": 4,
                    "value_kind": "target_pointer",
                }
            ]
        },
    ],
)
def test_bad_record_declaration_is_atomic(tmp_path, monkeypatch, updates):
    _, target, _, call = editable(tmp_path, monkeypatch, pointer_rows=True)
    create(call)
    body = request(call, **updates)
    before = snapshot(target)
    with pytest.raises((ValueError, RuntimeError)):
        call("interpret", **body)
    assert snapshot(target) == before


def test_record_declaration_preserves_interior_alias_and_unknown_gaps(
    tmp_path, monkeypatch
):
    _, target, _, call = editable(tmp_path, monkeypatch, scalar_array=True)
    create(call, 12)
    saved = call(
        "interpret",
        **request(
            call,
            end=12,
            fields=[
                {"name": "firstByte", "type": "UBYTE", "offset": 0, "size": 1},
                FIELDS[1],
            ],
        ),
    )
    assert saved["verification"]["media_exact"]
    text = (target / "main.s").read_text()
    assert "existingArrayWord:" in text and "dc.b" in text and "dc.w" in text
    data = metadata(target)
    assert (
        data["data_block_layouts"][-1]["elements"][0]["type_binding"][
            "record_contract"
        ]["fields"][0]["size"]
        == 1
    )


def test_record_cannot_replace_scalar_or_conflicting_record(tmp_path, monkeypatch):
    _, target, _, call = editable(tmp_path, monkeypatch, pointer_rows=True)
    create(call)
    selected = call("inspect", source_offset=4, end_offset=8, row_kind="data")
    call(
        "interpret",
        **data_request(
            selected,
            "range.data_block.element.set",
            {"kind": "scalar", "name": "keptField"},
        ),
    )
    before = snapshot(target)
    with pytest.raises(ValueError, match="overlap|contract"):
        call("interpret", **request(call))
    assert snapshot(target) == before


def test_identical_record_reuses_type_and_preserves_journal_prefix(
    tmp_path, monkeypatch
):
    _, target, _, call = editable(tmp_path, monkeypatch, pointer_rows=True)
    create(call)
    first = call("interpret", **request(call))
    owner = DiskSet.load(target, project_root=target.parent.parent)
    log = (
        target
        / owner.members["main"]["analysis"]["state"]["manual_actions.jsonl"]["path"]
    )
    prefix = log.read_bytes()
    record = next(t for t in metadata(target)["custom_structs"] if t["name"] == "Pair")
    second = call("interpret", **request(call))
    assert log.read_bytes().startswith(prefix)
    assert (
        next(t for t in metadata(target)["custom_structs"] if t["name"] == "Pair")
        == record
    )
    assert first["revision"] != second["revision"]
    bad = request(
        call, fields=[{"name": "changed", "type": "ULONG", "offset": 0, "size": 4}]
    )
    before = snapshot(target)
    with pytest.raises(ValueError, match="conflict|contract"):
        call("interpret", **bad)
    assert snapshot(target) == before


def test_forged_record_member_revision_and_bad_batch_are_atomic(tmp_path, monkeypatch):
    _, target, _, call = editable(tmp_path, monkeypatch, pointer_rows=True)
    create(call)
    body = request(call)
    before = snapshot(target)
    forged = copy.deepcopy(body)
    forged["context"]["locators"][0]["member_id"] = "overlay"
    with pytest.raises(ValueError, match="subject|revision"):
        call("interpret", **forged)
    with pytest.raises(ValueError, match="stale_revision"):
        call("interpret", **{**body, "expected_revision": "0" * 64})
    bad = copy.deepcopy(body)
    bad["parameters"]["record_stride"] = 2
    with pytest.raises(ValueError, match="stride"):
        call(
            "interpret_batch",
            expected_revision=body["expected_revision"],
            entries=[
                {k: v for k, v in b.items() if k != "expected_revision"}
                for b in [body, bad]
            ],
        )
    assert snapshot(target) == before


def test_independent_imported_scalar_contract_is_not_overwritten(tmp_path, monkeypatch):
    _, target, _, call = editable(tmp_path, monkeypatch, pointer_rows=True)
    create(call)
    saved = call("interpret", **request(call))
    assert saved["verification"]["media_exact"]
    data = metadata(target)
    assert any(
        e["addr"] == 28
        and e["end"] == 32
        and e["unit"] == "long"
        and e["citation"] == "Independent scalar"
        for e in data["seeded_entities"]
    )
    assert "existingRecord:" in (target / "main.s").read_text()


def test_shared_view_records_use_canonical_offsets_and_history(tmp_path, monkeypatch):
    from amiga_reversing.disasm.disk_codecs import digest
    from amiga_reversing.disasm.disk_set import compose_source_package
    from amiga_reversing.disasm.source_package_publish import publish_source_package
    from tests.test_disk_set import packages_for

    _, target, _, call = editable(tmp_path, monkeypatch, pointer_rows=True)
    path = target / "manifest.json"
    manifest = json.loads(path.read_bytes())
    manifest["members"].append(
        {
            "id": "record_view",
            "kind": "data",
            "size": 8,
            "sha256": digest(bytes.fromhex("0000102000001020")),
            "context": {
                "address_model": "runtime_absolute",
                "load_address": 0x1004,
                "entrypoint": None,
                "code_start_offset": None,
                "phase": "decoded_resource",
            },
            "source": None,
            "analysis": None,
        }
    )
    manifest["relationships"].append(
        {
            "kind": "embedded",
            "member": "record_view",
            "owner": "main",
            "offset": 4,
            "size": 8,
            "evidence": "Exact independent synthetic data slice.",
        }
    )
    package = compose_source_package(manifest, packages_for(target, manifest))
    publish_source_package(package, target)
    manifest["package_sha256"] = package["sha256"]
    path.write_text(json.dumps(manifest))
    inspected = call(
        "inspect", member="record_view", source_offset=0, end_offset=8, row_kind="data"
    )
    call(
        "interpret",
        member="record_view",
        **data_request(
            inspected, "range.data_block.layout.create", {"default_unit": "word"}
        ),
    )
    inspected = call(
        "inspect", member="record_view", source_offset=0, end_offset=8, row_kind="data"
    )
    saved = call(
        "interpret",
        member="record_view",
        **data_request(
            inspected,
            "range.data_block.records.declare",
            {
                "record_type": "ViewPair",
                "record_size": 4,
                "record_count": 2,
                "record_stride": 4,
                "fields": FIELDS,
            },
        ),
    )
    assert saved["verification"]["media_exact"]
    subject = saved["actions"][0]["interpretation"]["member_subject"]
    assert subject["analysis_member_id"] == "main"
    layout = metadata(target)["data_block_layouts"][-1]
    assert (layout["source_start"], layout["source_end"]) == (4, 12)
    assert layout["elements"][0]["type_binding"]["element_offset"] == 0
    assert (
        call("history", member="record_view")["items"][0]["kind"]
        == "declare_manual_record_array"
    )
    assert not any("record_view" in p.name for p in (target / "analysis").iterdir())
    before = snapshot(target)
    with pytest.raises(ValueError, match="bounded data range"):
        call(
            "inspect",
            member="record_view",
            source_offset=0,
            end_offset=10,
            row_kind="data",
        )
    assert snapshot(target) == before


def test_changed_record_type_fails_closed_during_replay(tmp_path, monkeypatch):
    from amiga_reversing.disasm.disk_set_state import _artifact, state_context
    from amiga_reversing.disasm.effective_metadata import effective_target_metadata
    from amiga_reversing.disasm.manual_actions import (
        ManualActionKind,
        append_manual_actions,
    )

    project, target, paths, call = editable(tmp_path, monkeypatch, scalar_array=True)
    create(call)
    call("interpret", **request(call))
    owner = DiskSet.load(target, project_root=project)
    source, artifact = _artifact(owner, "main", paths)
    artifact.close()
    with state_context(owner, "main"):
        # Low-level append still goes through normal native validation: a later
        # incompatible type edit must not silently reinterpret an old witness.
        with pytest.raises(ValueError, match="lost or changed"):
            append_manual_actions(
                target,
                binary_source=source,
                actions=[
                    (
                        ManualActionKind.CREATE_MANUAL_CUSTOM_STRUCT,
                        {
                            "custom_struct": {
                                "name": "Pair",
                                "size": 4,
                                "fields": [
                                    {
                                        "name": "changed",
                                        "type": "ULONG",
                                        "offset": 0,
                                        "size": 4,
                                    }
                                ],
                            }
                        },
                    )
                ],
            )
        effective_target_metadata(target)


@pytest.mark.parametrize(
    ("fields", "size"),
    [
        ([{"name": "oddWord", "type": "UWORD", "offset": 1, "size": 2}], 4),
        ([{"name": "word", "type": "UWORD", "offset": 0, "size": 2}], 3),
        ([{"name": "tooFar", "type": "UBYTE", "offset": 2**32, "size": 1}], 4),
    ],
)
def test_record_alignment_and_field_extent_are_atomic(
    tmp_path, monkeypatch, fields, size
):
    _, target, _, call = editable(tmp_path, monkeypatch, scalar_array=True)
    create(call)
    body = request(call, fields=fields, record_size=size, record_stride=size)
    before = snapshot(target)
    with pytest.raises(ValueError, match="even|offset|stride|extent|width"):
        call("interpret", **body)
    assert snapshot(target) == before

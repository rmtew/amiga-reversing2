"""Scalar arrays use the existing scoped operation, ownership and history path."""

import copy
import json

import pytest

from amiga_reversing.disasm.disk_set import DiskSet
from tests.test_disk_set_state import data_request, editable


def create(call, end=32):
    inspected = call("inspect", source_offset=4, end_offset=end, row_kind="data")
    return call(
        "interpret",
        **data_request(
            inspected, "range.data_block.layout.create", {"default_unit": "word"}
        ),
    )


def array_request(call, *, end=32, stride=4, count=7, **fields):
    ins = call("inspect", source_offset=4, end_offset=end, row_kind="data")
    return data_request(
        ins,
        "range.data_block.element.set",
        {
            "kind": "array",
            "width": end - 4,
            "array_count": count,
            "array_stride": stride,
            **fields,
        },
    )


def snapshot(target):
    return {
        p.relative_to(target): p.read_bytes() for p in target.rglob("*") if p.is_file()
    }


@pytest.mark.parametrize(
    ("stride", "end", "count"), [(1, 8, 4), (2, 12, 4), (4, 32, 7)]
)
def test_scoped_plain_array_preserves_width_numeric_values_and_siblings(
    tmp_path, monkeypatch, stride, end, count
):
    _, target, _, call = editable(tmp_path, monkeypatch, pointer_rows=True)
    create(call, end)
    before_overlay = (target / "overlay.s").read_bytes()
    saved = call(
        "interpret", **array_request(call, end=end, stride=stride, count=count)
    )
    assert (
        saved["verification"]["media_exact"]
        and saved["verification"]["all_placement_coverage"]
    )
    owner = DiskSet.load(target, project_root=target.parent.parent)
    metadata = json.loads(
        (target / owner.members["main"]["analysis"]["metadata"]["path"]).read_bytes()
    )
    element = metadata["data_block_layouts"][-1]["elements"][0]
    assert (
        element["kind"] == "array"
        and element["array_stride"] == stride
        and element["array_count"] == count
    )
    text = (target / "main.s").read_text()
    assert {"1": "dc.b", "2": "dc.w", "4": "dc.l"}[str(stride)] in text
    assert (target / "overlay.s").read_bytes() == before_overlay
    assert "existingRecord:" in text
    assert not metadata["manual_runtime_address_refs"]
    assert call("regenerate", expected_revision=saved["revision"])["verification"][
        "media_exact"
    ]


def test_large_word_array_one_action_replay_review_undo_redo(tmp_path, monkeypatch):
    _, target, _, call = editable(tmp_path, monkeypatch, scalar_array=True)
    create(call, 1032)
    before = (target / "main.s").read_bytes()
    saved = call(
        "interpret",
        **array_request(call, end=1032, stride=2, count=514, name="screenWords"),
    )
    action_id = saved["actions"][0]["action_id"]
    assert len(saved["actions"]) == 1
    text = (target / "main.s").read_bytes()
    assert b"dc.w" in text and b"dc.b $CA,$FE" in text and b"existingArrayWord:" in text
    undone = call("rollback", expected_revision=saved["revision"], action_id=action_id)
    assert (target / "main.s").read_bytes() == before
    redone = call(
        "rollback", expected_revision=undone["revision"], action_id=action_id, redo=True
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
        action_id=action_id,
        decision="accept",
        reason="Exact synthetic scalar-array reconstruction.",
        verification_id=proof["receipt_id"],
    )
    assert (
        next(
            item for item in call("history")["items"] if item["action_id"] == action_id
        )["decision"]["action"]
        == "accept_fact"
    )


@pytest.mark.parametrize(
    "fields",
    [
        {"array_count": 0},
        {"array_count": -1},
        {"array_count": True},
        {"array_count": 2**32},
        {"array_count": 8},
        {"array_stride": 3},
        {"array_stride": 0},
        {"array_stride": 2**32},
        {"width": 24},
        {"binding_kind": "custom_struct", "type_id": "unproved"},
    ],
)
def test_scoped_bad_array_is_atomic(tmp_path, monkeypatch, fields):
    _, target, _, call = editable(tmp_path, monkeypatch, pointer_rows=True)
    create(call)
    request = array_request(call, **fields)
    before = snapshot(target)
    with pytest.raises((ValueError, RuntimeError)):
        call("interpret", **request)
    assert snapshot(target) == before


@pytest.mark.parametrize("interpreted", [False, True])
def test_array_cannot_replace_manual_scalar_or_reference(
    tmp_path, monkeypatch, interpreted
):
    _, target, _, call = editable(tmp_path, monkeypatch, pointer_rows=True)
    create(call)
    scalar = call("inspect", source_offset=4, end_offset=8, row_kind="data")
    call(
        "interpret",
        **data_request(
            scalar,
            "range.data_block.element.set",
            {"kind": "scalar", "name": "keptScalar"},
        ),
    )
    if interpreted:
        selected = call("inspect", source_offset=4, row_kind="data")
        call(
            "interpret",
            **data_request(
                selected,
                "row.data_block.element.interpret_ref",
                {
                    "reference_kind": "absolute",
                    "source_value": 0x1020,
                    "runtime_address": 0x1020,
                    "target_hunk": 0,
                    "target_offset": 32,
                },
            ),
        )
    before = snapshot(target)
    with pytest.raises(ValueError, match="overlap|existing|contract"):
        call("interpret", **array_request(call))
    assert snapshot(target) == before


def test_scoped_array_forged_revision_and_bad_batch_keep_all_state(
    tmp_path, monkeypatch
):
    _, target, _, call = editable(tmp_path, monkeypatch, pointer_rows=True)
    create(call)
    request = array_request(call)
    forged = copy.deepcopy(request)
    forged["context"]["locators"][0]["member_id"] = "overlay"
    before = snapshot(target)
    with pytest.raises(ValueError, match="subject|revision"):
        call("interpret", **forged)
    with pytest.raises(ValueError, match="stale_revision"):
        call("interpret", **{**request, "expected_revision": "0" * 64})
    bad = copy.deepcopy(request)
    bad["parameters"]["array_count"] = 8
    entries = [
        {k: v for k, v in item.items() if k != "expected_revision"}
        for item in [request, bad]
    ]
    with pytest.raises(ValueError, match="count times stride"):
        call(
            "interpret_batch",
            expected_revision=request["expected_revision"],
            entries=entries,
        )
    assert snapshot(target) == before


def test_compatible_array_update_preserves_name_and_undo_history(tmp_path, monkeypatch):
    _, target, _, call = editable(tmp_path, monkeypatch, pointer_rows=True)
    create(call)
    call("interpret", **array_request(call, name="keptArray", representation="hex"))
    saved = call("interpret", **array_request(call))
    owner = DiskSet.load(target, project_root=target.parent.parent)
    metadata = json.loads(
        (target / owner.members["main"]["analysis"]["metadata"]["path"]).read_bytes()
    )
    element = metadata["data_block_layouts"][-1]["elements"][0]
    assert element["name"] == "keptArray" and element["representation"] == "hex"
    text = (target / "main.s").read_bytes()
    call(
        "rollback",
        expected_revision=saved["revision"],
        action_id=saved["actions"][0]["action_id"],
    )
    assert (target / "main.s").read_bytes() == text


def test_shared_data_view_array_edits_only_canonical_owner(tmp_path, monkeypatch):
    from amiga_reversing.disasm.disk_codecs import digest

    _, target, _, call = editable(tmp_path, monkeypatch, pointer_rows=True)
    path = target / "manifest.json"
    manifest = json.loads(path.read_bytes())
    manifest["members"].append(
        {
            "id": "array_view",
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
            "member": "array_view",
            "owner": "main",
            "offset": 4,
            "size": 8,
            "evidence": "Independent synthetic exact data slice.",
        }
    )
    from amiga_reversing.disasm.disk_set import compose_source_package
    from amiga_reversing.disasm.source_package_publish import publish_source_package
    from tests.test_disk_set import packages_for

    package = compose_source_package(manifest, packages_for(target, manifest))
    publish_source_package(package, target)
    manifest["package_sha256"] = package["sha256"]
    path.write_text(json.dumps(manifest))
    inspected = call(
        "inspect", member="array_view", source_offset=0, end_offset=8, row_kind="data"
    )
    call(
        "interpret",
        member="array_view",
        **data_request(
            inspected, "range.data_block.layout.create", {"default_unit": "word"}
        ),
    )
    inspected = call(
        "inspect", member="array_view", source_offset=0, end_offset=8, row_kind="data"
    )
    saved = call(
        "interpret",
        member="array_view",
        **data_request(
            inspected,
            "range.data_block.element.set",
            {"kind": "array", "width": 8, "array_count": 4, "array_stride": 2},
        ),
    )
    assert saved["verification"]["media_exact"]
    assert (
        call("history", member="array_view")["items"][0]["kind"]
        == "set_manual_data_block_element"
    )
    assert not any("array_view" in p.name for p in (target / "analysis").iterdir())
    before = snapshot(target)
    with pytest.raises(ValueError, match="bounded data range"):
        call(
            "inspect",
            member="array_view",
            source_offset=0,
            end_offset=10,
            row_kind="data",
        )
    assert snapshot(target) == before


def test_array_cannot_replace_declared_pointer_columns(tmp_path, monkeypatch):
    from tests.test_declared_data_pointer_table import declaration

    _, target, _, call = editable(tmp_path, monkeypatch, pointer_rows=True)
    create(call, 28)
    selected = call("inspect", source_offset=4, row_kind="data")
    call(
        "interpret",
        **data_request(selected, "row.data_block.layout.pointer_table", declaration()),
    )
    before = snapshot(target)
    with pytest.raises(ValueError, match="pointer-table contract"):
        call("interpret", **array_request(call, end=28, count=6))
    assert snapshot(target) == before


@pytest.mark.parametrize(
    "fields",
    [
        {"offset": -1},
        {"offset": 2**32},
        {"width": 0},
        {"width": 2**32},
        {"offset": 0xFFFFFFFE, "width": 2},
        {"array_count": 2**32},
        {"array_count": True},
        {"array_stride": True},
        {"type_binding": {"binding_kind": "custom_struct"}},
        {"reference_interpretation": {"reference_kind": "absolute"}},
    ],
)
def test_scalar_array_math_and_semantics_fail_before_native_allocation(fields):
    from amiga_reversing.disasm.target_metadata import validate_scalar_data_array

    value = {
        "kind": "array",
        "offset": 0,
        "width": 8,
        "array_count": 4,
        "array_stride": 2,
        **fields,
    }
    with pytest.raises(ValueError, match="scalar array|scoped scalar array"):
        validate_scalar_data_array(value)


def test_scalar_array_owner_rejects_full_extent_overflow():
    from amiga_reversing.disasm.target_metadata import validate_scalar_data_array_owner

    value = {
        "kind": "array",
        "offset": 2,
        "width": 8,
        "array_count": 4,
        "array_stride": 2,
    }
    with pytest.raises(ValueError, match="outside its owner"):
        validate_scalar_data_array_owner(
            value, {"source_start": 4, "source_end": 12, "elements": []}
        )


@pytest.mark.parametrize("boundary", ["label", "gap", "section", "owner"])
def test_catalog_array_groups_bytes_and_preserves_scope_boundaries(boundary):
    from amiga_reversing.disasm.manual_action_catalog import (
        listing_range_action_catalog,
    )

    layout = {"layout_id": "one", "hunk": 0, "source_start": 4, "source_end": 12}
    first = {
        "kind": "data",
        "row_index": 1,
        "section_index": 0,
        "start_offset": 4,
        "end_offset": 6,
        "active_data_block_layout": layout,
    }
    second = {
        "kind": "data",
        "row_index": 3,
        "section_index": 0,
        "start_offset": 6,
        "end_offset": 8,
        "active_data_block_layout": layout,
    }
    if boundary == "gap":
        second.update(start_offset=8, end_offset=10)
    if boundary == "section":
        second.update(section_index=1, active_data_block_layout={**layout, "hunk": 1})
    if boundary == "owner":
        second["active_data_block_layout"] = {**layout, "layout_id": "two"}
    rows = [
        first,
        {
            "kind": "label",
            "row_index": 2,
            "section_index": 0,
            "start_offset": 6,
            "end_offset": 6,
        },
        second,
    ]
    action = next(
        a
        for a in listing_range_action_catalog(rows)
        if a["action_id"] == "range.data_block.element.set"
    )
    assert len(action["applicable_subranges"]) == (1 if boundary == "label" else 2)


def test_existing_array_cannot_silently_discard_requested_type_binding(
    tmp_path, monkeypatch
):
    _, target, _, call = editable(tmp_path, monkeypatch, pointer_rows=True)
    create(call)
    call("interpret", **array_request(call))
    selected = call("inspect", source_offset=4, end_offset=32, row_kind="data")
    before = snapshot(target)
    with pytest.raises(ValueError, match="typed/reference bindings|byte/word/long scalars"):
        call(
            "interpret",
            **data_request(
                selected,
                "range.data_block.element.set",
                {"binding_kind": "custom_struct", "type_id": "unproved"},
            ),
        )
    assert snapshot(target) == before

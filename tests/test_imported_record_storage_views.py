"""Record views retain imported storage provenance and source annotations."""

import json

import pytest

from amiga_reversing.disasm.disk_set import DiskSet
from tests.test_disk_set_state import data_request, editable
from tests.test_scoped_scalar_arrays import snapshot


def prepared(
    tmp_path, monkeypatch, *, protection=None, import_offset=22, import_width=4
):
    payload = (
        (0x1020).to_bytes(4, "big")
        + bytes.fromhex("000a00240004")
        + (0x1020).to_bytes(4, "big")
        + bytes.fromhex("001c00400007")
        + bytes.fromhex("a55a0000")
        + bytes(16)
    )
    imported = {
        "hunk": 0,
        "addr": import_offset,
        "end": import_offset + import_width,
        "type": "data",
        "unit": {1: "byte", 2: "word", 4: "long"}[import_width],
        "seed_origin": "manual_analysis",
        "review_status": "seeded",
        "source_id": "fixture-import",
        "citation": "Imported scalar storage without value interpretation",
    }
    if protection:
        imported.update(protection)
    project, target, paths, call = editable(
        tmp_path, monkeypatch, record_data=payload, record_imports=[imported]
    )
    selected = call("inspect", source_offset=4, end_offset=28, row_kind="data")
    call(
        "interpret",
        **data_request(
            selected,
            "range.data_block.layout.create",
            {"name": "displayRows", "default_unit": "word"},
        ),
    )
    return project, target, call


def request(call):
    selected = call("inspect", source_offset=4, end_offset=24, row_kind="data")
    fields = [
        {
            "name": "glyphs",
            "type": "APTR",
            "offset": 0,
            "size": 4,
            "value_kind": "target_pointer",
            "pointer_address_domain": "mapped_source",
        }
    ]
    fields += [
        {"name": n, "type": "WORD", "offset": 4 + 2 * j, "size": 2}
        for j, n in enumerate(["phasePosition", "row", "count"])
    ]
    return data_request(
        selected,
        "range.data_block.records.declare",
        {
            "record_type": "DisplayRow",
            "record_size": 10,
            "record_count": 2,
            "record_stride": 10,
            "fields": fields,
            "field_presentation": True,
        },
    )


def test_record_word_within_weak_long_storage_preserves_tail_and_import(
    tmp_path, monkeypatch
):
    project, target, call = prepared(tmp_path, monkeypatch)
    owner = DiskSet.load(target, project_root=project)
    original_path = (
        target
        / owner.members["main"]["analysis"]["state"]["target_metadata.json"]["path"]
    )
    original = original_path.read_bytes()
    before = (target / "main.s").read_bytes()
    saved = call("interpret", **request(call))
    assert saved["verification"]["media_exact"]
    text = (target / "main.s").read_text()
    assert "dc.w $0007\t; count" in text
    assert "$A5,$5A" in text
    assert original_path.read_bytes() == original
    assert any(
        r["addr"] == 22 and r["end"] == 26 and r["unit"] == "long"
        for r in json.loads(original)["seeded_entities"]
    )
    action = saved["actions"][0]["action_id"]
    undone = call("rollback", expected_revision=saved["revision"], action_id=action)
    assert (target / "main.s").read_bytes() == before
    restored = call(
        "rollback", expected_revision=undone["revision"], action_id=action, redo=True
    )
    assert restored["verification"]["media_exact"]
    assert (target / "main.s").read_text() == text


@pytest.mark.parametrize(
    "protection",
    [
        {"name": "ownedScalar"},
        {"comment": "Independent scalar meaning"},
        {"c_type": "LONG"},
        {"field_type": "LONG"},
        {"review_status": "validated"},
        {"source_id": "manual_action_log"},
        {"source_evidence_id": "independent-proof"},
    ],
)
def test_additive_record_view_retains_stronger_import_and_visible_annotations(
    tmp_path, monkeypatch, protection
):
    project, target, call = prepared(tmp_path, monkeypatch, protection=protection)
    owner = DiskSet.load(target, project_root=project)
    original_path = (
        target
        / owner.members["main"]["analysis"]["state"]["target_metadata.json"]["path"]
    )
    original = original_path.read_bytes()
    before = (target / "main.s").read_text()
    saved = call("interpret", **request(call))
    assert saved["verification"]["media_exact"]
    assert original_path.read_bytes() == original
    raw = next(r for r in json.loads(original)["seeded_entities"] if r["addr"] == 22)
    assert all(raw[k] == v for k, v in protection.items())
    text = (target / "main.s").read_text()
    for key in ("name", "comment"):
        annotation = protection.get(key)
        if annotation and annotation in before:
            assert annotation in text
    assert "$A5,$5A" in text


def test_existing_owned_scalar_cannot_be_replaced_by_a_record_view(
    tmp_path, monkeypatch
):
    _, target, call = prepared(tmp_path, monkeypatch)
    inspected = call("inspect", source_offset=22, end_offset=26, row_kind="data")
    call(
        "interpret",
        **data_request(
            inspected,
            "range.data_block.element.set",
            {"kind": "scalar", "name": "keptWholeScalar"},
        ),
    )
    req = request(call)
    before = snapshot(target)
    with pytest.raises(ValueError, match="conflict|overlap|contract"):
        call("interpret", **req)
    assert snapshot(target) == before


@pytest.mark.parametrize("replacement", ["Reviewed source observation"])
def test_promoted_comment_replacement_replays_and_undo_restores_original(
    tmp_path, monkeypatch, replacement
):
    _, target, call = prepared(
        tmp_path, monkeypatch, protection={"comment": "Original scalar observation"}
    )
    call("interpret", **request(call))
    before = (target / "main.s").read_text()
    assert before.count("Original scalar observation") == 1
    selected = call("inspect", source_offset=22, row_kind="data")
    assert len(selected["row"]["imported_entry_comments"]) == 1
    req = data_request(
        selected,
        "comment.edit",
        {
            "text": replacement,
            "replace_imported_comment": "Original scalar observation",
        },
    )
    saved = call("interpret", **req)
    after = (target / "main.s").read_text()
    assert "Original scalar observation" not in after
    if replacement:
        assert after.count(replacement) == 1
    assert call("regenerate", expected_revision=saved["revision"])["verification"][
        "media_exact"
    ]
    action = saved["actions"][0]["action_id"]
    undone = call("rollback", expected_revision=saved["revision"], action_id=action)
    assert (target / "main.s").read_text() == before
    call("rollback", expected_revision=undone["revision"], action_id=action, redo=True)
    assert (target / "main.s").read_text() == after


@pytest.mark.parametrize("offset", [23, 26])
def test_record_view_preserves_interior_and_outside_comment_points(
    tmp_path, monkeypatch, offset
):
    _, target, call = prepared(
        tmp_path,
        monkeypatch,
        import_offset=offset,
        import_width=1,
        protection={"comment": "Exact source point"},
    )
    call("interpret", **request(call))
    text = (target / "main.s").read_text()
    assert text.count("Exact source point") == 1
    assert "$A5,$5A" in text or "$A5" in text and "$5A" in text


def test_empty_promoted_comment_replacement_keeps_existing_refusal(
    tmp_path, monkeypatch
):
    _, target, call = prepared(
        tmp_path, monkeypatch, protection={"comment": "Original scalar observation"}
    )
    call("interpret", **request(call))
    selected = call("inspect", source_offset=22, row_kind="data")
    req = data_request(
        selected,
        "comment.edit",
        {"text": "", "replace_imported_comment": "Original scalar observation"},
    )
    before = snapshot(target)
    with pytest.raises(ValueError, match="requires parameter text"):
        call("interpret", **req)
    assert snapshot(target) == before

"""Imported declarations remain correctable regardless of their storage layer."""

import json
from types import SimpleNamespace

from amiga_reversing.disasm import server
from amiga_reversing.disasm.manual_action_catalog import listing_row_action_catalog
from amiga_reversing.disasm.target_metadata import (
    TargetMetadata,
    target_metadata_json_payload,
    write_target_metadata,
    write_target_seeded_metadata,
)


def metadata(addr=4, end=12, generated=False):
    payload = json.loads(
        json.dumps(
            target_metadata_json_payload(
                TargetMetadata(target_type="raw_binary", entry_register_seeds=())
            )
        )
    )
    payload["seeded_entities"] = [
        {
            "addr": addr,
            "end": end,
            "hunk": 0,
            "name": "imported_record",
            "type": "data",
            "unit": "byte",
            "seed_origin": "manual_analysis",
            "review_status": "seeded",
            "citation": "Source import",
            "source_id": "fixture-import",
            "source_path": "fixture-facts.json" if generated else None,
            "source_locator": "$.record" if generated else None,
        }
    ]
    return TargetMetadata.from_dict(payload)


def test_base_import_without_optional_locator_has_a_full_extent_correction(
    monkeypatch, tmp_path
):
    write_target_metadata(tmp_path, metadata())
    before = (tmp_path / "target_metadata.json").read_bytes()
    monkeypatch.setattr(
        server,
        "resolve_project_paths",
        lambda *args, **kwargs: SimpleNamespace(target_dir=tmp_path),
    )
    items = server._target_suppressible_seeded_items("fixture")
    assert (
        len(items) == 1 and items[0]["end"] == 12 and "source_locator" not in items[0]
    )
    row = {
        "kind": "data",
        "section_index": 0,
        "start_offset": 8,
        "end_offset": 10,
        "addr": 8,
        "text": "dc.b $00",
    }
    server._annotate_suppressible_seeded_items(row, items)
    actions = listing_row_action_catalog(row)
    correction = next(
        a
        for a in actions
        if a["action_id"] == "correction.suppress_seeded_item.seeded_entity"
    )
    assert correction["parameters"] == {
        "kind": "seeded_entity",
        "hunk": 0,
        "addr": 4,
        "end": 12,
    }
    assert (tmp_path / "target_metadata.json").read_bytes() == before


def test_base_and_generated_declarations_share_one_merged_identity_surface(
    monkeypatch, tmp_path
):
    write_target_metadata(tmp_path, metadata())
    write_target_seeded_metadata(tmp_path, metadata(20, 24, True))
    monkeypatch.setattr(
        server,
        "resolve_project_paths",
        lambda *args, **kwargs: SimpleNamespace(target_dir=tmp_path),
    )
    assert {
        (i["addr"], i["end"])
        for i in server._target_suppressible_seeded_items("fixture")
    } == {(4, 12), (20, 24)}


def test_missing_declared_metadata_does_not_invent_a_suppressible_item(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(
        server,
        "resolve_project_paths",
        lambda *args, **kwargs: SimpleNamespace(target_dir=tmp_path),
    )
    assert server._target_suppressible_seeded_items("fixture") == []

"""LONG source relations retain their width through replay, native IR and asm."""
from __future__ import annotations

import json

import pytest

from amiga_reversing.disasm import c_backend
from amiga_reversing.disasm.effective_metadata import (
    effective_metadata_file,
    effective_metadata_text,
    effective_target_metadata,
)
from amiga_reversing.disasm.manual_action_catalog import target_catalog_manual_payload
from amiga_reversing.disasm.manual_actions import append_manual_actions
from tests.test_base_displacement_data_refs import _write_log
from tests.test_base_displacement_integration import _round_trip
from tests.test_base_displacement_ranges import _fixture, _params
from tests.test_base_displacement_struct_fields import _struct_fixture


@pytest.mark.parametrize("updates", [
    {"entry_width": 1}, {"entry_width": True}, {"entry_width": 8},
    {"width": 6}, {"width": 4 * 65536}, {"source_value": 1 << 32},
    {"source_value": 0xFFFFFFFF, "target_offset": 2047},
])
def test_long_range_refuses_ambiguous_width_or_wrapped_target(updates):
    with pytest.raises(ValueError, match="base_displacement_range"):
        target_catalog_manual_payload("target.data_block.element.interpret_ref", parameters=_params(
            **{"entry_width": 4, "width": 8, **updates}))


@pytest.mark.c_backend
@pytest.mark.parametrize(("values", "signed", "scale"), [
    ([0, 0x8000, 0x10004], False, 1),
    ([0x10004, 0x10008], False, 1),
    ([0xFFFFFFFF, 0], True, 1),
    ([0, 4, 0xFFFFFFFC], True, 1),
    ([0, 1, 0xFFFFFFFF], True, 18),
])
def test_native_long_range_roundtrip_and_bidirectional_xrefs(tmp_path, values, signed, scale):
    source, original, action, base = _fixture(tmp_path, values, signed, scale, entry_width=4)
    append_manual_actions(tmp_path, actions=[action], binary_source=source)
    metadata = json.loads(effective_metadata_text(tmp_path))
    assert metadata["manual_data_references"][0]["entry_width"] == 4
    with effective_metadata_file(tmp_path) as path:
        rendered = c_backend.render_project_source_with_c_backend(source, metadata_path=path)
        _, _, artifact = c_backend.build_listing_artifact_profile_from_binary_source(source, metadata_path=path)
        try:
            for n, raw in enumerate(values):
                refs = artifact.query_payload("references", section_index=0, source_offset=6+n*4,
                                              direction="outgoing")["items"]
                refs = [r for r in refs if r.get("owner_kind") == "data_block_interpreted_ref"]
                assert {r["reference_role"] for r in refs} == {"base", "target"}
                assert all(r["source_value"] == raw and r["width"] == 4 for r in refs)
                delta = raw - (1 << 32) if signed and raw >= 1 << 31 else raw
                incoming = artifact.query_payload("references", section_index=0, source_offset=base+delta*scale,
                                                  direction="incoming")["items"]
                assert any(r.get("source_offset") == 6+n*4 and r.get("reference_role") == "target" for r in incoming)
        finally:
            artifact.close()
    assert "\tdc.l " in rendered
    if scale == 1:
        assert sum(line.startswith("\tdc.l ") and "pixel_bank" in line for line in rendered.splitlines()) == len(values)
    assert not any(line.startswith("\tdc.w ") and "pixel_bank" in line for line in rendered.splitlines())
    _round_trip(tmp_path, rendered, original)


@pytest.mark.parametrize(("fields", "valid"), [
    ([("LONG", 0, 4), ("LONG", 4, 4)], True),
    ([("WORD", 0, 2), ("WORD", 2, 2), ("LONG", 4, 4)], False),
    ([("BYTE", 0, 4), ("LONG", 4, 4)], False),
])
def test_long_ranges_require_exact_long_struct_leaves(tmp_path, fields, valid):
    _struct_fixture(tmp_path, fields=fields, offset=0, count=2)
    records = [json.loads(line) for line in (tmp_path / "manual_actions.jsonl").read_text().splitlines()]
    ref = records[-1]["data_block_interpreted_ref"]
    ref.update(_params(entry_width=4, width=16, base_locator={"hunk": 0, "offset": 0x9000}, target_offset=0x9000))
    ref["target_locator"] = {"hunk": 0, "offset": 0x9000}
    _write_log(tmp_path, records)
    if valid:
        metadata = effective_target_metadata(tmp_path, include_decision_journal=False)
        assert metadata.manual_data_references[0].entry_width == 4
        assert metadata.data_block_layouts[0].elements[0].kind == "struct"
    else:
        with pytest.raises(ValueError, match="exact declared LONG leaf"):
            effective_target_metadata(tmp_path, include_decision_journal=False)


@pytest.mark.c_backend
@pytest.mark.parametrize(("values", "scale"), [([0, 0xFFFFFFFF], 1), ([0, 0xFFFFFFFF], 0xFFFFFFFF)])
def test_native_later_long_target_refuses_overflow_atomically(tmp_path, values, scale):
    source, _, action, _ = _fixture(tmp_path, [0, 1], entry_width=4, encoded_values=values)
    # The exact input identity already includes the hostile later cell.
    action[1]["data_block_interpreted_ref"]["scale"] = scale
    history = (tmp_path / "manual_actions.jsonl").read_bytes()
    with pytest.raises((ValueError, RuntimeError)):
        append_manual_actions(tmp_path, actions=[action], binary_source=source)
    assert (tmp_path / "manual_actions.jsonl").read_bytes() == history


@pytest.mark.c_backend
@pytest.mark.parametrize("typed", [False, True])
def test_http_long_ranges_keep_owner_and_validate_source_bytes(tmp_path, monkeypatch, typed):
    from dataclasses import replace
    from types import SimpleNamespace

    from amiga_reversing.disasm import restoration, server
    from amiga_reversing.disasm.binary_source import write_source_descriptor
    from tests.test_disasm_server import _binary_project, _seed_c_listing_artifact

    source, original, action, _ = _fixture(tmp_path, [0, 4, 8], entry_width=4, typed=typed)
    with effective_metadata_file(tmp_path) as path:
        _, _, artifact = c_backend.build_listing_artifact_profile_from_binary_source(source, metadata_path=path)
    write_source_descriptor(tmp_path, {"kind": "raw_binary", "path": str(source.path),
        "address_model": "local_offset", "load_address": 0, "entrypoint": 0, "code_start_offset": 0})
    monkeypatch.setattr(server, "resolve_project_paths", lambda *_a, **_kw: SimpleNamespace(
        target_dir=tmp_path, binary_source=source))
    monkeypatch.setattr(server, "get_project", lambda name: replace(
        _binary_project(name, ready=True), target_dir=str(tmp_path), binary_path=str(source.path)))
    monkeypatch.setattr(server, "mark_project_updated", lambda _name: None)
    _seed_c_listing_artifact(monkeypatch, "bloodwych", artifact)
    try:
        catalog = server._command_catalog_payload("bloodwych", {"context": ["target"]})
        command = next(r for r in catalog["commands"] if r["command_id"] == "target.data_block.element.interpret_ref")
        assert command["parameter_schema"]["properties"]["entry_width"]["enum"] == [2, 4]
        entry = {"command_id": command["command_id"], "context": command["target_context"],
                 "parameters": action[1]["data_block_interpreted_ref"], "evidence": {
                     "reason": "Inspected bounded LONG array and exact encoded source cells.",
                     "source_evidence_refs": [artifact.row_for_source_offset(section_index=0, offset=6)["row_key"]]}}
        result = server.route_request("POST", "/api/projects/bloodwych/restoration", {}, {
            "operation": "interpret_batch", "expected_revision": restoration.revisions("bloodwych")["revision"],
            "entries": [entry]})
        assert result["ok"] is True
        metadata = json.loads(effective_metadata_text(tmp_path))
        assert metadata["data_block_layouts"][0]["elements"][0]["kind"] == ("struct" if typed else "array")
        with effective_metadata_file(tmp_path) as path:
            rendered = c_backend.render_project_source_with_c_backend(source, metadata_path=path)
        assert sum(l.startswith("\tdc.l ") and "pixel_bank" in l for l in rendered.splitlines()) == 3
        _round_trip(tmp_path, rendered, original)
    finally:
        server._LISTING_PROJECTION_SERVICE.reset()
        artifact.close()


@pytest.mark.c_backend
def test_long_range_first_cell_must_match_actual_input(tmp_path):
    source, _, action, _ = _fixture(tmp_path, [0, 1], first_override=1, entry_width=4)
    history = (tmp_path / "manual_actions.jsonl").read_bytes()
    with pytest.raises((ValueError, RuntimeError)):
        append_manual_actions(tmp_path, actions=[action], binary_source=source)
    assert (tmp_path / "manual_actions.jsonl").read_bytes() == history


@pytest.mark.c_backend
def test_long_range_cannot_render_across_an_interior_label(tmp_path):
    from amiga_reversing.disasm.manual_actions import ManualActionKind

    source, original, action, _ = _fixture(tmp_path, [0, 4], entry_width=4)
    kind, payload = target_catalog_manual_payload("target.code_label.add", parameters={
        "hunk": 0, "addr": 8, "name": "interior_offset"})
    append_manual_actions(tmp_path, actions=[(ManualActionKind(kind), payload), action], binary_source=source)
    with effective_metadata_file(tmp_path) as path:
        rendered = c_backend.render_project_source_with_c_backend(source, metadata_path=path)
    assert "interior_offset:" in rendered
    assert not any(line.startswith("\tdc.w ") and "pixel_bank" in line for line in rendered.splitlines())
    # A split array may conservatively retain numeric cells throughout.
    assert not any("pixel_bank" in line and line.startswith("\tdc.w ") for line in rendered.splitlines())
    _round_trip(tmp_path, rendered, original)


def test_long_range_cannot_retype_a_declared_pointer_as_a_scalar_offset(tmp_path):
    _struct_fixture(tmp_path, fields=[("LONG", 0, 4), ("LONG", 4, 4)], offset=0)
    path = tmp_path / "target_seeded_metadata.json"
    seeded = json.loads(path.read_text())
    field = seeded["custom_structs"][0]["fields"][0]
    field.update(value_kind="struct_pointer", pointer_struct="RepeatCommand")
    path.write_text(json.dumps(seeded))
    records = [json.loads(line) for line in (tmp_path / "manual_actions.jsonl").read_text().splitlines()]
    ref = records[-1]["data_block_interpreted_ref"]
    ref.update(_params(entry_width=4, width=4, base_locator={"hunk": 0, "offset": 0x9000}, target_offset=0x9000))
    ref["target_locator"] = {"hunk": 0, "offset": 0x9000}
    _write_log(tmp_path, records)
    with pytest.raises(ValueError, match="exact declared LONG leaf"):
        effective_target_metadata(tmp_path, include_decision_journal=False)


@pytest.mark.c_backend
def test_name_of_anonymous_storage_owner_enables_relative_interior_labels(tmp_path):
    from amiga_reversing.disasm.manual_actions import ManualActionKind
    from amiga_reversing.disasm.target_metadata import (
        SeededEntityMetadata,
        TargetMetadata,
        write_target_metadata,
    )

    source, original, action, base = _fixture(tmp_path, [4, 8], entry_width=4)
    # Retain the layouts in MAL but replace the synthetic named target layout
    # with the same kind of anonymous enclosing saved-data owner as FOFT.
    records = [json.loads(line) for line in (tmp_path / "manual_actions.jsonl").read_text().splitlines()]
    records = [r for r in records if r.get("data_block_layout", {}).get("layout_id") != "pixels"
               and r.get("data_block_element", {}).get("layout_id") != "pixels"]
    _write_log(tmp_path, records)
    write_target_metadata(tmp_path, TargetMetadata(target_type="program", entry_register_seeds=(), seeded_entities=(
        SeededEntityMetadata.from_dict({"hunk": 0, "addr": base, "end": len(original), "type": "data",
            "name": None, "unit": "word", "seed_origin": "manual_analysis", "review_status": "seeded",
            "citation": "Synthetic saved anonymous array", "source_locator": "saved:anonymous-array"}),)))
    actions = []
    for at, name in [(base, "sample_storage"), (base+4, "sample_start"), (base+8, "repeat_start")]:
        kind, payload = target_catalog_manual_payload("target.data.name", parameters={"hunk": 0, "addr": at, "name": name})
        actions.append((ManualActionKind(kind), payload))
    actions.append(action)
    append_manual_actions(tmp_path, actions=actions, binary_source=source)
    metadata = effective_target_metadata(tmp_path, include_decision_journal=False)
    owner = next(r for r in metadata.seeded_entities if r.addr == base and r.end == len(original))
    assert owner.name == "sample_storage" and owner.unit == "word"
    assert owner.citation == "Synthetic saved anonymous array"
    with effective_metadata_file(tmp_path) as path:
        rendered = c_backend.render_project_source_with_c_backend(source, metadata_path=path)
    assert "\tdc.l sample_start-sample_storage" in rendered
    assert "\tdc.l repeat_start-sample_storage" in rendered
    _round_trip(tmp_path, rendered, original)

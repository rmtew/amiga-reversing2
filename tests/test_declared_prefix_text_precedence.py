"""Confirmed scalar/text boundaries supersede only unowned legacy byte guesses."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from amiga_reversing.disasm import c_backend
from amiga_reversing.disasm.binary_source import (
    BinarySourceKind,
    RawAddressModel,
    RawBinarySource,
)
from amiga_reversing.disasm.effective_metadata import (
    effective_metadata_file,
    effective_target_metadata,
)
from amiga_reversing.disasm.manual_actions import MANUAL_ACTION_LOG_FILE_NAME
from amiga_reversing.disasm.project_paths import PROJECT_ROOT
from amiga_reversing.disasm.target_metadata import TargetMetadata, write_target_metadata


def fixture(tmp_path: Path, *, legacy_role="string", mode="proved"):
    message = b"Message!\0"
    body = bytes.fromhex("0004006c") + message + b"\0"
    raw = bytes([0x60, len(body)]) + body + bytes.fromhex("4e75") + b"Ordinary\0"
    path = tmp_path / "input.bin"
    path.write_bytes(raw)
    write_target_metadata(tmp_path, TargetMetadata(target_type="program", entry_register_seeds=()))
    metadata_path = tmp_path / "target_metadata.json"
    metadata = json.loads(metadata_path.read_text())
    legacy = {"hunk": 0, "addr": 5, "end": 15 if legacy_role == "string" else 16,
              "type": "data", "subtype": legacy_role, "unit": "byte",
              "encoding": "ascii" if legacy_role == "string" else None,
              "seed_origin": "manual_analysis", "review_status": "seeded",
              "source_id": "imported-analysis", "source_locator": "legacy-guess",
              "citation": "Imported preliminary byte classification"}
    if mode == "named":
        legacy["name"] = "legacyText"
    if mode == "commented":
        legacy["comment"] = "Independent authored interpretation"
    if mode == "authored":
        legacy.update(source_id="manual_action_log", citation="manual_action_log:authored-legacy")
    if mode == "partial_text":
        legacy["end"] = 16
    if mode == "validated":
        legacy["review_status"] = "validated"
    if mode == "other_section":
        legacy["hunk"] = 1
    metadata["seeded_entities"] = [legacy, {
        "hunk": 0, "addr": 18, "end": 27, "type": "data", "subtype": "string", "unit": "byte",
        "encoding": "ascii", "seed_origin": "manual_analysis", "review_status": "seeded",
        "source_id": "imported-analysis", "source_locator": "ordinary-string",
        "citation": "Unchanged ordinary string"}]
    if mode in {"imported_scalar_only", "typed_padding", "ambiguous_field"}:
        metadata["seeded_entities"].append({
            "hunk": 0, "addr": 2 if mode == "ambiguous_field" else 4, "end": 6,
            "type": "data", "unit": "long" if mode == "ambiguous_field" else "word",
            "source_id": "imported-analysis" if mode == "imported_scalar_only" else "manual_action_log",
            "comment": "typed data block gap" if mode == "typed_padding" else None,
            "seed_origin": "manual_analysis", "review_status": "seeded",
            "citation": "manual_action_log:prior-name-or-type"})
    if mode == "imported_text_only":
        metadata["seeded_entities"].append({**legacy, "addr": 6, "citation": "Imported text-boundary guess"})
    if mode.startswith("record_"):
        field = dict(hunk=0, addr=4, end=6, type="data", unit="word",
                     seed_origin="manual_analysis", review_status="seeded",
                     struct_name="Point", field_name="y", field_type="WORD", c_type="WORD",
                     source_id="manual_action_log", citation="manual_action_log:record",
                     owner_action_id="record")
        if mode == "record_imported":
            field.update(source_id="imported-analysis", citation="Imported record")
        if mode == "record_no_owner":
            field.pop("owner_action_id")
        if mode == "record_pointer":
            field.update(field_type="APTR", c_type="APTR")
        if mode == "record_mismatch":
            field["c_type"] = "UWORD"
        if mode == "record_domain":
            field["value_domain"] = "independent-enum"
        if mode == "record_long":
            field.update(addr=2, unit="long", field_type="LONG", c_type="LONG")
        metadata["seeded_entities"].append(field)
    metadata_path.write_text(json.dumps(metadata))
    actions = [("create_manual_data_block_layout", "data_block_layout", {
        "layout_id": "prefix", "hunk": 0, "source_start": 2, "source_end": 6, "default_unit": "word"})]
    if mode != "record_long":
        actions.append(("set_manual_data_block_element", "data_block_element", {
            "layout_id": "prefix", "offset": 0, "width": 2, "kind": "scalar"}))
    if mode not in {"no_scalar", "imported_scalar_only", "typed_padding"} and not mode.startswith("record_"):
        actions.append(("set_manual_data_block_element", "data_block_element", {
            "layout_id": "prefix", "offset": 2, "width": 2, "kind": "scalar"}))
    if mode not in {"no_text", "imported_text_only"}:
        actions.append(("create_manual_seed", "seed", {
            "seed_id": "confirmed-text", "kind": "data", "mode": "required", "hunk": 0,
            "addr": 6, "end": 15, "data_role": "string", "unit": "byte", "encoding": "ascii"}))
    records = [{"record": "manual_action_log_header", "version": 1, "target_identity": {}}]
    records.extend({"record": "manual_action", "action_id": f"a{i}", "sequence": i,
                    "created_at": "2026-11-18T00:00:00+00:00", "kind": kind, key: payload}
                   for i, (kind, key, payload) in enumerate(actions, 1))
    journal = tmp_path / MANUAL_ACTION_LOG_FILE_NAME
    journal.write_text("\n".join(json.dumps(row) for row in records)+"\n")
    source = RawBinarySource(kind=BinarySourceKind.RAW_BINARY, path=path,
        address_model=RawAddressModel.RUNTIME_ABSOLUTE, load_address=0x800, entrypoint=0x800,
        code_start_offset=0, display_path="synthetic", analysis_cache_path=tmp_path / "analysis")
    return source, raw, legacy


@pytest.mark.parametrize("legacy_role", ["string", "opaque_data"])
def test_declared_boundaries_keep_original_evidence_and_opaque_tail(tmp_path, legacy_role):
    source, raw, legacy = fixture(tmp_path, legacy_role=legacy_role)
    metadata_bytes = (tmp_path / "target_metadata.json").read_bytes()
    journal_bytes = (tmp_path / MANUAL_ACTION_LOG_FILE_NAME).read_bytes()
    metadata = effective_target_metadata(tmp_path)
    assert any(e.addr == 5 and e.end == legacy["end"] for e in metadata.seeded_entities)
    with effective_metadata_file(tmp_path) as path:
        native = c_backend.effective_policy_project_source_with_c_backend(source, metadata_path=path)
    items = native["analysis_policy"]["structured_data_items"]
    assert not any(e["offset"] == 5 and e["size"] == legacy["end"] - 5 for e in items)
    if legacy_role == "opaque_data":
        assert any(e["offset"] == 15 and e["size"] == 1 for e in items)
    ordinary, = [e for e in metadata.seeded_entities if e.source_locator == "ordinary-string"]
    assert (ordinary.addr, ordinary.end, ordinary.encoding) == (18, 27, "ascii")
    assert effective_target_metadata(tmp_path) == metadata
    assert (tmp_path / "target_metadata.json").read_bytes() == metadata_bytes
    assert (tmp_path / MANUAL_ACTION_LOG_FILE_NAME).read_bytes() == journal_bytes
    assert (tmp_path / "input.bin").read_bytes() == raw


@pytest.mark.parametrize("mode", ["no_scalar", "no_text", "named", "commented", "authored", "partial_text",
                                  "validated", "other_section", "imported_scalar_only", "imported_text_only",
                                  "typed_padding", "ambiguous_field"])
def test_missing_corroboration_or_independent_annotation_preserves_legacy(tmp_path, mode):
    source, _, legacy = fixture(tmp_path, mode=mode)
    metadata = effective_target_metadata(tmp_path)
    assert any(e.addr == legacy["addr"] and e.end == legacy["end"]
               and e.source_locator == "legacy-guess" for e in metadata.seeded_entities)
    if mode == "other_section":
        return
    with effective_metadata_file(tmp_path) as path:
        native = c_backend.effective_policy_project_source_with_c_backend(source, metadata_path=path)
    assert any(e["offset"] == legacy["addr"] and e["size"] == legacy["end"] - legacy["addr"]
               for e in native["analysis_policy"]["structured_data_items"])


@pytest.mark.c_backend
@pytest.mark.parametrize("legacy_role", ["string", "opaque_data"])
def test_native_coordinate_word_and_text_render_exactly(tmp_path, legacy_role):
    source, raw, _ = fixture(tmp_path, legacy_role=legacy_role)
    with effective_metadata_file(tmp_path) as metadata:
        text = c_backend.render_project_source_with_c_backend(
            source, metadata_path=metadata, project_root=PROJECT_ROOT)
    assert '\tdc.w $0004\n\tdc.w $006C\n\tdc.b "Message!",$00' in text
    assert '"Ordinary",$00' in text
    assert '"lMessage!"' not in text
    rebuilt, _ = c_backend.assemble_platform_source_text_with_c_backend(
        "amiga-raw", text, project_root=PROJECT_ROOT)
    assert rebuilt == raw


@pytest.mark.c_backend
@pytest.mark.parametrize("legacy_role", ["string", "opaque_data"])
@pytest.mark.parametrize("mode,directive", [("record_proved", "dc.w $006C"),
                                           ("record_long", "dc.l $0004006C")])
def test_declared_record_field_and_text_preserve_exact_numeric_prefix(tmp_path, legacy_role, mode, directive):
    source, raw, legacy = fixture(tmp_path, mode=mode, legacy_role=legacy_role)
    original = (tmp_path / "target_metadata.json").read_bytes()
    with effective_metadata_file(tmp_path) as metadata:
        text = c_backend.render_project_source_with_c_backend(
            source, metadata_path=metadata, project_root=PROJECT_ROOT)
    assert '\t' + directive in text and '"lMessage!"' not in text
    assert '"Message!",$00' in text and '"Ordinary",$00' in text
    rebuilt, _ = c_backend.assemble_platform_source_text_with_c_backend(
        "amiga-raw", text, project_root=PROJECT_ROOT)
    assert rebuilt == raw
    assert (tmp_path / "target_metadata.json").read_bytes() == original
    assert any(e.addr == 5 and e.end == legacy["end"] for e in effective_target_metadata(tmp_path).seeded_entities)


@pytest.mark.parametrize("mode", ["record_imported", "record_no_owner", "record_pointer",
                                  "record_mismatch", "record_domain"])
def test_record_prefix_requires_numeric_field_and_checked_provenance(tmp_path, mode):
    source, _, _ = fixture(tmp_path, mode=mode)
    with effective_metadata_file(tmp_path) as metadata:
        native = c_backend.effective_policy_project_source_with_c_backend(source, metadata_path=metadata)
    assert any(e["offset"] == 5 and e["size"] == 10
               for e in native["analysis_policy"]["structured_data_items"])


def test_undo_and_redo_restore_precedence_without_erasing_legacy_evidence(tmp_path):
    source, _, _ = fixture(tmp_path)
    initial = effective_target_metadata(tmp_path)
    def policy():
        with effective_metadata_file(tmp_path) as metadata:
            return c_backend.effective_policy_project_source_with_c_backend(source, metadata_path=metadata)["analysis_policy"]["structured_data_items"]
    initial_policy = policy()
    path = tmp_path / MANUAL_ACTION_LOG_FILE_NAME
    prefix = path.read_bytes()
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    rows.append({"record": "manual_action", "action_id": "undo-text", "sequence": 5,
                 "created_at": "2026-11-18T00:00:00+00:00", "kind": "undo_action", "undoes_action_id": "a4"})
    path.write_text("\n".join(json.dumps(row) for row in rows)+"\n")
    assert any(e.source_locator == "legacy-guess" for e in effective_target_metadata(tmp_path).seeded_entities)
    assert any(e["offset"] == 5 and e["size"] == 10 for e in policy())
    rows.append({"record": "manual_action", "action_id": "redo-text", "sequence": 6,
                 "created_at": "2026-11-18T00:00:00+00:00", "kind": "redo_action", "redoes_action_id": "a4"})
    path.write_text("\n".join(json.dumps(row) for row in rows)+"\n")
    assert effective_target_metadata(tmp_path) == initial
    assert policy() == initial_policy
    assert path.read_bytes().startswith(prefix)

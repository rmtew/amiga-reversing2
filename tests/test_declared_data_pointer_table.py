"""One row/column declaration feeds existing native absolute data-table facts."""
from __future__ import annotations

import json

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
from amiga_reversing.disasm.target_metadata import (
    TargetMetadata,
    validate_data_pointer_table,
    write_target_metadata,
)


def declaration(count=2, stride=12, offsets=None):
    return {"row_count": count, "row_stride": stride, "pointer_offsets": [0, 8] if offsets is None else offsets,
                "encoding": "abs32", "target_kind": "data", "address_domain": "mapped_source"}


def fixture(tmp_path, *, second=0x82A):
    # Two rows: pointer, equal-looking scalar, pointer. Followed by an adjacent
    # equal-looking LONG, an RTS used by the branch, and data (also RTS-shaped).
    values = [0x826, 0x826, second, 0, 0x826, 0xDEADBEEF, 0x826]
    raw = bytes.fromhex("6000001e") + b"".join(v.to_bytes(4, "big") for v in values)
    raw += bytes.fromhex("4e75") + b"DATA" + bytes.fromhex("4e75") + b"NEXT\0\0"
    path = tmp_path / "source.bin"
    path.write_bytes(raw)
    write_target_metadata(tmp_path, TargetMetadata(target_type="program", entry_register_seeds=()))
    metadata = json.loads((tmp_path / "target_metadata.json").read_text())
    metadata["seeded_entities"] = [{"hunk": 0, "addr": 38, "end": 42, "type": "data", "unit": "long", "name": "keptData",
        "seed_origin": "manual_analysis", "review_status": "seeded", "citation": "Existing independent data symbol"}]
    metadata["seeded_entities"].append({"hunk": 0, "addr": 28, "end": 32, "type": "data", "unit": "long",
        "name": "adjacentScalar", "seed_origin": "manual_analysis", "review_status": "seeded", "citation": "Explicit scalar"})
    (tmp_path / "target_metadata.json").write_text(json.dumps(metadata))
    actions = [("create_manual_data_block_layout", {"layout_id": "rows", "hunk": 0,
        "source_start": 4, "source_end": 28, "name": "dataRows", "default_unit": "long"})]
    # Preserve scalar ownership and a named slot while upgrading only declared columns.
    records = [{"record": "manual_action_log_header", "version": 1, "target_identity": {}}]
    for i, (kind, payload) in enumerate(actions, 1):
        records.append({"record": "manual_action", "action_id": f"a{i}", "sequence": i,
            "created_at": "2026-11-18T00:00:00+00:00", "kind": kind, "data_block_layout": payload})
    for offset in range(0, 24, 4):
        i = len(records)
        records.append({"record": "manual_action", "action_id": f"a{i}", "sequence": i,
            "created_at": "2026-11-18T00:00:00+00:00", "kind": "set_manual_data_block_element",
            "data_block_element": {"layout_id": "rows", "offset": offset, "width": 4, "kind": "scalar",
                                    "name": "keptPointerSlot" if offset == 0 else None}})
    i = len(records)
    records.append({"record": "manual_action", "action_id": f"a{i}", "sequence": i,
        "created_at": "2026-11-18T00:00:00+00:00", "kind": "edit_manual_data_block_layout",
        "data_block_layout": {"layout_id": "rows", "pointer_table": declaration()}})
    (tmp_path / MANUAL_ACTION_LOG_FILE_NAME).write_text("\n".join(json.dumps(r) for r in records)+"\n")
    source = RawBinarySource(kind=BinarySourceKind.RAW_BINARY, path=path,
        address_model=RawAddressModel.RUNTIME_ABSOLUTE, load_address=0x800, entrypoint=0x800,
        code_start_offset=0, display_path="synthetic", analysis_cache_path=tmp_path / "analysis")
    return source, raw


def test_projection_retains_shape_provenance_and_no_manual_runtime_refs(tmp_path):
    fixture(tmp_path)
    metadata = effective_target_metadata(tmp_path)
    table = metadata.data_block_layouts[0].pointer_table
    assert table == {**declaration(), "citation": "manual_action_log:a8"}
    assert not metadata.manual_runtime_address_refs
    assert not metadata.manual_representations and not metadata.target_equates
    pointers = [e for e in metadata.seeded_entities if e.subtype == "pointer_table"]
    assert {(e.addr, e.end) for e in pointers} == {(4, 8), (12, 16), (16, 20), (24, 28)}
    assert all(e.pointer_address_domain == "mapped_source" for e in pointers)
    assert any(e.name == "keptPointerSlot" for e in metadata.seeded_entities)
    assert any(e.name == "keptData" for e in metadata.seeded_entities)


@pytest.mark.parametrize("change", [{"row_count": 0}, {"row_count": True}, {"row_stride": 8},
    {"pointer_offsets": [0, 0]}, {"pointer_offsets": [0, 2]}, {"pointer_offsets": [10]},
    {"pointer_offsets": [False]}, {"pointer_offsets": []}, {"target_kind": "code"},
    {"address_domain": "runtime_only"}, {"encoding": "abs16"}, {"extra": 1}])
def test_invalid_or_different_semantics_rejected(change):
    with pytest.raises(ValueError, match="data pointer table"):
        validate_data_pointer_table({**declaration(), **change}, 24)


@pytest.mark.c_backend
@pytest.mark.parametrize("second", [0x82A, 0, 0xDEADBEEF, 0x802])
def test_native_both_columns_map_without_scalar_conversion_or_code_admission(tmp_path, second):
    source, raw = fixture(tmp_path, second=second)
    with effective_metadata_file(tmp_path) as metadata:
        _, _, artifact = c_backend.build_listing_artifact_profile_from_binary_source(
            source, metadata_path=metadata, project_root=PROJECT_ROOT)
        try:
            code = artifact.query_payload("instructions", section_index=0, source_offset=38, end_offset=40)
            assert not code["items"]  # A data target beginning with RTS is still data.
            if second == 0x82A:
                incoming = artifact.query_payload("references", section_index=0, source_offset=42,
                                                  direction="incoming", limit=100)
                assert any(ref["source_offset"] == 12 for ref in incoming["items"])
        finally:
            artifact.close()
        rendered = c_backend.render_project_source_with_c_backend(
            source, metadata_path=metadata, project_root=PROJECT_ROOT)
    assert "keptData:" in rendered and "keptPointerSlot:" in rendered
    longs = [line.strip().split(";", 1)[0].strip() for line in rendered.splitlines()
             if line.strip().startswith("dc.l ")]
    assert longs[0] == "dc.l keptData"
    assert longs[1] == "dc.l $00000826"  # In-row scalar, although it maps.
    if second == 0x82A:
        assert "$" not in longs[2]  # Second column creates a data label.
    else:
        assert longs[2] == f"dc.l ${second:08X}"
    assert longs[3] == "dc.l $00000000"
    assert longs[4] == "dc.l $00000826"
    assert longs[5] == "dc.l $DEADBEEF"
    assert longs[6] == "dc.l $00000826"  # Adjacent scalar outside declared extent.
    rebuilt, _ = c_backend.assemble_platform_source_text_with_c_backend(
        "amiga-raw", rendered, project_root=PROJECT_ROOT)
    assert rebuilt == raw


def test_layout_description_does_not_reassign_declaration_provenance(tmp_path):
    fixture(tmp_path)
    path = tmp_path / MANUAL_ACTION_LOG_FILE_NAME
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    index = len(rows)
    rows.append({"record": "manual_action", "action_id": f"a{index}", "sequence": index,
        "created_at": "2026-11-18T00:00:00+00:00", "kind": "edit_manual_data_block_layout",
        "data_block_layout": {"layout_id": "rows", "role": "paired record lookups"}})
    path.write_text("\n".join(json.dumps(row) for row in rows)+"\n")
    assert effective_target_metadata(tmp_path).data_block_layouts[0].pointer_table["citation"] == "manual_action_log:a8"

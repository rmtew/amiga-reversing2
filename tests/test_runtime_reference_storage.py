"""Manual pointer families are not bounded by a fixed native policy array."""
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
from amiga_reversing.disasm.effective_metadata import effective_metadata_file
from amiga_reversing.disasm.manual_action_catalog import _data_block_element_ref_payload
from amiga_reversing.disasm.manual_actions import MANUAL_ACTION_LOG_FILE_NAME
from amiga_reversing.disasm.project_paths import PROJECT_ROOT
from amiga_reversing.disasm.target_metadata import TargetMetadata, write_target_metadata


@pytest.mark.c_backend
@pytest.mark.parametrize(("count", "invalid_tail"), [(128, None), (129, None), (257, None), (257, "target"), (257, "span")])
def test_large_pointer_family_loads_renders_and_roundtrips(tmp_path: Path, count: int, invalid_tail: str | None) -> None:
    from tests.test_c_backend import _requires_c_backend_dlls
    _requires_c_backend_dlls()
    end = 4 + count * 4
    encoded = 0x40000 + end
    original = bytes.fromhex("6000") + (end - 2).to_bytes(2, "big")
    original += encoded.to_bytes(4, "big") * count + bytes.fromhex("4e75")
    path = tmp_path / "pointers.bin"
    path.write_bytes(original)
    write_target_metadata(tmp_path, TargetMetadata(target_type="program", entry_register_seeds=()))
    actions = [("create_manual_data_block_layout", "data_block_layout", {
        "layout_id": "pointers", "hunk": 0, "source_start": 4, "source_end": end,
        "role": "values", "default_unit": "long"}),
        ("set_manual_data_block_element", "data_block_element", {
            "layout_id": "pointers", "offset": 0, "width": count * 4,
            "kind": "array", "array_count": count, "array_stride": 4})]
    for i in range(count):
        ref = _data_block_element_ref_payload([], {
            "layout_id": "pointers", "offset": i * 4, "width": 4,
            "reference_kind": "absolute", "target_hunk": 0, "target_offset": end,
            "source_value": encoded, "runtime_address": encoded})
        actions.append(("interpret_manual_data_block_element_ref", "data_block_interpreted_ref", ref))
    records = [{"record": "manual_action_log_header", "version": 1, "target_identity": {}}]
    records.extend({"record": "manual_action", "action_id": f"a{i}", "sequence": i,
                    "created_at": "2026-11-18T00:00:00+00:00", "kind": kind, key: value}
                   for i, (kind, key, value) in enumerate(actions, 1))
    (tmp_path / MANUAL_ACTION_LOG_FILE_NAME).write_text(
        "\n".join(json.dumps(record) for record in records) + "\n")
    source = RawBinarySource(kind=BinarySourceKind.RAW_BINARY, path=path,
        address_model=RawAddressModel.RUNTIME_ABSOLUTE, load_address=0x40000,
        entrypoint=0x40000, code_start_offset=0, display_path=str(path),
        analysis_cache_path=tmp_path / "binary.analysis")
    with effective_metadata_file(tmp_path) as metadata_path:
        if invalid_tail:
            metadata = json.loads(metadata_path.read_text())
            last = metadata["manual_runtime_address_refs"][-1]
            if invalid_tail == "target":
                last["target_offset"] = len(original)
            else:
                last["addr"] = len(original) - 1
            metadata_path.write_text(json.dumps(metadata))
            with pytest.raises(RuntimeError, match="out of range"):
                c_backend.build_listing_artifact_profile_from_binary_source(
                    source, metadata_path=metadata_path, project_root=PROJECT_ROOT)
            return
        _, _, artifact = c_backend.build_listing_artifact_profile_from_binary_source(
            source, metadata_path=metadata_path, project_root=PROJECT_ROOT)
        try:
            for i in range(count):
                row = artifact.row_for_source_offset(section_index=0, offset=4 + i * 4)
                refs = [r for r in row["runtime_address_refs"]
                        if r["owner_kind"] == "data_block_interpreted_ref"
                        and r["owner_element_offset"] == i * 4]
                assert len(refs) == 1
                assert refs[0]["target_offset"] == end
            incoming = []
            for offset in range(0, count + 100, 100):
                page = artifact.query_payload("references", section_index=0, source_offset=end,
                    direction="incoming", offset=offset, limit=100)
                incoming.extend(page["items"])
                if not page["has_more"]:
                    break
            assert {4 + i * 4 for i in range(count)} <= {r["source_offset"] for r in incoming}
        finally:
            artifact.close()
        rendered = c_backend.render_project_source_with_c_backend(
            source, metadata_path=metadata_path, project_root=PROJECT_ROOT)
    lines = [line.strip() for line in rendered.splitlines() if line.strip().startswith("dc.l ")]
    assert len(lines) == count
    assert all("$" not in line.split(";", 1)[0] for line in lines)
    rebuilt, _ = c_backend.assemble_platform_source_text_with_c_backend(
        "amiga-raw", rendered, project_root=PROJECT_ROOT)
    assert rebuilt == original

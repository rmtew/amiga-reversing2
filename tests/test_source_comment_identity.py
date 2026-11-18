"""Comment sublines never acquire the byte identity of their grouped row."""

import json
from contextlib import contextmanager

import pytest

from amiga_reversing.disasm import c_backend, restoration
from amiga_reversing.disasm.effective_metadata import effective_metadata_file
from amiga_reversing.disasm.project_paths import PROJECT_ROOT
from amiga_reversing.disasm.target_metadata import TargetMetadata, write_target_metadata


@contextmanager
def commented_artifact(tmp_path, *, at=6, unit="word", multiline=False, zero_fill=True):
    raw, _ = c_backend.assemble_platform_source_text_with_c_backend(
        "amiga-raw",
        "section code,code\nlea.l payload(pc),a0\nrts\npayload:\ndc.w "
        + ("0,0,0,0" if zero_fill else "1,2,3,4")
        + "\n",
    )
    path = tmp_path / "source.bin"
    path.write_bytes(raw)
    metadata = {
        "target_type": "program",
        "entry_register_seeds": [],
        "entry_comments": [
            {
                "hunk": 0,
                "addr": at,
                "comment": "First annotation\nSecond annotation"
                if multiline
                else "First annotation",
                "seed_origin": "manual_analysis",
                "review_status": "seeded",
                "citation": "fixture-comment",
            }
        ],
        "seeded_entities": [
            {
                "hunk": 0,
                "addr": 6,
                "end": 14,
                "name": "payload",
                "type": "data",
                "unit": unit,
                "seed_origin": "manual_analysis",
                "review_status": "seeded",
                "citation": "fixture-data",
            }
        ],
    }
    metadata_path = tmp_path / "target_metadata.json"
    metadata["data_block_layouts"] = [
        {
            "version": 1,
            "layout_id": "fixture-words",
            "hunk": 0,
            "source_start": 6,
            "source_end": 14,
            "name": "payload",
            "default_unit": unit,
            "elements": [],
            "seed_origin": "manual_analysis",
            "review_status": "seeded",
            "citation": "manual_action_log:fixture-words",
        }
    ]
    write_target_metadata(
        tmp_path, TargetMetadata(target_type="program", entry_register_seeds=())
    )
    base = json.loads(metadata_path.read_text())
    base.update(metadata)
    metadata_path.write_text(json.dumps(base))
    with effective_metadata_file(tmp_path) as projected_path:
        value = c_backend.CListingArtifact.create(
            c_backend._CBackendSourceFile(
                path, "amiga-raw", 0, runtime_load_address=0x800
            ),
            runtime_observation_views=(
                {"source_start": 0, "source_end": len(raw), "base_addr": 0x800},
            ),
            metadata_text=str(projected_path),
            include_dir="",
            project_root=PROJECT_ROOT,
        )
        try:
            yield value, raw
        finally:
            value.close()


@pytest.mark.parametrize("zero_fill", [False, True])
@pytest.mark.parametrize("unit", ["word", "long"])
@pytest.mark.parametrize("multiline", [False, True])
def test_data_identity_excludes_authored_comment_sublines(
    tmp_path, unit, multiline, zero_fill
):
    with commented_artifact(
        tmp_path, unit=unit, multiline=multiline, zero_fill=zero_fill
    ) as (
        artifact,
        raw,
    ):
        row = artifact.row_for_source_identity(section_index=0, offset=6, kind="data")
        assert (
            row["kind"] == "data" and row["start_offset"] == 6 and row["end_offset"] > 6
        )
        assert row["text"].lstrip().startswith(("dc.", "dcb."))
        assert (
            artifact.row_for_source_identity(section_index=0, offset=7, kind="data")
            is None
        )
        assert (
            artifact.row_for_source_identity(section_index=1, offset=6, kind="data")
            is None
        )
        assert (
            artifact.row_for_source_identity(
                section_index=0, offset=6, kind="instruction"
            )
            is None
        )
        # A request inside a grouped data statement must not pick its comment.
        interior = artifact.row_for_source_offset(section_index=0, offset=8)
        assert (
            interior["kind"] == "data"
            and interior["start_offset"] <= 8 < interior["end_offset"]
        )
        runtime_row = artifact.row_for_runtime_address(address=0x808)
        assert runtime_row["kind"] == "data"
        assert runtime_row["start_offset"] <= 8 < runtime_row["end_offset"]
        window, _ = artifact.window_payload(
            start=max(0, row["row_index"] - 3), count=10
        )
        comments = [r for r in window["rows"] if "annotation" in r.get("text", "")]
        assert comments and all(
            r["kind"] == "comment" and not r.get("bytes") for r in comments
        )
        text, _ = artifact.inline_source_text_with_profile()
        rebuilt, _ = c_backend.assemble_platform_source_text_with_c_backend(
            "amiga-raw", text
        )
        assert rebuilt == raw


def test_instruction_comment_does_not_create_another_byte_identity(tmp_path):
    with commented_artifact(tmp_path, at=0, multiline=True) as (artifact, _):
        row = artifact.row_for_source_identity(
            section_index=0, offset=0, kind="instruction"
        )
        assert row["kind"] == "instruction" and row["opcode_or_directive"] == "lea.l"
        assert (
            artifact.row_for_source_identity(section_index=0, offset=0, kind="data")
            is None
        )
        body = {
            "command_id": "comment.edit",
            "context": {"locator": {"section_index": 0, "start_offset": 6}},
            "evidence": {
                "reason": "Current byte-bearing data row",
                "evidence_refs": ["s0:00000006:data"],
            },
        }
        assert restoration._interpretation_body(
            "fixture", body, {"subject_revision": "current"}, artifact
        )
        body["evidence"]["evidence_refs"] = ["s0:00000007:data"]
        with pytest.raises(ValueError, match="not a current canonical row"):
            restoration._interpretation_body(
                "fixture", body, {"subject_revision": "current"}, artifact
            )

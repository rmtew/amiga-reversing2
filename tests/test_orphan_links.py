import json
from copy import deepcopy

import pytest

from amiga_reversing.disasm.orphan_links import orphan_link_hypotheses


def snapshot():
    return {
        "sections": [
            {
                "section_index": 0,
                "section_size": 32,
                "accepted_code_runs": [
                    {"start_offset": 0, "end_offset": 4},
                    {"start_offset": 8, "end_offset": 14},
                    {"start_offset": 20, "end_offset": 22},
                ],
                "blocks": [
                    {"start_offset": 0, "end_offset": 4},
                    {"start_offset": 8, "end_offset": 12},
                    {"start_offset": 12, "end_offset": 14},
                    {"start_offset": 20, "end_offset": 22},
                ],
                "edges": [
                    {
                        "kind": 3,
                        "source_block_index": 0,
                        "target_block_index": 1,
                        "source_offset": 0,
                    },
                    {
                        "kind": 1,
                        "source_block_index": 1,
                        "target_block_index": 2,
                        "source_offset": 8,
                    },
                    {
                        "kind": 5,
                        "source_block_index": 2,
                        "target_block_index": 0xFFFFFFFF,
                        "source_offset": 12,
                    },
                    {
                        "kind": 5,
                        "source_block_index": 3,
                        "target_block_index": 0xFFFFFFFF,
                        "source_offset": 20,
                    },
                ],
                "code_start_refs": [],
            }
        ]
    }


def test_hypotheses_preserve_overlap_and_do_not_promote_code_or_operand_words():
    analysis = snapshot()
    original = deepcopy(analysis)
    manifest = {
        "case_source_offsets": [10, 12, 20, 24],
        "entry_groups": {"outer": [0], "callee": [8], "bad": [2, 24]},
    }
    result = orphan_link_hypotheses(analysis, manifest)
    assert result["hypothesis_only"] is True
    assert result["case_status_counts"] == {
        "linked_nonterminal_code_position": 1,
        "linked_terminal_instruction": 1,
        "accepted_terminal_without_group_link": 1,
        "unaccepted_position": 1,
    }
    assert result["cases"][1]["linked_families"] == ["callee", "outer"]
    assert result["groups"]["bad"]["roots_not_at_accepted_block_start"] == [2, 24]
    assert result["groups"]["outer"]["reachable_native_terminal_positions"] == [12]
    assert result["groups"]["outer"]["native_block_path_witnesses"][1] == {
        "case_source_offset": 12,
        "assumed_entry_source_offset": 0,
        "block_source_offsets": [0, 8, 12],
    }
    assert analysis == original


def test_native_candidate_edges_supplement_cfg_but_vector_installations_do_not():
    analysis = snapshot()
    section = analysis["sections"][0]
    section["edges"] = [e for e in section["edges"] if e["source_block_index"] != 0]
    section["code_start_refs"] = [
        {
            "source_section_index": 0,
            "source_offset": 0,
            "offset": 8,
            "evidence_kind": "initial_pointer_control_target",
        },
        {
            "source_section_index": 0,
            "source_offset": 0,
            "offset": 20,
            "evidence_kind": "vector_store_control_target",
        },
    ]
    result = orphan_link_hypotheses(
        analysis, {"case_source_offsets": [12, 20], "entry_groups": {"root": [0]}}
    )
    assert result["groups"]["root"]["reachable_native_terminal_positions"] == [12]
    section["code_start_refs"][0]["source_section_index"] = 1
    assert not orphan_link_hypotheses(
        analysis, {"case_source_offsets": [12], "entry_groups": {"root": [0]}}
    )["groups"]["root"]["reachable_case_positions"]
    section["code_start_refs"][0].update(source_section_index=0, offset=10)
    assert not orphan_link_hypotheses(
        analysis, {"case_source_offsets": [12], "entry_groups": {"root": [0]}}
    )["groups"]["root"]["reachable_case_positions"]


@pytest.mark.parametrize("value", [-2, 1, 32, True, "12"])
def test_coordinates_require_valid_source_frame_and_alignment(value):
    with pytest.raises(ValueError, match="even in-range source offsets"):
        orphan_link_hypotheses(
            snapshot(), {"case_source_offsets": [value], "entry_groups": {}}
        )


def test_cli_receipt_does_not_change_snapshot_or_manifest(tmp_path, monkeypatch):
    from amiga_reversing.tools import orphan_link_report

    analysis = tmp_path / "analysis.json"
    manifest = tmp_path / "manifest.json"
    output = tmp_path / "report.json"
    analysis.write_text(json.dumps(snapshot()))
    manifest.write_text(
        json.dumps({"case_source_offsets": [12], "entry_groups": {"root": [0]}})
    )
    before = (analysis.read_bytes(), manifest.read_bytes())
    monkeypatch.setattr(
        "sys.argv",
        [
            "orphan_link_report",
            "--analysis-json",
            str(analysis),
            "--manifest",
            str(manifest),
            "--output",
            str(output),
        ],
    )
    orphan_link_report.main()
    report = json.loads(output.read_text())
    assert report["case_status_counts"] == {"linked_terminal_instruction": 1}
    assert len(report["provenance"]["native_snapshot_sha256"]) == 64
    assert (analysis.read_bytes(), manifest.read_bytes()) == before
    monkeypatch.setattr(
        "sys.argv",
        [
            "orphan_link_report",
            "--analysis-json",
            str(analysis),
            "--manifest",
            str(manifest),
            "--output",
            str(manifest),
        ],
    )
    with pytest.raises(SystemExit):
        orphan_link_report.main()
    assert (analysis.read_bytes(), manifest.read_bytes()) == before

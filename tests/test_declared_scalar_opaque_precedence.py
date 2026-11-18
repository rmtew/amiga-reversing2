"""Authored packed scalars shadow only the overlapping weak opaque footprint."""

from __future__ import annotations

import json
import re

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


def fixture(tmp_path, *, opaque=(4, 20), arrays=((8, 16),), protection=None, stride=2):
    raw = bytes.fromhex("6016") + bytes(range(22)) + bytes.fromhex("4e75")
    path = tmp_path / "input.bin"
    path.write_bytes(raw)
    write_target_metadata(
        tmp_path, TargetMetadata(target_type="program", entry_register_seeds=())
    )
    meta_path = tmp_path / "target_metadata.json"
    meta = json.loads(meta_path.read_text())
    legacy = {
        "hunk": 0,
        "addr": opaque[0],
        "end": opaque[1],
        "type": "data",
        "subtype": "opaque_data",
        "unit": "byte",
        "seed_origin": "manual_analysis",
        "review_status": "seeded",
        "source_id": "fixture-import",
        "citation": "Inherited preliminary opaque classification",
    }
    if protection == "comment":
        legacy["comment"] = "Independent interpretation"
    if protection == "named":
        legacy["name"] = "ownedBytes"
    if protection == "manual":
        legacy.update(source_id="manual_action_log", citation="manual_action_log:owned")
    if protection == "validated":
        legacy["review_status"] = "validated"
    if protection == "owner":
        legacy["owner_action_id"] = "prior-owner"
    if protection == "parents":
        legacy["parent_evidence_ids"] = ["prior-evidence"]
    if protection == "evidence":
        legacy["source_evidence_id"] = "confirmed-evidence"
    if protection == "string":
        legacy.update(subtype="string", encoding="ascii")
    if protection == "typed":
        legacy.update(subtype=None, unit="long")
    meta["seeded_entities"] = [legacy]
    for at, name in [
        (4, "opaqueStart"),
        (8, "arrayStart"),
        (10, "arrayInterior"),
        (16, "arrayEnd"),
        (18, "opaqueInterior"),
        (20, "opaqueEnd"),
    ]:
        meta["seeded_entities"].append(
            {
                "hunk": 0,
                "addr": at,
                "name": name,
                "seed_origin": "manual_analysis",
                "review_status": "seeded",
                "citation": "Existing label",
            }
        )
    # A separate comment is independent of the opaque item's type footprint.
    meta["entry_comments"] = [
        {
            "hunk": 0,
            "addr": 10,
            "comment": "Keep this interior annotation",
            "seed_origin": "manual_analysis",
            "review_status": "seeded",
            "citation": "Existing comment",
        }
    ]
    for at, comment in [(6, "Keep prefix annotation"), (18, "Keep suffix annotation")]:
        meta["entry_comments"].append(
            {**meta["entry_comments"][0], "addr": at, "comment": comment}
        )
    if protection == "contradictory":
        meta["seeded_entities"].append(
            {
                "hunk": 0,
                "addr": 12,
                "end": 16,
                "type": "data",
                "unit": "long",
                "name": "strongLong",
                "seed_origin": "manual_analysis",
                "review_status": "seeded",
                "source_id": "manual_action_log",
                "citation": "manual_action_log:typed",
            }
        )
    meta_path.write_text(json.dumps(meta))
    rows = [{"record": "manual_action_log_header", "version": 1, "target_identity": {}}]
    for i, (lo, hi) in enumerate(arrays):
        for kind, key, value in [
            (
                "create_manual_data_block_layout",
                "data_block_layout",
                {
                    "layout_id": f"words{i}",
                    "hunk": 0,
                    "source_start": lo,
                    "source_end": hi,
                    "default_unit": "word" if stride == 2 else "long",
                },
            ),
            (
                "set_manual_data_block_element",
                "data_block_element",
                {
                    "layout_id": f"words{i}",
                    "offset": 0,
                    "kind": "array",
                    "width": hi - lo,
                    "array_count": (hi - lo) // stride,
                    "array_stride": stride,
                },
            ),
        ]:
            seq = len(rows)
            rows.append(
                dict(
                    record="manual_action",
                    action_id=f"a{seq}",
                    sequence=seq,
                    created_at="2026-11-18T00:00:00+00:00",
                    kind=kind,
                    **{key: value},
                )
            )
    journal = tmp_path / MANUAL_ACTION_LOG_FILE_NAME
    journal.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    source = RawBinarySource(
        kind=BinarySourceKind.RAW_BINARY,
        path=path,
        address_model=RawAddressModel.RUNTIME_ABSOLUTE,
        load_address=0x800,
        entrypoint=0x800,
        code_start_offset=0,
        display_path="synthetic",
        analysis_cache_path=tmp_path / "analysis",
    )
    return source, raw, legacy


def policy(source, tmp_path):
    with effective_metadata_file(tmp_path) as path:
        return c_backend.effective_policy_project_source_with_c_backend(
            source, metadata_path=path
        )["analysis_policy"]["structured_data_items"]


@pytest.mark.parametrize(
    ("opaque", "arrays", "expected"),
    [
        ((4, 20), ((8, 16),), [(4, 4), (16, 4)]),
        ((12, 20), ((8, 16),), [(16, 4)]),
        ((4, 12), ((8, 16),), [(4, 4)]),
        ((10, 14), ((8, 16),), []),
        ((4, 20), ((6, 10), (14, 18)), [(4, 2), (10, 4), (18, 2)]),
        ((4, 20), ((8, 12), (12, 16)), [(4, 4), (16, 4)]),
        ((4, 20), ((20, 22),), [(4, 16)]),
    ],
)
def test_only_authored_extent_is_removed_from_native_opaque_projection(
    tmp_path, opaque, arrays, expected
):
    source, raw, legacy = fixture(tmp_path, opaque=opaque, arrays=arrays)
    paths = [tmp_path / "target_metadata.json", tmp_path / MANUAL_ACTION_LOG_FILE_NAME]
    before = [p.read_bytes() for p in paths]
    items = policy(source, tmp_path)
    # Opaque items carry the normal role preview; WORD array items do not.
    actual = [
        (i["offset"], i["size"])
        for i in items
        if i.get("semantic_role") == "opaque_data" and i["size"]
    ]
    assert sorted(actual) == expected
    assert any(
        e.addr == legacy["addr"]
        and e.end == legacy["end"]
        and e.source_id == "fixture-import"
        for e in effective_target_metadata(tmp_path).seeded_entities
    )
    assert [p.read_bytes() for p in paths] == before
    assert source.path.read_bytes() == raw
    with effective_metadata_file(tmp_path) as path:
        text = c_backend.render_project_source_with_c_backend(
            source, metadata_path=path, project_root=PROJECT_ROOT
        )
    rebuilt, _ = c_backend.assemble_platform_source_text_with_c_backend(
        "amiga-raw", text, project_root=PROJECT_ROOT
    )
    assert rebuilt == raw


@pytest.mark.parametrize(
    "protection",
    [
        "comment",
        "named",
        "manual",
        "validated",
        "evidence",
        "owner",
        "parents",
        "string",
        "typed",
    ],
)
def test_independent_or_contradictory_legacy_facts_are_not_split(tmp_path, protection):
    source, _, _ = fixture(tmp_path, protection=protection)
    assert any(i["offset"] == 4 and i["size"] == 16 for i in policy(source, tmp_path))


@pytest.mark.parametrize("protection", [None, "contradictory"])
def test_render_preserves_labels_comments_bytes_and_stronger_types(
    tmp_path, protection
):
    source, raw, _ = fixture(tmp_path, protection=protection)
    with effective_metadata_file(tmp_path) as path:
        text = c_backend.render_project_source_with_c_backend(
            source, metadata_path=path, project_root=PROJECT_ROOT
        )
    for label in [
        "opaqueStart",
        "arrayStart",
        "arrayInterior",
        "arrayEnd",
        "opaqueInterior",
        "opaqueEnd",
    ]:
        assert label + ":" in text
    for comment in [
        "Keep this interior annotation",
        "Keep prefix annotation",
        "Keep suffix annotation",
    ]:
        assert comment in text
    if protection is None:
        assert "arrayStart:\n\tdc.w $0607" in text
        assert "\tdc.w $0809" in text
        body = text.split("arrayStart:", 1)[1].split("arrayEnd:", 1)[0]
        words = [
            int(value[1:], 16)
            for line in body.splitlines()
            if line.startswith("\tdc.w ")
            for value in line.split(";", 1)[0].split(None, 1)[1].split(",")
        ]
        assert words == [0x0607, 0x0809, 0x0A0B, 0x0C0D]
        assert not re.search(r"^\s*dc\.[bl] ", body, re.MULTILINE)
    else:
        assert "strongLong:" in text
        assert any(
            i["offset"] == 12 and i["size"] == 4 and i.get("label") == "strongLong"
            for i in policy(source, tmp_path)
        )
    rebuilt, _ = c_backend.assemble_platform_source_text_with_c_backend(
        "amiga-raw", text, project_root=PROJECT_ROOT
    )
    assert rebuilt == raw


def test_undo_redo_restores_projection_without_changing_imported_fact(tmp_path):
    source, _, _ = fixture(tmp_path)
    initial_metadata = effective_target_metadata(tmp_path)
    initial = policy(source, tmp_path)
    journal = tmp_path / MANUAL_ACTION_LOG_FILE_NAME
    prefix = journal.read_bytes()
    rows = [json.loads(line) for line in journal.read_text().splitlines()]
    for kind, relation, action_id, seq in [
        ("undo_action", "undoes_action_id", "undo-array", 3),
        ("redo_action", "redoes_action_id", "redo-array", 4),
    ]:
        rows.append(
            dict(
                record="manual_action",
                action_id=action_id,
                sequence=seq,
                created_at="2026-11-18T00:00:00+00:00",
                kind=kind,
                **{relation: "a2"},
            )
        )
        journal.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
        if kind == "undo_action":
            assert any(
                i["offset"] == 4 and i["size"] == 16 for i in policy(source, tmp_path)
            )
        else:
            assert policy(source, tmp_path) == initial
            assert effective_target_metadata(tmp_path) == initial_metadata
    assert journal.read_bytes().startswith(prefix)


def test_an_imported_scalar_guess_is_not_sufficient_precedence(tmp_path):
    source, _, _ = fixture(tmp_path, arrays=())
    path = tmp_path / "target_metadata.json"
    meta = json.loads(path.read_text())
    meta["seeded_entities"].append(
        {
            "hunk": 0,
            "addr": 8,
            "end": 16,
            "type": "data",
            "unit": "word",
            "seed_origin": "manual_analysis",
            "review_status": "seeded",
            "source_id": "fixture-import",
            "citation": "Imported type",
        }
    )
    path.write_text(json.dumps(meta))
    assert any(i["offset"] == 4 and i["size"] == 16 for i in policy(source, tmp_path))


def test_odd_interior_label_is_preserved_without_forcing_word_rendering(tmp_path):
    source, raw, _ = fixture(tmp_path)
    path = tmp_path / "target_metadata.json"
    meta = json.loads(path.read_text())
    meta["seeded_entities"].append(
        {
            "hunk": 0,
            "addr": 13,
            "name": "oddInterior",
            "seed_origin": "manual_analysis",
            "review_status": "seeded",
            "citation": "Independent byte anchor",
        }
    )
    path.write_text(json.dumps(meta))
    with effective_metadata_file(tmp_path) as metadata:
        text = c_backend.render_project_source_with_c_backend(
            source, metadata_path=metadata, project_root=PROJECT_ROOT
        )
    assert "oddInterior:" in text
    rebuilt, _ = c_backend.assemble_platform_source_text_with_c_backend(
        "amiga-raw", text, project_root=PROJECT_ROOT
    )
    assert rebuilt == raw


def test_long_array_subtracts_only_its_validated_extent(tmp_path):
    source, _, _ = fixture(tmp_path, stride=4)
    items = policy(source, tmp_path)
    assert [
        (i["offset"], i["size"])
        for i in items
        if i.get("semantic_role") == "opaque_data" and i["size"]
    ] == [(4, 4), (16, 4)]
    assert any(
        i["offset"] == 8 and i["size"] == 8 and i["kind"] == "longs" for i in items
    )


def test_out_of_range_section_still_fails_existing_source_validation(tmp_path):
    source, _, _ = fixture(tmp_path, arrays=())
    path = tmp_path / "target_metadata.json"
    meta = json.loads(path.read_text())
    meta["seeded_entities"].append(
        {
            "hunk": 1,
            "addr": 8,
            "end": 16,
            "type": "data",
            "unit": "word",
            "seed_origin": "manual_analysis",
            "review_status": "seeded",
            "source_id": "manual_action_log",
            "citation": "manual_action_log:other-section",
        }
    )
    path.write_text(json.dumps(meta))
    before = path.read_bytes()
    with pytest.raises(RuntimeError, match="hunk is out of range"):
        policy(source, tmp_path)
    assert path.read_bytes() == before

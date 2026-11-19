"""Checked record views preserve primitive aliases and adjacent source owners."""

import json
import subprocess
from contextlib import closing

import pytest

from amiga_reversing.disasm import c_backend
from amiga_reversing.disasm.binary_source import (
    BinarySourceKind,
    RawAddressModel,
    RawBinarySource,
)
from amiga_reversing.disasm.effective_metadata import effective_metadata_file
from amiga_reversing.disasm.manual_action_catalog import target_catalog_manual_payload
from amiga_reversing.disasm.manual_actions import (
    ManualActionKind,
    append_manual_actions,
)
from amiga_reversing.disasm.target_metadata import TargetMetadata, write_target_metadata


def fixture(
    tmp_path,
    *,
    split=False,
    gap=0,
    raw=None,
    conflict=False,
    code=None,
    record_size=6,
    count=3,
    inspection=None,
    unsigned=False,
    raw_properties=None,
    scalar_long=False,
):
    assembly = (
        code or " lea.l TABLE(pc),a6\n move.w 14(a6),d0\n move.w 18(a6),d1\n rts\n"
    )
    code_bytes, _ = c_backend.assemble_platform_source_text_with_c_backend(
        "amiga-raw", "TABLE EQU 128\n SECTION code,code\n" + assembly
    )
    assert len(code_bytes) < 128
    original = code_bytes + bytes(max(192, 128 + record_size * count) - len(code_bytes))
    binary = tmp_path / "input.bin"
    binary.write_bytes(original)
    source = RawBinarySource(
        kind=BinarySourceKind.RAW_BINARY,
        path=binary,
        address_model=RawAddressModel.LOCAL_OFFSET,
        load_address=0,
        entrypoint=0,
        code_start_offset=0,
        display_path=str(binary),
        analysis_cache_path=tmp_path / "analysis",
    )
    write_target_metadata(
        tmp_path, TargetMetadata(target_type="program", entry_register_seeds=())
    )
    actions = []

    def add(command, parameters):
        kind, payload = target_catalog_manual_payload(command, parameters)
        actions.append((ManualActionKind(kind), payload))
        return payload

    for name in ["Point", "Other"]:
        fields = [
            {"name": n, "type": "UWORD" if unsigned else "WORD", "offset": i * 2, "size": 2}
            for i, n in enumerate(["x", "y", "z"])
        ]
        if record_size == 4:
            fields = [
                {
                    "name": "pointer",
                    "type": "APTR",
                    "offset": 0,
                    "size": 4,
                    "value_kind": "target_pointer",
                    "pointer_address_domain": "mapped_source",
                }
            ]
        if record_size == 4 and scalar_long:
            fields = [{"name": "value", "type": "ULONG" if unsigned else "LONG", "offset": 0, "size": 4}]
        if record_size == 18:
            fields += [
                {"name": "w" + str(i), "type": "UWORD" if unsigned else "WORD", "offset": i * 2, "size": 2}
                for i in range(3, 7)
            ] + [{"name": "relative", "type": "ULONG" if unsigned else "LONG", "offset": 14, "size": 4}]
        add(
            "target.custom_struct.add",
            {"name": name, "size": record_size, "fields": fields},
        )
    for start, owner_count, name in (
        [(128, 1, "head"), (128 + record_size + gap, 2, "tail")]
        if split
        else [(128, count, "points")]
    ):
        owner = add(
            "target.data_block.layout.create",
            {
                "hunk": 0,
                "source_start": start,
                "source_end": start + owner_count * record_size,
                "name": name,
                "role": "data",
                "default_unit": "word",
            },
        )
        add(
            "target.data_block.element.set",
            {
                "layout_id": owner["data_block_layout"]["layout_id"],
                "offset": 0,
                "width": owner_count * record_size,
                "kind": "struct",
                "array_count": owner_count,
                "array_stride": record_size,
                "binding_kind": "custom_struct",
                "type_id": "Point",
            },
        )
    # The supported field-presentation fact exercises expanded leaves as well
    # as the compact adjacent owners. It preserves the same source contract.
    if not split:
        actions[-1][1]["data_block_element"]["type_binding"][
            "record_field_presentation"
        ] = True
    append_manual_actions(tmp_path, binary_source=source, actions=actions)
    with effective_metadata_file(tmp_path) as path:
        metadata = json.loads(path.read_text())
    if raw:
        start, size, unit = raw
        metadata["seeded_entities"].append(
            {
                "addr": start,
                "end": start + size,
                "hunk": 0,
                "unit": unit,
                "name": "retained_view",
                "seed_origin": "manual_analysis",
                "review_status": "seeded",
                "citation": "synthetic retained primitive view",
            }
        )
    if raw and raw_properties:
        metadata["seeded_entities"][-1].update(raw_properties)
    if conflict:
        metadata["seeded_entities"].append(
            {
                "addr": 130,
                "end": 132,
                "hunk": 0,
                "unit": "word",
                "struct_name": "Other",
                "field_name": "y",
                "field_type": "WORD",
                "seed_origin": "manual_analysis",
                "review_status": "seeded",
                "citation": "independent conflicting type",
            }
        )
    path = tmp_path / "effective.json"
    path.write_text(json.dumps(metadata))
    before = path.read_bytes()
    with closing(
        c_backend.build_listing_artifact_profile_from_binary_source(
            source, metadata_path=path
        )[2]
    ) as a:
        text = a.inline_source_text_with_profile()[0]
        facts = a.query_payload("instructions", limit=100)["items"]
        if inspection is not None:
            inspection.update(a.analysis_payload()[0])
    assert path.read_bytes() == before
    asm = tmp_path / "rendered.s"
    asm.write_text(text)
    assert (
        c_backend.assemble_platform_source_path_with_c_backend("amiga-raw", asm)[0]
        == original
    )
    output = tmp_path / "oracle.bin"
    run = subprocess.run(
        [
            str(c_backend.PROJECT_ROOT / "tools/vasmm68k_mot.exe"),
            "-quiet",
            "-no-opt",
            "-Fbin",
            "-o",
            str(output),
            str(asm),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert run.returncode == 0, run.stderr
    assert output.read_bytes() == original
    return text, facts


@pytest.mark.parametrize("split", [False, True])
def test_structural_view_crosses_compatible_owners_without_merging_them(
    tmp_path, split
):
    text, _ = fixture(tmp_path, split=split)
    assert "Point_y+2*Point_SIZEOF(a6)" in text
    assert "move.w $0012(a6),d1" in text
    if split:
        assert "head:" in text and "tail:" in text


@pytest.mark.parametrize(
    "raw",
    [
        (128, 18, "word"),
        (134, 6, "word"),
        (130, 2, "word"),
        (126, 24, "word"),
        (144, 8, "word"),
        (128, 4, "long"),
    ],
)
def test_compatible_retained_primitive_views_preserve_record_coverage(tmp_path, raw):
    text, _ = fixture(tmp_path, raw=raw)
    assert "Point_y+2*Point_SIZEOF(a6)" in text
    if raw[0] != 128:
        assert "retained_view" in text


@pytest.mark.parametrize(
    "options",
    [
        {"split": True, "gap": 2},
        {"raw": (129, 2, "word")},
        {"raw": (128, 8, "long")},
        {"conflict": True},
    ],
)
def test_gaps_partial_primitives_and_contradictory_types_do_not_extend_view(
    tmp_path, options
):
    text, _ = fixture(tmp_path, **options)
    assert "Point_y+2*Point_SIZEOF(a6)" not in text


def test_address_bearing_views_do_not_create_a_cross_owner_pointer_collection(tmp_path):
    analysis = {}
    text, _ = fixture(
        tmp_path,
        split=True,
        record_size=4,
        inspection=analysis,
        code=" lea.l TABLE(pc),a6\n move.l 8(a6),d0\n rts\n",
    )
    assert "Point_pointer+2*Point_SIZEOF(a6)" in text
    tables = analysis["sections"][0]["table_descriptors"]
    assert not [
        t for t in tables if t["start_offset"] == 128 and t["end_offset"] == 140
    ]

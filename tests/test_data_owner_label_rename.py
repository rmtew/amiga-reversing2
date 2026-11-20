"""Renaming a typed data owner must not introduce a code-address declaration."""

from dataclasses import replace

import pytest

from amiga_reversing.disasm.effective_metadata import _rename_manual_data_owner
from amiga_reversing.disasm.manual_actions import ManualLabelScope
from amiga_reversing.disasm.target_metadata import SeededEntityMetadata


def entity():
    return SeededEntityMetadata.from_dict(
        {
            "addr": 10,
            "end": 12,
            "name": "old_record",
            "hunk": 0,
            "type": "data",
            "unit": "word",
            "struct_name": "Voice",
            "field_name": "left",
            "field_type": "word",
            "seed_origin": "manual_analysis",
            "review_status": "seeded",
            "citation": "Synthetic saved analysis",
            "source_locator": "fixture:Voice",
            "source_owner_start": 10,
            "source_owner_size": 4,
        }
    )


def test_exact_data_rename_preserves_every_non_name_fact_and_saved_replay():
    original = entity()
    label = {
        "addr": 10,
        "hunk": 0,
        "name": "voice_state",
        "previous_name": "old_record",
        "address_domain": "source",
    }
    changed, renamed = _rename_manual_data_owner([original], label)
    assert changed and renamed == [replace(original, name="voice_state")]
    assert _rename_manual_data_owner(renamed, label) == (True, renamed)
    assert original.name == "old_record"
    for bad in [
        dict(label, addr=11),
        dict(label, hunk=1),
        dict(label, address_domain="runtime"),
        dict(label, scope=ManualLabelScope.LOCAL),
        dict(label, previous_name="foreign"),
    ]:
        assert _rename_manual_data_owner([original], bad) == (False, [original])
    with pytest.raises(ValueError, match="unique named data owner"):
        _rename_manual_data_owner([original, replace(original, unit="byte")], label)


@pytest.mark.parametrize("declared_layout", [False, True])
def test_data_owner_rename_keeps_native_field_inference_and_exact_assembly(tmp_path, declared_layout):
    import json
    import subprocess
    from pathlib import Path

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
    from amiga_reversing.disasm.manual_actions import (
        ManualActionKind,
        append_manual_actions,
    )
    from amiga_reversing.disasm.target_metadata import (
        CustomStructMetadata,
        TargetMetadata,
        write_target_metadata,
    )

    text = "SECTION code,code\n lea old_record(pc),a0\n move.w 2(a0),d0\n rts\nold_record:\n dc.w 0,7\n"
    raw = c_backend.assemble_platform_source_text_with_c_backend("amiga-raw", text)[0]
    assert len(raw) == 14
    path = tmp_path / "image.bin"
    path.write_bytes(raw)
    source = RawBinarySource(
        kind=BinarySourceKind.RAW_BINARY,
        path=path,
        address_model=RawAddressModel.LOCAL_OFFSET,
        load_address=0,
        entrypoint=0,
        code_start_offset=0,
        display_path=str(path),
        analysis_cache_path=tmp_path / "analysis",
    )
    (tmp_path / "source_binary.json").write_text(
        json.dumps(
            {
                "kind": "raw_binary",
                "path": str(path),
                "address_model": "local_offset",
                "load_address": 0,
                "entrypoint": 0,
                "code_start_offset": 0,
            }
        )
    )
    struct = CustomStructMetadata.from_dict(
        {
            "name": "Voice",
            "size": 4,
            "fields": [
                {
                    "name": "left",
                    "type": "word",
                    "offset": 0,
                    "size": 2,
                    "available_since": "1.0",
                    "struct": None,
                    "pointer_struct": None,
                    "named_base": None,
                    "value_kind": "scalar",
                },
                {
                    "name": "right",
                    "type": "word",
                    "offset": 2,
                    "size": 2,
                    "available_since": "1.0",
                    "struct": None,
                    "pointer_struct": None,
                    "named_base": None,
                    "value_kind": "scalar",
                },
            ],
            "seed_origin": "manual_analysis",
            "review_status": "seeded",
            "citation": "Synthetic schema",
            "source": "synthetic test",
            "base_offset": 0,
            "base_struct": None,
            "available_since": "1.0",
        }
    )
    first = entity()
    second = replace(
        first,
        addr=12,
        end=14,
        name=None,
        field_name="right",
        source_owner_start=None,
        source_owner_size=None,
    )
    write_target_metadata(
        tmp_path,
        TargetMetadata(
            target_type="program",
            entry_register_seeds=(),
            custom_structs=(struct,),
            seeded_entities=(first, second),
        ),
    )
    if declared_layout:
        from amiga_reversing.disasm.manual_action_catalog import (
            target_catalog_manual_payload,
        )
        commands = [
            ("target.data_block.layout.create", {"layout_id": "voice-owner", "hunk": 0,
                "source_start": 10, "source_end": 14, "name": "old_record", "default_unit": "word"}),
            ("target.data_block.element.set", {"layout_id": "voice-owner", "offset": 0,
                "width": 4, "kind": "struct", "binding_kind": "custom_struct", "type_id": "Voice"}),
        ]
        append_manual_actions(tmp_path, binary_source=source, actions=[
            (ManualActionKind(kind), payload)
            for command, parameters in commands
            for kind, payload in [target_catalog_manual_payload(command, parameters)]
        ])
        write_target_metadata(tmp_path, effective_target_metadata(tmp_path, binary_source=source))
        (tmp_path / "manual_actions.jsonl").unlink()
    append_manual_actions(
        tmp_path,
        binary_source=source,
        actions=[
            (
                ManualActionKind.CREATE_MANUAL_LABEL,
                {
                    "label": {
                        "label_id": "rename",
                        "hunk": 0,
                        "addr": 10,
                        "name": "voice_state",
                        "previous_name": "old_record",
                        "address_domain": "source",
                        "scope": "global",
                        **({"data_block_layout_id": "voice-owner"} if declared_layout else {}),
                    }
                },
            )
        ],
    )
    append_manual_actions(
        tmp_path,
        binary_source=source,
        actions=[
            (
                ManualActionKind.RENAME_MANUAL_CUSTOM_STRUCT_FIELD,
                {
                    "custom_struct_field": {
                        "struct_name": "Voice",
                        "offset": 2,
                        "name": "sample_count",
                    }
                },
            )
        ],
    )
    metadata = effective_target_metadata(tmp_path, binary_source=source)
    assert metadata.seeded_entities[0].name == "voice_state"
    assert metadata.seeded_entities[1].field_name == "sample_count"
    assert not metadata.seeded_code_labels
    if declared_layout:
        assert metadata.data_block_layouts[0].name == "voice_state"
        assert metadata.data_block_layouts[0].layout_id == "voice-owner"
        assert not any(e.name == "old_record" for e in metadata.seeded_entities)
        write_target_metadata(tmp_path, metadata)
        assert effective_target_metadata(tmp_path, binary_source=source) == metadata
    with effective_metadata_file(tmp_path) as effective:
        artifact = c_backend.build_listing_artifact_profile_from_binary_source(
            source, metadata_path=effective
        )[2]
    try:
        rendered = artifact.inline_source_text_with_profile()[0]
        analysis = artifact.analysis_payload()[0]
        fields = analysis["sections"][0]["recovered_platform_typed_accesses"]
        assert any(
            r["offset"] == 4
            and r["field_name"] == "sample_count"
            and r["owner_struct_name"] == "Voice"
            for r in fields
        )
        assert "voice_state:" in rendered and "Voice_sample_count(a0)" in rendered
    finally:
        artifact.close()
    assert (
        c_backend.assemble_platform_source_text_with_c_backend("amiga-raw", rendered)[0]
        == raw
    )
    assembly = tmp_path / "output.s"
    assembly.write_text(rendered)
    out = tmp_path / "rebuilt.bin"
    root = Path(__file__).resolve().parents[1]
    subprocess.run(
        [
            str(root / "tools/vasmm68k_mot.exe"),
            "-quiet",
            "-Fbin",
            "-m68000",
            "-no-opt",
            "-o",
            str(out),
            str(assembly),
        ],
        check=True,
        capture_output=True,
    )
    assert out.read_bytes() == raw


def test_field_rename_follows_unique_declaring_owner_and_refuses_shadowed_names():
    from amiga_reversing.disasm.effective_metadata import (
        _rename_seeded_custom_field_references,
    )
    from amiga_reversing.disasm.target_metadata import (
        CustomStructFieldMetadata,
        CustomStructMetadata,
    )

    leaf = entity()
    base = CustomStructMetadata(
        name="Voice",
        size=4,
        fields=(CustomStructFieldMetadata(name="left", type="word", offset=0, size=2),),
        seed_origin=leaf.seed_origin,
        review_status=leaf.review_status,
        citation="Synthetic parent",
    )
    child = replace(
        base,
        name="ExtendedVoice",
        size=6,
        base_struct="Voice",
        base_offset=4,
        fields=(
            CustomStructFieldMetadata(name="extra", type="word", offset=4, size=2),
        ),
    )
    inherited = replace(leaf, struct_name="ExtendedVoice")
    renamed = _rename_seeded_custom_field_references(
        [inherited], [base, child], {("Voice", 0): "dma_mask"}
    )
    assert renamed == [replace(inherited, field_name="dma_mask")]
    assert _rename_seeded_custom_field_references(
        [inherited], [base, child], {("Other", 0): "foreign"}
    ) == [inherited]
    shadow = replace(
        child,
        fields=(CustomStructFieldMetadata(name="left", type="word", offset=4, size=2),),
    )
    assert _rename_seeded_custom_field_references(
        [inherited], [base, shadow], {("Voice", 0): "dma_mask"}
    ) == [inherited]


def test_source_data_name_binds_only_a_unique_exact_anonymous_owner():
    from amiga_reversing.disasm.effective_metadata import _name_anonymous_data_owner

    original = replace(entity(), name=None, source_owner_start=None, source_owner_size=None)
    seed = {"seed_id": "data-symbol:h0:0000000A", "hunk": 0, "addr": 10, "name": "voice_data"}
    changed, named = _name_anonymous_data_owner([original], seed)
    assert changed and named == [replace(original, name="voice_data")]
    assert original.name is None
    for existing, update in [
        ([entity()], seed),
        ([original], dict(seed, addr=11)),
        ([original], dict(seed, hunk=1)),
        ([original], dict(seed, end=12)),
        ([original], dict(seed, seed_id="generic-seed")),
        ([original, replace(original, end=14)], seed),
        ([replace(original, end=None)], seed),
    ]:
        assert _name_anonymous_data_owner(existing, update) == (False, existing)

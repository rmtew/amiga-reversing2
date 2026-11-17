"""Source-local owners retain identity beside a proven runtime alias."""

from dataclasses import replace

from amiga_reversing.disasm.assembler_profiles import VASM_PROFILE
from amiga_reversing.disasm.binary_source import (
    BinarySourceKind,
    RawAddressModel,
    RawBinarySource,
)
from amiga_reversing.disasm.manual_actions import (
    ManualLabelScope,
    _manual_label_conflict_items,
)
from amiga_reversing.disasm.target_metadata import ExecutionViewMetadata, TargetMetadata


def test_runtime_source_alias_conflicts_require_unique_mapping_and_include_all_peers(
    tmp_path,
):
    path = tmp_path / "image.bin"
    path.write_bytes(b"\0" * 16)
    source = RawBinarySource(
        kind=BinarySourceKind.RAW_BINARY,
        path=path,
        address_model=RawAddressModel.RUNTIME_ABSOLUTE,
        load_address=0x1000,
        entrypoint=0x1000,
        code_start_offset=0,
        display_path=str(path),
        analysis_cache_path=tmp_path / "analysis",
    )
    runtime = {
        "label_id": "runtime",
        "name": "voice",
        "scope": ManualLabelScope.GLOBAL,
        "hunk": 0,
        "addr": 0x1000,
        "address_domain": "runtime",
    }
    owner = {
        "label_id": "source",
        "name": "voice",
        "scope": ManualLabelScope.GLOBAL,
        "hunk": 0,
        "addr": 0,
        "address_domain": "source",
    }
    metadata = TargetMetadata(target_type="program", entry_register_seeds=())

    def audit(labels, model=source, meta=metadata, views=()):
        return _manual_label_conflict_items(
            {r["label_id"]: r for r in labels},
            stronger_metadata=meta,
            assembler_profile=VASM_PROFILE,
            binary_source=model,
            execution_views=views,
        )

    assert audit([runtime, owner]) == []
    for bad in [
        dict(owner, addr=2),
        dict(owner, addr=0x1000),
        dict(owner, hunk=1),
        dict(runtime, label_id="other"),
    ]:
        assert audit([runtime, bad])
    assert audit(
        [runtime, owner],
        model=replace(source, address_model=RawAddressModel.LOCAL_OFFSET),
    )
    assert audit([dict(runtime, addr=0x2000), owner])
    ambiguous = replace(
        metadata,
        execution_views=(
            ExecutionViewMetadata.from_dict(
                {
                    "name": "overlay",
                    "seed_origin": "manual_analysis",
                    "review_status": "seeded",
                    "citation": "Synthetic ambiguous view",
                    "source_start": 4,
                    "source_end": 8,
                    "base_addr": 0x1000,
                }
            ),
        ),
    )
    assert audit([runtime, owner], meta=ambiguous)
    assert audit(
        [runtime, owner],
        views=[{"source_start": 4, "source_end": 8, "base_addr": 0x1000}],
    )
    assert (
        audit(
            [runtime, owner],
            views=[{"source_start": 0, "source_end": 8, "base_addr": 0x1000}],
        )
        == []
    )
    third = dict(owner, label_id="foreign", addr=4)
    conflicts = audit([runtime, owner, third])
    assert set(conflicts[-1]["label_ids"]) == {"runtime", "source", "foreign"}
    # Input order cannot leave the explicit owner active beside a foreign alias.
    for labels in ([third, runtime, owner], [owner, third, runtime]):
        assert {r["label_id"] for r in labels} <= {
            i for c in audit(labels) for i in c["label_ids"]
        }


def test_mapped_alias_keeps_source_owner_through_projection_and_both_assemblers(
    tmp_path,
):
    import json
    import subprocess
    from pathlib import Path

    from amiga_reversing.disasm import c_backend
    from amiga_reversing.disasm.effective_metadata import (
        effective_metadata_file,
        effective_target_metadata,
    )
    from amiga_reversing.disasm.manual_actions import (
        ManualActionKind,
        append_manual_actions,
    )
    from amiga_reversing.disasm.target_metadata import write_target_metadata

    raw = c_backend.assemble_platform_source_text_with_c_backend(
        "amiga-raw", "SECTION code,code\n ORG $1000\n bra.b done\n nop\ndone:\n rts\n"
    )[0]
    path = tmp_path / "image.bin"
    path.write_bytes(raw)
    source = RawBinarySource(
        kind=BinarySourceKind.RAW_BINARY,
        path=path,
        address_model=RawAddressModel.RUNTIME_ABSOLUTE,
        load_address=0x1000,
        entrypoint=0x1000,
        code_start_offset=0,
        display_path=str(path),
        analysis_cache_path=tmp_path / "analysis",
    )
    (tmp_path / "source_binary.json").write_text(
        json.dumps(
            {
                "kind": "raw_binary",
                "path": str(path),
                "address_model": "runtime_absolute",
                "load_address": 0x1000,
                "entrypoint": 0x1000,
                "code_start_offset": 0,
            }
        )
    )
    write_target_metadata(
        tmp_path, TargetMetadata(target_type="program", entry_register_seeds=())
    )
    labels = [
        {
            "label_id": "runtime",
            "name": "voice",
            "hunk": 0,
            "addr": 0x1000,
            "address_domain": "runtime",
            "scope": "global",
        },
        {
            "label_id": "source",
            "name": "voice",
            "hunk": 0,
            "addr": 0,
            "address_domain": "source",
            "scope": "global",
        },
        {
            "label_id": "local",
            "name": ".done",
            "hunk": 0,
            "addr": 4,
            "address_domain": "source",
            "scope": "local",
            "owner_offset": 0,
            "owner_id": "s0:00000000:label",
        },
    ]
    append_manual_actions(
        tmp_path,
        binary_source=source,
        actions=[(ManualActionKind.CREATE_MANUAL_LABEL, {"label": r}) for r in labels],
    )
    metadata = effective_target_metadata(tmp_path, binary_source=source)
    assert [(r.addr, r.name) for r in metadata.seeded_code_labels] == [
        (0, "voice"),
        (4, "voice\\.done"),
    ]
    with effective_metadata_file(tmp_path) as effective:
        artifact = c_backend.build_listing_artifact_profile_from_binary_source(
            source, metadata_path=effective
        )[2]
    try:
        text = artifact.inline_source_text_with_profile()[0]
    finally:
        artifact.close()
    assert (
        c_backend.assemble_platform_source_text_with_c_backend("amiga-raw", text)[0]
        == raw
    )
    assembly = tmp_path / "output.s"
    assembly.write_text(text)
    binary = tmp_path / "rebuilt.bin"
    root = Path(__file__).resolve().parents[1]
    subprocess.run(
        [
            str(root / "tools/vasmm68k_mot.exe"),
            "-quiet",
            "-Fbin",
            "-m68000",
            "-no-opt",
            "-o",
            str(binary),
            str(assembly),
        ],
        check=True,
        capture_output=True,
    )
    assert binary.read_bytes() == raw

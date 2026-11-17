"""Initial source import of the independently matched 4,000-byte boot stage.

Only original entry/call targets and the consumed resource records are named.
No instruction, protection behavior or original private input is changed.
"""

from __future__ import annotations

import copy
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from amiga_reversing.disasm import game_catalog
from amiga_reversing.disasm.binary_source import write_source_descriptor
from amiga_reversing.disasm.effective_metadata import effective_metadata_file
from amiga_reversing.disasm.projects import create_project_at_path
from amiga_reversing.disasm.target_metadata import (
    TargetMetadata,
    target_metadata_json_payload,
    write_target_metadata,
)

TARGET = "amiga_raw_foft_boot_loader_sps0613"


def main():
    if (ROOT / "targets" / TARGET).exists():
        raise ValueError(
            "initial import requires a fresh target; use target commands afterward"
        )
    family = game_catalog.load_family(ROOT, "foft")
    binding = family["targets"][TARGET]
    data = game_catalog.materialize(ROOT, "foft", binding["artifact"]).read_bytes()
    recipe = json.loads((ROOT / "recipes/foft/sps0613-resources.json").read_bytes())
    reader = recipe["evidence"]["boot_reader"]
    records = [struct.unpack_from(">4I", data, 0x8EA + 16 * n) for n in range(3)]
    expected = [
        (d["destination"], d["game_track"], d["offset"], d["length"])
        for d in reader["descriptors"]
    ]
    if (
        records != expected
        or records[1][0] + records[1][3] != records[2][0]
        or records[2][0] + records[2][3] != 0x78000
    ):
        raise ValueError("original boot descriptor transfer differs")
    payload = json.loads(
        json.dumps(
            target_metadata_json_payload(
                TargetMetadata(target_type="raw_binary", entry_register_seeds=())
            )
        )
    )
    payload["source_output_policy"] = {
        "mode": "binary_assets",
        "minimum_asset_size": 256,
    }
    proof = {
        "seed_origin": "manual_analysis",
        "review_status": "seeded",
        "citation": "Original SPS0613 stored loader, exact historical $78000 prefix identity; native original-instruction call/consumer trace",
        "source_id": "foft-sps0613-boot-stage",
    }
    names = {
        0: "BootLoaderEntry",
        0x160: "InitializeBootFloppyReader",
        0x1CC: "ReadBootDecodedTrack",
        0x2E6: "ReadBootRawTrack",
        0x4E2: "WaitBootDiskDma",
        0x4FA: "SeekBootLogicalTrack",
        0x570: "AdvanceBootLogicalTrack",
        0x68E: "DecodeBootMfmBytes",
        0x6A6: "DecodeBootMfmByte",
        0x806: "ChecksumBootEncodedWords",
        0x81C: "LoadBootResource",
    }
    payload["seeded_code_entrypoints"] = [
        dict(addr=at, name=name, **proof) for at, name in names.items()
    ]
    payload["seeded_code_labels"] = [
        dict(addr=at, name=name, **proof) for at, name in names.items()
    ]
    with effective_metadata_file(ROOT / "targets/amiga_raw_foft") as metadata_path:
        parent = json.loads(Path(metadata_path).read_bytes())
    definition = next(
        s for s in parent["custom_structs"] if s["name"] == "DiskResourceDescriptor"
    )
    payload["custom_structs"] = [copy.deepcopy(definition)]
    # The same 16-byte layout is established independently by the original
    # boot consumer's four fields and byte-copy/update loop, not byte similarity.
    for at, count, name in [
        (0x8EA, 3, "bootResourceCatalog"),
        (0x8A2, 1, "bootResourceWork"),
    ]:
        payload["seeded_entities"].append(
            dict(
                addr=at,
                end=at + 16 * count,
                name=name,
                type="data",
                unit="long",
                struct_name="DiskResourceDescriptor",
                **proof,
            )
        )
    payload["entry_comments"] = [
        dict(
            addr=0x81C,
            comment="Original resource order 0: title, 1: $800/456000 bytes, 2: $6FD40/33472 bytes; main segments are adjacent.",
            **proof,
        )
    ]
    target = create_project_at_path(
        "targets/" + TARGET,
        ROOT,
        origin={
            "kind": "resource_import",
            "family": "foft",
            "artifact": binding["artifact"],
        },
    )
    write_source_descriptor(
        target, {"kind": "artifact", "family": "foft", "target": TARGET}
    )
    write_target_metadata(target, TargetMetadata.from_dict(payload))
    print(
        json.dumps(
            {
                "target": TARGET,
                "sha256": binding["artifact"],
                "bytes": len(data),
                "named_entries": len(names),
                "resource_descriptors": records,
                "source": "First two independently checked sectors of game track2",
                "unknown": "Final 2000 track bytes excluded; no new runtime observation",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

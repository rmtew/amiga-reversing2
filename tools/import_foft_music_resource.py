"""Initial import of the independently decoded, content-bound music resource 9.

Snapshot supported facts from the same-address, byte-identical restored source
span. This is not live inheritance, runtime installation or callback closure.
"""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from amiga_reversing.disasm import game_catalog
from amiga_reversing.disasm.binary_source import (
    resolve_target_binary_source,
    write_source_descriptor,
)
from amiga_reversing.disasm.effective_metadata import effective_metadata_file
from amiga_reversing.disasm.metadata_slice import slice_raw_metadata
from amiga_reversing.disasm.projects import create_project_at_path
from amiga_reversing.disasm.target_metadata import (
    SeededCodeEntrypointMetadata,
    TargetMetadata,
    target_metadata_json_payload,
    write_target_metadata,
)

PARENT = "amiga_raw_foft"
CHILD = "amiga_raw_foft_music_bank9_sps0613"
OFFSET = 0x57800
SIZE = 50000


def main():
    family = game_catalog.load_family(ROOT, "foft")
    binding = family["targets"][CHILD]
    child_path = ROOT / "targets" / CHILD
    if child_path.exists():
        raise ValueError(
            "initial import requires a fresh target; use normal commands afterward"
        )
    parent = resolve_target_binary_source(ROOT / "targets" / PARENT, ROOT)
    data = parent.read_bytes()
    if game_catalog.digest(data) != family["targets"][PARENT]["artifact"]:
        raise ValueError("parent reconstruction source identity changed")
    # Materialization runs the declared stored-sector recipe, not a direct bank
    # binding or the RAM source. Both independent origins must agree.
    path = game_catalog.materialize(ROOT, "foft", binding["artifact"])
    bank = path.read_bytes()
    if len(bank) != SIZE or data[OFFSET : OFFSET + SIZE] != bank:
        raise ValueError("decoded bank does not match the reconstructed source span")
    if parent.load_address + OFFSET != binding["context"]["load_address"]:
        raise ValueError("metadata import requires unchanged runtime addresses")
    with effective_metadata_file(ROOT / "targets" / PARENT) as metadata_path:
        payload = json.loads(Path(metadata_path).read_bytes())
    metadata, counts = slice_raw_metadata(
        TargetMetadata.from_dict(payload), start=OFFSET, size=SIZE
    )
    provenance = {
        "seed_origin": "manual_analysis",
        "review_status": "seeded",
        "citation": "Verified resource 9 byte correspondence and MusicMenuSelectTrack entry ABI",
        "source_id": "foft-sps0613-resource9",
    }
    entries = list(metadata.seeded_code_entrypoints)
    for offset, name in [
        (0, "MusicEntryStart"),
        (4, "MusicEntryTick"),
        (14, "MusicEntryStop"),
    ]:
        if not any(e.addr == offset for e in entries):
            entries.append(
                SeededCodeEntrypointMetadata.from_dict(
                    dict(addr=offset, name=name, **provenance)
                )
            )
    metadata = replace(metadata, seeded_code_entrypoints=tuple(entries))
    target = create_project_at_path(
        "targets/" + CHILD,
        ROOT,
        origin={
            "kind": "resource_import",
            "family": "foft",
            "artifact": binding["artifact"],
            "parent": PARENT,
        },
    )
    write_source_descriptor(
        target, {"kind": "artifact", "family": "foft", "target": CHILD}
    )
    write_target_metadata(target, metadata)
    receipt = {
        "schema_version": 1,
        "parent": PARENT,
        "target": CHILD,
        "resource_sha256": binding["artifact"],
        "source_offset": OFFSET,
        "bytes": SIZE,
        "parent_artifact": family["targets"][PARENT]["artifact"],
        "parent_effective_metadata_sha256": game_catalog.digest(
            json.dumps(payload, sort_keys=True).encode()
        ),
        "imported_metadata_sha256": game_catalog.digest(
            json.dumps(target_metadata_json_payload(metadata), sort_keys=True).encode()
        ),
        "facts": counts,
        "explicit_abi_entrypoints": 3,
        "limits": "Same-address initial snapshot only. No runtime initialization or closed callback domain. Runtime-only aliases/equates and execution views are not inherited. Subsequent changes use target commands.",
    }
    (target / "resource-import.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()

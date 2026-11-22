"""Initialize the repo's raw analyzer on the original retail gameplay member."""

import argparse
import json
import sys
from pathlib import Path

from decode_resident import RESIDENT_BASE, RESIDENT_ENTRY, decode_image
from inspect_media import require, sha

TARGET = Path(__file__).resolve().parent
ROOT = TARGET.parents[1]
SOURCE_MEMBER = "binary.bin"
LOCAL_ID = "amiga_raw_gameplay"
TARGET_ID = f"{TARGET.name}__{LOCAL_ID}"
ANALYSIS_DIR = TARGET / "targets" / LOCAL_ID
JOURNALS = {
    "renderer-manual-actions.jsonl": "manual_actions.jsonl",
    "renderer-decision-journal.jsonl": "decision_journal.jsonl",
}
DISPATCH_PC = 0x56D44
DISPATCH_SHA256 = "2ce423b4fc45d527aa4332e8f0a2bddd5c67624678513e88e0fc8345c7d48ef3"

# Internal blocks are labels rather than speculative function starts.
ROOT_ENTRIES = {
    "game_iteration", "queue_viewport_clear",
    "rasterize_terrain_quad", "sample_terrain_height_and_type",
    "translate_and_project_model_vertices",
}


def seed_metadata(receipt, output):
    from amiga_reversing.disasm.target_metadata import TargetMetadata

    refs = receipt["resident"]["renderer_entries"]
    records = {}
    for key, fact in refs.items():
        pc = int(fact["guest_pc"], 16)
        require(pc - RESIDENT_BASE == fact["source_offset"] and pc % 2 == 0,
                f"inconsistent source offset at {key}")
        name = "prepare_scene_terrain" if key == "queue_viewport_clear" else key
        records[key] = {
            "addr": fact["source_offset"], "hunk": 0, "name": name,
            "seed_origin": "manual_analysis", "review_status": "seeded",
            "citation": f"Retail natural gameplay trace PC {pc:06X}; "
                        "resident-verification.json fingerprint.",
            "source_locator": f"runtime:{pc:06x}",
        }
    handoff = {
        "addr": RESIDENT_ENTRY - RESIDENT_BASE, "hunk": 0,
        "name": "retail_gameplay_handoff", "seed_origin": "manual_analysis",
        "review_status": "seeded",
        "citation": "Original disk cold boot at first instruction 057B8A; "
                    "the complete resident matched the decoded image.",
        "source_locator": f"runtime:{RESIDENT_ENTRY:06x}",
    }
    dispatch_offset = DISPATCH_PC - RESIDENT_BASE
    require(sha(output[dispatch_offset:dispatch_offset + 32]) == DISPATCH_SHA256,
            "model dispatch fingerprint differs")
    dispatch = {
        "addr": dispatch_offset, "hunk": 0,
        "name": "dispatch_model_projection", "seed_origin": "manual_analysis",
        "review_status": "seeded",
        "citation": "Driving trace executes BSR at 056D28 to 056D44; "
                    "32-byte fingerprint matches three captured resident views.",
        "source_locator": f"runtime:{DISPATCH_PC:06x}",
    }
    require(len(records) == 9 and ROOT_ENTRIES <= records.keys(),
            "unrecognized renderer anchor set")
    return TargetMetadata.from_dict({
        "target_type": "raw_binary",
        "entry_register_seeds": [], "bootblock": None, "resident": None,
        "library": None, "custom_structs": [], "rsset_layout_regions": [],
        "seeded_code_entrypoints": [handoff, dispatch] + [records[k] for k in sorted(ROOT_ENTRIES)],
        "seeded_code_labels": [handoff, dispatch] + [records[k] for k in sorted(records)],
    })


def initialize(image, *, target=ANALYSIS_DIR, owner=TARGET, root=ROOT):
    from amiga_reversing.disasm.binary_source import write_source_descriptor
    from amiga_reversing.disasm.projects import initialize_project_metadata
    from amiga_reversing.disasm.target_metadata import write_target_metadata

    # One runtime analysis view inside the retail project, not an independent
    # disk set. Never overwrite existing decisions or binary materialization.
    private_paths = ("binary.bin", "source_binary.json", "target_metadata.json",
                     ".project.json", *JOURNALS.values())
    require(not any((target / p).exists() or (target / p).is_symlink()
                    for p in private_paths),
            "analysis already exists; retain it and use Restore")
    if target != owner:
        require(not any((owner / p).exists() or (owner / p).is_symlink()
                        for p in private_paths),
                "old analysis still exists in the owner; back it up before bootstrapping")
    journals = {local_name: (owner / template).read_bytes()
                for template, local_name in JOURNALS.items()}
    intake = json.loads((owner / "inventory.json").read_text())
    expected = json.loads((owner / "resident-verification.json").read_text())
    output, receipt = decode_image(image, intake)
    require(receipt == expected, "resident receipt differs")
    metadata = seed_metadata(receipt, output)
    binary = target / SOURCE_MEMBER
    recorded_path = binary.relative_to(root).as_posix()
    target.mkdir(parents=True, exist_ok=True)
    with binary.open("xb") as dst:
        dst.write(output)
    write_source_descriptor(target, {
        "kind": "raw_binary",
        "path": recorded_path,
        "address_model": "runtime_absolute",
        "load_address": RESIDENT_BASE,
        "entrypoint": RESIDENT_ENTRY,
        "code_start_offset": 0,
    })
    write_target_metadata(target, metadata)
    initialize_project_metadata(target, origin={
        "kind": "original_media_handoff",
        "target_type": "raw_binary",
        "target_role": "primary_program",
        "source_media_sha256": receipt["input_image_sha256"],
        "payload_sha256": sha(output),
        "load_address": RESIDENT_BASE,
        "entrypoint": RESIDENT_ENTRY,
        "byte_length": len(output),
        "provenance": "Original retail IPF, first natural Copperline handoff."
    })
    for name, content in journals.items():
        with (target / name).open("xb") as dst:
            dst.write(content)
    return {"target": TARGET_ID, "payload_sha256": sha(output), "size": len(output),
            "load_address": RESIDENT_BASE, "entrypoint": RESIDENT_ENTRY,
            "runtime_root_count": 2 + len(ROOT_ENTRIES), "named_sites": 11}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("ipf", type=Path)
    args = p.parse_args()
    sys.path.insert(0, str(ROOT))
    try:
        print(json.dumps(initialize(args.ipf.read_bytes()), indent=2, sort_keys=True))
    except (ValueError, OSError) as err:
        p.exit(1, f"Conqueror analysis: {err}\n")


if __name__ == "__main__":
    main()

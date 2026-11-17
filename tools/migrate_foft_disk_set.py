"""Rehearse the one-time FOFT migration in private storage; never move live targets.

After conversion the common owner reads only its bundle, sealed member state,
codec recipe and bound media. This script is not a build/runtime dependency.
"""

from __future__ import annotations

import argparse
import copy
import json
import struct
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from amiga_reversing.disasm.disk_codecs import IpfResources, digest
from amiga_reversing.disasm.disk_set import create_disk_set, execute_owner
from amiga_reversing.disasm.effective_metadata import effective_metadata_file
from amiga_reversing.disasm.projects import list_projects
from amiga_reversing.disasm.source_package_publish import load_published_source_package
from tools.foft_disk import private_directory

LEGACY = {
    "main": "amiga_raw_foft",
    "boot": "amiga_raw_foft_boot_loader_sps0613",
    "music-5": "amiga_raw_foft_music_bank5_sps0613",
}


def stage(image_path, output, *, exercise_missing=False, editable=False):
    output = private_directory(output)
    recipe = json.loads((ROOT / "recipes/foft/sps0613-resources.json").read_bytes())
    extra = json.loads(
        (ROOT / "recipes/foft/sps0613-music-resource5.json").read_bytes()
    )
    if any(
        extra[k] != recipe[k] for k in ("kind", "codec", "image_sha256", "geometry")
    ):
        raise ValueError("legacy source media contracts differ")
    recipe["actions"] += extra["actions"]
    for action in recipe["actions"]:
        action["resource"].pop("analysis_target", None)
    recipe["evidence"]["ownership"] = (
        "One disk-set owner; member identities and build/analysis boundaries are in its manifest."
    )
    image = image_path.read_bytes()
    _, recovered = IpfResources.extract(image, recipe, project_root=ROOT)
    # Independently bind the published static loader recipe to its actual bytes.
    boot, main = recovered["foft-boot-loader.bin"], recovered["foft-program.bin"]
    assert struct.unpack_from(">4I", boot, 0x8FA) == (0x800, 3, 0, 456000)
    assert struct.unpack_from(">4I", boot, 0x90A) == (0x6FD40, 79, 0, 33472)
    assert struct.unpack_from(">4I", main, 0x403F0 - 0x800) == (0x58000, 132, 0, 29578)
    assert struct.unpack_from(">4I", main, 0x40430 - 0x800) == (0x58000, 102, 0, 50000)
    names = {
        "foft-program.bin": "main",
        "foft-boot-loader.bin": "boot",
        "foft-music-bank5.bin": "music-5",
        "foft-music-bank9.bin": "music-9",
    }
    owned_files, packages, members = {}, {}, []
    recipe_bytes = (json.dumps(recipe, indent=2) + "\n").encode()
    owned_files["recipes/sps0613.json"] = recipe_bytes
    for member, legacy in LEGACY.items():
        directory = ROOT / "targets" / legacy
        packages[member] = load_published_source_package(directory)
        with effective_metadata_file(directory) as path:
            snapshot = Path(path).read_bytes()
        path = "analysis/" + member + ".metadata.json"
        owned_files[path] = snapshot
        refs = []
        for filename in (
            "target_metadata.json",
            "target_seeded_metadata.json",
            "target_corrections.json",
            "manual_actions.jsonl",
            "decision_journal.jsonl",
            "source_binary.json",
        ):
            original = directory / filename
            if original.is_file():
                relative = "analysis/" + member + ".original-" + filename
                data = original.read_bytes()
                owned_files[relative] = data
                refs.append({"path": relative, "sha256": digest(data)})
        data = recovered[next(f for f, m in names.items() if m == member)]
        start = 0x800 if member == "main" else 0x78000 if member == "boot" else 0x58000
        phase = (
            "handoff"
            if member == "main"
            else "pre_handoff"
            if member == "boot"
            else "decoded_resource"
        )
        members.append(
            {
                "id": member,
                "kind": "mixed",
                "sha256": digest(data),
                "size": len(data),
                "source": member + ".s",
                "context": {
                    "address_model": "runtime_absolute",
                    "load_address": start,
                    "entrypoint": start,
                    "code_start_offset": 0,
                    "phase": phase,
                },
                "analysis": {
                    "metadata": {"path": path, "sha256": digest(snapshot)},
                    "state_files": refs,
                },
            }
        )
        if editable:
            from amiga_reversing.disasm.analysis_state_paths import STATE_FILES
            from amiga_reversing.disasm.disk_set_state import import_state

            original = {
                name: (directory / name).read_bytes()
                if (directory / name).exists()
                else None
                for name in STATE_FILES
            }
            state, files, _ = import_state(members[-1], original, platform="amiga")
            members[-1]["analysis"]["state"] = state
            owned_files.update(files)
    bank9 = recovered["foft-music-bank9.bin"]
    if bank9 != main[0x57800:0x63B50]:
        raise ValueError("bank9 embedded/separate byte identity differs")
    members.append(
        {
            "id": "music-9",
            "kind": "mixed",
            "sha256": digest(bank9),
            "size": len(bank9),
            "source": None,
            "analysis": None,
            "context": {
                "address_model": "runtime_absolute",
                "load_address": 0x58000,
                "entrypoint": 0x58000,
                "code_start_offset": 0,
                "phase": "decoded_resource",
            },
        }
    )
    relationships = [
        {
            "kind": "embedded",
            "member": "music-9",
            "owner": "main",
            "offset": 0x57800,
            "size": 50000,
            "evidence": "Complete independently decoded disk resource9 equals the main source span. One canonical analysis owner; no callback or runtime closure.",
        }
    ]
    for source, member, descriptor, target_offset, size, trigger in [
        ("boot", "main", 0x8FA, 0, 456000, "Original boot descriptor1"),
        ("boot", "main", 0x90A, 456000, 33472, "Original boot descriptor2"),
        (
            "main",
            "music-5",
            0x3FBF0,
            0,
            29578,
            "HELP / disc prompt / menu9 or17 / Return",
        ),
        ("main", "music-9", 0x3FC30, 0, 50000, "HELP / disc prompt / menu18 / Return"),
    ]:
        target = next(v for v in members if v["id"] == member)
        relationships.append(
            {
                "kind": "load",
                "source": source,
                "member": member,
                "source_offset": descriptor,
                "source_size": 16,
                "member_offset": target_offset,
                "size": size,
                "destination": target["context"]["load_address"] + target_offset,
                "trigger": trigger,
                "evidence": "Static original descriptor bytes rechecked during migration; does not assert a newly observed transfer.",
            }
        )
    manifest = {
        "schema_version": 1,
        "kind": "disk_set",
        "id": "amiga_raw_foft",
        "name": "Federation of Free Traders — SPS 0613",
        "project_id": "foft",
        "build_id": "amiga_sps0613",
        "platform": "amiga",
        "package_sha256": "0" * 64,
        "media": [
            {
                "id": "game-disc",
                "sha256": digest(image),
                "size": len(image),
                "codec": "ipf_resource_recovery",
                "recipe": {
                    "path": "recipes/sps0613.json",
                    "sha256": digest(recipe_bytes),
                },
                "outputs": names,
            }
        ],
        "members": members,
        "relationships": relationships,
    }
    bindings = {"game-disc": str(image_path.resolve())}
    target = output / "targets" / manifest["id"]
    owner = create_disk_set(
        target, manifest, packages, owned_files, bindings, project_root=output
    )
    print("Verified one disk-set owner and recovered four members", flush=True)
    projects = list_projects(output)
    if len(projects) != 1 or projects[0].target_count != 4:
        raise ValueError("migration did not produce exactly one four-member owner")
    summaries = {
        member: execute_owner(
            target,
            {
                "operation": "query",
                "kind": "summary",
                "member_id": member,
                "media_paths": bindings,
            },
            project_root=output,
        )["items"]
        for member in LEGACY
    }
    view = execute_owner(
        target,
        {
            "operation": "query",
            "kind": "instructions",
            "member_id": "music-9",
            "media_paths": bindings,
            "source_offset": 0,
            "end_offset": 4,
            "limit": 1,
        },
        project_root=output,
    )
    if (
        view["scope"]["analysis_member_id"] != "main"
        or view["scope"]["source_offset_bias"] != 0x57800
    ):
        raise ValueError("bank9 acquired a competing analysis owner")
    regenerated = owner.regenerate(bindings)
    (output / "regeneration.json").write_text(json.dumps(regenerated, indent=2) + "\n")
    print(
        "All three native member projections reproduce the owned source bundle",
        flush=True,
    )
    built = owner.build(
        output / "rebuilt", bindings, vasm=ROOT / "tools/vasmm68k_mot.exe"
    )
    print("Both assemblers and aggregate IPF re-decode are exact", flush=True)
    negative = None
    if exercise_missing:
        rebuild = IpfResources.rebuild

        def skip_copy(original, plan, outputs, *, project_root):
            reduced = copy.deepcopy(plan)
            reduced["actions"] = [
                a for a in reduced["actions"] if a["file"] != "foft-music-bank9.bin"
            ]
            result, receipt = rebuild(
                original,
                reduced,
                {f: b for f, b in outputs.items() if f != "foft-music-bank9.bin"},
                project_root=project_root,
            )
            if result != original:
                raise AssertionError(
                    "counterexample must preserve the whole original image hash"
                )
            return result, receipt

        with patch.object(IpfResources, "rebuild", staticmethod(skip_copy)):
            try:
                owner.build(
                    output / "missing-placement-negative",
                    bindings,
                    vasm=ROOT / "tools/vasmm68k_mot.exe",
                )
            except ValueError as error:
                if "placement write coverage" not in str(error):
                    raise
                negative = {
                    "missing": "music-9 separate disk copy",
                    "whole_image_still_exact": True,
                    "rejected": str(error),
                }
            else:
                raise AssertionError("a template-backed omitted placement passed")
    summary = {
        "owner": owner.manifest["id"],
        "project_id": "foft",
        "build_id": "amiga_sps0613",
        "status": "private migration rehearsal; live targets unchanged",
        "revision": owner.revision,
        "source_package_sha256": owner.package["sha256"],
        "members": built["members"],
        "summaries": summaries,
        "regeneration": regenerated,
        "coverage": built["coverage"],
        "image_sha256": built["media"]["game-disc"]["sha256"],
        "regenerated_sectors": built["media"]["game-disc"]["codec_receipt"][
            "regenerated_sectors"
        ],
        "missing_placement_negative": negative,
        "runtime": "not tested",
    }
    (output / "migration-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check-missing-placement", action="store_true")
    parser.add_argument(
        "--editable",
        action="store_true",
        help="Rehearse explicit member journal bindings, retaining original files",
    )
    args = parser.parse_args()
    result = stage(
        args.image,
        args.output,
        exercise_missing=args.check_missing_placement,
        editable=args.editable,
    )
    print(json.dumps({k: v for k, v in result.items() if k != "coverage"}, indent=2))


if __name__ == "__main__":
    main()

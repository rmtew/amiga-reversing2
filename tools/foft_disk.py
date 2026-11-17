"""Extract verified private FOFT resources or rebuild exact spans in an IPF template.

The rebuild runs both source-only assemblers before selecting either span. It
does not launch an emulator, write the original, or register a runtime scenario.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from amiga_reversing.disasm.ipf_resources import (
    digest,
    rebuild_resources,
    recover_resources,
)
from amiga_reversing.disasm.source_package_publish import load_published_source_package
from amiga_reversing.disasm.stx_recovery import read_ipf
from tools.foft_baseline import build

RECIPE = ROOT / "recipes/foft/sps0613-resources.json"


def resource_plan(music_resource=9):
    """Select only a reviewed content identity, never an address-based bank."""
    if type(music_resource) is not int or music_resource not in (5, 9):
        raise ValueError("unsupported reviewed music resource")
    plan = json.loads(RECIPE.read_bytes())
    recipes = {str(RECIPE.relative_to(ROOT)): digest(RECIPE.read_bytes())}
    if music_resource == 5:
        path = ROOT / "recipes/foft/sps0613-music-resource5.json"
        extra = json.loads(path.read_bytes())
        if any(
            extra[k] != plan[k] for k in ("image_sha256", "geometry", "codec", "kind")
        ):
            raise ValueError("music resource source/geometry differs")
        plan["actions"] = [
            a for a in plan["actions"] if a["resource"]["id"] != "music-resource-9"
        ] + extra["actions"]
        plan["evidence"]["selected_music_resource"] = extra["evidence"]
        recipes[str(path.relative_to(ROOT))] = digest(path.read_bytes())
    return plan, recipes


def private_directory(path):
    path = path.resolve()
    allowed = [Path("/tmp").resolve(), ROOT / "bin/rebuilt", ROOT / ".amiga_reversing"]
    if not any(path.is_relative_to(base) and path != base for base in allowed):
        raise ValueError(
            "output must be a fresh private scratch or ignored build directory"
        )
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["extract", "rebuild"])
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--vasm", type=Path)
    parser.add_argument("--music-resource", type=int, choices=[5, 9], default=9)
    args = parser.parse_args()
    if args.operation == "rebuild" and not args.vasm:
        parser.error("rebuild requires an independent --vasm assembler")
    image, _ = read_ipf(args.image)
    if args.image.read_bytes() != image:
        raise ValueError("use the exact raw bound IPF input")
    plan, recipes = resource_plan(args.music_resource)
    receipt, resources = recover_resources(image, plan, project_root=ROOT)
    output = private_directory(args.output)
    if args.operation == "rebuild":
        package = load_published_source_package(ROOT / "targets/amiga_raw_foft")
        build_receipt = build(output / "assembly", args.vasm)
        if (
            load_published_source_package(ROOT / "targets/amiga_raw_foft")["sha256"]
            != package["sha256"]
        ):
            raise ValueError("source package changed during assembly")
        program = (output / "assembly/foft-native.bin").read_bytes()
        oracle = (output / "assembly/foft-vasm.bin").read_bytes()
        if program != oracle:
            raise ValueError("independent source assemblies differ")
        bank_target = (
            ROOT / f"targets/amiga_raw_foft_music_bank{args.music_resource}_sps0613"
        )
        bank_package = load_published_source_package(bank_target)
        bank_action = next(
            a
            for a in plan["actions"]
            if a["resource"]["id"] == f"music-resource-{args.music_resource}"
        )
        bank_build = build(
            output / "bank-assembly",
            args.vasm,
            target=bank_target,
            expected=bank_action["sha256"],
            size=bank_action["size"],
            load_address=0x58000,
            stem="bank",
        )
        bank = (output / "bank-assembly/bank-native.bin").read_bytes()
        if (
            args.music_resource == 9 and bank != program[0x57800:0x63B50]
        ) or load_published_source_package(bank_target)["sha256"] != bank_package[
            "sha256"
        ]:
            raise ValueError("independent bank source or correspondence changed")
        # Fixed reviewed correspondence to the one restored source image. Bank
        # identity comes from the recipe, never from its destination address.
        assembled = {
            "foft-program.bin": program,
            bank_action["file"]: bank,
        }
        loader_target = ROOT / "targets/amiga_raw_foft_boot_loader_sps0613"
        loader_package = load_published_source_package(loader_target)
        loader_action = next(
            a for a in plan["actions"] if a["resource"]["id"] == "boot-loader-prefix"
        )
        loader_build = build(
            output / "loader-assembly",
            args.vasm,
            target=loader_target,
            expected=loader_action["sha256"],
            size=4000,
            load_address=0x78000,
            stem="loader",
        )
        assembled["foft-boot-loader.bin"] = (
            output / "loader-assembly/loader-native.bin"
        ).read_bytes()
        if (
            load_published_source_package(loader_target)["sha256"]
            != loader_package["sha256"]
        ):
            raise ValueError("loader source package changed during assembly")
        rebuilt, receipt = rebuild_resources(image, plan, assembled, project_root=ROOT)
        path = output / "foft-rebuilt.ipf"
        path.write_bytes(rebuilt)
        path.chmod(0o600)
        receipt["source_build"] = {
            "target": "amiga_raw_foft",
            "package_sha256": package["sha256"],
            "recipe_sha256": digest(RECIPE.read_bytes()),
            "recipes": recipes,
            "music_resource": args.music_resource,
            "builds": build_receipt,
            "bank_build": {
                "target": bank_target.name,
                "package_sha256": bank_package["sha256"],
                "builds": bank_build,
            },
            "spans": [
                {"file": "foft-program.bin", "source_offset": 0, "length": 489472},
                {
                    "file": bank_action["file"],
                    "target": bank_target.name,
                    "source_offset": 0,
                    "parent_correspondence": {"source_offset": 0x57800, "length": 50000}
                    if args.music_resource == 9
                    else None,
                    "length": bank_action["size"],
                },
                {
                    "file": "foft-boot-loader.bin",
                    "target": loader_target.name,
                    "source_offset": 0,
                    "length": 4000,
                },
            ],
            "loader_build": {
                "target": loader_target.name,
                "package_sha256": loader_package["sha256"],
                "builds": loader_build,
            },
        }
    else:
        for name, data in resources.items():
            path = output / name
            path.write_bytes(data)
            path.chmod(0o600)
    if args.image.read_bytes() != image:
        # This command accepts a raw IPF, not an archive. Reject accidental
        # ambiguity before describing original-byte preservation as checked.
        raise ValueError("use the exact raw bound IPF input")
    receipt["original_file_unchanged"] = (
        digest(args.image.read_bytes()) == plan["image_sha256"]
    )
    if not receipt["original_file_unchanged"]:
        raise ValueError("original media changed during operation")
    path = output / "receipt.json"
    path.write_text(json.dumps(receipt, indent=2) + "\n")
    path.chmod(0o600)
    print(
        json.dumps(
            {
                "operation": args.operation,
                "receipt": str(path),
                "image_sha256": plan["image_sha256"],
                "resources": {
                    name: {"size": len(data), "sha256": digest(data)}
                    for name, data in resources.items()
                },
                "runtime": "Not tested; no supported FOFT original-media scenario",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

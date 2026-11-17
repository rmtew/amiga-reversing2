"""Bind private input, regenerate native source, or assemble the committed package.

Build requires no original program, ROM, disk, emulator or Ghidra installation.
Regeneration requires only the hash-verified private program and native backend.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
TARGET = ROOT / "targets/amiga_raw_foft"
ID = TARGET.name
EXPECTED = "85e2684b03badc7308e7eaa059b7c717441808798f55b4642e1d8b1895914c9b"
SIZE = 489472


def require_legacy_binary_target():
    manifest = TARGET / "manifest.json"
    if manifest.exists() and json.loads(manifest.read_bytes()).get("kind") == "disk_set":
        raise ValueError("Use disk-set Restore with member_id and private media bindings for input and regeneration operations")


def verify(data, *, expected=EXPECTED, size=SIZE, load_address=0x800):
    actual = hashlib.sha256(data).hexdigest()
    if len(data) != size or actual != expected:
        raise ValueError(f"Whole program differs: {len(data)} bytes, SHA256 {actual}")
    return {
        "bytes": len(data),
        "sha256": actual,
        "start": hex(load_address),
        "end_exclusive": hex(load_address+size),
        "whole_file_exact": True,
    }


def bind(path):
    require_legacy_binary_target()
    data = path.read_bytes()
    result = verify(data)
    if (TARGET / "binary.bin").exists() and (
        TARGET / "binary.bin"
    ).read_bytes() != data:
        raise ValueError("Refusing to replace different private bound bytes")
    (TARGET / "binary.bin").write_bytes(data)
    return dict(operation="bind", private=True, **result)


def render(check=False):
    require_legacy_binary_target()
    from amiga_reversing.disasm.binary_source import resolve_target_binary_source
    from amiga_reversing.disasm.effective_metadata import effective_metadata_file
    from amiga_reversing.disasm.source_package import validate_source_package
    from amiga_reversing.disasm.source_package_publish import (
        load_published_source_package,
    )
    from amiga_reversing.disasm.source_rendering import (
        publish_rendered_source,
        render_source_from_binary_source_or_raise,
    )

    verify((TARGET / "binary.bin").read_bytes())
    source = resolve_target_binary_source(TARGET, ROOT)
    with effective_metadata_file(TARGET) as metadata:
        result = render_source_from_binary_source_or_raise(
            target_id=ID,
            binary_source=source,
            target_dir=TARGET,
            metadata_path=metadata,
            project_root=ROOT,
        )
    package = result.source_package
    if not package:
        raise ValueError("Persisted binary-asset output policy was not honored")
    if check:
        current = load_published_source_package(TARGET)
        if current["sha256"] != package["sha256"] or validate_source_package(
            current
        ) != validate_source_package(package):
            raise ValueError(
                "Committed source/support/assets differ from clean native regeneration"
            )
    else:
        publish_rendered_source(
            result, TARGET / "source.s", target_id=ID, project_root=ROOT
        )
    records = package["manifest"]["files"]
    return {
        "operation": "render",
        "checked": check,
        "package_sha256": package["sha256"],
        "files": len(records),
        "assets": [
            {"path": r["path"], "bytes": r["size"], "sha256": r["sha256"]}
            for r in records
            if r["kind"] == "asset"
        ],
    }


def build(output, vasm=None, *, target=None, expected=EXPECTED, size=SIZE,
          load_address=0x800, stem="foft"):
    from amiga_reversing.disasm.c_backend import (
        assemble_platform_source_path_with_c_backend,
    )
    from amiga_reversing.disasm.source_package import materialize_source_package
    from amiga_reversing.disasm.source_package_publish import (
        load_published_source_package,
    )

    package = load_published_source_package(TARGET if target is None else target)
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    # The assemblers see only committed source, INCBINs and collected SDK files
    # in a fresh package directory, not a hidden binary.bin or caller's CWD.
    with tempfile.TemporaryDirectory(prefix="foft-clean-assembly-") as tmp:
        stage = Path(tmp)
        source = materialize_source_package(package, stage)
        native, _ = assemble_platform_source_path_with_c_backend(
            "amiga-raw",
            source,
            include_dir=stage,
            target_cpu="68000",
            project_root=ROOT,
        )
        result = {"operation": "build", "native": verify(native, expected=expected, size=size, load_address=load_address)}
        (output / f"{stem}-native.bin").write_bytes(native)
        if vasm:
            binary = output / f"{stem}-vasm.bin"
            completed = subprocess.run(
                [
                    str(vasm.resolve()),
                    "-quiet",
                    "-Fbin",
                    "-m68000",
                    "-no-opt",
                    "-nosym",
                    "-o",
                    str(binary),
                    source.name,
                ],
                cwd=stage,
                text=True,
                capture_output=True,
            )
            if completed.returncode:
                raise ValueError("vasm failed:\n" + completed.stdout + completed.stderr)
            result["vasm"] = verify(binary.read_bytes(), expected=expected, size=size, load_address=load_address)
            if binary.read_bytes() != native:
                raise ValueError("C and vasm differ")
    return result


def inventory():
    require_legacy_binary_target()
    from amiga_reversing.disasm.binary_source import resolve_target_binary_source
    from amiga_reversing.disasm.c_backend import (
        analyze_project_source_with_render_evidence_from_c_backend,
    )
    from amiga_reversing.disasm.effective_metadata import effective_metadata_file

    verify((TARGET / "binary.bin").read_bytes())
    with effective_metadata_file(TARGET) as metadata:
        analysis = analyze_project_source_with_render_evidence_from_c_backend(
            resolve_target_binary_source(TARGET, ROOT),
            metadata_path=metadata,
            project_root=ROOT,
        )
    return summarize_analysis(analysis)


def summarize_analysis(analysis):
    from amiga_reversing.disasm.c_backend import native_backend_identity
    from amiga_reversing.disasm.progress_scorecard import build_scorecard

    data = (json.dumps(analysis, sort_keys=True) + "\n").encode()
    output = ROOT / "bin/rebuilt/foft"
    output.mkdir(parents=True, exist_ok=True)
    (output / "baseline-analysis.json").write_bytes(data)
    metadata = json.loads((TARGET / "target_metadata.json").read_text())
    package = json.loads((TARGET / "source-package-manifest.json").read_text())
    identity = {
        "target": ID,
        "payload_sha256": EXPECTED,
        "source_version": hashlib.sha256(
            (TARGET / "source.s").read_bytes()
        ).hexdigest(),
        "analysis_sha256": hashlib.sha256(data).hexdigest(),
        "analyzer": {"native_sha256": native_backend_identity(ROOT)["sha256"]},
        "metadata_sha256": hashlib.sha256(
            (TARGET / "target_metadata.json").read_bytes()
        ).hexdigest(),
        "package_manifest_sha256": hashlib.sha256(
            (TARGET / "source-package-manifest.json").read_bytes()
        ).hexdigest(),
    }
    card = build_scorecard(
        analysis, identity=identity, metadata=metadata, package=package, entry_offset=0
    )
    from collections import Counter

    s = analysis["sections"][0]
    counts = Counter()
    for row in s.get("range_ownerships", []):
        if row.get("status_name") == "accepted":
            counts[row.get("role") or row.get("kind_name") or "unspecified"] += (
                row["end_offset"] - row["start_offset"]
            )
    return {
        "schema_version": 1,
        "identity": identity,
        "metrics": card["metrics"],
        "ownership_record_bytes_by_role": dict(sorted(counts.items())),
        "caveat": "Role totals count ownership records and can overlap; payload.unclassified_bytes is a clipped union complement. Exact byte assembly is not semantic completion. No workspace or gameplay qualification is claimed.",
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="operation", required=True)
    q = sub.add_parser("bind")
    q.add_argument("path", type=Path)
    q = sub.add_parser("render")
    q.add_argument("--check", action="store_true")
    q = sub.add_parser("build")
    q.add_argument("--output", type=Path, default=ROOT / "bin/rebuilt/foft")
    q.add_argument("--vasm", type=Path)
    sub.add_parser("inventory")
    args = p.parse_args()
    if args.operation == "bind":
        r = bind(args.path)
    elif args.operation == "render":
        r = render(args.check)
    elif args.operation == "build":
        r = build(args.output, args.vasm)
    else:
        r = inventory()
    print(json.dumps(r, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

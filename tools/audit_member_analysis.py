"""Audit existing standalone raw member facts before sharing their analysis.

Read-only: unmatched facts are not dropped, accepted or automatically rebased.
Output is analysis/provenance, never the source media or member payload.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from amiga_reversing.disasm.binary_source import (
    RawBinarySource,
    read_binary_source_bytes,
    resolve_target_binary_source,
)
from amiga_reversing.disasm.disk_codecs import digest
from amiga_reversing.disasm.effective_metadata import effective_metadata_file
from amiga_reversing.disasm.metadata_slice import audit_raw_metadata_slice
from amiga_reversing.disasm.target_metadata import TargetMetadata


def audit(owner, member, *, start, size):
    sources, metadata, inventories = {}, {}, {}
    for name in (owner, member):
        directory = ROOT / "targets" / name
        if directory.parent != ROOT / "targets":
            raise ValueError("use an existing canonical target ID")
        source = resolve_target_binary_source(directory)
        if not isinstance(source, RawBinarySource):
            raise ValueError("audit requires existing raw source contexts")
        sources[name] = source
        with effective_metadata_file(directory) as path:
            metadata[name] = TargetMetadata.from_dict(
                json.loads(Path(path).read_bytes())
            )
        inventories[name] = {
            p: digest((directory / p).read_bytes())
            for p in (
                "target_metadata.json",
                "target_seeded_metadata.json",
                "target_corrections.json",
                "manual_actions.jsonl",
                "decision_journal.jsonl",
            )
            if (directory / p).is_file()
        }
    a, b = (
        read_binary_source_bytes(sources[owner]),
        read_binary_source_bytes(sources[member]),
    )
    if (
        type(start) is not int
        or start < 0
        or size != len(b)
        or a[start : start + size] != b
    ):
        raise ValueError("member bytes do not match the exact proposed owner slice")
    if (
        sources[owner].address_model != sources[member].address_model
        or sources[owner].load_address + start != sources[member].load_address
    ):
        raise ValueError("member runtime address correspondence differs")
    return {
        "kind": "existing_member_analysis_audit",
        "owner": owner,
        "member": member,
        "owner_sha256": digest(a),
        "member_sha256": digest(b),
        "original_files": inventories,
        **audit_raw_metadata_slice(
            metadata[owner], metadata[member], start=start, size=size
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--member", required=True)
    parser.add_argument("--start", type=lambda x: int(x, 0), required=True)
    parser.add_argument("--size", type=lambda x: int(x, 0), required=True)
    args = parser.parse_args()
    result = audit(args.owner, args.member, start=args.start, size=args.size)
    print(json.dumps(result, indent=2))
    return 0 if result["safe_to_retire_without_resolution"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

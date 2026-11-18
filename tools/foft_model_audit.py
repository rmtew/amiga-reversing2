"""Recheck only pinned FOFT face spans and existing native operand witnesses.

Read-only; no scanning, instruction decoding, CFG inference, code admission,
rendering or media writes. Private input bytes remain in the bound disk member.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from amiga_reversing.disasm.disk_set import DiskSet
from amiga_reversing.disasm.disk_set_state import _artifact
from amiga_reversing.disasm.projected_face_audit import (
    audit_face_views,
    check_immediate_operand,
)
from amiga_reversing.disasm.target_history import target_lock


def audit_native(payload, mapping, *, instruction, references):
    """Callbacks query the normal native artifact, never synthesized code facts."""
    if hashlib.sha256(payload).hexdigest() != mapping["main_payload_sha256"]:
        raise ValueError("source member fingerprint differs from the pinned map")
    base = mapping["load_address"]
    results = []
    for entry in mapping["entries"]:
        if not entry["body_protocol_traced"]:
            continue
        body, operands = entry["recognized_body"], entry["routine_operands"]
        lo, hi = body["runtime_start"] - base, body["runtime_end"] - base
        if (
            not 0 <= lo < hi <= len(payload)
            or hashlib.sha256(payload[lo:hi]).hexdigest() != body["sha256"]
        ):
            raise ValueError("recognized model body fingerprint differs")
        projection = instruction(operands["projection_argument_runtime"])
        check_immediate_operand(
            projection, value=body["projection_max_byte_offset"], register="D0"
        )
        projected = instruction(operands["projection_call_runtime"])
        if not any(
            f["access"] == "branch_target"
            and f["absolute_address"] == operands["projection_reader_runtime"]
            for f in projected["operand_facts"]
        ):
            raise ValueError("native projection dispatch differs")
        for view in entry["geometry"]["views"]:
            count = instruction(
                view.get(
                    "face_count_argument_runtime",
                    operands["face_count_argument_runtime"],
                )
            )
            check_immediate_operand(count, value=view["face_count"] - 1, register="D0")
            refs = [
                r
                for r in references(view["load_runtime"])
                if r["source_offset"] + base == view["load_runtime"]
                and r["operand_index"] == 0
            ]
            if (
                len(refs) != 1
                or refs[0]["target_offset"] + base != view["start_runtime"]
            ):
                raise ValueError("native face-load reference differs")
            dispatch = instruction(view["call_runtime"])
            if not any(
                f["access"] == "branch_target"
                and f["absolute_address"] == operands["face_reader_runtime"]
                for f in dispatch["operand_facts"]
            ):
                raise ValueError("native face dispatch differs")
        parsed = audit_face_views(
            payload,
            load_address=base,
            views=[
                {**v, "projection_max_byte_offset": body["projection_max_byte_offset"]}
                for v in entry["geometry"]["views"]
            ],
            projection_stride=10,
            style_count=32,
        )
        geometry = entry["geometry"]
        if (
            parsed["covered_spans"]
            != [
                {
                    "start_runtime": geometry["start_runtime"],
                    "end_runtime": geometry["end_runtime"],
                }
            ]
            or parsed["unique_physical_records"] != geometry["unique_face_records"]
            or parsed["shared_record_starts"] != geometry["shared_face_record_runtimes"]
        ):
            raise ValueError("face union or sharing differs from the map")
        results.append({"index": entry["index"], "symbol": entry["symbol"], **parsed})
    coverage = mapping.get("coverage")
    if coverage is not None and (
        coverage["body_protocols_traced"] != len(results)
        or coverage["geometry_unique_faces"]
        != sum(r["unique_physical_records"] for r in results)
        or coverage["geometry_union_bytes"] != sum(r["covered_bytes"] for r in results)
    ):
        raise ValueError("aggregate face coverage differs from checked spans")
    return {
        "kind": "pinned_projected_face_span_audit",
        "revision": mapping["revision"],
        "models": results,
        "model_count": len(results),
        "physical_face_records": sum(r["unique_physical_records"] for r in results),
        "geometry_bytes": sum(r["covered_bytes"] for r in results),
        "inference_or_mutation": False,
        "runtime_verified": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--map", type=Path, default=ROOT / "docs/validation/foft-ship-model-map.json"
    )
    parser.add_argument(
        "--media", action="append", required=True, metavar="ID=PRIVATE_PATH"
    )
    args = parser.parse_args()
    mapping = json.loads(args.map.read_text())
    if mapping["target_id"] != "amiga_raw_foft" or mapping["member_id"] != "main":
        raise ValueError("this recipe uses the existing FOFT main member only")
    media = dict(value.split("=", 1) for value in args.media)
    root = ROOT / "targets" / mapping["target_id"]
    with target_lock(root):
        owner = DiskSet.load(root, project_root=ROOT)
        if owner.revision != mapping["revision"]:
            raise ValueError("map revision differs; review before re-pinning it")
        source, artifact = _artifact(owner, "main", media)
        try:
            base = mapping["load_address"]

            def instruction(address):
                rows = artifact.query_payload(
                    "instructions",
                    section_index=0,
                    source_offset=address - base,
                    end_offset=address - base + 2,
                    limit=2,
                )["items"]
                if len(rows) != 1 or rows[0]["source_offset"] + base != address:
                    raise ValueError(
                        "witness is not an existing native instruction boundary"
                    )
                return rows[0]

            def references(address):
                page = artifact.query_payload(
                    "references",
                    section_index=0,
                    source_offset=address - base,
                    end_offset=address - base + 2,
                    direction="outgoing",
                    limit=100,
                )
                if page["has_more"]:
                    raise ValueError("ambiguous or unsupported native reference extent")
                return page["items"]

            print(
                json.dumps(
                    audit_native(
                        source.read_bytes(),
                        mapping,
                        instruction=instruction,
                        references=references,
                    ),
                    indent=2,
                )
            )
        finally:
            artifact.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

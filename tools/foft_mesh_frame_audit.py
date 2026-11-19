"""Read-only frame-WORD provenance inventory and explicitly conditional induction."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.foft_music_menu_probe import probe as resource_probe


def instruction_digest(rows):
    """Bind accepted bytes to source coordinates, including repeated opcodes."""
    return hashlib.sha256(
        json.dumps(
            [(r["source_offset"], r["bytes"]) for r in rows], separators=(",", ":")
        ).encode()
    ).hexdigest()


def write_inventory(rows, start, size):
    counts = {
        "explicit_memory_write_operands": 0,
        "absolute": 0,
        "indirect_exact": 0,
        "indirect_without_exact_address": 0,
    }
    hits = []
    for r in rows:
        for o in r["operand_facts"]:
            # Register writes and register-list outputs are not memory writes.
            if not o.get("memory") or o["access"] != "memory_write":
                continue
            counts["explicit_memory_write_operands"] += 1
            absolute = o.get("absolute_address")
            spans = []
            if absolute is not None:
                counts["absolute"] += 1
                width = o["width_bytes"]
                if o.get("bulk_transfer"):
                    lists = [
                        x["register_list"]
                        for x in r["operand_facts"]
                        if x["access"] == "register_list_read"
                        and x.get("register_list")
                    ]
                    if len(lists) != 1:
                        raise ValueError("bulk write register footprint is unknown")
                    width *= len(lists[0])
                if width <= 0:
                    raise ValueError("absolute write footprint is unknown")
                spans = [(absolute, width)]
            else:
                spans = sorted(
                    {
                        (e["address"], e["width_bytes"])
                        for e in r["address_evidence"]
                        if e["operand_index"] == o["operand_index"]
                        and e.get("has_address")
                        and not e.get("conflicted")
                        and e.get("width_bytes", 0) > 0
                    }
                )
                counts[
                    "indirect_exact"
                    if len(spans) == 1
                    else "indirect_without_exact_address"
                ] += 1
                if len(spans) != 1:
                    continue
            for address, width in spans:
                if address < start + size and address + width > start:
                    hits.append(
                        {
                            "source_offset": r["source_offset"],
                            "operand_index": o["operand_index"],
                            "start_runtime": address,
                            "bytes": width,
                        }
                    )
    return {
        "counts": counts,
        "frame_write_sites": hits,
        "global_alias_closure": False,
        "scope": "Explicit accepted memory-write operand sites, not dynamic write counts; implicit stack/DMA effects are separate.",
    }


def conditional_induction(initial, offsets, frame_bytes, owner_bytes):
    if initial != 0 or not offsets or frame_bytes <= 0:
        raise ValueError("initial state or frame contract differs")
    n = len(offsets)
    if n > 32767 or offsets != [i * frame_bytes for i in range(n)]:
        raise ValueError("frame offsets differ")
    if 2 * (n - 1) > 32767 or any(o > 32767 for o in offsets):
        raise ValueError("signed WORD index/offset domain exceeded")
    if any(o + frame_bytes > owner_bytes for o in offsets):
        raise ValueError("frame extent exceeds the owner")
    # These are mathematical transition cases, not execution of game inputs.
    cases = [(old, old, old + increment) for old in range(n) for increment in (0, 1)]
    if any(
        not 0 <= selected < n or not 0 <= after <= n for _, selected, after in cases
    ):
        raise ValueError("ordinary transition is not closed")
    return {
        "initial": 0,
        "conditional_stored_range": [0, n],
        "conditional_selected_range": [0, n - 1],
        "transition_cases": len(cases),
        "selection_uses_old_value": True,
        "terminal_guard_stops_at": n,
        "requires_other_writers_to_preserve_word": True,
        "unconditional_receiver_fact": False,
    }


def audit(payload, rows, mapping):
    if (
        len(payload) != mapping["size"]
        or hashlib.sha256(payload).hexdigest() != mapping["sha256"]
    ):
        raise ValueError("source identity differs")
    if (
        len(rows) != mapping["instruction_count"]
        or instruction_digest(rows) != mapping["instruction_coordinate_sha256"]
    ):
        raise ValueError("accepted instruction witness differs")
    result = write_inventory(rows, mapping["frame_runtime"], 2)
    if result["frame_write_sites"] != mapping["expected_frame_write_sites"]:
        raise ValueError("known frame writer inventory differs")
    initial = int.from_bytes(
        payload[mapping["frame_runtime"] - 2048 : mapping["frame_runtime"] - 2048 + 2],
        "big",
    )
    lo = mapping["offsets_runtime"] - 2048
    offsets = [
        int.from_bytes(payload[lo + i * 2 : lo + i * 2 + 2], "big") for i in range(12)
    ]
    result["conditional_induction"] = conditional_induction(initial, offsets, 90, 1080)
    resources = resource_probe(payload)["resource_descriptors"]
    result["initial_resource_overlaps_frame"] = [
        r["index"]
        for r in resources
        if r["destination"] < mapping["frame_runtime"] + 2
        and r["end"] > mapping["frame_runtime"]
    ]
    if result["initial_resource_overlaps_frame"]:
        raise ValueError("initial resource range intersects frame WORD")
    result.update(
        kind="foft_mesh_frame_boundary_audit",
        offline_work_closed=True,
        global_frame_invariant_proved=False,
        guest_execution=False,
    )
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--map",
        type=Path,
        default=ROOT / "docs/validation/foft-mesh-frame-boundary.json",
    )
    p.add_argument("--media", action="append", required=True)
    args = p.parse_args()
    m = json.loads(args.map.read_text())
    from amiga_reversing.disasm.disk_set import DiskSet
    from amiga_reversing.disasm.disk_set_state import _artifact
    from amiga_reversing.disasm.target_history import target_lock

    root = ROOT / "targets" / m["target_id"]
    with target_lock(root):
        owner = DiskSet.load(root, project_root=ROOT)
        if owner.revision != m["revision"]:
            raise ValueError("review before repinning audit revision")
        source, a = _artifact(owner, "main", dict(x.split("=", 1) for x in args.media))
        try:
            rows = []
            offset = 0
            while True:
                page = a.query_payload(
                    "instructions", section_index=0, offset=offset, limit=100
                )
                rows += page["items"]
                offset += len(page["items"])
                if not page["has_more"]:
                    break
            result = audit(source.read_bytes(), rows, m)
            refs = a.query_payload(
                "references",
                section_index=0,
                source_offset=m["frame_runtime"] - 2048,
                end_offset=m["frame_runtime"] - 2046,
                direction="incoming",
                limit=100,
            )
            if refs["has_more"] or [
                (r["source_offset"], r["operand_index"]) for r in refs["items"]
            ] != [tuple(x) for x in m["expected_incoming_refs"]]:
                raise ValueError("frame reference witness differs")
            result["revision"] = owner.revision
            print(json.dumps(result, indent=2))
        finally:
            a.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

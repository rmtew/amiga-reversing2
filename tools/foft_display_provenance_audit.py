"""Read-only checks of reviewed display stores, source windows and native facts.

This parses existing sprite-source bytes and arithmetic view relations. It
neither executes guest code nor predicts live Copper/IRQ/DMA scheduling.
"""

import argparse
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.foft_burst_audit import digest, span


def sprite_source(data, contract):
    rows = contract["body_pairs"]
    if type(rows) is not int or rows < 1 or len(data) != 8 + rows * 4:
        raise ValueError("sprite source extent differs")
    position = int.from_bytes(data[:2], "big")
    control = int.from_bytes(data[2:4], "big")
    pair = b"".join(w.to_bytes(2, "big") for w in contract["body_pair_words"])
    if len(pair) != 4 or data[4:-4] != pair * rows or data[-4:] != bytes(4):
        raise ValueError("uniform body or final zero pair differs")
    if position != contract["position_word"] or control != contract["control_word"]:
        raise ValueError("initial sprite header differs")
    decode = lambda pos, ctl: (
        ((pos >> 8) & 255) | ((ctl & 4) << 6),
        ((ctl >> 8) & 255) | ((ctl & 2) << 7),
    )
    start, stop = decode(
        int.from_bytes(pair[:2], "big"), int.from_bytes(pair[2:], "big")
    )
    if start != stop:
        raise ValueError("remaining source pairs are not zero-height controls")
    low, high = contract["conditional_offsets"]
    if any(type(v) is not int for v in [low, high]) or not 0 <= low <= high <= 255:
        raise ValueError("conditional offset range differs")
    heights = []
    next_pairs = []
    for offset in range(low, high + 1):
        low_start = (contract["header_base"] - offset) & 255
        start, stop = decode((low_start << 8) | (position & 255), control)
        height = stop - start
        if not 0 <= height <= rows:
            raise ValueError("conditional first segment exceeds the known source")
        heights.append(height)
        next_pairs.append(4 + height * 4)
    return {
        "first_rows_min": min(heights),
        "first_rows_max": max(heights),
        "first_next_pair_min": min(next_pairs),
        "first_next_pair_max": max(next_pairs),
        "remaining_pairs_zero_height": True,
        "final_zero_pair_offset": len(data) - 4,
        "live_fetch_or_termination_proved": False,
    }


def audit(payload, mapping):
    if len(payload) != mapping["size"] or digest(payload) != mapping["sha256"]:
        raise ValueError("source member identity differs")
    base = mapping["load_address"]
    stores = []
    sprites = []
    for s in mapping["sprites"]:
        data = span(payload, base, s["start_runtime"], s["end_runtime"])
        if digest(data) != s["sha256"]:
            raise ValueError("sprite source fingerprint differs")
        sprites.append(dict(name=s["name"], **sprite_source(data, s)))
        stores.append((s["start_runtime"], s["end_runtime"]))
    if any(
        a[1] > b[0] for a, b in zip(sorted(stores), sorted(stores)[1:], strict=False)
    ):
        raise ValueError("physically distinct sprite sources overlap")
    scratch = mapping["scratch"]
    src = scratch["source"]
    dst = scratch["backup"]
    for region in [src, dst]:
        data = span(payload, base, region["start_runtime"], region["end_runtime"])
        if len(data) != scratch["bytes"] or digest(data) != region["sha256"]:
            raise ValueError("scratch view extent or fingerprint differs")
    if (
        src["start_runtime"] < dst["end_runtime"]
        and dst["start_runtime"] < src["end_runtime"]
    ):
        raise ValueError("scratch source and backup overlap")
    for store in scratch["surviving_stores"]:
        data = span(payload, base, store["start_runtime"], store["end_runtime"])
        if digest(data) != store["sha256"]:
            raise ValueError("surviving store fingerprint differs")
        if (
            store["start_runtime"] < src["end_runtime"]
            and store["end_runtime"] > src["start_runtime"]
        ):
            raise ValueError("claimed surviving store is inside the restored window")
    scan = mapping["scenery_scan"]
    view_bytes = len(
        span(payload, base, scan["view_start_runtime"], scan["view_end_runtime"])
    )
    producer, reader = scan["producer_stride"], scan["reader_stride"]
    if any(
        type(v) is not int or v < 1
        for v in [producer, reader, scan["conditional_max_count"]]
    ):
        raise ValueError("scan strides/count must be positive")
    residues = [
        i * reader % producer for i in range(producer // math.gcd(producer, reader))
    ]
    if residues != scan["producer_byte_residues"]:
        raise ValueError("overlapping scan relation differs")
    last = reader * (scan["conditional_max_count"] - 1) + scan["last_word_offset"] + 2
    if (
        last > producer * scan["conditional_max_count"]
        or producer * scan["conditional_max_count"] > view_bytes
        or last != scan["conditional_read_end"]
    ):
        raise ValueError("conditional scan extent differs")
    return {
        "kind": "foft_display_provenance_audit",
        "revision": mapping["revision"],
        "sprite_sources": sprites,
        "scratch_bytes": scratch["bytes"],
        "surviving_stores": len(scratch["surviving_stores"]),
        "scan_residues": residues,
        "conditional_scan_end": last,
        "new_ownership_or_code_inferred": False,
        "guest_execution": False,
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--map",
        type=Path,
        default=ROOT / "docs/validation/foft-display-provenance.json",
    )
    p.add_argument("--media", action="append", default=[])
    args = p.parse_args(argv)
    mapping = json.loads(args.map.read_text())
    from amiga_reversing.disasm.disk_set import DiskSet
    from amiga_reversing.disasm.disk_set_state import _artifact
    from amiga_reversing.disasm.target_history import target_lock

    root = ROOT / "targets" / mapping["target_id"]
    with target_lock(root):
        owner = DiskSet.load(root, project_root=ROOT)
        if owner.revision != mapping["revision"]:
            raise ValueError("review and repin the map revision")
        source, artifact = _artifact(
            owner, "main", dict(x.split("=", 1) for x in args.media)
        )
        try:
            result = audit(source.read_bytes(), mapping)
            typed = 0
            for w in mapping["readers"]:
                rows = []
                cursor = 0
                while True:
                    page = artifact.query_payload(
                        "instructions",
                        section_index=0,
                        source_offset=w["start_runtime"] - mapping["load_address"],
                        end_offset=w["end_runtime"] - mapping["load_address"],
                        offset=cursor,
                        limit=100,
                    )
                    rows += page["items"]
                    cursor += len(page["items"])
                    if not page["has_more"]:
                        break
                if (
                    len(rows) != w["instructions"]
                    or digest(b"".join(bytes.fromhex(r["bytes"]) for r in rows))
                    != w["sha256"]
                ):
                    raise ValueError("reviewed native reader window differs")
                if w["name"] == "straight_line_object_producer":
                    typed = sum(
                        sum(
                            a.get("root_struct_name") == "ObjectStateRecord"
                            for a in r["typed_accesses"]
                        )
                        for r in rows
                    )
            if typed != mapping["straight_line_typing"]["after_operands"]:
                raise ValueError(f"native producer field bindings differ: {typed}")
            result.update(
                native_windows=len(mapping["readers"]),
                native_bound_object_operands=typed,
            )
            print(json.dumps(result, indent=2))
        finally:
            artifact.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

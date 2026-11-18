"""Read-only recheck of pinned display-record pointer lists and reader windows.

No pointer scanning, instruction decoding, target admission or source mutation.
The nonempty/look-ahead contract comes from the reviewed original reader.
"""

import argparse
import collections
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def span(payload, base, start, end):
    if (
        type(start) is not int
        or type(end) is not int
        or not 0 <= start - base < end - base <= len(payload)
    ):
        raise ValueError("declared display-data span is outside the member")
    return payload[start - base : end - base]


def audit(payload, mapping):
    if len(payload) != mapping["size"] or digest(payload) != mapping["sha256"]:
        raise ValueError("source member identity differs")
    base = mapping["load_address"]
    records, identical = {}, collections.defaultdict(list)
    for record in mapping["records"]:
        start, end = record["start_runtime"], record["end_runtime"]
        data = span(payload, base, start, end)
        if start in records or start % 2 or len(data) < 6:
            raise ValueError(
                "display records need distinct aligned prefixes and nonempty text"
            )
        text = data[4:]
        if (
            text[-1] != 0
            or any(not 32 <= v < 127 for v in text[:-1])
            or record["text_start_runtime"] != start + 4
            or int.from_bytes(data[:2], "big") != record["x"]
            or int.from_bytes(data[2:4], "big") != record["y"]
            or digest(data) != record["sha256"]
        ):
            raise ValueError(
                "display prefix, exact ASCII/NUL extent or fingerprint differs"
            )
        records[start] = record
        identical[digest(data)].append(start)
    outer = mapping["outer"]
    data = span(payload, base, outer["start_runtime"], outer["end_runtime"])
    if len(data) != 4 * len(mapping["lists"]) or digest(data) != outer["sha256"]:
        raise ValueError("counted outer selector extent differs")
    refs, cells, terminators, list_starts = collections.Counter(), 0, 0, set()
    for index, item in enumerate(mapping["lists"]):
        start, end, count = (
            item["start_runtime"],
            item["end_runtime"],
            item["nonnull_count"],
        )
        if (
            type(count) is not int
            or count < 1
            or start % 2
            or start in list_starts
            or int.from_bytes(data[index * 4 : index * 4 + 4], "big") != start
        ):
            raise ValueError("nonempty list or indexed source address differs")
        values = span(payload, base, start, end)
        if len(values) != (count + 1) * 4 or digest(values) != item["sha256"]:
            raise ValueError("exact pointer-list extent or fingerprint differs")
        pointers = [
            int.from_bytes(values[i : i + 4], "big") for i in range(0, len(values), 4)
        ]
        if pointers[-1] != 0 or any(v == 0 or v not in records for v in pointers[:-1]):
            raise ValueError(
                "list needs valid prefix addresses then an unconsumed zero sentinel"
            )
        list_starts.add(start)
        refs.update(pointers[:-1])
        cells += len(pointers)
        terminators += 1
    if set(refs) != set(records) or any(
        refs[at] != r["references"] for at, r in records.items()
    ):
        raise ValueError("shared-record reference inventory differs")
    for reader in mapping["readers"]:
        code = span(payload, base, reader["start_runtime"], reader["end_runtime"])
        if digest(code) != reader["sha256"]:
            raise ValueError("reviewed reader instruction bytes differ")
    result = {
        "kind": "pinned_ship_specification_audit",
        "revision": mapping["revision"],
        "lists": len(list_starts),
        "pointer_cells": cells,
        "nonnull_references": sum(refs.values()),
        "zero_sentinels": terminators,
        "distinct_display_records": len(records),
        "shared_records": [
            {"runtime": at, "references": n} for at, n in sorted(refs.items()) if n > 1
        ],
        "identical_record_groups_at_distinct_addresses": [
            v for v in identical.values() if len(v) > 1
        ],
        "display_record_bytes": sum(r["end_runtime"] - at for at, r in records.items()),
        "native_reader_windows": len(mapping["readers"]),
        "ownership_or_code_inferred": False,
        "guest_execution": False,
    }
    for key, value in mapping["expected_counts"].items():
        if result[key] != value:
            raise ValueError("aggregate specification inventory differs")
    return result


def main():
    from amiga_reversing.disasm.disk_set import DiskSet
    from amiga_reversing.disasm.disk_set_state import _artifact
    from amiga_reversing.disasm.target_history import target_lock

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--map",
        type=Path,
        default=ROOT / "docs/validation/foft-ship-specifications.json",
    )
    parser.add_argument(
        "--media", action="append", required=True, metavar="ID=PRIVATE_PATH"
    )
    args = parser.parse_args()
    mapping = json.loads(args.map.read_text())
    if mapping["target_id"] != "amiga_raw_foft" or mapping["member_id"] != "main":
        raise ValueError("recipe requires the canonical FOFT main member")
    root = ROOT / "targets" / mapping["target_id"]
    with target_lock(root):
        owner = DiskSet.load(root, project_root=ROOT)
        if owner.revision != mapping["revision"]:
            raise ValueError("map revision differs; review before re-pinning")
        source, artifact = _artifact(
            owner, "main", dict(v.split("=", 1) for v in args.media)
        )
        try:
            base = mapping["load_address"]
            for reader in mapping["readers"]:
                page = artifact.query_payload(
                    "instructions",
                    section_index=0,
                    source_offset=reader["start_runtime"] - base,
                    end_offset=reader["end_runtime"] - base,
                    limit=100,
                )
                rows = page["items"]
                if (
                    page["has_more"]
                    or len(rows) != reader["instructions"]
                    or digest(b"".join(bytes.fromhex(r["bytes"]) for r in rows))
                    != reader["sha256"]
                ):
                    raise ValueError(
                        "reader window is not the pinned existing native instruction sequence"
                    )
            payload = source.read_bytes()
            result = audit(payload, mapping)
            rendered = artifact.inline_source_text_with_profile()[0]
            labels = set(re.findall(r"^([A-Za-z_][A-Za-z0-9_]*):", rendered, re.M))
            targets = {}
            for record in mapping["records"]:
                offset = record["start_runtime"] - base
                rows = artifact.query_payload(
                    "symbols",
                    section_index=0,
                    source_offset=offset,
                    end_offset=offset + 1,
                    limit=100,
                )
                if rows["has_more"]:
                    raise ValueError("unsupported target-symbol extent")
                targets[offset] = {
                    r["name"]
                    for r in rows["items"]
                    if r["source_offset"] == offset and r["name"] in labels
                }
            checked = 0
            for item in mapping["lists"]:
                page = artifact.query_payload(
                    "references",
                    section_index=0,
                    source_offset=item["start_runtime"] - base,
                    end_offset=item["end_runtime"] - base,
                    direction="outgoing",
                    limit=100,
                )
                if page["has_more"]:
                    raise ValueError("unsupported data-reference extent")
                rows = page["items"]
                body = rendered.split(item["name"] + ":\n", 1)[1]
                cells = body.splitlines()[: item["nonnull_count"] + 1]
                if len(cells) != item["nonnull_count"] + 1:
                    raise ValueError("rendered list extent differs")
                for i in range(item["nonnull_count"]):
                    offset = item["start_runtime"] - base + i * 4
                    target = int.from_bytes(payload[offset : offset + 4], "big") - base
                    refs = [r for r in rows if r["source_offset"] == offset]
                    if (
                        not refs
                        or {r["target_offset"] for r in refs} != {target}
                        or cells[i].strip().split(";", 1)[0].strip()
                        not in {"dc.l " + name for name in targets[target]}
                    ):
                        raise ValueError(
                            "pointer cell lacks its exact defined source-data label"
                        )
                    checked += 1
                zero_offset = item["end_runtime"] - base - 4
                if cells[-1].strip().split(";", 1)[
                    0
                ].strip() != "dc.l $00000000" or any(
                    r["source_offset"] == zero_offset for r in rows
                ):
                    raise ValueError("zero sentinel gained a symbolic reference")
            result["native_symbolic_data_references"] = checked
            print(json.dumps(result, indent=2))
        finally:
            artifact.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

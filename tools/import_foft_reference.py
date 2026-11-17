"""Initial, bounded import of the byte-identical private FoFT_sps reference.

The saved Ghidra JSON and full program stay private. This is an import adapter,
not a competing analysis database: the result is ordinary target metadata.
Subsequent annotation changes use the repository's revision-checked commands.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
BASE, SIZE = 0x800, 489472
EXPECTED = "85e2684b03badc7308e7eaa059b7c717441808798f55b4642e1d8b1895914c9b"
TARGET = ROOT / "targets/amiga_raw_foft"
AUTO = re.compile(
    r"^(?:FUN|LAB|DAT|PTR|BYTE|WORD|DWORD|CHAR|STRING|(?:BYTE|WORD|DWORD)_ARRAY)_[0-9A-Fa-f]+$"
)
HEX = re.compile(r"^[0-9a-fA-F]+$")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def dump(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def address(value):
    return int(value, 16) if isinstance(value, str) and HEX.fullmatch(value) else None


def clean(name):
    value = re.sub(r"[^A-Za-z0-9_]", "_", name.strip()).strip("_")
    if not value or value[0].isdigit():
        value = "foft_" + value
    if re.fullmatch(r"(?:[ad][0-7]|sp|pc|sr|ccr)", value, re.I):
        value = "foft_" + value
    return value[:50]


def provenance(locator):
    return {
        "seed_origin": "manual_analysis",
        "review_status": "seeded",
        "citation": "Private FoFT_sps saved analysis; byte identity verified at original-media handoff; "
        + locator,
        "source_id": "foft-sps-ghidra",
        "source_path": "FoFT.zip/FoFT_sps/foft_sps_800_78000",
        "source_locator": locator,
    }


def import_reference(reference, payload, target=TARGET):
    from amiga_reversing.disasm.binary_source import write_source_descriptor
    from amiga_reversing.disasm.projects import initialize_project_metadata
    from amiga_reversing.disasm.target_metadata import (
        TargetMetadata,
        target_metadata_json_payload,
        write_target_metadata,
    )

    raw = payload.read_bytes()
    facts = json.loads(reference.read_text())
    if len(raw) != SIZE or digest(raw) != EXPECTED:
        raise ValueError("Exact original handoff payload required")
    blocks = facts["memory_blocks"]
    if (
        len(blocks) != 1
        or int(blocks[0]["start"], 16) != BASE
        or blocks[0]["size"] != SIZE
        or blocks[0]["sha256"] != EXPECTED
    ):
        raise ValueError("Reference program bytes or mapping differ")
    if facts["language"] != "68000:BE:32:MC68030":
        raise ValueError("Unexpected saved Ghidra language")
    if (target / "target_metadata.json").exists():
        raise ValueError("Initial import refuses existing target annotations")
    m = json.loads(
        json.dumps(
            target_metadata_json_payload(
                TargetMetadata(target_type="raw_binary", entry_register_seeds=())
            )
        )
    )
    m["source_output_policy"] = {"mode": "binary_assets", "minimum_asset_size": 256}
    report = {
        "schema_version": 1,
        "payload_sha256": EXPECTED,
        "extent": {"start": BASE, "end": BASE + SIZE, "size": SIZE},
        "reference_sha256": digest(reference.read_bytes()),
        "archive_sha256": "ec50dc30b503a5abe077d817ab94c4c3e9f94723aeed0687fd34d11c435a0d48",
        "policy": "Structural import of saved human analysis, seeded/unassessed semantics; native decoder/roundtrip independently checked. Automatic labels are not manual evidence.",
        "saved_language": facts["language"],
        "target_cpu": "68000",
        "architecture_policy": "The saved MC68030 language is a superset reference only. No Ghidra instruction encoding or ABI is imported; the native 68000 decoder owns code and exact assembly.",
        "carried": [],
        "cleaned": [],
        "deferred": [],
        "rejected": [],
        "counts": {},
    }
    # Function bodies are used only for ownership/overlap checks, never invented
    # code-range or function-end assertions in native metadata.
    ranges = []
    for f in facts["functions"]:
        for rr in f["ranges"]:
            ranges.append((int(rr["start"], 16), int(rr["end"], 16) + 1, f))

    def owners(a):
        return {f["entry"]: f for lo, hi, f in ranges if lo <= a < hi}

    def code(a):
        return bool(owners(a))

    refs = defaultdict(list)
    for r in facts["references"]:
        a = address(r["to"])
        if a is not None:
            refs[a].append(r)
    user = []
    for s in facts["symbols"]:
        a = address(s["address"])
        if s["source"] != "USER_DEFINED" or not s["primary"]:
            continue
        if (
            s["kind"] not in ("Label", "Function")
            or a is None
            or not BASE <= a < BASE + SIZE
        ):
            report["deferred"].append(
                {
                    "kind": "symbol",
                    "original": s["qualified_name"],
                    "reason": "non-memory/non-primary-program symbol",
                }
            )
            continue
        if AUTO.fullmatch(s["name"]):
            report["rejected"].append(
                {
                    "kind": "symbol",
                    "address": a,
                    "original": s["name"],
                    "reason": "generic Ghidra auto-style spelling despite USER_DEFINED provenance",
                }
            )
            continue
        user.append((a, s))
    allocated = {"foft_entry": BASE}
    names = {BASE: "foft_entry"}

    # Non-local definitions first, then canonical owner\\.name scoped locals.
    def allocate(a, original, local_owner=None):
        stem = clean(original.lstrip("."))
        prefix = local_owner + "\\." if local_owner else ""
        limit = 63 - len(prefix)
        value = prefix + stem[:limit]
        if value in allocated and allocated[value] != a:
            value = prefix + stem[: limit - 9] + f"_{a:08x}"
        allocated[value] = a
        if value != original:
            report["cleaned"].append(
                {
                    "address": a,
                    "original": original,
                    "name": value,
                    "reason": "assembler spelling, explicit scope, or duplicate normalization",
                }
            )
        return value

    for a, s in sorted(user, key=lambda x: (x[0], x[1]["name"])):
        if s["name"].startswith("."):
            continue
        if a not in names:
            names[a] = allocate(a, s["name"])
    for a, s in sorted(user, key=lambda x: x[0]):
        if not s["name"].startswith(".") or a in names:
            continue
        own = owners(a)
        if len(own) != 1:
            report["deferred"].append(
                {
                    "kind": "local",
                    "address": a,
                    "original": s["qualified_name"],
                    "reason": "no unique saved function owner",
                }
            )
            continue
        f = next(iter(own.values()))
        entry = int(f["entry"], 16)
        if entry not in names or names[entry].startswith(".") or a <= entry:
            report["deferred"].append(
                {
                    "kind": "local",
                    "address": a,
                    "original": s["qualified_name"],
                    "reason": "owner has no accepted human global name",
                }
            )
            continue
        # Cross-function incoming control edges make this a public target.
        crossing = [
            r
            for r in refs[a]
            if any(k in r["type"] for k in ("CALL", "JUMP"))
            and int(r["from"], 16)
            not in range(
                int(f["entry"], 16), max(int(q["end"], 16) for q in f["ranges"]) + 1
            )
        ]
        if crossing:
            report["deferred"].append(
                {
                    "kind": "local",
                    "address": a,
                    "original": s["qualified_name"],
                    "reason": "incoming control edge from outside owner",
                }
            )
            continue
        names[a] = allocate(a, s["name"], names[entry])
    # Human-named function roots, plus the observed entry, are code seeds.
    entry_names = {BASE: "foft_entry"}
    for f in facts["functions"]:
        a = int(f["entry"], 16)
        if (
            f["source"] == "USER_DEFINED"
            and a in names
            and not AUTO.fullmatch(f["name"])
        ):
            entry_names[a] = names[a]
    m["seeded_code_entrypoints"] = [
        dict(addr=a - BASE, hunk=0, name=n, **provenance(f"function:{a:08x}"))
        for a, n in sorted(entry_names.items())
    ]
    m["seeded_code_labels"] = [
        dict(addr=a - BASE, hunk=0, name=n, **provenance(f"function-label:{a:08x}"))
        for a, n in sorted(entry_names.items())
    ]
    m["seeded_code_entrypoints"][0]["citation"] = (
        "Original unchanged IPF boot, Copperline1.1.0 natural PC=$800, all489472 bytes match FoFT_sps; entry is observed"
    )
    # Retain meaningful saved custom structures. Anonymous fields are explicit
    # offset placeholders; pointer-looking fields remain raw LONGs until flow is
    # checked. No Ghidra inferred function ABI/register contracts are imported.
    custom = {t["path"]: t for t in facts["types"] if t["kind"] == "StructureDB"}
    for t in custom.values():
        fields = []
        for f in t["fields"]:
            if f["length"] not in (1, 2, 4):
                continue
            fields.append(
                {
                    "name": clean(f["name"])
                    if f["name"]
                    else f"unknown_{f['offset']:02x}",
                    "type": {1: "byte", 2: "word", 4: "long"}[f["length"]],
                    "offset": f["offset"],
                    "size": f["length"],
                    "available_since": "1.0",
                    "struct": None,
                    "pointer_struct": None,
                    "named_base": None,
                    "value_kind": "scalar",
                }
            )
        m["custom_structs"].append(
            {
                "name": clean(t["name"]),
                "size": t["length"],
                "fields": fields,
                "source": "foft-sps-ghidra",
                "base_offset": 0,
                "base_struct": None,
                "available_since": "1.0",
                "seed_origin": "manual_analysis",
                "review_status": "seeded",
                "citation": "FoFT_sps saved structure "
                + t["path"]
                + "; pointer fields deliberately remain scalar LONGs",
            }
        )
    defined = {int(d["address"], 16): d for d in facts["defined_data"]}
    # Audio samples: the saved 12-byte audio records independently bind a
    # pointer and Paula WORD count to an exact named source extent.
    sample_lengths = defaultdict(list)
    for d in defined.values():
        if d["type"] == "/AudioChannelData" and d["length"] == 12:
            ptr, count = struct.unpack_from(">IH", raw, int(d["address"], 16) - BASE)
            if ptr and count:
                sample_lengths[ptr].append(count * 2)
    entities = []
    covered = set()
    for a, d in sorted(defined.items()):
        n = d["length"]
        typ = d["type"]
        name = names.get(a)
        if not BASE <= a < a + n <= BASE + SIZE or any(
            lo < a + n and a < hi for lo, hi, _ in ranges
        ):
            report["rejected"].append(
                {
                    "kind": "data",
                    "address": a,
                    "type": typ,
                    "reason": "outside payload or intersects saved function code",
                }
            )
            continue
        if typ.startswith("/undefined") and not name:
            report["deferred"].append(
                {
                    "kind": "data",
                    "address": a,
                    "size": n,
                    "type": typ,
                    "reason": "anonymous undefined storage; leave native unknown",
                }
            )
            continue
        base = dict(
            addr=a - BASE,
            end=a - BASE + n,
            hunk=0,
            type="data",
            unit="byte",
            subtype="opaque_data",
            **provenance(f"data:{a:08x}:{typ}"),
        )
        if name:
            base["name"] = name
            covered.add(a)
        if typ in custom:
            # A struct instance is expanded into its exact stored field leaves,
            # retaining the native custom type for later register-flow use.
            for f in custom[typ]["fields"]:
                leaf = dict(
                    base,
                    addr=a - BASE + f["offset"],
                    end=a - BASE + f["offset"] + f["length"],
                    unit={1: "byte", 2: "word", 4: "long"}[f["length"]],
                    subtype="lookup_table",
                    struct_name=clean(custom[typ]["name"]),
                    field_name=clean(f["name"])
                    if f["name"]
                    else f"unknown_{f['offset']:02x}",
                    field_type={1: "byte", 2: "word", 4: "long"}[f["length"]],
                    c_type=f["type"],
                )
                if f["offset"]:
                    leaf.pop("name", None)
                entities.append(leaf)
            continue
        if name and name.startswith("dataSound") and n in sample_lengths[a]:
            base.update(subtype="sound_sample", unit="byte")
            base["citation"] += "; exact audio record pointer + 2*WORD-count extent"
            report["carried"].append(
                {
                    "kind": "asset_role",
                    "address": a,
                    "size": n,
                    "name": name,
                    "role": "sound_sample",
                    "evidence": "AudioChannelData pointer and WORD count, PlaySoundN consumers",
                }
            )
        elif (
            typ == "/string"
            and raw[a - BASE : a - BASE + n].endswith(b"\0")
            and all(
                32 <= c < 127 or c in (9, 10, 13)
                for c in raw[a - BASE : a - BASE + n - 1]
            )
        ):
            base.update(subtype="string", encoding="ascii")
        elif typ in ("/word", "/undefined2") or re.fullmatch(r"/word\[\d+\]", typ):
            base.update(unit="word", subtype="lookup_table")
        elif typ in ("/dword", "/undefined4") or re.fullmatch(r"/dword\[\d+\]", typ):
            base.update(unit="long", subtype="lookup_table")
        elif typ in ("/pointer", "/undefined *"):
            ptr = int.from_bytes(raw[a - BASE : a - BASE + n], "big")
            if n == 4 and BASE <= ptr < BASE + SIZE and refs[a]:
                base.update(
                    unit="long",
                    subtype="pointer_table",
                    value_kind="target_pointer",
                    pointer_address_domain="mapped_source",
                )
            else:
                base.update(unit="long" if n == 4 else "byte")
        elif typ.startswith("/undefined"):
            report["deferred"].append(
                {
                    "kind": "data_type",
                    "address": a,
                    "type": typ,
                    "reason": "name retained; no semantic type inferred",
                }
            )
        entities.append(base)
    # Named non-code locations not otherwise typed retain only an address
    # label (zero extent); do not guess their data boundary from neighbours.
    for a, s in user:
        if a not in names or a in covered or a in entry_names:
            continue
        n = names[a]
        if code(a):
            m["seeded_code_labels"].append(
                dict(
                    addr=a - BASE,
                    hunk=0,
                    name=n,
                    **provenance(f"label:{a:08x}:{s['qualified_name']}"),
                )
            )
        else:
            entities.append(
                dict(
                    addr=a - BASE,
                    hunk=0,
                    name=n,
                    **provenance(f"label:{a:08x}:{s['qualified_name']}"),
                )
            )
    m["seeded_entities"] = entities
    comments = defaultdict(list)
    for c in facts["comments"]:
        a = int(c["address"], 16)
        if BASE <= a < BASE + SIZE and c["text"].strip():
            comments[a].append(c["text"].strip())
    for f in facts["functions"]:
        for k in ("comment", "repeatable_comment"):
            if f.get(k):
                comments[int(f["entry"], 16)].append(f[k].strip())
    m["entry_comments"] = [
        dict(
            addr=a - BASE,
            hunk=0,
            comment=" | ".join(dict.fromkeys(lines)),
            **provenance(f"comment:{a:08x}"),
        )
        for a, lines in sorted(comments.items())
    ]
    report["deferred"].append(
        {
            "kind": "bulk",
            "reason": "Generic Ghidra auto labels/functions, inferred ABIs/stack/register variables, equates without operand policy bindings, bookmarks and ambiguous asset roles are reference-only; no assumed code end bounds.",
        }
    )
    report["counts"] = {
        k: len(m[k])
        for k in (
            "seeded_code_entrypoints",
            "seeded_code_labels",
            "seeded_entities",
            "entry_comments",
            "custom_structs",
        )
    }
    report["counts"]["scoped_locals"] = sum(
        "\\." in x["name"] for x in m["seeded_code_labels"]
    )
    metadata = TargetMetadata.from_dict(m)
    target.mkdir(parents=True, exist_ok=True)
    (target / "binary.bin").write_bytes(raw)
    write_source_descriptor(
        target,
        {
            "kind": "raw_binary",
            "path": f"targets/{target.name}/binary.bin",
            "address_model": "runtime_absolute",
            "load_address": BASE,
            "entrypoint": BASE,
            "code_start_offset": 0,
        },
    )
    write_target_metadata(target, metadata)
    initialize_project_metadata(
        target,
        timestamp=datetime(2026, 11, 17, tzinfo=UTC),
        origin={
            "kind": "original_media_handoff",
            "target_type": "raw_binary",
            "target_role": "primary_program",
            "source_media_sha256": "da33fc1e068d73078094fc4cb6f72ab69a9c2f30f4094b8321033aedb6237b93",
            "payload_sha256": EXPECTED,
            "load_address": BASE,
            "entrypoint": BASE,
            "byte_length": SIZE,
            "provenance": "Original IPF natural boot in official Copperline1.1.0 A500OCS PAL 68000 512K chip+512K slow, first main instruction not executed; matching FoFT_sps saved program",
        },
    )
    dump(
        ROOT / "docs/validation/foft-reference-import.json"
        if target == TARGET
        else target / "reference-import.json",
        report,
    )
    print(json.dumps(report["counts"], indent=2))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--reference", type=Path, required=True)
    p.add_argument("--payload", type=Path, required=True)
    args = p.parse_args()
    import_reference(args.reference, args.payload)

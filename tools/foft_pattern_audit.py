"""Read-only shape/bounds audit of SPS 0613 conversation patterns.

This recognizes only the matcher reads documented in foft-pattern-anchors.md.
It neither matches player input nor interprets reply scripts.
"""

import argparse
import hashlib
import json
from pathlib import Path


def pattern_shape(pattern: bytes) -> dict:
    if any(byte < 32 or byte >= 127 for byte in pattern):
        raise ValueError("unsupported pattern byte")
    cursor = 0
    tokens = []
    while cursor < len(pattern):
        while cursor < len(pattern) and pattern[cursor] == 32:
            cursor += 1
        if cursor == len(pattern):
            raise ValueError("trailing spaces: matcher may read beyond pattern NUL")
        start = cursor
        byte = pattern[cursor]
        if byte == 42:
            cursor += 1
            capture = cursor < len(pattern) and pattern[cursor] == 61
            cursor += int(capture)
            tokens.append(
                {
                    "kind": "capture" if capture else "wildcard",
                    "start": start,
                    "end": cursor,
                }
            )
        elif byte == 40:
            close = pattern.find(b")", cursor + 1)
            if close < 0:
                raise ValueError("unterminated alternative group")
            body = pattern[cursor + 1 : close]
            if b"(" in body:
                raise ValueError(
                    "nested alternatives are outside the proven scanner shape"
                )
            alternatives = body.split(b"/")
            if any(len(alt) >= 64 for alt in alternatives):
                raise ValueError(
                    "alternative exceeds the observed 64-byte scratch reservation"
                )
            branches = [
                pattern_shape(alt)["tokens"] if alt else [] for alt in alternatives
            ]
            cursor = close + 1
            tokens.append(
                {
                    "kind": "alternatives",
                    "start": start,
                    "end": cursor,
                    "branches": branches,
                    "empty_branches": sum(not alt for alt in alternatives),
                }
            )
        else:
            while cursor < len(pattern) and pattern[cursor] != 32:
                cursor += 1
            if cursor - start >= 24:
                raise ValueError(
                    "literal exceeds the observed 24-byte scratch reservation"
                )
            tokens.append({"kind": "literal", "start": start, "end": cursor})
    return {"tokens": tokens, "bytes": len(pattern), "complete_match_semantics": False}


def audit(payload: bytes, manifest: dict, prior: dict) -> dict:
    main = next(member for member in manifest["members"] if member["id"] == "main")
    if (
        len(payload) != main["size"]
        or hashlib.sha256(payload).hexdigest() != main["sha256"]
    ):
        raise ValueError("payload identity does not match canonical main member")
    lo, hi = prior["source_extent"]["start"], prior["source_extent"]["end"]
    base = main["context"]["load_address"]
    pointers = []
    for slot in range(lo, hi, 4):
        value = int.from_bytes(payload[slot : slot + 4], "big")
        if value & 0x80000000:
            if slot + 4 != hi or value != 0xFFFFFFFF:
                raise ValueError("unexpected negative stop or table extent")
            break
        target = value - base
        if not 0 <= target < len(payload):
            raise ValueError("pattern outside main source")
        end = payload.index(0, target) + 1
        pattern = payload[target : end - 1]
        pointers.append(
            {
                "slot_source_offset": slot,
                "source_start": target,
                "source_end": end,
                "initial_reply_source_offset": end,
                "sha256": hashlib.sha256(pattern + b"\0").hexdigest(),
                "shape": pattern_shape(pattern),
            }
        )
    else:
        raise ValueError("missing negative table stop")
    overlaps = [
        {"a": i, "b": j, "same_start": a["source_start"] == b["source_start"]}
        for i, a in enumerate(pointers)
        for j, b in enumerate(pointers[:i])
        if a["source_start"] < b["source_end"] and b["source_start"] < a["source_end"]
    ]
    return {
        "patterns": pointers,
        "overlaps": overlaps,
        "pointer_count": len(pointers),
        "bounds_kind": "NUL reads plus caller's following-reply transition",
        "limits": [
            "Token shape is not a matcher emulator or complete grammar.",
            "Input/capture-buffer bounds and reply grammar remain unproved.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "targets/amiga_raw_foft/manifest.json").read_bytes())
    prior = json.loads(
        (root / "docs/validation/foft-conversation-rules.json").read_bytes()
    )
    print(json.dumps(audit(args.payload.read_bytes(), manifest, prior), indent=2))


if __name__ == "__main__":
    main()

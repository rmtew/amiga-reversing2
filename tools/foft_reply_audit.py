"""Read-only, content-bound audit of FOFT table reply records, not an interpreter."""

import hashlib

from tools.foft_pattern_audit import audit as audit_patterns


def reply_shape(record: bytes) -> dict:
    """Describe the original decoder's reads within one NUL-terminated record.

    Offsets exclude the final NUL. Capture lengths and decoder error recovery
    remain unknown. Random alternatives handle '+' but print '-' literally:
    the original second CMP is also '+', so its clear branch is unreachable.
    """
    if not record or record[-1] != 0 or 0 in record[:-1]:
        raise ValueError("expected one complete NUL-terminated reply record")
    data = record[:-1]
    cursor = 0
    guard = None
    operations = []
    if data.startswith(b"?"):
        if len(data) < 2 or data[1] >= 128:
            raise ValueError("unsupported leading guard flag")
        guard = {"offset": 0, "flag_index": data[1], "next_record_if_clear": True}
        cursor = 2
    while cursor < len(data):
        start = cursor
        byte = data[cursor]
        cursor += 1
        if byte in (43, 45):
            if cursor == len(data) or data[cursor] >= 128:
                raise ValueError("missing or negative flag operand")
            operations.append(
                {
                    "kind": "set_flag" if byte == 43 else "clear_flag",
                    "start": start,
                    "end": cursor + 1,
                    "flag_index": data[cursor],
                }
            )
            cursor += 1
        elif byte == 37:
            if cursor == len(data):
                raise ValueError("missing percent operand")
            selector = data[cursor]
            cursor += 1
            if selector != 114:
                if not 49 <= selector <= 57:
                    raise ValueError("capture selector outside bounded 1..9 audit")
                operations.append(
                    {
                        "kind": "capture",
                        "start": start,
                        "end": cursor,
                        "ordinal": selector - 48,
                        "trailing_space": True,
                        "output_bound": None,
                    }
                )
                continue
            if (
                cursor + 1 >= len(data)
                or not 49 <= data[cursor] <= 57
                or data[cursor + 1] != 40
            ):
                raise ValueError("invalid random count or opening delimiter")
            count = data[cursor] - 48
            header_end = cursor + 2
            close = data.find(b")", header_end)
            if close < 0:
                raise ValueError("unterminated random alternatives")
            choices = data[header_end:close].split(b"/")
            if len(choices) < count:
                raise ValueError("fewer alternatives than random divisor")
            branches = []
            branch_start = header_end
            for choice in choices:
                i = 0
                writes = []
                while i < len(choice):
                    if choice[i] == 43:
                        if i + 1 == len(choice):
                            raise ValueError("missing random-branch set operand")
                        writes.append(
                            {"offset": branch_start + i, "flag_index": choice[i + 1]}
                        )
                        i += 2
                    else:
                        i += 1
                branches.append(
                    {
                        "start": branch_start,
                        "end": branch_start + len(choice),
                        "set_flags": writes,
                        "literal_bytes": len(choice) - 2 * len(writes),
                    }
                )
                branch_start += len(choice) + 1
            operations.append(
                {
                    "kind": "random",
                    "start": start,
                    "header_end": header_end,
                    "end": close + 1,
                    "divisor": count,
                    "available_alternatives": len(choices),
                    "branches": branches,
                }
            )
            cursor = close + 1
        else:
            if (
                operations
                and operations[-1]["kind"] == "literal"
                and operations[-1]["end"] == start
            ):
                operations[-1]["end"] = cursor
            else:
                operations.append({"kind": "literal", "start": start, "end": cursor})
    literal_bound = sum(
        op["end"] - op["start"]
        if op["kind"] == "literal"
        else max(branch["literal_bytes"] for branch in op["branches"][: op["divisor"]])
        if op["kind"] == "random"
        else 0
        for op in operations
    )
    return {
        "guard": guard,
        "operations": operations,
        "literal_output_upper_bound_excluding_nul": literal_bound,
        "capture_output_bound_known": not any(
            op["kind"] == "capture" for op in operations
        ),
    }


def audit(payload: bytes, manifest: dict, prior: dict) -> dict:
    patterns = audit_patterns(payload, manifest, prior)["patterns"]
    starts = sorted({p["source_start"] for p in patterns})
    chains = []
    for pattern in patterns:
        cursor = pattern["initial_reply_source_offset"]
        upper = next((s for s in starts if s > pattern["source_start"]), len(payload))
        records = []
        while cursor < upper:
            try:
                end = payload.index(0, cursor, upper) + 1
            except ValueError as error:
                raise ValueError(
                    "reply record crosses next pattern or source end"
                ) from error
            shape = reply_shape(payload[cursor:end])
            records.append(
                {
                    "source_start": cursor,
                    "source_end": end,
                    "sha256": hashlib.sha256(payload[cursor:end]).hexdigest(),
                    **shape,
                }
            )
            cursor = end
            if shape["guard"] is None:
                break
        else:
            raise ValueError("guard chain lacks an unconditional fallback within bound")
        chains.append(
            {
                "pattern_source_start": pattern["source_start"],
                "records": records,
                "source_end": cursor,
                "upper_source_bound": upper,
            }
        )
    return {
        "chains": chains,
        "pattern_count": len(patterns),
        "reply_record_count": sum(len(c["records"]) for c in chains),
        "limits": [
            "Static byte-read shape, not observed reply selection or playback.",
            "No decoder input/capture/output/error-recovery safety proof.",
            "Other direct-call reply scripts are outside this table audit.",
        ],
    }


def main():
    import argparse
    import json
    from pathlib import Path

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

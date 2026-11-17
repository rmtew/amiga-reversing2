"""Bounded original resource5 pattern/order reads; no bank9 grammar inheritance."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from collections import Counter
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.foft_audio_layout_probe import (
    COMMAND_PARAMETERS,
    decode_order_prefix,
    decode_pattern_prefix,
)

EXPECTED = "3fa229a343d5fa6e050abc696911c36e55d5ee96cc7b2d852dbdd4404b299190"
# Actual byte reads in this player's $5946E C6 handler and $5948A C7 handler.
# Initial bank9's C6 takes one byte and C7 reaches ILLEGAL; do not change it.
RESOURCE5_COMMAND_PARAMETERS = {**COMMAND_PARAMETERS, 0xC6: 3, 0xC7: 0}


def probe(data):
    if len(data) != 29578 or hashlib.sha256(data).hexdigest() != EXPECTED:
        raise ValueError("verified original resource5 required")
    offsets = struct.unpack_from(">42H", data, 0xD70)
    if offsets[0] != 0 or list(offsets) != sorted(set(offsets)):
        raise ValueError("resource5 initial pattern offsets differ")
    patterns, orders, tails, counts = [], [], [], Counter()
    for index, offset in enumerate(offsets):
        start = 0x53A + offset
        bound = 0x53A + offsets[index + 1] if index < 41 else 0xD70
        events, end = decode_pattern_prefix(
            data, start, bound, command_parameters=RESOURCE5_COMMAND_PARAMETERS
        )
        counts.update(e["kind"] for e in events)
        patterns.append(
            {"index": index, "source_start": start, "source_end": end, "events": events}
        )
        if end != bound:
            tails.append(
                {
                    "source_start": end,
                    "source_end": bound,
                    "adjacent_to": "pattern",
                    "index": index,
                    "interpretation": "unconsumed bytes; no packet or code classification",
                }
            )
    starts = struct.unpack_from(">8H", data, 0xDC4)
    if starts[0] != 16 or list(starts) != sorted(set(starts)):
        raise ValueError("resource5 initial order offsets differ")
    for index, offset in enumerate(starts):
        start = 0xDC4 + offset
        bound = 0xDC4 + starts[index + 1] if index < 7 else 0xEF6
        events, indices, end = decode_order_prefix(data, start, bound, len(patterns))
        orders.append(
            {
                "index": index,
                "source_start": start,
                "source_end": end,
                "events": events,
                "pattern_indices": indices,
                "descriptor": index // 4,
                "channel": index % 4,
            }
        )
        if end != bound:
            tails.append(
                {
                    "source_start": end,
                    "source_end": bound,
                    "adjacent_to": "order",
                    "index": index,
                    "interpretation": "unconsumed bytes; no packet or code classification",
                }
            )
    return {
        "schema": "foft-resource5-audio-data/v1",
        "payload_sha256": EXPECTED,
        "command_parameters": {
            hex(k): v for k, v in RESOURCE5_COMMAND_PARAMETERS.items()
        },
        "patterns": patterns,
        "orders": orders,
        "unconsumed_tails": tails,
        "pattern_event_counts": dict(counts),
        "scope": "Two initial four-channel descriptors and bounded stored streams; no song/runtime closure. Tails stay outside the parsed stream.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.input.read_bytes()), indent=2))


if __name__ == "__main__":
    main()

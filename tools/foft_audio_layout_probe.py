"""Validate FOFT's initial audio data using its accepted in-game consumers.

Read-only, target-specific format probe; this is not an M68K decoder. Consumer
addresses and opcode meanings are documented in docs/validation/foft-audio-data.md.
It refuses unsupported/truncated packets and requires the exact verified payload
for the target report. It emits coordinates/counts, never sample bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

EXPECTED = "85e2684b03badc7308e7eaa059b7c717441808798f55b4642e1d8b1895914c9b"
LOAD = 0x800
# Operand reads at $58EF4-$58F68 establish these parameter counts. C7-FE
# reach ILLEGAL; FF is handled earlier as advance-order, not as a parameter.
COMMAND_PARAMETERS = {0xC0: 3, 0xC1: 0, 0xC2: 3, 0xC3: 0, 0xC4: 1, 0xC5: 0, 0xC6: 1}


def _bounds(data, start, end):
    if not 0 <= start < end <= len(data):
        raise ValueError("Audio packet range lies outside the input")


def decode_pattern(data: bytes, start: int, end: int):
    """Decode one exactly bounded initial stream, requiring its final FF."""
    _bounds(data, start, end)
    cursor = start
    events = []
    while cursor < end:
        at = cursor
        op = data[at]
        if op == 0xFF:
            width, kind = 1, "end"
        elif op >= 0xC0:
            if op not in COMMAND_PARAMETERS:
                raise ValueError(f"Unsupported pattern command at {at:#x}")
            width = 1 + COMMAND_PARAMETERS[op]
            kind = (
                "slide_command"
                if op == 0xC0
                else "volume_mod_command"
                if op == 0xC2
                else "control"
            )
        elif op >= 0x89:
            width, kind = 1, "command_nibble"
        elif op >= 0x80:
            width, kind = 1, "instrument_select"
        elif op == 0x7F:
            width, kind = 2, "rest"
        else:
            if at + 1 >= end:
                raise ValueError(f"Truncated note at {at:#x}")
            width = 3 if data[at + 1] == 0 else 2
            kind = "held_note" if width == 3 else "note"
        cursor += width
        if cursor > end:
            raise ValueError(f"Truncated pattern packet at {at:#x}")
        events.append({"offset": at - start, "width": width, "kind": kind})
        if op == 0xFF:
            if cursor != end:
                raise ValueError("Pattern terminator precedes the declared boundary")
            return events
    raise ValueError("Pattern has no FF terminator at its boundary")


def decode_order(data: bytes, start: int, end: int, pattern_count: int):
    """Validate the byte/parameter reads at $58D20-$58D82, without executing."""
    _bounds(data, start, end)
    cursor = start
    events, indices = [], []
    while cursor < end:
        at = cursor
        op = data[at]
        width = 2 if 0xF0 <= op <= 0xFE else 1
        cursor += width
        if cursor > end:
            raise ValueError(f"Truncated order packet at {at:#x}")
        if op < 200:
            if op >= pattern_count:
                raise ValueError(
                    f"Initial order references an absent pattern at {at:#x}"
                )
            indices.append(op)
        events.append(
            {
                "offset": at - start,
                "width": width,
                "kind": "order_parameter" if width == 2 else "order_byte",
            }
        )
        if op == 0xFF:
            if cursor != end:
                raise ValueError("Order terminator precedes the declared boundary")
            return events, sorted(set(indices))
    raise ValueError("Order has no FF terminator at its boundary")


def probe(data: bytes):
    if len(data) != 489472 or hashlib.sha256(data).hexdigest() != EXPECTED:
        raise ValueError("Input is not the verified original FOFT handoff")
    bank = 0x590B0 - LOAD
    instrument_offsets = struct.unpack_from(">8I", data, bank)
    if instrument_offsets != tuple(range(32, 256, 28)):
        raise ValueError("Initial instrument-header collection differs")
    instruments = []
    for index, offset in enumerate(instrument_offsets):
        values = struct.unpack_from(">2I10H", data, bank + offset)
        for relative, words in ((values[0], values[2]), (values[1], values[3])):
            if bank + relative + 2 * words > len(data):
                raise ValueError("Initial sample span lies outside the payload")
        instruments.append(
            {
                "index": index,
                "source_offset": bank + offset,
                "bank_offset": offset,
                "sample_bytes": 2 * values[2],
                "repeat_bytes": 2 * values[3],
            }
        )
    starts = struct.unpack_from(">17H", data, 0x5892C - LOAD)
    if starts[0] != 0 or list(starts) != sorted(set(starts)):
        raise ValueError("Initial pattern offsets are not unique and increasing")
    patterns, counts = [], Counter()
    for index, offset in enumerate(starts):
        start = 0x58536 - LOAD + offset
        end = 0x58536 - LOAD + starts[index + 1] if index < 16 else 0x5892C - LOAD
        events = decode_pattern(data, start, end)
        counts.update(event["kind"] for event in events)
        patterns.append(
            {"index": index, "source_start": start, "source_end": end, "events": events}
        )
    starts = struct.unpack_from(">4H", data, 0x5894E - LOAD)
    if starts[0] != 8 or list(starts) != sorted(set(starts)):
        raise ValueError("Initial channel order offsets differ")
    orders = []
    for index, offset in enumerate(starts):
        start = 0x5894E - LOAD + offset
        end = 0x5894E - LOAD + starts[index + 1] if index < 3 else 0x5899C - LOAD
        events, indices = decode_order(data, start, end, len(patterns))
        orders.append(
            {
                "index": index,
                "source_start": start,
                "source_end": end,
                "pattern_indices": indices,
                "events": events,
            }
        )
    return {
        "schema": "foft-initial-audio-data/v1",
        "payload_sha256": EXPECTED,
        "instruments": instruments,
        "patterns": patterns,
        "orders": orders,
        "pattern_event_counts": dict(counts),
        "scope": "Initial bytes and accepted consumer grammar; no future-write, selector or runtime closure.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.input.read_bytes()), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

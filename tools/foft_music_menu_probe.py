"""Read-only inventory of FOFT's initial music menu and nominal disk-copy spans.

Serialization bounds and transfer grammar come from accepted in-game consumers;
see docs/validation/foft-music-loader.md. This is not an M68K or IPF decoder.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.foft_audio_layout_probe import EXPECTED, LOAD

CALLBACKS = (0x58212, 0x58234, 0x58256, 0x58278)


def nominal_copy_chunks(destination: int, track: int, offset: int, length: int):
    """Model only positive, bounded initial descriptors, not arbitrary guest state."""
    if any(type(v) is not int or v < 0 for v in (destination, track, offset, length)):
        raise ValueError("Descriptor values must be nonnegative integers")
    if not length or offset >= 6000 or destination + length > 0x100000000:
        raise ValueError("Unsupported nominal descriptor span")
    chunks = []
    while length:
        size = min(6000-offset, length)
        chunks.append({"track": track, "track_offset": offset, "start": destination, "end": destination+size})
        destination += size
        length -= size
        track += 1
        offset = 0
    return chunks


def probe(data: bytes):
    if len(data) != 489472 or hashlib.sha256(data).hexdigest() != EXPECTED:
        raise ValueError("Input is not the verified FOFT handoff")
    resources = []
    for index in range(10):
        destination, track, offset, length = struct.unpack_from(">4I", data, 0x403A0-LOAD+16*index)
        chunks = nominal_copy_chunks(destination, track, offset, length)
        resources.append({"index": index, "destination": destination, "track": track, "track_offset": offset,
                          "bytes": length, "end": destination+length, "nominal_chunks": chunks,
                          "callback_cells_fully_overwritten": [at for at in CALLBACKS if destination <= at and at+4 <= destination+length]})
    choices = []
    pointers = struct.unpack_from(">19I", data, 0x47038-LOAD)
    for index, pointer in enumerate(pointers):
        song, resource = struct.unpack_from(">2H", data, 0x46FEC-LOAD+4*index)
        if not 4 <= resource <= 9:
            raise ValueError("Music selection references an unexpected resource")
        end = pointers[index+1]-LOAD if index < 18 else 0x472EE-LOAD
        start = pointer-LOAD
        if not 0 <= start+4 < end <= len(data):
            raise ValueError("Unbounded music title record")
        terminator = data.find(b"\0", start+4, end)
        if terminator < 0:
            raise ValueError("Music title lacks a bounded terminator")
        choices.append({"index": index, "song_index": song, "resource_index": resource,
                        "title_address": pointer, "title": data[start+4:terminator].decode("ascii")})
    keyboard = {}
    for language, address in [("French", 0x10F92), ("English", 0x11094), ("German", 0x11196)]:
        keyboard[language] = {}
        for name, raw in [("Help", 0x5F), ("Return", 0x44), ("Space", 0x40), ("Up", 0x4C), ("Down", 0x4D)]:
            index = data[0x10B96-LOAD+raw]
            logical = struct.unpack_from(">H", data, address-LOAD+2*index)[0]
            keyboard[language][name] = 2*logical
    assert all(struct.unpack_from(">I", data, at-LOAD)[0] == 0 for at in CALLBACKS)
    return {"schema": "foft-initial-music-menu/v1", "payload_sha256": EXPECTED,
            "menu_choices": choices, "resource_descriptors": resources,
            "selected_resource_indices": sorted({r["resource_index"] for r in choices}),
            "initial_language_key_state_offsets": keyboard,
            "scope": "Initial menu, descriptors and nominal successful copy spans only; disk contents, successful loads, playback and writer closure are not proven."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.input.read_bytes()), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

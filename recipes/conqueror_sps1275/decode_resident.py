"""Recover the original Conqueror SPS 1275 gameplay resident, offline."""

import argparse
import json
import struct
from pathlib import Path

from inspect_media import inventory, require, sha

FIRST_TRACK = 126
LAST_TRACK = 140
TRACK_LOAD_BASE = 0x1C000
PACKED_HEADER_OFFSET = 0x10C
PACKED_SIZE = 64_944
RESIDENT_BASE = 0x21000
RESIDENT_SIZE = 300_368
RESIDENT_ENTRY = 0x57B8A
RESIDENT_SHA256 = "6428d23379667b19c7397721ed31a2a90369be99865440692ba95c6bf265f24c"


class BackwardBits:
    """Longwords consumed from the end, with low-bit-first input within each."""

    def __init__(self, packed, checksum):
        self.packed = packed
        self.cursor = len(packed)
        self.checksum = checksum
        self.pending = self.refill()
        require(self.pending != 0, "missing initial bit sentinel")

    def refill(self):
        require(self.cursor >= 4, "packed bitstream exhausted")
        self.cursor -= 4
        word, = struct.unpack_from(">I", self.packed, self.cursor)
        self.checksum ^= word
        return word

    def read(self, n):
        result = 0
        for _ in range(n):
            bit = self.pending & 1
            self.pending >>= 1
            if self.pending == 0:
                # The high sentinel is not itself a data bit.
                word = self.refill()
                bit = word & 1
                self.pending = (word >> 1) | 0x80000000
            result = (result << 1) | bit
        return result

    def finish(self):
        require(self.cursor == self.checksum == 0 and self.pending == 1,
                "trailing packed bits or failed checksum")


def unpack(packed, output_size, checksum):
    """Expand backward literal and already-written byte-copy runs."""
    require(len(packed) >= 4 and len(packed) % 4 == 0, "invalid packed length")
    require(0 < output_size <= 512 * 1024, "invalid output length")
    bits = BackwardBits(packed, checksum)
    output = bytearray(output_size)
    cursor = output_size
    while cursor:
        if bits.read(1) == 0:
            if bits.read(1) == 0:
                literal_count, copy_count = bits.read(3) + 1, 0
            else:
                literal_count, copy_count, width = 0, 2, 8
        else:
            kind = bits.read(2)
            if kind == 3:
                literal_count, copy_count = bits.read(8) + 9, 0
            elif kind == 2:
                literal_count, copy_count, width = 0, bits.read(8) + 1, 12
            else:
                literal_count, copy_count, width = 0, kind + 3, kind + 9
        require(cursor >= literal_count + copy_count, "run exceeds output size")
        if literal_count:
            for _ in range(literal_count):
                cursor -= 1
                output[cursor] = bits.read(8)
        else:
            distance = bits.read(width)
            require(0 < distance <= output_size - cursor,
                    "copy does not reference an already written byte")
            for _ in range(copy_count):
                cursor -= 1
                output[cursor] = output[cursor + distance]
    bits.finish()
    return bytes(output)


def decode_image(image, intake):
    _, tracks = inventory(image)
    stage = b"".join(tracks[n] for n in range(FIRST_TRACK, LAST_TRACK + 1))
    end_header = PACKED_HEADER_OFFSET + 12
    packed_size, output_size, checksum = struct.unpack_from(">III", stage, PACKED_HEADER_OFFSET)
    require((packed_size, output_size) == (PACKED_SIZE, RESIDENT_SIZE),
            "unexpected retail packed header")
    packed = stage[end_header:end_header+packed_size]
    require(len(packed) == packed_size, "truncated packed bytes")
    output = unpack(packed, output_size, checksum)
    require(sha(output) == RESIDENT_SHA256, "unexpected retail resident SHA256")

    entries = {}
    for name, expected in intake["runtime_renderer"]["entries"].items():
        pos = int(expected["guest_pc"], 16) - RESIDENT_BASE
        fingerprint_size = expected["fingerprint_size"]
        require(0 <= pos <= len(output) - fingerprint_size,
                f"{name} outside resident")
        require(sha(output[pos:pos+fingerprint_size]) == expected["sha256"],
                f"runtime fingerprint differs at {name}")
        entries[name] = {"source_offset": pos, "guest_pc": expected["guest_pc"],
                         "sha256": expected["sha256"]}
    require(len(entries) == 9, "incomplete renderer receipt")

    return output, {
        "codec": "retail backward literal/copy stream",
        "input_image_sha256": intake["image"]["sha256"],
        "source": {"track_first": FIRST_TRACK,
                   "track_last_with_packed_bytes": FIRST_TRACK + (end_header + packed_size - 1) // 5120,
                   "track_first_header_offset": PACKED_HEADER_OFFSET,
                   "track_first_packed_offset": end_header,
                   "packed_size": len(packed), "packed_sha256": sha(packed)},
        "resident": {"load_address": RESIDENT_BASE, "observed_handoff": RESIDENT_ENTRY,
                     "size": len(output), "sha256": sha(output),
                     "renderer_entries": entries},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--check", type=Path)
    parser.add_argument("--compare-handoff-ram", type=Path,
                        help="local 512 KiB RAM captured at the original $57B8A handoff")
    parser.add_argument("--output-local", type=Path,
                        help="optional newly created private binary; never committed")
    args = parser.parse_args()
    try:
        intake = json.loads(Path(__file__).with_name("inventory.json").read_text())
        output, receipt = decode_image(args.image.read_bytes(), intake)
        if args.compare_handoff_ram:
            ram = args.compare_handoff_ram.read_bytes()
            require(len(ram) == 512 * 1024, "handoff capture must be 512 KiB Chip RAM")
            require(ram[RESIDENT_BASE:RESIDENT_BASE + RESIDENT_SIZE] == output,
                    "native handoff resident differs")
        if args.check:
            require(receipt == json.loads(args.check.read_text()), "resident receipt differs")
        if args.output_local:
            with args.output_local.open("xb") as dst:
                dst.write(output)
        print(json.dumps(receipt, indent=2, sort_keys=True))
    except (OSError, ValueError, KeyError, struct.error) as err:
        parser.exit(1, f"Conqueror resident: {err}\n")


if __name__ == "__main__":
    main()

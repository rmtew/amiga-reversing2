"""Read-only intake for Conqueror's SPS 1275 IPF. Emits metadata, never media."""

import argparse
import hashlib
import json
import struct
import zlib
from collections import Counter
from pathlib import Path

MEDIA_SHA256 = "4f8b5ec7b59d0a6a89873d37ae52feb5b4ed53335ab1ff5dba96eb82fb72b9fb"
MEDIA_SIZE = 962776
# Guest PCs for groups independently attributed in the matched native traces.
RENDERER_ENTRIES = {
    "game_iteration": 0x58010,
    "queue_viewport_clear": 0x566AA,
    "sample_and_project_terrain": 0x566B0,
    "submit_scene": 0x5692C,
    "sample_terrain_height_and_type": 0x56AE8,
    "rotate_and_project_model_vertices": 0x56D4C,
    "model_face_normal_test": 0x56E58,
    "translate_and_project_model_vertices": 0x56F38,
    "rasterize_terrain_quad": 0x57634,
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def words(data):
    return (n for (n,) in struct.iter_unpack(">I", data))


def u32(data, offset):
    return struct.unpack_from(">I", data, offset)[0]


def sha(data):
    return hashlib.sha256(data).hexdigest()


# Bounded identity slices in all three captures. These are not assertions about
# when the loader transferred the bytes or whether the whole track is resident.
DISK_RAM_SLICES = ((1, 0, 467, 0x400), (1, 471, 1829, 0x5D7),
                   (127, 1032, 5120, 0x1D808), (128, 0, 5120, 0x1E800),
                   (129, 0, 5120, 0x1FC00))


def split_decode(data):
    """Collapse an IPF data-only even/odd field into ordinary big-endian bytes."""
    require(len(data) % 2 == 0, "split MFM field has odd length")

    def spread(n):
        return sum(((n >> bit) & 1) << (2 * bit) for bit in range(4))

    half = len(data) // 2
    spread_nibbles = tuple(map(spread, range(16)))
    result = bytearray()
    for a, b in zip(data[:half], data[half:], strict=True):
        result.append((spread_nibbles[a >> 4] << 1) | spread_nibbles[b >> 4])
        result.append((spread_nibbles[a & 15] << 1) | spread_nibbles[b & 15])
    return bytes(result)


def split_encode(data):
    """Inverse packed data-bit transform; never writes the source image."""
    require(len(data) % 2 == 0, "split MFM field has odd length")
    # Gather alternating bits independently from the decoder's spreading map.
    def gather(n):
        return (n & 1) | ((n >> 1) & 2) | ((n >> 2) & 4) | ((n >> 3) & 8)

    even, odd = bytearray(), bytearray()
    for a, b in struct.iter_unpack("BB", data):
        even.append((gather(a >> 1) << 4) | gather(b >> 1))
        odd.append((gather(a) << 4) | gather(b))
    return bytes(even + odd)


def dos_checksum(data):
    checksum = 0
    for n in words(data):
        checksum ^= n
    return (checksum ^ (checksum >> 1)) & 0x55555555


def sectors_from_standard(blocks, track):
    sectors = {}
    for block in blocks:
        require(len(block) == 3 and block[0] == (3, bytes(2))
                and block[1] == (1, b"D\x89D\x89")
                and block[2][0] == 2 and len(block[2][1]) == 540, f"unexpected standard block shape on track {track}")
        raw = block[2][1]
        header = split_decode(raw[:4]) + split_decode(raw[4:20])
        header_checksum = u32(split_decode(raw[20:24]), 0)
        data_checksum = u32(split_decode(raw[24:28]), 0)
        payload = split_decode(raw[28:])
        mark, encoded_track, sector, sectors_to_gap = header[:4]
        require(mark == 255 and encoded_track == track and sector < 11
                and 1 <= sectors_to_gap <= 11 and sector not in sectors,
                f"invalid standard sector header on track {track}")
        require(dos_checksum(header) == header_checksum
                and dos_checksum(payload) == data_checksum,
                f"invalid standard checksum on track {track}, sector {sector}")
        rebuilt = b"".join(map(split_encode, (header[:4], header[4:],
                           struct.pack(">I", dos_checksum(header)),
                           struct.pack(">I", dos_checksum(payload)), payload)))
        require(rebuilt == raw, f"standard field round-trip mismatch on track {track}")
        sectors[sector] = payload
    require(set(sectors) == set(range(11)), f"incomplete standard track {track}")
    return b"".join(sectors[i] for i in range(11))


def rainbow_track(blocks, track):
    block, = blocks
    require(len(block) == 3 and block[0] == (3, bytes(2))
            and block[1][0] == 1 and block[1][1] in (b"D\x89", b"DE")
            and block[2][0] == 2 and len(block[2][1]) == 5125
            and block[2][1][0] == 0,
            f"unexpected Rainbow Arts block shape on track {track}")
    # The first eight data bits encode the MFM zero byte immediately after sync.
    raw = block[2][1][1:]
    decoded = b"".join(split_decode(raw[i:i+4]) for i in range(0, len(raw), 4))
    payload, checksum = decoded[:-4], u32(decoded, 5120)
    require(sum(words(payload)) & 0xFFFFFFFF == checksum,
            f"invalid Rainbow Arts additive checksum on track {track}")
    rebuilt = b"".join(split_encode(decoded[i:i+4])
                       for i in range(0, len(decoded), 4))
    require(rebuilt == raw, f"Rainbow Arts field round-trip mismatch on track {track}")
    return payload, block[1][1].hex()


def ipf_records(data):
    offset = 0
    while offset < len(data):
        require(offset + 12 <= len(data), "truncated IPF record header")
        tag, length, checksum = struct.unpack_from(">4sII", data, offset)
        end = offset + length
        require(12 <= length and end <= len(data), "invalid IPF header size")
        record = data[offset:end]
        require(zlib.crc32(record[:8] + bytes(4) + record[12:]) == checksum,
                f"invalid {tag!r} record CRC")
        payload = None
        if tag == b"DATA":
            require(length == 28, "unexpected DATA header size")
            size, bits, payload_crc = struct.unpack_from(">III", record, 12)
            require((bits + 7) // 8 == size and end + size <= len(data),
                    "invalid DATA payload size")
            payload = data[end:end+size]
            require(zlib.crc32(payload) == payload_crc, "invalid DATA payload CRC")
            end += size
        yield tag, record, payload
        offset = end


def ipf_blocks(payload, count):
    table_end = count * 32
    require(table_end <= len(payload), "truncated block table")
    offsets = [u32(payload, i*32 + 28) for i in range(count)]
    require(offsets == sorted(set(offsets)) and (not count or offsets[0] >= table_end),
            "invalid block data offsets")
    for start, limit in zip(offsets, offsets[1:] + [len(payload)]):
        entries = []
        cursor = start
        while cursor < limit and payload[cursor]:
            opcode = payload[cursor]
            type_id, size_width = opcode & 31, opcode >> 5
            cursor += 1
            require(type_id in (1, 2, 3) and 1 <= size_width <= 4
                    and cursor + size_width <= limit, "unexpected IPF stream opcode")
            size = int.from_bytes(payload[cursor:cursor+size_width], "big")
            cursor += size_width
            require(size > 0 and cursor + size <= limit, "invalid IPF stream size")
            entries.append((type_id, payload[cursor:cursor+size]))
            cursor += size
        require(cursor + 1 == limit and payload[cursor] == 0,
                "missing IPF block terminator or trailing stream bytes")
        yield entries


def inventory(disk):
    require(len(disk) == MEDIA_SIZE and sha(disk) == MEDIA_SHA256,
            "not the pinned retail SPS 1275 image")
    info = None
    images = {}
    streams = {}
    counts = Counter()
    for tag, record, payload in ipf_records(disk):
        counts[tag] += 1
        if tag == b"CAPS":
            require(len(record) == 12, "unexpected CAPS size")
        elif tag == b"INFO":
            require(len(record) == 96, "unexpected INFO size")
            info = list(words(record[12:]))
        elif tag == b"IMGE":
            require(len(record) == 80, "unexpected IMGE size")
            cyl, side, density, _, *other = words(record[12:])
            count, key = other[6], other[9]
            require(side in (0, 1) and key not in images, "invalid track identity")
            images[key] = (2*cyl + side, density, count)
        elif tag == b"DATA":
            key = u32(record, 24)
            require(key not in streams, "duplicate track DATA")
            streams[key] = payload
        else:
            raise ValueError(f"unexpected IPF record tag {tag!r}")
    require(counts == {b"CAPS": 1, b"INFO": 1, b"IMGE": 168, b"DATA": 168},
            "unexpected IPF record counts")
    require(info[:5] == [1, 1, 1, 1275, 1] and info[6:10] == [0, 83, 0, 1],
            "unexpected INFO image identity or geometry")
    require(set(images) == set(streams) and
            sorted(t for t, _, _ in images.values()) == list(range(168)),
            "missing or duplicate physical track")

    tracks = []
    decoded = {}
    for key, (track, density, count) in sorted(images.items(), key=lambda pair: pair[1][0]):
        payload = streams[key]
        entry = {"track": track, "encoded_data_sha256": sha(payload)}
        blocks = list(ipf_blocks(payload, count))
        if (density, count) == (1, 0) and not payload:
            codec, data = "empty", b""
        elif (density, count) == (2, 11):
            codec, data = "amiga_mfm_11x512", sectors_from_standard(blocks, track)
        elif (density, count) == (2, 1):
            codec = "rainbow_arts_mfm_1x5120"
            data, entry["sync"] = rainbow_track(blocks, track)
        else:
            raise ValueError(f"unsupported layout on track {track}")
        decoded[track] = data
        entry.update(codec=codec, size=len(data), sha256=sha(data))
        tracks.append(entry)
    result = {
        "schema_version": 1,
        "format": "conqueror_retail_ipf_intake",
        "image": {"sps_id": 1275, "sha256": MEDIA_SHA256, "size": MEDIA_SIZE},
        "geometry": {"cylinders": 84, "sides": 2, "track_count": 168},
        "track_counts": dict(Counter(t["codec"] for t in tracks)),
        "encoded_sector_field_roundtrip": True,
        "decoded_size": sum(t["size"] for t in tracks),
        "tracks": tracks,
    }
    return result, decoded


def renderer_receipt(captures, decoded, result):
    codec_by_track = {t["track"]: t["codec"] for t in result["tracks"]}
    traces = {}
    for capture in captures:
        receipt = json.loads((capture / "receipt.json").read_text())
        ram = (capture / "ram.bin").read_bytes()
        require(len(ram) == 512 * 1024, "unexpected Chip RAM size")
        begin, end = receipt["begin"], receipt["end"]
        require(begin["pc"] == end["pc"] == RENDERER_ENTRIES["game_iteration"]
                and end["cck"] > begin["cck"], "not an original one-iteration trace")
        hits = Counter()
        with (capture / "instructions.trace").open() as source:
            for line in source:
                pc = line.split(" ", 1)[0]
                if len(pc) == 6 and all(c in "0123456789abcdefABCDEF" for c in pc):
                    hits[int(pc, 16)] += 1
        cck = end["cck"] - begin["cck"]
        require(cck not in traces, "duplicate trace iteration interval")
        traces[cck] = (ram, hits)

    entries = {}
    for name, pc in RENDERER_ENTRIES.items():
        fingerprints = {ram[pc:pc+32] for ram, _ in traces.values()}
        require(len(fingerprints) == 1, f"unstable runtime fingerprint at {pc:06x}")
        fingerprint, = fingerprints
        visits = [hits[pc] for _, hits in traces.values()]
        require(all(visits), f"runtime entry not witnessed at {pc:06x}")
        matches = []
        for track, data in decoded.items():
            # A standard payload is contiguous only within one validated sector;
            # custom payload tracks form a single physical block.
            unit = 512 if codec_by_track[track] == "amiga_mfm_11x512" else 5120
            for offset in range(0, len(data), unit):
                part = data[offset:offset+unit]
                pos = part.find(fingerprint)
                while pos >= 0:
                    matches.append([track, offset + pos])
                    pos = part.find(fingerprint, pos + 1)
        entries[name] = {"guest_pc": f"{pc:06x}", "fingerprint_size": 32,
                         "sha256": sha(fingerprint), "executions": visits,
                         "exact_contained_disk_matches": matches}
    placements = []
    for track, start, end, address in DISK_RAM_SLICES:
        payload = decoded[track][start:end]
        require(len(payload) == end - start, "disk/RAM slice exceeds media unit")
        require(all(ram[address:address+len(payload)] == payload
                    for ram, _ in traces.values()),
                f"RAM content differs from pinned track {track} at {address:06x}")
        placements.append({"track": track, "decoded_offset": start,
                           "size": len(payload), "guest_start": f"{address:06x}",
                           "sha256": sha(payload)})
    return {
        "exact_disk_ram_identity_slices": placements,
        "coverage": "Observed guest entries only, not a source range or disk placement",
        "capture_order": [p.name for p in captures],
        "loop_cck": list(traces),
        "entries": entries,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--capture", type=Path, action="append", default=[])
    parser.add_argument("--check", type=Path, help="compare with a committed receipt")
    args = parser.parse_args()
    try:
        result, decoded = inventory(args.image.read_bytes())
        if args.capture:
            result["runtime_renderer"] = renderer_receipt(args.capture, decoded, result)
        if args.check:
            want = json.loads(args.check.read_text())
            if not args.capture:
                want.pop("runtime_renderer", None)
            require(want == result, "receipt differs")
            print("Conqueror SPS 1275: verified")
        else:
            print(json.dumps(result, indent=2, sort_keys=True))
    except (OSError, ValueError, struct.error) as err:
        parser.exit(1, f"Conqueror intake: {err}\n")


if __name__ == "__main__":
    main()

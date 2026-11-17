"""Bounded stored-track resources; no CPU, FDC, gap synthesis or media writes.

The FOFT codec follows the original reader and Keir Fraser's Disk-Utilities
federation_of_free_traders.c at aa616ccde1e46b5badb742234a4b90e2c15e5b67.
It verifies all three sectors, including MFM clocks and the encoded-word XOR.
Rebuilds edit only proven literal bytes in an immutable IPF template, retaining
all other bytes. This is deliberately not a general IPF encoder.
"""

from __future__ import annotations

import hashlib
import re
import zlib

from .c_backend import PROJECT_ROOT
from .mapped_execution import assemble_ipf_blocks
from .mapped_recipe import integer, keys
from .stx_recovery import inspect_ipf

MAX_BYTES = 32 * 1024 * 1024
CODEC = "foft_mfm_3x2000"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _sha(value):
    if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value):
        raise ValueError("invalid resource identity")
    return value


def _mfm(data, previous=1):
    result = bytearray()
    for value in data:
        word = 0
        for shift in range(7, -1, -1):
            bit = (value >> shift) & 1
            word = (word << 2) | (int(not (previous or bit)) << 1) | bit
            previous = bit
        result.extend(word.to_bytes(2, "big"))
    return bytes(result)


def decode_foft_block(raw, *, track, side):
    """Decode one aligned standard custom-sector block, refusing ambiguity.

    Clock context starts at the raw sync's last data bit, never at a fabricated
    first implied clock. The 13-byte prefix is not interpreted as payload.
    """
    integer(track, 127)
    integer(side, 1)
    sync = bytes.fromhex("44894489")
    if len(raw) != 4040 or raw[26:30] != sync or raw.count(sync) != 1:
        raise ValueError("unsupported or ambiguous FOFT block framing")
    encoded = raw[30:]
    decoded = bytes(
        sum(((word >> (2 * j)) & 1) << j for j in range(8))
        for word in (
            int.from_bytes(encoded[i : i + 2], "big") for i in range(0, len(encoded), 2)
        )
    )
    if _mfm(decoded) != encoded:
        raise ValueError("FOFT MFM clock mismatch")
    if decoded[0] != 255 or decoded[1] != ((2 * track + side) ^ 1) or decoded[2] >= 3:
        raise ValueError("FOFT sector header mismatch")
    checksum = 0
    for pos in range(6, 4006, 2):
        checksum ^= int.from_bytes(encoded[pos : pos + 2], "big")
    if checksum != int.from_bytes(decoded[2003:], "big"):
        raise ValueError("FOFT encoded-word checksum mismatch")
    return decoded[2], decoded[3:2003], checksum


def _track(image, analysis, cylinder, side, root, *, cells=None):
    matches = [
        t for t in analysis["tracks"] if (t["track"], t["side"]) == (cylinder, side)
    ]
    if len(matches) != 1 or len(matches[0]["blocks"]) != 3:
        raise ValueError("missing or ambiguous three-sector track")
    track = matches[0]
    blocks = track["blocks"]
    if any(b["decode_status"] != 0 or b["words"][0] != 32320 for b in blocks):
        raise ValueError("unsupported FOFT track cells")
    if cells is None:
        cells = assemble_ipf_blocks(
            image,
            [(track["index"], b["index"]) for b in blocks],
            3 * 4040,
            project_root=root,
        )
    sectors = {}
    for index, block in enumerate(blocks):
        sector, payload, checksum = decode_foft_block(
            cells[index * 4040 : (index + 1) * 4040], track=cylinder, side=side
        )
        if sector in sectors:
            raise ValueError("duplicate FOFT sector")
        sectors[sector] = {"payload": payload, "block": block, "checksum": checksum}
    if set(sectors) != {0, 1, 2}:
        raise ValueError("incomplete FOFT track")
    return track, sectors


def _read_tracks(image, analysis, plan, root):
    coordinates = sorted(
        {(s["track"], s["side"]) for a in plan["actions"] for s in a["spans"]}
    )
    pairs = []
    for coordinate in coordinates:
        matches = [
            t for t in analysis["tracks"] if (t["track"], t["side"]) == coordinate
        ]
        if len(matches) != 1 or len(matches[0]["blocks"]) != 3:
            raise ValueError("missing or ambiguous three-sector track")
        pairs.extend((matches[0]["index"], b["index"]) for b in matches[0]["blocks"])
    cells = assemble_ipf_blocks(
        image, pairs, len(coordinates) * 12120, project_root=root
    )
    return {
        coordinate: _track(
            image, analysis, *coordinate, root, cells=cells[n * 12120 : (n + 1) * 12120]
        )
        for n, coordinate in enumerate(coordinates)
    }


def validate_plan(plan):
    keys(plan, "schema_version kind image_sha256 geometry codec evidence actions")
    if (
        type(plan["schema_version"]) is not int
        or plan["schema_version"] != 1
        or plan["kind"] != "ipf_resource_recovery"
    ):
        raise ValueError("invalid IPF resource schema")
    _sha(plan["image_sha256"])
    if plan["codec"] != CODEC or not isinstance(plan["evidence"], dict):
        raise ValueError("unsupported resource codec or evidence")
    keys(plan["geometry"], "cylinders sides records")
    for key, maximum in [("cylinders", 128), ("sides", 2), ("records", 256)]:
        if not integer(plan["geometry"][key], maximum):
            raise ValueError("empty resource geometry")
    if not isinstance(plan["actions"], list) or not 1 <= len(plan["actions"]) <= 64:
        raise ValueError("invalid resource actions")
    files = set()
    for action in plan["actions"]:
        keys(action, "op file size sha256 spans resource")
        if (
            action["op"] != "capture"
            or not isinstance(action["file"], str)
            or not re.fullmatch(r"[A-Za-z0-9_-]+\.bin", action["file"])
            or action["file"] in files
        ):
            raise ValueError("invalid or duplicate resource output")
        files.add(action["file"])
        if not integer(action["size"], MAX_BYTES):
            raise ValueError("empty resource")
        _sha(action["sha256"])
        if not isinstance(action["resource"], dict):
            raise ValueError("missing resource evidence")
        keys(action["resource"], "id kind destination trigger reader analysis_target")
        if any(
            not isinstance(action["resource"][key], str) or not action["resource"][key]
            for key in ("id", "kind", "trigger", "reader", "analysis_target")
        ):
            raise ValueError("invalid resource evidence")
        integer(action["resource"]["destination"], 0xFFFFFF)
        if (
            not isinstance(action["spans"], list)
            or not 1 <= len(action["spans"]) <= 256
        ):
            raise ValueError("invalid resource spans")
        total = 0
        touched = []
        for span in action["spans"]:
            keys(span, "track side offset length")
            integer(span["track"], plan["geometry"]["cylinders"] - 1)
            integer(span["side"], plan["geometry"]["sides"] - 1)
            offset, length = (
                integer(span["offset"], 5999),
                integer(span["length"], 6000),
            )
            if not length or offset + length > 6000:
                raise ValueError("resource span outside decoded track")
            if any(
                (s["track"], s["side"]) == (span["track"], span["side"])
                and max(s["offset"], offset)
                < min(s["offset"] + s["length"], offset + length)
                for s in touched
            ):
                raise ValueError("resource spans overlap")
            touched.append(span)
            total += length
        if total != action["size"]:
            raise ValueError("resource span extent mismatch")
    if sum(a["size"] for a in plan["actions"]) > MAX_BYTES:
        raise ValueError("resource output budget exceeded")


def _prepare(image, plan, root):
    validate_plan(plan)
    if not 0 < len(image) <= MAX_BYTES or digest(image) != plan["image_sha256"]:
        raise ValueError("resource source identity mismatch")
    analysis = inspect_ipf(image, project_root=root)
    geometry = plan["geometry"]
    coordinates = [(t["track"], t["side"]) for t in analysis["tracks"]]
    if (
        len(coordinates) != geometry["records"]
        or len(set(coordinates)) != len(coordinates)
        or max(t for t, _ in coordinates) + 1 != geometry["cylinders"]
        or max(s for _, s in coordinates) + 1 != geometry["sides"]
    ):
        raise ValueError("resource media geometry mismatch")
    return analysis


def recover_resources(image, plan, *, project_root=PROJECT_ROOT):
    """The catalog recovery protocol: receipt plus hash-verified private outputs."""
    analysis = _prepare(image, plan, project_root)
    cache = _read_tracks(image, analysis, plan, project_root)
    outputs, captures = {}, []
    for action in plan["actions"]:
        data = bytearray()
        evidence = []
        for span in action["spans"]:
            coordinate = span["track"], span["side"]
            track, sectors = cache[coordinate]
            decoded = b"".join(sectors[n]["payload"] for n in range(3))
            data.extend(decoded[span["offset"] : span["offset"] + span["length"]])
            evidence.append(
                dict(
                    **span,
                    track_index=track["index"],
                    sectors=[
                        {
                            "sector": n,
                            "block": sectors[n]["block"]["index"],
                            "stream_offset": sectors[n]["block"]["stream_offset"],
                            "stream_end": sectors[n]["block"]["stream_end"],
                            "sha256": digest(sectors[n]["payload"]),
                            "checksum": sectors[n]["checksum"],
                        }
                        for n in range(3)
                    ],
                )
            )
        if digest(data) != action["sha256"]:
            raise ValueError("resource output identity mismatch: " + action["file"])
        outputs[action["file"]] = bytes(data)
        captures.append(
            {
                "file": action["file"],
                "size": len(data),
                "sha256": digest(data),
                "spans": evidence,
            }
        )
    return {
        "kind": "ipf_resource_result",
        "image_sha256": digest(image),
        "captures": captures,
        "scope": "Stored sectors only; no original-loader execution or playback",
    }, outputs


def _literal_sector_offset(image, block):
    """Accept exactly the proven encoder-1 literal profile, never infer a map."""
    start, end = block["stream_offset"], block["stream_end"]
    cursor = start
    expected = [(3, 13), (1, 4), (2, 2005)]
    offsets = []
    for kind, count in expected:
        if cursor >= end:
            raise ValueError("truncated literal sector stream")
        code = image[cursor]
        cursor += 1
        width = code >> 5
        if not 1 <= width <= 4 or cursor + width > end:
            raise ValueError("unsupported literal sector count")
        length = int.from_bytes(image[cursor : cursor + width], "big")
        cursor += width
        if code & 31 != kind or length != count or cursor + count > end:
            raise ValueError("unsupported literal sector encoding")
        offsets.append(cursor)
        cursor += count
    if (
        cursor + 1 != end
        or image[cursor] != 0
        or image[offsets[1] : offsets[1] + 4] != bytes.fromhex("44894489")
    ):
        raise ValueError("ambiguous literal sector end or sync")
    return offsets[2]


def _encode_foft_sector(header, payload):
    if len(header) != 3 or len(payload) != 2000:
        raise ValueError("invalid FOFT sector extent")
    body = bytes(header) + bytes(payload)
    encoded = _mfm(body)
    checksum = 0
    for pos in range(6, 4006, 2):
        checksum ^= int.from_bytes(encoded[pos : pos + 2], "big")
    return body + checksum.to_bytes(2, "big")


def rebuild_resources(image, plan, outputs, *, project_root=PROJECT_ROOT):
    """Template rebuild, allowing only exact assembled resource identities.

    Callers supply independently assembled files. Every output must match its
    declared original identity. Synthetic codec tests separately exercise real
    mutations; this first milestone is an exact restoration, not an editor.
    """
    original_receipt, original = recover_resources(
        image, plan, project_root=project_root
    )
    if set(outputs) != set(original) or any(
        outputs[n] != original[n] for n in original
    ):
        raise ValueError("assembled resource differs from bound original identity")
    analysis = _prepare(image, plan, project_root)
    if analysis["info_words"][1:3] != [1, 1]:
        raise ValueError("template writer requires encoder 1 revision 1")
    result = bytearray(image)
    cache = _read_tracks(image, analysis, plan, project_root)
    replacements = {}
    for action in plan["actions"]:
        cursor = 0
        for span in action["spans"]:
            track, sectors = cache[span["track"], span["side"]]
            for pos in range(span["offset"], span["offset"] + span["length"]):
                sector, within = divmod(pos, 2000)
                key = track["index"], sector
                if key not in replacements:
                    replacements[key] = [
                        track,
                        sectors[sector],
                        bytearray(sectors[sector]["payload"]),
                        set(),
                    ]
                record = replacements[key]
                value = outputs[action["file"]][cursor]
                cursor += 1
                if within in record[3] and record[2][within] != value:
                    raise ValueError("conflicting resource ownership")
                record[2][within] = value
                record[3].add(within)
    allowed = set()
    for track, sector, payload, _ in replacements.values():
        block = sector["block"]
        at = _literal_sector_offset(image, block)
        # Reject descriptor/stream aliasing rather than changing another owner.
        for other in analysis["tracks"]:
            if other["index"] != track["index"] and max(
                track["data_offset"], other["data_offset"]
            ) < min(
                track["data_offset"] + track["data_size"],
                other["data_offset"] + other["data_size"],
            ):
                raise ValueError("aliased IPF DATA payload ownership")
            for candidate in other["blocks"]:
                if (
                    (other["index"], candidate["index"])
                    != (track["index"], block["index"])
                    and candidate["stream_end"] >= 0
                    and max(block["stream_offset"], candidate["stream_offset"])
                    < min(block["stream_end"], candidate["stream_end"])
                ):
                    raise ValueError("aliased IPF stream ownership")
        if block["stream_offset"] < track["data_offset"] + 32 * len(track["blocks"]):
            raise ValueError("literal stream overlaps descriptors")
        result[at : at + 2005] = _encode_foft_sector(image[at : at + 3], payload)
        allowed.update(range(at, at + 2005))
    for offset in sorted(
        {record[0]["data_offset"] for record in replacements.values()}
    ):
        chunks = [
            c
            for c in analysis["chunks"]
            if c["tag"] == "DATA" and c["offset"] + c["size"] == offset
        ]
        if len(chunks) != 1:
            raise ValueError("ambiguous IPF DATA header")
        chunk = chunks[0]
        header = chunk["offset"]
        result[header + 20 : header + 24] = zlib.crc32(
            result[offset : offset + chunk["payload_size"]]
        ).to_bytes(4, "big")
        result[header + 8 : header + 12] = b"\0" * 4
        result[header + 8 : header + 12] = zlib.crc32(result[header:offset]).to_bytes(
            4, "big"
        )
        allowed.update(range(header + 8, header + 12))
        allowed.update(range(header + 20, header + 24))
    if len(result) != len(image) or any(
        a != b and n not in allowed
        for n, (a, b) in enumerate(zip(image, result, strict=False))
    ):
        raise ValueError("template preservation failed")
    rebuilt_plan = dict(plan, image_sha256=digest(result))
    receipt, recovered = recover_resources(
        bytes(result), rebuilt_plan, project_root=project_root
    )
    if recovered != outputs:
        raise ValueError("rebuilt resource re-decode mismatch")
    receipt.update(
        kind="ipf_template_rebuild_result",
        original_sha256=digest(image),
        rebuilt_sha256=digest(result),
        untouched_bytes_preserved=True,
        regenerated_sectors=len(replacements),
        original_captures=original_receipt["captures"],
        scope="Exact literal template rebuild; boot and playback not tested",
    )
    return bytes(result), receipt

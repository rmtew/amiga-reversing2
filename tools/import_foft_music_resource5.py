"""Initial, independent resource-5 import; never inherit bank9's voice/grammar.

Only the static ABI, independently inspected consumers, instrument headers and
their bounded PCM extents are imported. Later edits use target commands.
"""

from __future__ import annotations

import copy
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from amiga_reversing.disasm import game_catalog
from amiga_reversing.disasm.binary_source import write_source_descriptor
from amiga_reversing.disasm.effective_metadata import effective_metadata_file
from amiga_reversing.disasm.projects import create_project_at_path
from amiga_reversing.disasm.target_metadata import (
    TargetMetadata,
    target_metadata_json_payload,
    write_target_metadata,
)

TARGET = "amiga_raw_foft_music_bank5_sps0613"
BASE = 0x58000
BANK = 0x15E0


def instrument_spans(data):
    """Initial eight LONG offsets; shared headers/samples retain their aliases.

    New consumers at $58298 / $58438 establish base+LONG and AUDxLEN WORD
    counts. $593C2 indexes the initial offset table; runtime mutations stay open.
    """
    if len(data) < BANK + 32:
        raise ValueError("truncated bank5 instrument offsets")
    offsets = struct.unpack_from(">8I", data, BANK)
    records, spans = [], {}
    for index, offset in enumerate(offsets):
        at = BANK + offset
        if offset < 32 or offset & 1 or at + 28 > len(data):
            raise ValueError("instrument header outside bank")
        sample, repeat, sample_words, repeat_words = struct.unpack_from(
            ">2I2H", data, at
        )
        records.append(
            {
                "index": index,
                "offset": at,
                "sample": sample,
                "repeat": repeat,
                "sample_words": sample_words,
                "repeat_words": repeat_words,
            }
        )
        for kind, value, count in [
            ("Sample", sample, sample_words),
            ("Repeat", repeat, repeat_words),
        ]:
            if not count:
                continue
            start, length = BANK + value, count * 2
            if start < BANK + 32 or start + length > len(data):
                raise ValueError("instrument PCM outside bank")
            spans.setdefault((start, length, kind), []).append(index)
    headers = {(r["offset"], r["offset"] + 28) for r in records}
    if any(a != c and max(a, c) < min(b, d) for a, b in headers for c, d in headers):
        raise ValueError("partially overlapping instrument headers")
    unique = sorted(spans)
    for i, (start, length, _) in enumerate(unique):
        if any(max(start, a) < min(start + length, b) for a, b in headers):
            raise ValueError("instrument PCM overlaps a header")
        if any(max(start, at) < min(start + length, at + n) for at, n, _ in unique[:i]):
            raise ValueError("partially overlapping PCM ownership needs review")
    return records, [
        {
            "start": s,
            "length": n,
            "kind": k,
            "indices": spans[s, n, k],
            "name": "bank5" + k + "_".join(map(str, spans[s, n, k])),
        }
        for s, n, k in unique
    ]


def main():
    if (ROOT / "targets" / TARGET).exists():
        raise ValueError(
            "initial import requires a fresh target; use target commands afterward"
        )
    family = game_catalog.load_family(ROOT, "foft")
    binding = family["targets"][TARGET]
    data = game_catalog.materialize(ROOT, "foft", binding["artifact"]).read_bytes()
    records, spans = instrument_spans(data)
    payload = json.loads(
        json.dumps(
            target_metadata_json_payload(
                TargetMetadata(target_type="raw_binary", entry_register_seeds=())
            )
        )
    )
    payload["source_output_policy"] = {
        "mode": "binary_assets",
        "minimum_asset_size": 256,
    }
    proof = {
        "seed_origin": "manual_analysis",
        "review_status": "seeded",
        "citation": "Original resource5, independently checksum-verified. Native original-code consumer trace; not bank9 layout inheritance.",
        "source_id": "foft-sps0613-resource5",
    }
    names = {
        0: "MusicEntryStart",
        4: "MusicEntryTick",
        14: "MusicEntryStop",
        0x298: "Bank5StartVoice",
        0x35A: "Bank5MuteAudio",
        0x39E: "Bank5UpdateVoices",
        0x3C0: "Bank5UpdateVoice",
        0x41E: "Bank5UpdateLoopedVoice",
        0x470: "Bank5UpdateOneShotVoice",
        0x1015: "bank5InstrumentMap",
        0x1036: "Bank5StartSong",
        0x11AE: "Bank5UpdateSong",
        0x13C2: "Bank5DecodePatternCommand",
        0x153C: "Bank5UpdatePeriodSlide",
        0x1590: "Bank5UpdateVolumeModulation",
    }
    for at, name in names.items():
        if at == 0x1015:
            continue
        payload["seeded_code_entrypoints"].append(dict(addr=at, name=name, **proof))
        payload["seeded_code_labels"].append(dict(addr=at, name=name, **proof))
    with effective_metadata_file(ROOT / "targets/amiga_raw_foft") as metadata_path:
        parent = json.loads(Path(metadata_path).read_bytes())
    # Shared definition is retained only after checking this bank's consumers
    # for every used +0..+26 field. The 40-byte voice structure is NOT Audio2.
    payload["custom_structs"] = [
        copy.deepcopy(
            next(s for s in parent["custom_structs"] if s["name"] == "AudioInstrument")
        )
    ]

    def entity(at, end, name, **extra):
        payload["seeded_entities"].append(
            dict(addr=at, end=end, name=name, type="data", **proof, **extra)
        )

    entity(24, 0xD8, "bank5PitchOctaveRatios", unit="long")
    entity(0xD8, 0x1F8, "bank5PitchScaleTable", unit="long")
    entity(BANK, BANK + 32, "bank5InstrumentOffsets", unit="long")
    for at in sorted({r["offset"] for r in records}):
        indices = [r["index"] for r in records if r["offset"] == at]
        entity(
            at,
            at + 28,
            "bank5Instrument" + "_".join(map(str, indices)),
            unit="word",
            struct_name="AudioInstrument",
        )
    for span in spans:
        entity(
            span["start"],
            span["start"] + span["length"],
            span["name"],
            unit="byte",
            subtype="sound_sample",
        )
    for index, at in enumerate([0x1F8, 0x220, 0x248, 0x270]):
        entity(at, at + 40, f"bank5Voice{index}", unit="word")
    for index, at in enumerate([0xEF6, 0xF3E, 0xF86, 0xFCE]):
        # Roots have a72-byte stride. The accepted note-command write at$12EE
        # proves byte+70; the71-byte prefix ends at the next known boundary.
        # A full fourth stride would overlap the instrument map at$1015.
        entity(at, at + 71, f"bank5PatternTrack{index}", unit="byte")
    entity(0xDC4, 0xDD4, "bank5InitialSongOffsets", unit="word")
    entity(0x1015, 0x1035, "bank5InstrumentMap", unit="byte")
    payload["entry_comments"] = [
        dict(
            addr=0x3C0,
            comment="Resource5 voice stride is 40 bytes; callback LONG +32, instrument pointer +36. Initial bank9 Audio2 is incompatible; callback targets remain open.",
            **proof,
        ),
        dict(
            addr=0x1036,
            comment="Masks subsong to a byte and reads four WORD offsets per descriptor at bank5InitialSongOffsets. Menu uses indices 0 and 1; no general bound or song-count closure.",
            **proof,
        ),
    ]
    target = create_project_at_path(
        "targets/" + TARGET,
        ROOT,
        origin={
            "kind": "resource_import",
            "family": "foft",
            "artifact": binding["artifact"],
        },
    )
    write_source_descriptor(
        target, {"kind": "artifact", "family": "foft", "target": TARGET}
    )
    write_target_metadata(target, TargetMetadata.from_dict(payload))
    receipt = {
        "target": TARGET,
        "sha256": binding["artifact"],
        "bytes": len(data),
        "instrument_records": records,
        "pcm_spans": spans,
        "voice_stride": 40,
        "callback_offset": 32,
        "instrument_pointer_offset": 36,
        "limits": "Initial descriptors only. No copied Audio2, pattern grammar, callback closure or playback claim.",
    }
    (target / "resource-import.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()

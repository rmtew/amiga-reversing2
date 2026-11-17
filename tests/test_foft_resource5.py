"""Distinct stored bank, conservative initial PCM ownership and inert run plan."""

import json
import struct
from pathlib import Path

import pytest

from amiga_reversing.disasm.effective_metadata import effective_metadata_file
from amiga_reversing.disasm.source_package_publish import load_published_source_package
from amiga_reversing.disasm.target_metadata import load_target_metadata
from amiga_reversing.tools.copperline_session import compile_scenario
from amiga_reversing.tools.original_media_prefix import validate_prefix_target
from tools.foft_disk import resource_plan
from tools.import_foft_music_resource5 import BANK, instrument_spans

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "targets/amiga_raw_foft_music_bank5_sps0613"
PLAN = ROOT / "docs/validation/plans/foft-natural-music-resource5.json"


def synthetic_bank():
    data = bytearray(BANK + 512)
    struct.pack_into(">8I", data, BANK, *([32] * 8))
    struct.pack_into(">2I2H", data, BANK + 32, 64, 264, 100, 50)
    return data


def test_initial_header_aliases_share_owned_pcm_and_lengths_are_words():
    records, spans = instrument_spans(synthetic_bank())
    assert len(records) == 8 and len({r["offset"] for r in records}) == 1
    assert [(s["start"], s["length"]) for s in spans] == [
        (BANK + 64, 200),
        (BANK + 264, 100),
    ]
    assert all(s["indices"] == list(range(8)) for s in spans)


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (lambda b: b.clear(), "truncated"),
        (lambda b: struct.pack_into(">I", b, BANK, 31), "header"),
        (lambda b: struct.pack_into(">I", b, BANK + 32, 40), "overlaps a header"),
        (lambda b: struct.pack_into(">I", b, BANK + 32, 500), "outside bank"),
        (lambda b: struct.pack_into(">I", b, BANK + 36, 164), "overlapping PCM"),
    ],
)
def test_pcm_probe_refuses_bad_bounds_or_ambiguous_ownership(mutation, reason):
    data = synthetic_bank()
    mutation(data)
    with pytest.raises(ValueError, match=reason):
        instrument_spans(data)


def test_zero_length_repeat_is_not_promoted_to_a_reference_or_asset():
    data = synthetic_bank()
    struct.pack_into(">I", data, BANK + 36, 0xFFFFFFFF)
    struct.pack_into(">H", data, BANK + 42, 0)
    _, spans = instrument_spans(data)
    assert len(spans) == 1 and spans[0]["kind"] == "Sample"


def test_reviewed_resource_plan_keeps_distinct_identities_at_the_same_address():
    nine, _ = resource_plan(9)
    five, recipes = resource_plan(5)
    a = next(a for a in nine["actions"] if a["resource"]["id"] == "music-resource-9")
    b = next(a for a in five["actions"] if a["resource"]["id"] == "music-resource-5")
    assert a["resource"]["destination"] == b["resource"]["destination"] == 0x58000
    assert (
        a["sha256"] != b["sha256"]
        and a["resource"]["analysis_target"] != b["resource"]["analysis_target"]
    )
    assert len(recipes) == 2
    assert len(b["spans"]) == 5 and sum(s["length"] for s in b["spans"]) == 29578
    assert [(s["track"], s["side"]) for s in b["spans"]] == [
        (66, 1),
        (66, 0),
        (67, 1),
        (67, 0),
        (68, 1),
    ]
    with pytest.raises(ValueError, match="unsupported reviewed"):
        resource_plan(4)


def test_resource5_has_its_own_voice_type_and_shared_relative_long_aliases():
    with effective_metadata_file(TARGET) as path:
        payload = json.loads(Path(path).read_bytes())
    voice = next(s for s in payload["custom_structs"] if s["name"] == "Bank5Voice")
    assert voice["size"] == 40
    assert {f["name"]: f["offset"] for f in voice["fields"]}["update_callback"] == 32
    assert not any(s["name"] == "Audio2" for s in payload["custom_structs"])
    text = (TARGET / "source.s").read_text()
    assert "Bank5Voice_update_callback" in text
    assert "dc.l bank5Instruments-bank5InstrumentOffsets" in text
    assert "dc.l bank5Repeat2_7-bank5InstrumentOffsets" in text
    assert len(load_target_metadata(TARGET).seeded_code_entrypoints) >= 3


def test_review_plan_is_inert_and_existing_prefix_guard_still_refuses_foft(tmp_path):
    plan = json.loads(PLAN.read_bytes())
    assert (
        plan["execution_enabled"] is False
        and "phases" not in plan
        and "identifier" not in plan
    )
    with pytest.raises(ValueError, match="non-empty identifier"):
        compile_scenario("amiga_raw_foft", PLAN, tmp_path / "not-created.json")
    assert not (tmp_path / "not-created.json").exists()
    with pytest.raises(ValueError, match="Original-media"):
        validate_prefix_target("foft", "amiga_raw_foft")
    assert (
        plan["inputs"]["resource"]["package_sha256"]
        == load_published_source_package(TARGET)["sha256"]
    )
    assert plan["installed_bytes_contract"]["read_count"] == 8

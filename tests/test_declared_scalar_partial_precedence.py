"""Compatible weak scalar spans retain only their uncovered native footprint."""

import json
import re
from collections import Counter

import pytest
from test_declared_scalar_opaque_precedence import fixture, policy

from amiga_reversing.disasm import c_backend
from amiga_reversing.disasm.effective_metadata import effective_metadata_file
from amiga_reversing.disasm.manual_actions import MANUAL_ACTION_LOG_FILE_NAME
from amiga_reversing.disasm.project_paths import PROJECT_ROOT


def scalar_fixture(tmp_path, *, unit=2, arrays=((8, 16),), protection=None):
    source, raw, _ = fixture(
        tmp_path, arrays=arrays, stride=unit, protection=protection
    )
    path = tmp_path / "target_metadata.json"
    meta = json.loads(path.read_text())
    meta["seeded_entities"][0].update(
        subtype=None, unit="word" if unit == 2 else "long"
    )
    for entity in meta["seeded_entities"][1:]:
        entity["type"] = "data"
    meta["seeded_entities"].append(
        {
            "hunk": 0,
            "addr": 6,
            "name": "prefixInterior",
            "type": "data",
            "seed_origin": "manual_analysis",
            "review_status": "seeded",
            "citation": "Existing label",
        }
    )
    path.write_text(json.dumps(meta))
    return source, raw


@pytest.mark.parametrize("unit", [2, 4])
@pytest.mark.parametrize(
    ("arrays", "remaining"),
    [
        (((4, 12),), [(12, 8)]),
        (((8, 16),), [(4, 4), (16, 4)]),
        (((12, 20),), [(4, 8)]),
        (((4, 20),), []),
        (((8, 12), (12, 16)), [(4, 4), (16, 4)]),
        (((20, 24),), [(4, 16)]),
    ],
)
def test_compatible_partial_scalar_projection(tmp_path, unit, arrays, remaining):
    source, raw = scalar_fixture(tmp_path, unit=unit, arrays=arrays)
    paths = [tmp_path / "target_metadata.json", tmp_path / MANUAL_ACTION_LOG_FILE_NAME]
    before = [p.read_bytes() for p in paths]
    kind = "words" if unit == 2 else "longs"
    actual = Counter(
        (i["offset"], i["size"])
        for i in policy(source, tmp_path)
        if i["size"] and i["kind"] == kind
    )
    assert actual == Counter(remaining + [(lo, hi - lo) for lo, hi in arrays])
    with effective_metadata_file(tmp_path) as metadata:
        text = c_backend.render_project_source_with_c_backend(
            source, metadata_path=metadata, project_root=PROJECT_ROOT
        )
    for label in [
        "opaqueStart",
        "arrayStart",
        "arrayEnd",
        "opaqueEnd",
    ]:
        assert re.search(r"^" + label + r"(?::|\s+(?:EQU|equ)\s)", text, re.MULTILINE)
    for comment in [
        "Keep prefix annotation",
        "Keep suffix annotation",
        "Keep this interior annotation",
    ]:
        assert comment in text
    rebuilt, _ = c_backend.assemble_platform_source_text_with_c_backend(
        "amiga-raw", text, project_root=PROJECT_ROOT
    )
    assert rebuilt == raw
    # All independent interior labels remain authoritative, including labels
    # the ordinary render plan elects not to emit in scalar storage.
    metadata = json.loads(paths[0].read_text())
    assert {e.get("name") for e in metadata["seeded_entities"]} >= {
        "arrayInterior",
        "opaqueInterior",
    }
    assert [p.read_bytes() for p in paths] == before
    assert source.path.read_bytes() == raw


@pytest.mark.parametrize(
    "protection",
    ["comment", "named", "manual", "validated", "evidence", "owner", "parents"],
)
def test_owned_scalar_span_is_not_trimmed(tmp_path, protection):
    source, _ = scalar_fixture(tmp_path, protection=protection)
    assert any(i["offset"] == 4 and i["size"] == 16 for i in policy(source, tmp_path))


@pytest.mark.parametrize("mismatch", ["kind", "phase", "mixed"])
def test_incompatible_overlap_keeps_original_scalar_fact(tmp_path, mismatch):
    source, _ = scalar_fixture(
        tmp_path, unit=4, arrays=((6, 14),) if mismatch == "phase" else ((8, 16),)
    )
    path = tmp_path / "target_metadata.json"
    meta = json.loads(path.read_text())
    if mismatch == "kind":
        meta["seeded_entities"][0]["unit"] = "word"
    if mismatch == "mixed":
        meta["seeded_entities"].append(
            {
                "hunk": 0,
                "addr": 16,
                "end": 18,
                "type": "data",
                "unit": "word",
                "source_id": "manual_action_log",
                "citation": "manual_action_log:other",
                "seed_origin": "manual_analysis",
                "review_status": "seeded",
            }
        )
    path.write_text(json.dumps(meta))
    assert any(i["offset"] == 4 and i["size"] == 16 for i in policy(source, tmp_path))

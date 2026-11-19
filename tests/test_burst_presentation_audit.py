"""Synthetic reviewed spans; no original game data or guest execution."""

import copy
import json

import pytest

from tools.foft_burst_audit import audit, digest


def fixture():
    base = 0x1000
    payload = bytearray(128)
    payload[32:42] = bytes.fromhex("000e00030000000a0014")
    payload[64:66] = bytes.fromhex("0001")
    payload = bytes(payload)
    field = lambda n, o, t="WORD", s=2: {"name": n, "offset": o, "type": t, "size": s}
    xyz = {
        "name": "XYZ",
        "size": 6,
        "fields": [field(n, i * 2) for i, n in enumerate("xyz")],
    }
    face = {
        "name": "Triangle",
        "size": 10,
        "fields": [
            field(n, i * 2, "UWORD")
            for i, n in enumerate(["style", "count", "a", "b", "c"])
        ],
    }
    control = {
        "name": "Control",
        "size": 14,
        "fields": [field("word" + str(i), i * 2) for i in range(7)],
    }
    particle = {
        "name": "Particle",
        "size": 18,
        "fields": [field("word" + str(i), i * 2) for i in range(7)]
        + [field("relativeRowOffset", 14, "LONG", 4)],
    }
    views = []
    for name, lo, hi, count, typ in [
        ("burstMeshFrameOffsets", 0, 2, 1, None),
        ("burstMeshVertexFrames", 8, 26, 3, xyz),
        ("projectedBurstFaces", 32, 42, 1, face),
        ("projectedBurstOrigin", 48, 54, 1, xyz),
        ("projectedBurstControl", 56, 70, 1, control),
        ("hyperspaceParticleRecords", 72, 90, 1, particle),
    ]:
        v = {
            "name": name,
            "lo": lo + base,
            "hi": hi + base,
            "count": count,
            "sha256": digest(payload[lo:hi]),
        }
        if typ is None:
            v["scalar"] = True
        else:
            v["typ"] = typ
        views.append(v)
    mapping = {
        "size": len(payload),
        "sha256": digest(payload),
        "revision": "synthetic",
        "load_address": base,
        "views": views,
        "origin_initial": [0, 0, 0],
        "control_initial": [0, 0, 0, 0, 1, 0, 0],
        "mesh": {
            "frame_count": 1,
            "vertices_per_frame": 3,
            "source_stride": 6,
            "frame_bytes": 18,
            "projection_stride": 10,
            "faces": {
                "start_runtime": base + 32,
                "end_runtime": base + 42,
                "face_count": 1,
                "projection_max_byte_offset": 20,
                "sha256": digest(payload[32:42]),
            },
            "unclassified": [
                {
                    "start_runtime": base + 114,
                    "end_runtime": base + 116,
                    "sha256": digest(payload[114:116]),
                }
            ],
        },
        "particles": {"stride": 18, "record_count": 1, "relative_row_long_offset": 14},
        "atlas": {
            "start_runtime": base + 96,
            "bytes": 16,
            "sha256": digest(payload[96:112]),
            "conditional_snapshots": [0],
            "rows": 1,
            "source_row_pitch": 16,
            "read_bytes_per_row": 16,
            "conditional_read_min": 0,
            "conditional_read_max": 15,
            "conditional_unique_read_bytes": 16,
            "conditional_source_read_set_sha256": digest(
                json.dumps(list(range(16)), separators=(",", ":")).encode()
            ),
        },
    }
    mapping["atlas"].update(
        caller_cached_bounds={
            "x_minus_16_min": 16,
            "x_minus_16_max": 31,
            "y_min": 16,
            "y_max": 16,
        },
        caller_center_bounds={"x_min": 32, "x_max": 47, "y_min": 16, "y_max": 16},
        destination={
            "row_min": 0,
            "row_max": 0,
            "byte_column_min": 2,
            "byte_column_max": 5,
        },
    )
    return payload, mapping


def test_checked_views_keep_bytes_and_mapping_unchanged():
    payload, mapping = fixture()
    before = copy.deepcopy(mapping)
    result = audit(payload, mapping)
    assert result["record_instances"] == 7 and result["record_fields"] == 32
    assert result["bounded_bytes"] == 68 and result["face_records"] == 1
    assert not result["guest_execution"] and not result["ownership_or_code_inferred"]
    assert mapping == before


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ("count", "count/stride"),
        ("stride", "frame contract"),
        ("source", "outside"),
        ("overlap", "unclassified"),
        ("icon", "conditional icon"),
        ("pointer", "relative LONG"),
        ("center", "cached center"),
    ],
)
def test_inconsistent_reviewed_contracts_fail_without_inference(change, match):
    payload, m = fixture()
    if change == "count":
        m["views"][1]["count"] = 4
    if change == "stride":
        m["mesh"]["source_stride"] = 8
    if change == "source":
        m["views"][1]["hi"] = 0x2000
    if change == "overlap":
        m["mesh"]["unclassified"][0].update(start_runtime=0x1008, end_runtime=0x100A)
    if change == "icon":
        m["atlas"]["conditional_snapshots"] = [1]
    if change == "pointer":
        m["views"][-1]["typ"]["fields"][-1].update(
            type="APTR",
            value_kind="target_pointer",
            pointer_address_domain="mapped_source",
        )
    if change == "center":
        m["atlas"]["caller_center_bounds"]["x_min"] = 16
    with pytest.raises(ValueError, match=match):
        audit(payload, m)


def test_frame_offset_is_rechecked_even_with_fresh_fingerprints():
    payload, m = fixture()
    payload = bytes.fromhex("0006") + payload[2:]
    m["sha256"] = digest(payload)
    m["views"][0]["sha256"] = digest(payload[:2])
    with pytest.raises(ValueError, match="frame offsets"):
        audit(payload, m)


def test_face_vertex_must_be_an_exact_projected_row():
    payload, m = fixture()
    payload = payload[:36] + bytes.fromhex("0001") + payload[38:]
    m["sha256"] = digest(payload)
    m["views"][2]["sha256"] = m["mesh"]["faces"]["sha256"] = digest(payload[32:42])
    with pytest.raises(ValueError, match="vertex"):
        audit(payload, m)

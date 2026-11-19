"""Recheck reviewed burst/particle views and native reader witnesses, read-only.

No scanning, new decoding, ownership inference or execution. The map supplies
all extents and relationships; native accepted facts pin the reviewed consumers.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def span(payload, base, lo, hi):
    if (
        type(lo) is not int
        or type(hi) is not int
        or not 0 <= lo - base < hi - base <= len(payload)
    ):
        raise ValueError("reviewed span is outside the source member")
    return payload[lo - base : hi - base]


def audit(payload, mapping):
    from amiga_reversing.disasm.projected_face_audit import audit_face_views
    from amiga_reversing.disasm.record_arrays import record_shape

    if len(payload) != mapping["size"] or digest(payload) != mapping["sha256"]:
        raise ValueError("source identity differs")
    base, views, records, fields, total = mapping["load_address"], {}, 0, 0, 0
    for view in mapping["views"]:
        lo, hi, count = view["lo"], view["hi"], view["count"]
        data = span(payload, base, lo, hi)
        if (
            view["name"] in views
            or lo % 2
            or type(count) is not int
            or count < 1
            or digest(data) != view["sha256"]
        ):
            raise ValueError("view identity, alignment or fingerprint differs")
        stride = 2 if view.get("scalar") else record_shape(view["typ"])["size"]
        if count * stride != len(data):
            raise ValueError("view count/stride does not consume its exact extent")
        if not view.get("scalar"):
            records += count
            fields += count * len(view["typ"]["fields"])
        total += len(data)
        views[view["name"]] = data
    ordered = sorted((v["lo"], v["hi"]) for v in mapping["views"])
    if any(a[1] > b[0] for a, b in zip(ordered, ordered[1:], strict=False)):
        raise ValueError("distinct reviewed source views overlap")
    mesh = mapping["mesh"]
    count, vertices, stride = (
        mesh["frame_count"],
        mesh["vertices_per_frame"],
        mesh["source_stride"],
    )
    if (
        any(type(v) is not int or v < 1 for v in [count, vertices, stride])
        or stride != 6
        or mesh["frame_bytes"] != vertices * stride
    ):
        raise ValueError("mesh frame contract differs")
    offsets = views["burstMeshFrameOffsets"]
    expected = [i * vertices * stride for i in range(count)]
    actual = [
        int.from_bytes(offsets[i : i + 2], "big", signed=True)
        for i in range(0, len(offsets), 2)
    ]
    if (
        actual != expected
        or len(views["burstMeshVertexFrames"]) != count * vertices * stride
    ):
        raise ValueError("reviewed frame offsets or vertex extent differ")
    faces = audit_face_views(
        payload,
        load_address=base,
        views=[mesh["faces"]],
        projection_stride=mesh["projection_stride"],
        style_count=16,
    )
    if (
        len(views["projectedBurstOrigin"]) != 6
        or [
            int.from_bytes(views["projectedBurstOrigin"][i : i + 2], "big")
            for i in [0, 2, 4]
        ]
        != mapping["origin_initial"]
    ):
        raise ValueError("initial origin differs")
    control = views["projectedBurstControl"]
    if (
        len(control) != 14
        or [int.from_bytes(control[i : i + 2], "big") for i in range(0, 14, 2)]
        != mapping["control_initial"]
    ):
        raise ValueError("initial control record differs")
    particles = mapping["particles"]
    particle_view = next(
        v for v in mapping["views"] if v["name"] == "hyperspaceParticleRecords"
    )
    row_field = next(
        (f for f in particle_view["typ"]["fields"] if f["offset"] == 14), {}
    )
    if (
        particles["stride"] != 18
        or particles["relative_row_long_offset"] != 14
        or row_field.get("type") != "LONG"
        or row_field.get("size") != 4
        or row_field.get("value_kind", "scalar") != "scalar"
        or len(views["hyperspaceParticleRecords"]) != particles["record_count"] * 18
        or any(views["hyperspaceParticleRecords"])
    ):
        raise ValueError("particle initial extent or relative LONG contract differs")
    for unknown in mesh["unclassified"]:
        data = span(payload, base, unknown["start_runtime"], unknown["end_runtime"])
        if digest(data) != unknown["sha256"] or any(
            lo < unknown["end_runtime"] and hi > unknown["start_runtime"]
            for lo, hi in ordered
        ):
            raise ValueError("preserved unclassified span differs or gained an owner")
    atlas = mapping["atlas"]
    data = span(
        payload, base, atlas["start_runtime"], atlas["start_runtime"] + atlas["bytes"]
    )
    if digest(data) != atlas["sha256"]:
        raise ValueError("existing icon source fingerprint differs")
    selected = sorted(
        {
            step * 16 + row * atlas["source_row_pitch"] + col
            for step in atlas["conditional_snapshots"]
            for row in range(atlas["rows"])
            for col in range(atlas["read_bytes_per_row"])
        }
    )
    if (
        not selected
        or selected[0] < 0
        or selected[-1] >= len(data)
        or selected[0] != atlas["conditional_read_min"]
        or selected[-1] != atlas["conditional_read_max"]
        or len(selected) != atlas["conditional_unique_read_bytes"]
        or digest(json.dumps(selected, separators=(",", ":")).encode())
        != atlas["conditional_source_read_set_sha256"]
    ):
        raise ValueError(
            "conditional icon reads exceed or differ from the reviewed source"
        )
    if "caller_cached_bounds" in atlas:
        cached = atlas["caller_cached_bounds"]
        center, dest = atlas["caller_center_bounds"], atlas["destination"]
        if (
            center["x_min"] != cached["x_minus_16_min"] + 16
            or center["x_max"] != cached["x_minus_16_max"] + 16
            or center["y_min"] != cached["y_min"]
            or center["y_max"] != cached["y_max"]
            or dest["row_min"] != cached["y_min"] - 16
            or dest["row_max"] != cached["y_max"] - 16 + atlas["rows"] - 1
            or dest["byte_column_min"] != cached["x_minus_16_min"] // 16 * 2
            or dest["byte_column_max"] != cached["x_minus_16_max"] // 16 * 2 + 3
        ):
            raise ValueError("cached center and destination bounds differ")
    return {
        "kind": "foft_burst_particle_audit",
        "revision": mapping["revision"],
        "typed_views": len(views),
        "bounded_bytes": total,
        "record_instances": records,
        "record_fields": fields,
        "mesh_frames": count,
        "mesh_vertices": count * vertices,
        "face_records": faces["views"][0]["face_count"],
        "particle_records": particles["record_count"],
        "conditional_icon_bytes": len(selected),
        "ownership_or_code_inferred": False,
        "guest_execution": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--map",
        type=Path,
        default=ROOT / "docs/validation/foft-burst-particle-presentation.json",
    )
    parser.add_argument("--media", action="append", default=[])
    args = parser.parse_args(argv)
    mapping = json.loads(args.map.read_text())
    from amiga_reversing.disasm.disk_set import DiskSet
    from amiga_reversing.disasm.disk_set_state import _artifact
    from amiga_reversing.disasm.target_history import target_lock

    root = ROOT / "targets" / mapping["target_id"]
    with target_lock(root):
        owner = DiskSet.load(root, project_root=ROOT)
        if owner.revision != mapping["revision"]:
            raise ValueError("map revision differs; review before repinning")
        source, artifact = _artifact(
            owner, "main", dict(v.split("=", 1) for v in args.media)
        )
        try:
            payload = source.read_bytes()
            result = audit(payload, mapping)
            for window in mapping["readers"]:
                rows = []
                cursor = 0
                while True:
                    page = artifact.query_payload(
                        "instructions",
                        section_index=0,
                        source_offset=window["start_runtime"] - mapping["load_address"],
                        end_offset=window["end_runtime"] - mapping["load_address"],
                        offset=cursor,
                        limit=100,
                    )
                    rows += page["items"]
                    cursor += len(page["items"])
                    if not page["has_more"]:
                        break
                code = b"".join(bytes.fromhex(r["bytes"]) for r in rows)
                if (
                    len(rows) != window["instructions"]
                    or digest(code) != window["sha256"]
                ):
                    raise ValueError("native reader witness differs")
            page = artifact.query_payload(
                "references",
                section_index=0,
                source_offset=0x14EF2 - mapping["load_address"],
                end_offset=0x14EF3 - mapping["load_address"],
                direction="incoming",
                limit=100,
            )
            if page["has_more"] or sorted(
                r["source_offset"] + mapping["load_address"] for r in page["items"]
            ) != sorted(r["runtime"] for r in mapping["callers"]):
                raise ValueError("recognized burst callers differ")
            result.update(
                native_reader_windows=len(mapping["readers"]),
                direct_callers=len(page["items"]),
            )
            print(json.dumps(result, indent=2))
        finally:
            artifact.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Recheck pinned native record proofs; no execution or byte-pattern inference."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.foft_burst_audit import audit as burst_audit
from tools.foft_burst_audit import digest
from tools.foft_model_audit import audit_native as model_audit
from tools.foft_ship_specs_audit import audit as specification_audit


def check_native(windows, mapping):
    particle = windows["particles"]
    mesh = windows["mesh"]
    loop_fields = [
        a for r in particle for a in r["typed_accesses"] if a.get("record_cursor_loop")
    ]
    if len(loop_fields) != 12:
        raise ValueError("particle field contract count differs")
    for a in loop_fields:
        d = a["record_cursor_loop"]
        if (
            d["header_offset"],
            d["tail_offset"],
            d["iteration_count"],
            d["iteration_stride"],
            d["record_count"],
            d["base_record_index"],
            d["counter_register"],
            d["body_only"],
        ) != (0x57FC, 0x5870, 100, 18, 100, 0, 0, True):
            raise ValueError("particle counter/cursor proof differs")
        if a["root_struct_name"] != "HyperspaceParticleRecord":
            raise ValueError("particle field type differs")
        if "word_index" in a:
            raise ValueError("translated cursor must not become a WORD index")
    observed = [
        {
            "source_offset": r["source_offset"],
            "operand_index": a["operand_index"],
            "field_name": a["field_name"],
            "displacement": a["displacement"],
            "field_size": a["field_size"],
        }
        for r in particle
        for a in r["typed_accesses"]
        if a.get("record_cursor_loop")
    ]
    if observed != mapping["particle_bindings"]:
        raise ValueError("particle source/field bindings differ")
    destination = [
        (r, a) for r in mesh for a in r["typed_accesses"] if a["base_register"] == "A6"
    ]
    expected = [row * 10 + field for row in range(15) for field in (0, 2, 4)]
    if (
        len(destination) != 45
        or [a["displacement"] for _, a in destination] != expected
    ):
        raise ValueError("fifteen projection rows differ")
    for (_, a), offset in zip(destination, expected, strict=True):
        if (a["root_struct_name"], a["field_name"], a["field_size"]) != (
            "ProjectedVertexRecord",
            ("x", "y", "z")[(offset % 10) // 2],
            2,
        ):
            raise ValueError("projection field binding differs")
    if any(a["base_register"] == "A0" for r in mesh for a in r["typed_accesses"]):
        raise ValueError("mesh source acquired an unproved frame-index receiver")
    return {
        "particle_body_fields": 12,
        "projection_xyz_fields": 45,
        "projection_rows": 15,
        "projection_written_bytes": 90,
        "projection_last_write_end": 146,
        "mesh_source_index_proved": False,
        "guest_execution": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--map",
        type=Path,
        default=ROOT / "docs/validation/foft-record-proof-closure.json",
    )
    p.add_argument("--media", action="append", required=True)
    args = p.parse_args()
    m = json.loads(args.map.read_text())
    from amiga_reversing.disasm.disk_set import DiskSet
    from amiga_reversing.disasm.disk_set_state import _artifact
    from amiga_reversing.disasm.target_history import target_lock

    root = ROOT / "targets" / m["target_id"]
    with target_lock(root):
        owner = DiskSet.load(root, project_root=ROOT)
        if owner.revision != m["revision"]:
            raise ValueError("review before repinning the closure revision")
        source, a = _artifact(owner, "main", dict(x.split("=", 1) for x in args.media))
        try:
            windows = {}
            for w in m["native_windows"]:
                rows = []
                offset = 0
                while True:
                    page = a.query_payload(
                        "instructions",
                        section_index=0,
                        source_offset=w["start_runtime"] - 2048,
                        end_offset=w["end_runtime"] - 2048,
                        offset=offset,
                        limit=100,
                    )
                    rows += page["items"]
                    offset += len(page["items"])
                    if not page["has_more"]:
                        break
                if (
                    len(rows) != w["instructions"]
                    or digest(b"".join(bytes.fromhex(r["bytes"]) for r in rows))
                    != w["sha256"]
                ):
                    raise ValueError("native instruction witness differs")
                windows[w["name"]] = rows
            result = check_native(windows, m)
            data = burst_audit(
                source.read_bytes(),
                json.loads(
                    (
                        ROOT / "docs/validation/foft-burst-particle-presentation.json"
                    ).read_text()
                ),
            )
            result.update(
                mesh_frames=data["mesh_frames"], mesh_vertices=data["mesh_vertices"]
            )

            def instruction(address):
                page = a.query_payload(
                    "instructions",
                    section_index=0,
                    source_offset=address - 2048,
                    end_offset=address - 2046,
                    limit=2,
                )
                if (
                    page["has_more"]
                    or len(page["items"]) != 1
                    or page["items"][0]["source_offset"] != address - 2048
                ):
                    raise ValueError("model witness is not one native instruction")
                return page["items"][0]

            def references(address):
                page = a.query_payload(
                    "references",
                    section_index=0,
                    source_offset=address - 2048,
                    end_offset=address - 2046,
                    direction="outgoing",
                    limit=100,
                )
                if page["has_more"]:
                    raise ValueError("model reference witness is truncated")
                return page["items"]

            model_map = json.loads(
                (ROOT / "docs/validation/foft-ship-model-map.json").read_text()
            )
            spec_map = json.loads(
                (ROOT / "docs/validation/foft-ship-specifications.json").read_text()
            )
            models = model_audit(
                source.read_bytes(),
                model_map,
                instruction=instruction,
                references=references,
            )
            specs = specification_audit(source.read_bytes(), spec_map)
            result.update(
                model_entries_rechecked=models["model_count"],
                specification_lists_data_rechecked=specs["lists"],
            )
            result.update(
                revision=m["revision"], kind="foft_record_proof_closure_audit"
            )
            print(json.dumps(result, indent=2))
        finally:
            a.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

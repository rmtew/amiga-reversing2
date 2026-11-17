"""Audit native image-memory observations against operand bindings and rendering.

Observations are not a proof of a unique temporal view. Missing/contradictory
bindings remain review evidence; this module never promotes code or labels.
"""

from bisect import bisect_right
from collections import Counter


def memory_operand_binding_audit(analysis, *, section_index=0):
    section = next(
        s for s in analysis["sections"] if s["section_index"] == section_index
    )
    runs = sorted(section["accepted_code_runs"], key=lambda r: r["start_offset"])
    starts = [r["start_offset"] for r in runs]
    bindings = {}
    for ref in section.get("runtime_address_refs", []):
        if (
            type(ref.get("target_section_index")) is int
            and type(ref.get("target_offset")) is int
        ):
            bindings.setdefault((ref["offset"], ref["operand_index"]), set()).add(
                (ref["target_section_index"], ref["target_offset"])
            )
    symbolic = {
        (r["offset"], r.get("operand_index"))
        for r in section.get("rendered_symbol_accesses", [])
        if r["access_kind"] == "operand" and not r.get("comment_only")
    }
    declared = {}
    for ref in section.get("rendered_symbol_accesses", []):
        if (
            ref["access_kind"] == "operand"
            and not ref.get("comment_only")
            and type(ref.get("target_section_index")) is int
            and type(ref.get("target_offset")) is int
        ):
            declared.setdefault((ref["offset"], ref.get("operand_index")), set()).add(
                (ref["target_section_index"], ref["target_offset"])
            )
    records = []
    for row in section.get("address_observations", []):
        if (
            row.get("source_name") != "absolute_operand"
            or row.get("access_kind_name")
            not in ("memory_read", "memory_write", "address")
            or row.get("owner_kind_name") not in ("runtime_range", "section_storage")
            or row.get("operand_is_immediate", False)
        ):
            continue
        at = row["offset"]
        i = bisect_right(starts, at) - 1
        if i < 0 or at >= runs[i]["end_offset"]:
            continue
        key = (at, row["operand_index"])
        target_section = row.get("target_section_index")
        target = row.get("target_offset")
        expected = (
            section_index if target_section is None else target_section,
            row["owner_offset"] if target is None else target,
        )
        known = bindings.get(key, set())
        status = (
            "conflicting_native_observation"
            if row.get("conflicted")
            else "conflicting_native_bindings"
            if known and known != {expected}
            else "conflicting_rendered_binding"
            if declared.get(key) and declared[key] != {expected}
            else "missing_native_operand_binding"
            if not known and expected not in declared.get(key, set())
            else "symbolic_operand"
            if key in symbolic
            else "bound_without_symbolic_operand"
        )
        records.append(
            {
                "source_offset": at,
                "operand_index": key[1],
                "target_section_index": expected[0],
                "target_offset": expected[1],
                "address": row.get("address"),
                "access": row["access_kind_name"],
                "status": status,
            }
        )
    records.sort(
        key=lambda r: (
            r["source_offset"],
            r["operand_index"],
            r["target_section_index"],
            r["target_offset"],
        )
    )
    return {
        "schema": "native-image-memory-operand-bindings/v1",
        "section_index": section_index,
        "scope": "Accepted absolute image-memory operands observed by native analysis; numeric immediates and external/platform owners excluded. Observations alone do not prove a unique temporal binding or authorize a display override.",
        "counts": dict(Counter(r["status"] for r in records)),
        "references": records,
    }

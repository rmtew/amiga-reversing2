"""Read-only checks for explicitly bounded projected-polygon face streams.

Contract: BE WORD style, vertex count, then that many record-byte offsets.
Callers supply reviewed bounds/counts and projection limits. This neither finds
streams nor infers code, control flow, register state or source ownership.
"""

import hashlib


def _integer(value, *, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError("face contract requires bounded nonnegative integers")
    return value


def audit_face_views(payload, *, load_address, views, projection_stride, style_count):
    """Check exact consumption and sharing by physical record address."""
    _integer(load_address)
    _integer(projection_stride, minimum=1)
    _integer(style_count, minimum=1)
    if not isinstance(payload, bytes) or not isinstance(views, list) or not views:
        raise ValueError("face audit requires immutable bytes and explicit views")
    records, results = {}, []
    for view in views:
        start = _integer(view["start_runtime"])
        end = _integer(view["end_runtime"])
        count = _integer(view["face_count"], minimum=1)
        maximum = _integer(view["projection_max_byte_offset"])
        lo, hi = start - load_address, end - load_address
        if (
            not 0 <= lo < hi <= len(payload)
            or start % 2
            or end % 2
            or maximum % projection_stride
            or count > (hi - lo) // 10
        ):
            raise ValueError("face view extent/count/alignment is inconsistent")
        cursor, starts, referenced = lo, [], set()
        histogram = {}
        for _ in range(count):
            if cursor + 4 > hi:
                raise ValueError("truncated face header")
            style = int.from_bytes(payload[cursor : cursor + 2], "big")
            vertices = int.from_bytes(payload[cursor + 2 : cursor + 4], "big")
            if (
                style >= style_count
                or vertices < 3
                or vertices > (hi - cursor - 4) // 2
            ):
                raise ValueError("face style/count is outside its declared bounds")
            offsets = [
                int.from_bytes(payload[at : at + 2], "big")
                for at in range(cursor + 4, cursor + 4 + vertices * 2, 2)
            ]
            if any(value % projection_stride or value > maximum for value in offsets):
                raise ValueError("face vertex is outside the projected record extent")
            address = cursor + load_address
            record_end = address + 4 + vertices * 2
            if address in records and records[address] != record_end:
                raise ValueError("conflicting shared face record")
            records[address] = record_end
            starts.append(address)
            referenced.update(offsets)
            histogram[str(vertices)] = histogram.get(str(vertices), 0) + 1
            cursor = record_end - load_address
        if cursor != hi:
            raise ValueError("face count does not consume the exact declared extent")
        digest = hashlib.sha256(payload[lo:hi]).hexdigest()
        if view.get("sha256") is not None and view["sha256"] != digest:
            raise ValueError("face view fingerprint differs")
        results.append(
            {
                "start_runtime": start,
                "end_runtime": end,
                "face_count": count,
                "sha256": digest,
                "record_starts": starts,
                "referenced_projection_offsets": sorted(referenced),
                "vertex_count_histogram": histogram,
            }
        )
    ordered, spans = sorted(records.items()), []
    for start, end in ordered:
        if spans and start < spans[-1][1]:
            raise ValueError("views overlap inside different physical face records")
        if spans and start == spans[-1][1]:
            spans[-1][1] = end
        else:
            spans.append([start, end])
    return {
        "views": results,
        "unique_physical_records": len(records),
        "covered_spans": [{"start_runtime": lo, "end_runtime": hi} for lo, hi in spans],
        "covered_bytes": sum(hi - lo for lo, hi in spans),
        "shared_record_starts": sorted(
            address
            for address in records
            if sum(address in result["record_starts"] for result in results) > 1
        ),
        "control_flow_or_ownership_inferred": False,
    }


def check_immediate_operand(instruction, *, value, register):
    """Recheck an explicit native operand witness; do not propagate registers."""
    facts = instruction["operand_facts"]
    if not (
        len(facts) == 2
        and facts[0]["immediate_value"] == value
        and facts[1]["direct_register"] == register
        and facts[1]["access"] == "register_write"
    ):
        raise ValueError("native immediate/register operand differs from the witness")

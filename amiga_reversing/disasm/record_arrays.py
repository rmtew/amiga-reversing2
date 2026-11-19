"""Positive contracts for bounded flat records using existing custom types.

These checks add record admission, not a relaxation of primitive-array or
member ownership rules. ABS32 address fields reuse the existing pointer-domain
contract without a pointee type. Inherited and nested records remain separate.
"""

import re
from copy import deepcopy
from collections.abc import Mapping
from dataclasses import asdict, is_dataclass

from .pointer_domains import validate_pointer_domain

_UINT32 = 0xFFFFFFFF
_WIDTHS = {
    "BYTE": 1,
    "UBYTE": 1,
    "WORD": 2,
    "UWORD": 2,
    "LONG": 4,
    "ULONG": 4,
    "APTR": 4,
}


def preserves_primitive_grid(shape, unit):
    fields = shape['fields']
    return len(fields) * unit == shape['size'] and all(
        f['offset'] == i * unit and f['size'] == unit
        and _WIDTHS[f['type']] == unit
        and f.get('value_kind', 'scalar') == 'scalar'
        for i, f in enumerate(fields)
    )


def _mapping(value):
    return asdict(value) if is_dataclass(value) else value


def _name(value):
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > 63
        or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value)
    ):
        raise ValueError("record and field names require bounded native identifiers")
    return value


def record_shape(value):
    """Return a semantic witness without discarding richer existing fields."""
    value = _mapping(value)
    if not isinstance(value, Mapping):
        raise ValueError("record requires an explicit custom type definition")
    name, size, fields = value.get("name"), value.get("size"), value.get("fields")
    _name(name)
    if type(size) is not int or not 0 < size <= _UINT32:
        raise ValueError("record size requires a positive uint32")
    if (
        value.get("base_struct")
        or value.get("base_offset", 0) != 0
        or any(
            value.get(k) is not None
            for k in ("tag_offset", "tag_value", "tag_root_struct")
        )
    ):
        raise ValueError(
            "bounded record declaration requires a flat non-inherited type"
        )
    if not isinstance(fields, list | tuple) or not fields:
        raise ValueError("record requires explicit scalar, BYTE-span or ABS32 address fields")
    result, used, cursor = [], set(), 0
    for field in fields:
        field = _mapping(field)
        if not isinstance(field, Mapping):
            raise ValueError("record fields must be objects")
        fname, kind = _name(field.get("name")), field.get("type")
        off, width = field.get("offset"), field.get("size")
        # Custom BYTE/UBYTE fields already use size as a bounded byte-span
        # extent (for example a fixed keyword). Other primitive fields retain
        # their scalar widths; this does not infer multibyte arrays.
        if (
            not isinstance(kind, str)
            or kind.upper() not in _WIDTHS
            or type(width) is not int
            or width <= 0
            or (kind.upper() not in {"BYTE", "UBYTE"} and width != _WIDTHS[kind.upper()])
            or type(off) is not int
            or not 0 <= off <= size - width
        ):
            raise ValueError(
                "record fields require matching primitive widths and contained offsets"
            )
        value_kind = field.get("value_kind", "scalar")
        if (
            not isinstance(value_kind, str)
            or value_kind not in {"scalar", "target_pointer"}
            or any(
                field.get(k)
                for k in ("struct", "pointer_struct", "named_base", "equate_group")
            )
            or field.get("available_since", "1.0") != "1.0"
        ):
            raise ValueError(
                "record declaration cannot discard a richer field contract"
            )
        domain, group = (
            field.get("pointer_address_domain"),
            field.get("pointer_symbol_group"),
        )
        if value_kind == "target_pointer":
            if (
                width != 4
                or kind.upper() not in {"LONG", "ULONG", "APTR"}
                or not isinstance(domain, str)
                or domain not in {"mapped_source", "runtime_only"}
            ):
                raise ValueError(
                    "ABS32 address field requires four bytes and an explicit pointer domain"
                )
            validate_pointer_domain(
                value_kind=value_kind,
                size=width,
                address_domain=domain,
                symbol_group=group,
            )
        elif kind.upper() == "APTR" or domain is not None or group is not None:
            raise ValueError(
                "address spelling/domain requires an explicit target_pointer field"
            )
        if fname in used:
            raise ValueError("record fields require unique names")
        used.add(fname)
        canonical = {"name": fname, "type": kind.upper(), "offset": off, "size": width}
        if value_kind == "target_pointer":
            canonical.update(value_kind=value_kind, pointer_address_domain=domain)
            if group is not None:
                canonical["pointer_symbol_group"] = group
        result.append(canonical)
    result.sort(key=lambda f: f["offset"])
    for field in result:
        if field["offset"] < cursor:
            raise ValueError("record fields overlap")
        if _WIDTHS[field["type"]] > 1 and (field["offset"] % 2 or size % 2):
            raise ValueError("multi-byte record fields require even offsets and stride")
        cursor = field["offset"] + field["size"]
    return {"name": name, "size": size, "fields": result}


def validate_record_array(element, record, layout):
    """Validate extent, exact stride and prior leaf ownership with safe bounds."""
    shape = record_shape(record)
    offset, width, count, stride = (
        element.get(k) for k in ("offset", "width", "array_count", "array_stride")
    )
    if (
        element.get("kind") != "array"
        or any(type(v) is not int for v in (offset, width, count, stride))
        or not 0 <= offset <= _UINT32
        or not 0 < width <= _UINT32 - offset
        or not 0 < count <= _UINT32
        or stride != shape["size"]
    ):
        raise ValueError(
            "record array requires bounded integers and stride equal to record size"
        )
    if count > width // stride or count * stride != width:
        raise ValueError(
            "record count times stride must equal the full inspected extent"
        )
    start, end = layout.get("source_start"), layout.get("source_end")
    if (
        type(start) is not int
        or type(end) is not int
        or not 0 <= start < end <= _UINT32
        or offset + width > end - start
    ):
        raise ValueError("record array falls outside its owner layout")
    if (start + offset) % 2 and any(_WIDTHS[f["type"]] > 1 for f in shape["fields"]):
        raise ValueError("record array requires aligned multi-byte fields")
    binding = element.get("type_binding") or {}
    if (
        element.get("reference_interpretation")
        or layout.get("pointer_table")
        or binding.get("binding_kind") != "custom_struct"
        or binding.get("bound_type_id") != shape["name"]
        or binding.get("record_contract") != shape
        or binding.get("array_count") != count
        or binding.get("element_offset") != offset
        or binding.get("element_width") != width
        or binding.get("layout_id") != element.get("layout_id")
    ):
        raise ValueError(
            "record array requires its exact custom-type witness and no separate pointer-table contract"
        )
    for prior in layout.get("elements", ()):
        if not isinstance(prior, Mapping):
            raise ValueError("record owner has an invalid element")
        lo, size = prior.get("offset"), prior.get("width")
        if type(lo) is not int or type(size) is not int:
            raise ValueError("record owner has an invalid element")
        if lo >= offset + width or lo + size <= offset:
            continue
        old = prior.get("type_binding") or {}
        if _refine_primitive_array(element, shape, prior):
            continue
        if (
            any(
                prior.get(k) != element.get(k)
                for k in ("kind", "offset", "width", "array_count", "array_stride")
            )
            or old.get("binding_kind") != "custom_struct"
            or old.get("bound_type_id") != shape["name"]
            or prior.get("reference_interpretation")
            or (
                old.get("record_contract") is not None
                and old["record_contract"] != shape
            )
        ):
            raise ValueError("record array overlaps an existing element contract")
        for key in ("name", "representation"):
            if prior.get(key) is not None:
                if element.get(key) not in (None, prior[key]):
                    raise ValueError(
                        "record array cannot replace an existing name or representation"
                    )
                element[key] = prior[key]
        # Preserve the prior binding identity and evidence on shape-preserving updates.
        element["type_binding"] = {**old, "record_contract": shape}
        if prior.get("provenance") is not None:
            if element.get("provenance") not in (None, prior["provenance"]):
                raise ValueError("record array cannot replace existing provenance")
            element["provenance"] = deepcopy(prior["provenance"])
    return shape


def _refine_primitive_array(element, shape, prior):
    """Regroup one complete primitive grid without changing a leaf footprint.

    A plain packed array carries width and extent evidence, not record roles.
    Keep that exact evidence in the new element's provenance and in history.
    Partial selections, gaps, widened leaves and address interpretations are
    different contracts and still require their existing checked operations.
    """
    if prior.get("kind") != "array" or prior.get("type_binding") is not None:
        return False
    unit = prior.get("array_stride")
    count = prior.get("array_count")
    fields = shape["fields"]
    if (
        type(unit) is not int or unit not in {1, 2, 4}
        or type(count) is not int or count <= 0
        or prior.get("reference_interpretation") is not None
        or prior.get("representation") is not None
        or prior.get("offset") != element["offset"]
        or prior.get("width") != element["width"]
        or count * unit != element["width"]
        or not preserves_primitive_grid(shape, unit)
    ):
        raise ValueError("record refinement must preserve the complete primitive array grid")
    for key in ("name", "representation"):
        if prior.get(key) is not None:
            if element.get(key) not in (None, prior[key]):
                raise ValueError("record refinement cannot replace an array annotation")
            element[key] = prior[key]
    provenance = deepcopy(prior.get("provenance") or {})
    if "primitive_array_refinement" in provenance:
        raise ValueError("primitive array already has conflicting refinement provenance")
    provenance["primitive_array_refinement"] = deepcopy(dict(prior))
    supplied = element.get("provenance")
    if supplied is not None:
        # Catalog metadata includes review/citation fields which the journal's
        # semantic projection does not duplicate. Recheck every element contract
        # while retaining the richer original inspected snapshot verbatim.
        if not isinstance(supplied, Mapping):
            raise ValueError("record refinement provenance must be an object")
        snapshot = supplied.get("primitive_array_refinement")
        keys = ("layout_id", "offset", "width", "kind", "array_count", "array_stride",
                "name", "representation", "type_binding", "reference_interpretation",
                "provenance")
        if (not isinstance(snapshot, Mapping)
                or any(snapshot.get(k) != prior.get(k) for k in keys)
                or {k: v for k, v in supplied.items() if k != "primitive_array_refinement"}
                != (prior.get("provenance") or {})):
            raise ValueError("record refinement provenance differs from the inspected array")
    else:
        element["provenance"] = provenance
    return True

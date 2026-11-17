"""Conservative import of facts for a byte-identical, same-address raw subview.

This is an initial import adapter, not live inheritance or relocation analysis.
The caller must prove the content correspondence and unchanged runtime address.
Unsupported selected facts fail explicitly; outside facts are not imported.
Subsequent edits use the ordinary target commands and histories.
"""

from __future__ import annotations

import copy
import json
import re

from .target_metadata import TargetMetadata, target_metadata_json_payload


def slice_raw_metadata(metadata, *, start, size):
    if type(start) is not int or type(size) is not int or start < 0 or size <= 0:
        raise ValueError("invalid metadata slice extent")
    source = json.loads(json.dumps(target_metadata_json_payload(metadata)))
    if source["target_type"] not in ("raw_binary", "raw"):
        raise ValueError("metadata slicing requires a raw source")
    end = start + size
    result = json.loads(
        json.dumps(
            target_metadata_json_payload(
                TargetMetadata(target_type="raw_binary", entry_register_seeds=())
            )
        )
    )
    result["source_output_policy"] = copy.deepcopy(source["source_output_policy"])
    counts = {}

    def coordinate(value, *, endpoint=False):
        if type(value) is not int or not start <= value < end + int(endpoint):
            raise ValueError("metadata slice references outside its proven source span")
        return value - start

    def scoped_locator(locator):
        if not isinstance(locator, str):
            return locator
        return re.sub(
            r"scope_owner=s0:([0-9A-Fa-f]{8}):label",
            lambda m: f"scope_owner=s0:{coordinate(int(m[1], 16)):08X}:label",
            locator,
        )

    for key in (
        "seeded_entities",
        "seeded_code_labels",
        "seeded_code_entrypoints",
        "entry_comments",
        "manual_representations",
        "manual_runtime_address_refs",
        "manual_data_references",
        "entry_register_seeds",
        "data_block_layouts",
    ):
        location = (
            "entry_offset"
            if key == "entry_register_seeds"
            else "source_start"
            if key == "data_block_layouts"
            else "addr"
        )
        for item in source[key]:
            at = item[location]
            extent = item.get("source_end", item.get("end"))
            if (
                item.get("hunk", 0) == 0
                and at is not None
                and extent is not None
                and at < start < extent
            ):
                raise ValueError("metadata slice partially overlaps an outside owner")
            if item.get("hunk", 0) != 0 or at is None or not start <= at < end:
                continue
            if key == "manual_representations":
                raise ValueError("metadata slice cannot inherit representation/equate dependencies")
            record = copy.deepcopy(item)
            record[location] = coordinate(record[location])
            for field in ("end", "source_end"):
                if record.get(field) is not None:
                    record[field] = coordinate(record[field], endpoint=True)
            if record.get("source_owner_start") is not None:
                coordinate(
                    record["source_owner_start"] + record["source_owner_size"],
                    endpoint=True,
                )
                record["source_owner_start"] = coordinate(record["source_owner_start"])
            if record.get("source_locator"):
                record["source_locator"] = scoped_locator(record["source_locator"])
            for field, hunk in [
                ("base_offset", "base_hunk"),
                ("target_offset", "target_hunk"),
            ]:
                if record.get(field) is not None:
                    if record.get(hunk, 0) != 0:
                        raise ValueError(
                            "metadata slice cannot import a cross-hunk reference"
                        )
                    record[field] = coordinate(record[field])
            if key == "data_block_layouts":
                if record.get("runtime_execution_view_id") is not None:
                    raise ValueError("metadata slice requires source-owned layouts")
                for element in record["elements"]:
                    reference = element.get("reference_interpretation")
                    if reference is None:
                        continue
                    for field in ("base_locator", "target_locator"):
                        if reference.get(field) is not None:
                            if reference[field]["hunk"] != 0:
                                raise ValueError(
                                    "metadata slice cannot import a cross-hunk locator"
                                )
                            reference[field]["offset"] = coordinate(
                                reference[field]["offset"]
                            )
                    if reference.get("target_offset") is not None:
                        if reference.get("target_hunk", 0) != 0:
                            raise ValueError(
                                "metadata slice cannot import a cross-hunk interpretation"
                            )
                        reference["target_offset"] = coordinate(
                            reference["target_offset"]
                        )
            result[key].append(record)
        counts[key] = len(result[key])

    # These facts use runtime addresses, deliberately unchanged in this adapter.
    # Source caller must enforce child_load == parent_load + start.
    for key in ("absolute_code_labels", "absolute_storage_slots", "target_equates"):
        counts[key] = 0
    # Runtime aliases/equates are not automatically owned by the slice. Source
    # labels and references are sufficient; no outside app state is inherited.
    for key in (
        "function_summaries",
        "abstract_regions",
        "rsset_layout_regions",
        "rsset_use_site_bindings",
        "suppressed_seeded_items",
    ):
        if source[key]:
            raise ValueError("metadata slice has an unsupported fact family: " + key)
    if source["bootblock"] or source["resident"] or source["library"]:
        raise ValueError("metadata slice cannot inherit a container header")

    # Carry only custom type definitions referenced by selected facts, including
    # transitive nested types. Named base and pointer types remain definitions,
    # never new object ownership or reachability claims.
    needed = set()

    def collect(value):
        if isinstance(value, dict):
            for key, entry in value.items():
                if key in (
                    "struct_name",
                    "struct",
                    "pointer_struct",
                    "base_struct",
                    "bound_type_id",
                ) and isinstance(entry, str):
                    needed.add(entry)
                collect(entry)
        elif isinstance(value, list):
            for entry in value:
                collect(entry)

    collect(result)
    definitions = {s["name"]: s for s in source["custom_structs"]}
    added = set()
    while needed - added:
        for name in sorted(needed - added):
            added.add(name)
            if name in definitions:
                definition = copy.deepcopy(definitions[name])
                result["custom_structs"].append(definition)
                collect(definition)
    counts["custom_structs"] = len(result["custom_structs"])
    return TargetMetadata.from_dict(result), counts

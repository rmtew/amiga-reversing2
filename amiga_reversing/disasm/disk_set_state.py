"""Member annotation transactions over the existing Manual Action Log.

Active state uses explicit flat owner paths. Immutable imported state remains
separate. A candidate edit is replayed, rendered and source/media verified in
private staging before its files are published under the owning target lock.
"""

from __future__ import annotations

import base64
import copy
import json
import os
import tempfile
from pathlib import Path

from amiga_reversing.disasm.analysis_state_paths import STATE_FILES, bind_state_paths
from amiga_reversing.disasm.disk_codecs import digest
from amiga_reversing.disasm.source_package import _json as package_manifest_bytes

MEMBER_OPERATIONS = (
    "inspect",
    "regenerate",
    "interpret",
    "interpret_batch",
    "history",
    "review",
    "rollback",
)


def validate_states(root, manifest, *, source_files=()):
    from amiga_reversing.disasm.disk_set import checked_file, file_at

    imported = {m["recipe"]["path"] for m in manifest["media"]} | set(source_files)
    for m in manifest["members"]:
        if m["analysis"]:
            imported.update(
                r["path"]
                for r in [m["analysis"]["metadata"], *m["analysis"]["state_files"]]
            )
    active = set()
    for m in manifest["members"]:
        state = (m["analysis"] or {}).get("state")
        if state is None:
            continue
        if not isinstance(state, dict) or set(state) != STATE_FILES:
            raise ValueError(
                "member state must declare the complete existing state file set"
            )
        for name, ref in state.items():
            if not isinstance(ref, dict) or set(ref) != {"path", "sha256"}:
                raise ValueError("invalid member state file reference")
            p = file_at(root, ref["path"])
            folded = ref["path"].casefold()
            if (
                folded in active
                or folded in {p.casefold() for p in imported}
                or not ref["path"].startswith("analysis/")
            ):
                raise ValueError("active member state ownership collision")
            active.add(folded)
            if ref["sha256"] is None:
                if p.exists() or name == "target_metadata.json":
                    raise ValueError("missing member state file unexpectedly exists")
            else:
                checked_file(root, ref)
        log = file_at(root, state["manual_actions.jsonl"]["path"])
        if log.exists():
            expected = subject(manifest, m["id"])
            for record in [
                json.loads(line)
                for line in log.read_text().splitlines()
                if line.strip()
            ][1:]:
                scope = record.get("interpretation", {}).get("member_subject")
                if scope is not None and scope != expected:
                    raise ValueError("member journal subject mismatch")
        journal = file_at(root, state["decision_journal.jsonl"]["path"])
        if journal.exists():
            for line in journal.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                scope = (record.get("scope") or {}).get("analysis_member_id")
                if scope is not None and (
                    scope != m["id"]
                    or record["selected_identity"]["target_id"] != manifest["id"]
                ):
                    raise ValueError("member decision subject mismatch")


def subject(manifest, member):
    m = next(m for m in manifest["members"] if m["id"] == member)
    return {
        "target_id": manifest["id"],
        "analysis_member_id": member,
        "artifact_sha256": m["sha256"],
        "context": m["context"],
    }


def import_state(member, original_files, *, platform):
    """Bind existing raw/artifact journals, retaining all original action bytes.

    The caller preserves original files separately as immutable provenance.
    Only an artifact-specific header may normalize to the common raw member
    identity after the exact content and complete address context agree.
    """
    if (
        set(original_files) != STATE_FILES
        or original_files["target_metadata.json"] is None
    ):
        raise ValueError(
            "import requires complete role mapping and original base metadata"
        )
    c = member["context"]
    expected = {
        "schema_version": 1,
        "source_kind": "raw_binary",
        "target_format": "raw_binary",
        "original_sha256": member["sha256"],
        "original_size": member["size"],
        "address_model": c["address_model"],
        "load_address": c["load_address"],
        "entrypoint": c["entrypoint"],
        "code_start_offset": c["code_start_offset"],
        "parent_disk_id": None,
    }
    files, state, rebound = {}, {}, False
    for name, data in original_files.items():
        path = "analysis/" + member["id"] + "." + name
        if data is not None and name == "manual_actions.jsonl":
            first, separator, rest = data.partition(b"\n")
            header = json.loads(first)
            actual = header.get("target_identity", {})
            if (
                header.get("record") != "manual_action_log_header"
                or header.get("version") != 1
            ):
                raise ValueError("invalid original member journal header")
            if actual != expected:
                allowed = {**expected, "source_kind": "artifact"}
                if (
                    any(actual.get(k) != v for k, v in allowed.items())
                    or actual.get("artifact_id") != member["sha256"]
                    or actual.get("platform") != platform
                ):
                    raise ValueError(
                        "original member journal identity or address context differs"
                    )
                header["target_identity"] = expected
                data = json.dumps(header, sort_keys=True).encode() + separator + rest
                rebound = True
        state[name] = {
            "path": path,
            "sha256": digest(data) if data is not None else None,
        }
        if data is not None:
            files[path] = data
    return (
        state,
        files,
        {"artifact_header_normalized": rebound, "action_bytes_preserved": True},
    )


def state_context(owner, member):
    from amiga_reversing.disasm.disk_set import file_at

    state = (owner.members[member]["analysis"] or {}).get("state")
    if state is None:
        raise ValueError(
            "sealed-import member: editable journal bindings are not declared"
        )
    return bind_state_paths(
        owner.root, {name: file_at(owner.root, r["path"]) for name, r in state.items()}
    )


def verify_journal_snapshots(owner, media_paths):
    from amiga_reversing.disasm.decision_journal import read_decision_journal
    from amiga_reversing.disasm.effective_metadata import effective_metadata_text
    from amiga_reversing.disasm.manual_actions import load_manual_projection

    values, _, _ = owner.recover(media_paths)
    results = {}
    for member, m in owner.members.items():
        if not (m["analysis"] or {}).get("state"):
            continue
        source, metadata = owner._analysis_input(member, values)
        with state_context(owner, member):
            projection = load_manual_projection(owner.root, binary_source=source)
            journal = read_decision_journal(owner.root)
            text = effective_metadata_text(owner.root, binary_source=source)
        if projection.review_state == "blocked" or not journal["valid"]:
            raise ValueError("member annotation/journal replay blocked: " + member)
        if json.loads(text) != json.loads(metadata.read_bytes()):
            raise ValueError(
                "member journal projection does not match its native metadata snapshot: "
                + member
            )
        results[member] = {
            "active_actions": len(projection.active_action_ids),
            "decision_records": len(journal.get("records", [])),
            "snapshot_exact": True,
        }
    return results


def history_member(owner, member, body):
    from amiga_reversing.disasm.decision_journal import read_decision_journal
    from amiga_reversing.disasm.manual_actions import (
        load_manual_projection,
        manual_action_interpretation,
    )
    from amiga_reversing.disasm.restoration import _envelope, _page, _pagination

    analysis_member, _ = owner.owner(member)
    values, _, _ = owner.recover(body.get("media_paths", {}))
    source, _ = owner._analysis_input(member, values)
    with state_context(owner, analysis_member):
        records = _member_records(owner.root)
        projection = load_manual_projection(owner.root, binary_source=source)
        journal = read_decision_journal(owner.root)
    if projection.review_state == "blocked" or not journal["valid"]:
        raise ValueError("invalid member decision history")
    decisions = _member_decisions(journal["records"])
    items = [
        {
            "action_id": r["action_id"],
            "kind": r["kind"],
            "sequence": r["sequence"],
            "active": r["action_id"] in projection.active_action_ids,
            "interpretation": manual_action_interpretation(r),
            "decision": decisions.get(r["action_id"]),
        }
        for r in reversed(records)
    ]
    filters = {"operation": "history", "member_id": member}
    offset, limit = _pagination(body, owner.revision, filters)
    return {
        **_envelope(
            _page(items, offset, limit),
            {"revision": owner.revision, "subject_revision": owner.revision},
            filters,
        ),
        "scope": {**subject(owner.manifest, analysis_member), "member_id": member},
        "preserved_decision_records": len(journal.get("records", [])),
    }


def _artifact(owner, member, media_paths):
    from amiga_reversing.disasm.c_backend import (
        build_listing_artifact_profile_from_binary_source,
    )

    values, _, _ = owner.recover(media_paths)
    source, metadata = owner._analysis_input(member, values)
    _, _, artifact = build_listing_artifact_profile_from_binary_source(
        source, metadata_path=metadata, project_root=owner.project_root
    )
    return source, artifact


def _member_locator(owner, member, row):
    from amiga_reversing.disasm.listing_projection import ListingProjectionService

    analysis_member, _ = owner.owner(member)
    locator = (
        ListingProjectionService()
        .locator_for_row(
            target_id=owner.manifest["id"], projection_hash=owner.revision, row=row
        )
        .to_dict()
    )
    locator.update(
        member_id=member,
        analysis_member_id=analysis_member,
        artifact_sha256=owner.members[analysis_member]["sha256"],
    )
    return locator


def _member_layouts(owner, member):
    from amiga_reversing.disasm.disk_set import file_at

    analysis_member, _ = owner.owner(member)
    metadata = json.loads(
        file_at(
            owner.root, owner.members[analysis_member]["analysis"]["metadata"]["path"]
        ).read_bytes()
    )
    return metadata.get("data_block_layouts", [])


def _conflicting_array_scalar_seed(row, layout, metadata):
    """Expose one revisable imported scalar beneath a proven scalar array.

    This ports the existing journal correction, not code suppression or automatic
    precedence. Independently owned/typed facts and partial identities stay closed.
    """
    from amiga_reversing.disasm.target_metadata import validate_scalar_data_array_owner

    start, end = row["start_offset"], row["end_offset"]
    unit = layout.get("default_unit")
    width = {"byte": 1, "word": 2, "long": 4}.get(unit)
    if not width or (width > 1 and start % 2) or (end - start) % width:
        return None
    elements = [
        e
        for e in layout.get("elements", ())
        if e.get("kind") == "array"
        and layout["source_start"] + e["offset"] <= start
        and end <= layout["source_start"] + e["offset"] + e["width"]
        and e.get("array_stride") == width
    ]
    if len(elements) != 1:
        return None
    element = elements[0]
    if not all(
        str(x.get("citation", "")).startswith("manual_action_log:")
        for x in (layout, element)
    ):
        return None
    if (start - layout["source_start"] - element["offset"]) % width:
        return None
    try:
        validate_scalar_data_array_owner(element, layout)
    except ValueError:
        return None
    overlapping = [
        e
        for e in metadata.get("seeded_entities", ())
        if e.get("hunk") == 0
        and type(e.get("end")) is int
        and e.get("addr", end) < end
        and start < e["end"]
    ]
    # The saved effective snapshot includes the authored array's own scalar
    # projection. Recognize only that exact provenance/shape, not other owners.
    array_start = layout["source_start"] + element["offset"]
    overlapping = [
        e
        for e in overlapping
        if not (
            e.get("addr") == array_start
            and e.get("end") == array_start + element["width"]
            and e.get("unit") == unit
            and e.get("type") == "data"
            and e.get("citation") == element.get("citation")
            and e.get("name") in {None, layout.get("name"), element.get("name")}
            and e.get("source_id") in {None, "manual_action_log"}
            and e.get("source_owner_start") is None
            and e.get("source_owner_size") is None
            and not any(
                e.get(k)
                for k in (
                    "comment",
                    "subtype",
                    "encoding",
                    "struct_name",
                    "field_name",
                    "field_type",
                    "c_type",
                    "pointer_struct",
                    "value_kind",
                    "value_domain",
                    "pointer_address_domain",
                    "pointer_symbol_group",
                    "source_owner_start",
                    "source_owner_size",
                    "owner_action_id",
                    "source_evidence_id",
                    "parent_evidence_ids",
                )
            )
        )
    ]
    if len(overlapping) != 1:
        return None
    seed = overlapping[0]
    if (
        seed.get("addr") != start
        or seed.get("end") != end
        or seed.get("type") != "data"
        or seed.get("unit") not in {"word", "long"}
        or seed["unit"] == unit
        or (end - start) % {"word": 2, "long": 4}[seed["unit"]]
        or seed.get("review_status") != "seeded"
        or seed.get("source_owner_start") is not None
        or seed.get("source_owner_size") is not None
        or seed.get("source_id") in {None, "", "manual_action_log"}
        or str(seed.get("citation", "")).startswith("manual_action_log:")
        or any(
            seed.get(k)
            for k in (
                "name",
                "comment",
                "subtype",
                "encoding",
                "struct_name",
                "field_name",
                "field_type",
                "c_type",
                "pointer_struct",
                "value_kind",
                "value_domain",
                "pointer_address_domain",
                "pointer_symbol_group",
                "source_owner_start",
                "source_owner_size",
                "owner_action_id",
                "source_evidence_id",
                "parent_evidence_ids",
            )
        )
    ):
        return None
    return {"kind": "seeded_entity", "hunk": 0, "addr": start, "end": end}


def _member_conflicting_scalar_seed(owner, member, row, layout):
    from amiga_reversing.disasm.disk_set import file_at

    start, end = row["start_offset"], row["end_offset"]
    analysis_member, bias = owner.owner(member)
    if not bias <= start < end <= bias + owner.members[member]["size"]:
        return None
    metadata = json.loads(
        file_at(
            owner.root, owner.members[analysis_member]["analysis"]["metadata"]["path"]
        ).read_bytes()
    )
    return _conflicting_array_scalar_seed(row, layout, metadata)


def _member_data_layout_row(owner, member, row, layouts=None):
    """Join hash-validated layout seeds to compact native catalog context.

    This is existing target metadata, not a new discovered analysis fact.
    """
    if layouts is None:
        layouts = _member_layouts(owner, member)
    layouts = [
        layout
        for layout in layouts
        if layout["hunk"] == 0
        and layout["source_start"] <= row["start_offset"]
        and row["end_offset"] <= layout["source_end"]
    ]
    if len(layouts) > 1:
        raise ValueError("ambiguous member data layout")
    result = {**row, **({"active_data_block_layout": layouts[0]} if layouts else {})}
    if layouts and row.get("kind") == "data":
        correction = _member_conflicting_scalar_seed(owner, member, row, layouts[0])
        if correction:
            result["suppressible_seeded_items"] = [correction]
    return result


def _inspect_member_data_range(owner, member, body, artifact):
    from amiga_reversing.disasm.manual_action_catalog import (
        listing_range_action_catalog,
    )
    from amiga_reversing.disasm.server import _command_entry

    analysis_member, bias = owner.owner(member)
    start, end = body["source_offset"], body["end_offset"]
    rows, cursor = [], start + bias
    while cursor < end + bias:
        row = artifact.row_for_source_identity(
            section_index=0, offset=cursor, kind="data"
        )
        if row is None:
            row = artifact.row_for_source_offset(section_index=0, offset=cursor)
        if (
            row is None
            or row["kind"] != "data"
            or not row["start_offset"] <= cursor < row["end_offset"]
        ):
            raise ValueError("data range requires contiguous native data coverage")
        rows.append(row)
        if len(rows) > 1000:
            raise ValueError("data range exceeds 1000 native rows")
        cursor = min(row["end_offset"], end + bias)
    context = {
        "kind": "range",
        "locators": [_member_locator(owner, member, row) for row in rows],
        "row_count": len(rows),
        "source_span": {
            "section_index": 0,
            "start_offset": start + bias,
            "end_offset": end + bias,
        },
    }
    # Native rows may group several scalar fields. Selection bounds are not
    # new analysis facts: only coordinate-sensitive catalog payloads use these
    # clipped copies, while locators/evidence retain the full native witnesses.
    selected = [
        {
            **row,
            "start_offset": max(row["start_offset"], start + bias),
            "end_offset": min(row["end_offset"], end + bias),
        }
        for row in rows
    ]
    layouts = _member_layouts(owner, member)
    selected = [
        _member_data_layout_row(owner, member, row, layouts) for row in selected
    ]
    supported = {
        "range.data_block.layout.create",
        "range.seed.data.string",
        "range.seed.data.opaque_data",
    }
    layout_ids = {
        row.get("active_data_block_layout", {}).get("layout_id") for row in selected
    }
    if len(layout_ids) == 1 and None not in layout_ids:
        supported.update({"range.data_block.element.set", "range.data_block.records.declare"})
    return {
        "context": context,
        "rows": rows,
        "selection_rows": selected,
        "commands": [
            _command_entry(c, context)
            for c in listing_range_action_catalog(selected)
            if c["action_id"] in supported
        ],
        "scope": {**subject(owner.manifest, analysis_member), "member_id": member},
        "revision": owner.revision,
        "subject_revision": owner.revision,
    }


def inspect_member(owner, member, body, *, artifact=None):
    """Discover a conservative subset of the normal row/element catalog."""
    from amiga_reversing.disasm.listing_context import listing_element_contexts
    from amiga_reversing.disasm.manual_action_catalog import (
        listing_element_action_catalog,
        listing_row_action_catalog,
    )

    analysis_member, bias = owner.owner(member)
    state_context(
        owner, analysis_member
    )  # Validate edit capability before costly analysis.
    offset = body.get("source_offset")
    row_kind = body.get("row_kind", "instruction")
    if (
        type(offset) is not int
        or not 0 <= offset < owner.members[member]["size"]
        or type(body.get("section_index", 0)) is not int
        or body.get("section_index", 0) != 0
        or row_kind not in {"instruction", "label", "data"}
    ):
        raise ValueError("inspect requires a bounded member source location")
    end = body.get("end_offset")
    if end is not None and (
        type(end) is not int
        or row_kind != "data"
        or not offset < end <= owner.members[member]["size"]
        or end - offset > 65536
    ):
        raise ValueError("inspect requires a bounded data range of at most 65536 bytes")
    owns_artifact = artifact is None
    if owns_artifact:
        _, artifact = _artifact(owner, member, body.get("media_paths", {}))
    try:
        if end is not None:
            return _inspect_member_data_range(owner, member, body, artifact)
        try:
            row = artifact.row_for_source_identity(
                section_index=0, offset=offset + bias, kind=row_kind
            )
        except RuntimeError as error:
            if "ambiguous canonical source identity" in str(error):
                raise ValueError(
                    "ambiguous member source identity; use an unambiguous native row"
                ) from error
            raise
        if row is None:
            raise ValueError("no canonical row at member location")
        if (
            not bias
            <= row["start_offset"]
            <= row["end_offset"]
            <= bias + owner.members[member]["size"]
        ):
            raise ValueError("canonical row crosses the member view boundary")
        if row["kind"] == "data":
            row = _member_data_layout_row(owner, member, row)
        from .imported_comments import annotate_imported_comments
        from .disk_set import file_at

        baseline = owner.members[analysis_member]["analysis"]["state"]["target_metadata.json"]
        declared = json.loads(file_at(owner.root, baseline["path"]).read_bytes())
        annotate_imported_comments(row, declared.get("entry_comments", ()))
        locator = _member_locator(owner, member, row)
        context = {"kind": "row", "locator": locator}
        commands = listing_row_action_catalog(row)
        if row["kind"] == "label":
            label = next(
                (
                    e
                    for e in listing_element_contexts(row)
                    if e.get("element_kind") == "label"
                ),
                None,
            )
            if label:
                context.update(kind="element", element_id=label["element_id"])
                commands = listing_element_action_catalog(row, label)
        supported = {"comment.edit", "label.rename"}
        if row["kind"] == "data" and row.get("suppressible_seeded_items"):
            supported.add("correction.suppress_seeded_item.seeded_entity")
        if row["kind"] == "data" and row.get("active_data_block_layout"):
            supported.update(
                {
                    "row.data_block.element.set",
                    "row.data_block.element.interpret_ref",
                    "row.data_block.layout.describe",
                    "row.data_block.layout.pointer_table",
                }
            )
        from amiga_reversing.disasm.server import _command_entry

        return {
            "context": context,
            "commands": [
                _command_entry(c, context)
                for c in commands
                if c["action_id"] in supported
            ],
            "row": row,
            "scope": {**subject(owner.manifest, analysis_member), "member_id": member},
            "revision": owner.revision,
            "subject_revision": owner.revision,
        }
    finally:
        if owns_artifact:
            artifact.close()


def _member_packages(owner, changed, source):
    from amiga_reversing.disasm.c_backend import (
        listing_artifact_source_projection_with_c_backend_profile,
    )
    from amiga_reversing.disasm.facts_v2_source_refusal import facts_v2_source_refused
    from amiga_reversing.disasm.source_package import (
        build_source_package,
        collect_package_includes,
        validate_source_package,
    )

    old = validate_source_package(owner.package)
    packages = {}
    for name, member in owner.members.items():
        if member["source"] is None:
            continue
        records = [
            copy.deepcopy(r)
            for r in owner.package["manifest"]["files"]
            if name in r["members"]
        ]
        manifest = copy.deepcopy(owner.package["manifest"])
        manifest.update(source=member["source"], target=name, files=records)
        package = {
            "manifest": manifest,
            "sha256": digest(package_manifest_bytes(manifest)),
            "files": [
                {
                    "path": r["path"],
                    "data_base64": base64.b64encode(old[r["path"]]).decode(),
                }
                for r in records
            ],
        }
        if name == changed or (changed == "*" and member["analysis"] is not None):
            from amiga_reversing.disasm.disk_set import file_at

            text, profile, native = (
                listing_artifact_source_projection_with_c_backend_profile(
                    source[name] if changed == "*" else source,
                    metadata_path=file_at(
                        owner.root, member["analysis"]["metadata"]["path"]
                    ),
                    project_root=owner.project_root,
                    use_persisted_policy=True,
                )
            )
            if facts_v2_source_refused(profile):
                raise ValueError("member edit source projection refused")
            payload = {
                "filename": member["source"],
                "source_text": text,
                "target": name,
                "assembler_profile": "vasm",
                "metadata_hash": member["analysis"]["metadata"]["sha256"],
                "target_identity_sha256": member["sha256"],
            }
            package = build_source_package(
                payload,
                native["assets"] if native else [],
                owner.package["manifest"]["policy"]["minimum_asset_size"],
                includes=collect_package_includes(text, owner.root),
            )
        packages[name] = package
    return packages


def _prepare_member_interpretation(owner, member, body, *, artifact=None, source=None):
    from amiga_reversing.disasm.manual_action_catalog import (
        listing_catalog_manual_payload,
        listing_range_catalog_manual_payload,
    )

    context = body.get("context", {})
    locators = context.get("locators") if context.get("kind") == "range" else None
    if locators is not None and (
        not isinstance(locators, list)
        or not locators
        or any(not isinstance(item, dict) for item in locators)
    ):
        raise ValueError("member range requires inspected locators")
    locator = locators[0] if locators else context.get("locator", {})
    analysis_member, bias = owner.owner(member)
    state_context(owner, analysis_member)
    span = context.get("source_span", {}) if locators else locator
    if not isinstance(span, dict):
        raise ValueError("member range requires an inspected source span")
    offset = span.get("start_offset")
    if type(offset) is not int:
        raise ValueError("member edit requires an inspected locator")
    selection = {
        "source_offset": offset - bias,
        "row_kind": locator.get("kind"),
        "media_paths": body.get("media_paths", {}),
    }
    if context.get("kind") == "range":
        end = span.get("end_offset")
        if type(end) is not int:
            raise ValueError("member range requires an inspected end")
        selection.update(row_kind="data", end_offset=end - bias)
    inspected = inspect_member(owner, member, selection, artifact=artifact)
    if context != inspected["context"]:
        raise ValueError("member locator subject or revision mismatch")
    command = body.get("command_id")
    if command not in {c["command_id"] for c in inspected["commands"]}:
        raise ValueError("command is not available for this member row")
    evidence = body.get("evidence")
    if (
        not isinstance(evidence, dict)
        or not isinstance(evidence.get("reason"), str)
        or not evidence["reason"].strip()
    ):
        raise ValueError("member interpretation needs concrete source evidence")
    rows = inspected.get("rows") or [inspected["row"]]
    keys = [row.get("stable_key") or row.get("row_key") for row in rows]
    refs = evidence.get("evidence_refs", evidence.get("source_evidence_refs"))
    if refs != keys:
        raise ValueError("member edit requires the inspected canonical row evidence")
    if context["kind"] == "range":
        actions = listing_range_catalog_manual_payload(
            inspected["selection_rows"], command, parameters=body.get("parameters")
        )
    else:
        element = None
        if context["kind"] == "element":
            from amiga_reversing.disasm.listing_context import (
                selected_listing_element_context,
            )

            element = selected_listing_element_context(rows[0], context)
        actions = [
            listing_catalog_manual_payload(
                rows[0],
                command,
                element_context=element,
                parameters=body.get("parameters"),
            )
        ]
    if command in {"range.seed.data.string", "range.seed.data.opaque_data"}:
        role = command.rsplit(".", 1)[1]
        _validate_member_data_seeds(actions, context["source_span"], role=role)
        start, end = (
            context["source_span"]["start_offset"],
            context["source_span"]["end_offset"],
        )
        if any(
            layout["source_start"] < end and layout["source_end"] > start
            for layout in _member_layouts(owner, member)
        ):
            raise ValueError(f"{role} seed overlaps an existing typed layout")
        value = source.read_bytes()[start:end]
        if role == "string" and (
            not value
            or value[-1] != 0
            or 0 in value[:-1]
            or any(byte < 32 or byte >= 127 for byte in value[:-1])
        ):
            raise ValueError(
                "scoped string seed requires one complete NUL-terminated ASCII span"
            )
    from .disk_set import file_at
    for kind, payload in actions:
        if kind == "declare_manual_record_array":
            from .record_arrays import record_shape, validate_record_array
            selected = inspected.get("selection_rows", rows)
            layout = selected[0].get("active_data_block_layout")
            element, record = payload["data_block_element"], payload["custom_struct"]
            if (command != "range.data_block.records.declare" or not layout
                    or element["layout_id"] != layout["layout_id"]
                    or not bias <= layout["source_start"] < layout["source_end"] <= bias + owner.members[member]["size"]
                    or element["offset"] != selected[0]["start_offset"] - layout["source_start"]
                    or element["width"] != selected[-1]["end_offset"] - selected[0]["start_offset"]):
                raise ValueError("record declaration must match the exact inspected member owner and span")
            validate_record_array(element, record, layout)
            metadata = json.loads(file_at(owner.root,
                owner.members[analysis_member]["analysis"]["metadata"]["path"]).read_bytes())
            for prior in metadata.get("custom_structs", ()):
                if prior["name"] == record["name"] and record_shape(prior) != record_shape(record):
                    raise ValueError("record declaration conflicts with an existing custom type")
        if kind == "suppress_seeded_item":
            layout = rows[0].get("active_data_block_layout")
            expected = (
                _member_conflicting_scalar_seed(owner, member, rows[0], layout)
                if layout
                else None
            )
            if not expected or payload.get("suppressed_seeded_item") != expected:
                raise ValueError(
                    "scalar correction must match the complete inspected imported data fact"
                )
        if kind == "create_manual_data_block_layout":
            new = payload["data_block_layout"]
            if any(
                layout["hunk"] == new["hunk"]
                and layout["source_start"] < new["source_end"]
                and layout["source_end"] > new["source_start"]
                for layout in _member_layouts(owner, member)
            ):
                raise ValueError("scoped layout creation overlaps an existing layout")
        if kind == "edit_manual_data_block_layout":
            layout = rows[0].get("active_data_block_layout")
            if (
                not layout
                or payload["data_block_layout"]["layout_id"] != layout["layout_id"]
                or not bias
                <= layout["source_start"]
                < layout["source_end"]
                <= bias + owner.members[member]["size"]
            ):
                raise ValueError(
                    "layout description must match the inspected member layout"
                )
        if (
            kind == "set_manual_data_block_element"
            and payload["data_block_element"]["kind"] == "array"
            and any(
                (body.get("parameters") or {}).get(key) is not None
                for key in (
                    "binding_kind",
                    "type_id",
                    "domain_id",
                    "type_binding_id",
                    "type_binding",
                    "reference_interpretation",
                )
            )
        ):
            # The generic set operation does not bind types; refuse rather than
            # silently discard a requested record/pointer interpretation.
            raise ValueError(
                "scoped scalar arrays do not accept typed/reference bindings"
            )
        if kind in {
            "set_manual_data_block_element",
            "interpret_manual_data_block_element_ref",
        }:
            _validate_member_data_action(
                owner,
                member,
                inspected.get("selection_rows", rows),
                kind,
                payload,
                source,
                artifact,
            )
        payload["interpretation"] = {
            "source_evidence_status": "hypothesis",
            **evidence,
            "evidence_refs": refs,
            "member_subject": subject(owner.manifest, analysis_member),
            "subject_revision": owner.revision,
            "subject": {
                "section_index": 0,
                "source_offset": offset,
                "row_key": keys[0],
                "command_id": command,
                **(
                    {"source_span": context["source_span"]}
                    if "source_span" in context
                    else {}
                ),
            },
        }
    return actions


def _validate_member_data_seeds(actions, span, *, role):
    """Require catalog classifications to exactly partition the selected span.

    Label rows split catalog subranges. Retain those fragment boundaries so the
    existing renderer preserves each slice and its interior declarations. The
    common inspected source span binds one classification, not duplicate bytes.
    """
    cursor = span["start_offset"]
    for kind, payload in actions:
        seed = payload.get("seed", {})
        end = seed.get("end")
        if (
            kind != "create_manual_seed"
            or seed.get("kind") != "data"
            or seed.get("hunk") != 0
            or seed.get("addr") != cursor
            or type(end) is not int
            or end <= cursor
            or seed.get("data_role") != role
            or seed.get("unit") != "byte"
            or seed.get("encoding") != ("ascii" if role == "string" else None)
        ):
            raise ValueError(
                f"{role} seed pieces must exactly cover the inspected data span"
            )
        cursor = end
    if not actions or cursor != span["end_offset"]:
        raise ValueError(
            f"{role} seed pieces must exactly cover the inspected data span"
        )


def _validate_member_data_action(owner, member, rows, kind, payload, source, artifact):
    analysis_member, bias = owner.owner(member)
    layout = rows[0].get("active_data_block_layout") or rows[0].get("data_block_layout")
    value = payload[
        "data_block_element"
        if kind == "set_manual_data_block_element"
        else "data_block_interpreted_ref"
    ]
    if (
        not isinstance(layout, dict)
        or value["layout_id"] != layout["layout_id"]
        or not bias
        <= layout["source_start"]
        < layout["source_end"]
        <= bias + owner.members[member]["size"]
        or value["offset"] != rows[0]["start_offset"] - layout["source_start"]
        or value["width"] != rows[-1]["end_offset"] - rows[0]["start_offset"]
    ):
        raise ValueError(
            "data action must match the inspected member layout and exact span"
        )
    if kind == "set_manual_data_block_element":
        if value["kind"] == "array":
            from amiga_reversing.disasm.target_metadata import (
                validate_scalar_data_array_owner,
            )

            validate_scalar_data_array_owner(value, layout)
            # A shape-preserving update must not silently drop an existing name
            # or scalar representation. Typed/reference owners were refused above.
            for prior in layout.get("elements", ()):
                if prior.get("offset") == value["offset"]:
                    for field in ("name", "representation"):
                        if prior.get(field) is not None:
                            value.setdefault(field, prior[field])
            return
        if value["kind"] != "scalar" or value["width"] not in {1, 2, 4}:
            raise ValueError(
                "scoped data elements currently require byte/word/long scalars"
            )
        return
    if value["reference_kind"] == "base_displacement":
        from amiga_reversing.disasm.target_metadata import (
            validate_base_displacement_reference,
        )

        validate_base_displacement_reference(
            value, source_hunk=0, source_addr=rows[0]["start_offset"]
        )
        base = value["base_locator"]
        context = owner.members[analysis_member]["context"]
        if (
            context["address_model"] != "runtime_absolute"
            or value.get("scale", 1) != 1
            or base["hunk"] != 0
            or value["target_hunk"] != 0
        ):
            raise ValueError(
                "scoped base displacement requires unscaled same-owner runtime-absolute points"
            )
        for point in (base["offset"], value["target_offset"]):
            if not 0 <= point < owner.members[analysis_member]["size"]:
                raise ValueError(
                    "base displacement point is outside the analysis owner"
                )
            address = context["load_address"] + point
            resolved = artifact.source_for_runtime_address(address=address)
            if (
                resolved.get("status") != "resolved"
                or resolved.get("section_index") != 0
                or resolved.get("source_offset") != point
            ):
                raise ValueError(
                    "base displacement requires uniquely mapped source points"
                )
        actual = int.from_bytes(
            source.read_bytes()[rows[0]["start_offset"] : rows[-1]["end_offset"]], "big"
        )
        if value["source_value"] != actual:
            raise ValueError(
                "base displacement bits differ from the original inspected WORD"
            )
        return
    if (
        value["reference_kind"] != "absolute"
        or value["target_hunk"] != 0
        or not 0 <= value["target_offset"] < owner.members[analysis_member]["size"]
    ):
        raise ValueError("scoped references require an absolute in-owner source target")
    actual = int.from_bytes(
        source.read_bytes()[rows[0]["start_offset"] : rows[-1]["end_offset"]], "big"
    )
    resolved = artifact.source_for_runtime_address(address=actual)
    if (
        value["source_value"] != actual
        or resolved.get("status") != "resolved"
        or resolved.get("section_index") != 0
        or resolved.get("source_offset") != value["target_offset"]
    ):
        raise ValueError(
            "reference bytes must resolve uniquely to the inspected owner target"
        )


def edit_member(owner, member, body):
    return _edit_member_entries(owner, member, body, [body])


def edit_member_batch(owner, member, body):
    entries = body.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("interpret_batch requires a nonempty entries list")
    if any(
        not isinstance(entry, dict)
        or set(entry) & {"operation", "expected_revision", "member_id", "media_paths"}
        for entry in entries
    ):
        raise ValueError(
            "batch entries must use the outer member, revision and media bindings"
        )
    return _edit_member_entries(owner, member, body, entries)


def _edit_member_entries(owner, member, body, entries):
    from amiga_reversing.disasm.manual_actions import (
        append_manual_actions,
        manual_action_kind,
    )

    analysis_member, _ = owner.owner(member)
    state_context(owner, analysis_member)  # Refuse sealed imports before media access.
    source, artifact = _artifact(owner, member, body.get("media_paths", {}))
    try:
        prepared = [
            action
            for entry in entries
            for action in _prepare_member_interpretation(
                owner,
                member,
                {**entry, "media_paths": body.get("media_paths", {})},
                artifact=artifact,
                source=source,
            )
        ]
    finally:
        artifact.close()

    def append(root, source):
        from .manual_actions import load_manual_projection
        from .source_label_identity import reuse_source_global_point_actions

        projection = load_manual_projection(root, binary_source=source)
        if projection.review_state == "blocked":
            raise ValueError("member annotation replay blocked before edit")
        normalized = reuse_source_global_point_actions(prepared, projection.labels)
        return {
            "actions": append_manual_actions(
                root,
                actions=[
                    (manual_action_kind(kind), payload) for kind, payload in normalized
                ],
                binary_source=source,
            )
        }

    return _apply_member_change(owner, member, body, append)


def rollback_member(owner, member, body):
    from amiga_reversing.disasm.manual_actions import (
        ManualActionKind,
        append_manual_action,
    )

    action_id = body.get("action_id")
    redo = body.get("redo", False)
    if not isinstance(action_id, str) or type(redo) is not bool:
        raise ValueError("rollback requires an action ID and boolean redo")

    def append(root, source):
        from amiga_reversing.disasm.manual_actions import load_manual_projection

        record = next(
            (r for r in _member_records(root) if r["action_id"] == action_id), None
        )
        if not record or record["kind"] in {"undo_action", "redo_action"}:
            raise ValueError(
                "rollback requires a source action in this analysis member"
            )
        projection = load_manual_projection(root, binary_source=source)
        from .source_label_identity import exact_duplicate_source_owner_undo

        recovering = (not redo and projection.review_state == "blocked"
                      and exact_duplicate_source_owner_undo(projection, record))
        if (
            (projection.review_state == "blocked" and not recovering)
            or (action_id in projection.active_action_ids) == redo
        ):
            raise ValueError(
                "member action is not in the required state for undo or redo"
            )
        action = append_manual_action(
            root,
            kind=ManualActionKind.REDO_ACTION if redo else ManualActionKind.UNDO_ACTION,
            payload={"redoes_action_id" if redo else "undoes_action_id": action_id},
            binary_source=source,
        )
        return {"action": action}

    return _apply_member_change(owner, member, body, append)


def _member_records(root):
    from amiga_reversing.disasm.manual_actions import manual_action_log_path

    path = manual_action_log_path(root)
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ][1:]


def _member_decisions(records):
    from amiga_reversing.disasm.decision_journal import project_decision_journal

    decisions = {}
    projected = project_decision_journal(records)
    for bucket in ("accepted_facts", "deferred_facts", "rejected_facts"):
        for record in projected[bucket]:
            if record.get("fact_type") != "restoration_interpretation":
                continue
            action_id = record["selected_identity"]["subject_id"]
            if action_id in decisions:
                raise ValueError("conflicting member interpretation decisions")
            decisions[action_id] = record
    return decisions


def persist_member_verification(owner, analysis_member, build, regeneration):
    from amiga_reversing.disasm.restoration_verification import _persist

    proof = build["members"][analysis_member]
    coverage = build["coverage"]
    if not (
        regeneration[analysis_member].get("whole_source_package_exact") is True
        and proof.get("native_exact") is True
        and proof.get("vasm_exact") is True
        and coverage["complete"]
        and coverage["independent_redecode"]
        and all(media["whole_file_exact"] for media in build["media"].values())
    ):
        raise ValueError(
            "member verification requires exact regeneration and aggregate coverage"
        )
    target = owner.manifest["id"]
    return _persist(
        target,
        {
            "kind": "disk_set_member_verification",
            "target_id": target,
            "subject_revision": owner.revision,
            "member_subject": subject(owner.manifest, analysis_member),
            "source_package_sha256": owner.package["sha256"],
            "exact": True,
            "member_build": proof,
            "media_sha256": {
                name: media["sha256"] for name, media in build["media"].items()
            },
            "coverage_sha256": digest(json.dumps(coverage, sort_keys=True).encode()),
        },
        project_root=owner.project_root,
    )


def review_member(owner, member, body):
    from amiga_reversing.disasm.decision_journal import (
        append_decision_records,
        read_decision_journal,
    )
    from amiga_reversing.disasm.manual_actions import (
        load_manual_projection,
        manual_action_interpretation,
    )
    from amiga_reversing.disasm.restoration import _prepare_review_records
    from amiga_reversing.disasm.restoration_verification import load_receipt

    choice, reason = body.get("decision"), body.get("reason")
    if (
        choice not in ("accept", "defer", "reject")
        or not isinstance(reason, str)
        or not 0 < len(reason.strip()) <= 4096
    ):
        raise ValueError(
            "member review requires accept, defer or reject and a reason of at most 4096 characters"
        )
    if body.get("probe_id") is not None:
        raise ValueError("member review does not accept runtime probe receipts")
    analysis_member, _ = owner.owner(member)
    verification_id = body.get("verification_id")
    verification = None
    if verification_id is not None or choice == "accept":
        try:
            verification = load_receipt(
                owner.manifest["id"], verification_id, project_root=owner.project_root
            )
        except FileNotFoundError as exc:
            raise ValueError("member verification receipt was not found") from exc
        if (
            verification.get("kind") != "disk_set_member_verification"
            or verification.get("exact") is not True
            or verification.get("subject_revision") != owner.revision
            or verification.get("member_subject")
            != subject(owner.manifest, analysis_member)
            or verification.get("source_package_sha256") != owner.package["sha256"]
        ):
            raise ValueError(
                "verification receipt does not match this member and revision"
            )

    def append(root, source):
        action_id = body.get("action_id")
        projection = load_manual_projection(root, binary_source=source)
        record = next(
            (r for r in _member_records(root) if r["action_id"] == action_id), None
        )
        if (
            projection.review_state == "blocked"
            or record is None
            or action_id not in projection.active_action_ids
        ):
            raise ValueError(
                "review requires a current active action in this analysis member"
            )
        evidence = manual_action_interpretation(record)
        if not evidence.get("evidence_refs"):
            raise ValueError("member review requires an evidence-bearing action")
        journal = read_decision_journal(root)
        if not journal["valid"]:
            raise ValueError("invalid member decision history")
        chain = journal["records"]
        item = {
            "action_id": action_id,
            "interpretation": evidence,
            "decision": _member_decisions(chain).get(action_id),
        }
        additions, decision = _prepare_review_records(
            owner.manifest["id"],
            body,
            {"subject_revision": owner.revision},
            item,
            chain,
        )
        decision["scope"]["analysis_member_id"] = analysis_member
        result = append_decision_records(root, additions)
        if result["status"] != "appended":
            raise ValueError(f"member decision rejected: {result.get('diagnostics')}")
        return {"decision": decision, "review_verification": verification}

    return _apply_member_change(owner, member, body, append)


def regenerate_member(owner, member, body):
    """Refresh derived source after a renderer change, preserving every journal."""
    verify_journal_snapshots(owner, body.get("media_paths", {}))
    return _apply_member_change(
        owner, member, body, lambda root, source: {}, regenerate_all=True
    )


def _apply_member_change(owner, member, body, append, *, regenerate_all=False):
    from amiga_reversing.disasm.disk_set import DiskSet, compose_source_package, file_at
    from amiga_reversing.disasm.effective_metadata import effective_metadata_text
    from amiga_reversing.disasm.source_package import validate_source_package
    from amiga_reversing.disasm.source_package_publish import publish_source_package

    analysis_member, _ = owner.owner(member)
    state_context(owner, analysis_member)
    values, _, _ = owner.recover(body.get("media_paths", {}))
    source, _ = owner._analysis_input(member, values)
    with tempfile.TemporaryDirectory(prefix="disk-set-edit-") as tmp:
        root = Path(tmp) / owner.root.name
        root.mkdir()
        publish_source_package(owner.package, root)
        # Copy only declared state/recipes, never private inputs or captures.
        refs = [m["recipe"] for m in owner.manifest["media"]]
        for m in owner.members.values():
            if m["analysis"]:
                refs += [
                    m["analysis"]["metadata"],
                    *m["analysis"]["state_files"],
                    *[
                        r
                        for r in m["analysis"].get("state", {}).values()
                        if r["sha256"] is not None
                    ],
                ]
        for ref in refs:
            p = file_at(root, ref["path"])
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(file_at(owner.root, ref["path"]).read_bytes())
        (root / "manifest.json").write_text(json.dumps(owner.manifest))
        candidate = DiskSet.load(root, project_root=owner.project_root)
        with state_context(candidate, analysis_member):
            before = effective_metadata_text(root, binary_source=source)
            if json.loads(before) != json.loads(
                file_at(
                    root,
                    candidate.members[analysis_member]["analysis"]["metadata"]["path"],
                ).read_bytes()
            ):
                raise ValueError(
                    "member journal projection does not match its native metadata snapshot"
                )
            mutation = append(root, source)
            from .manual_actions import load_manual_projection

            if load_manual_projection(root, binary_source=source).review_state == "blocked":
                raise ValueError("member annotation replay blocked after edit")
            metadata = effective_metadata_text(root, binary_source=source).encode()
        a = candidate.members[analysis_member]["analysis"]
        p = file_at(root, a["metadata"]["path"])
        p.write_bytes(metadata)
        a["metadata"]["sha256"] = digest(metadata)
        for ref in a["state"].values():
            path = file_at(root, ref["path"])
            ref["sha256"] = digest(path.read_bytes()) if path.exists() else None
        render_subject = analysis_member
        render_source = source
        if regenerate_all:
            render_subject = "*"
            render_source = {
                name: candidate._analysis_input(name, values)[0]
                for name, member_record in candidate.members.items()
                if member_record["source"] is not None
                and member_record["analysis"] is not None
            }
        package = compose_source_package(
            candidate.manifest,
            _member_packages(candidate, render_subject, render_source),
        )
        publish_source_package(package, root)
        candidate.manifest["package_sha256"] = package["sha256"]
        (root / "manifest.json").write_text(
            json.dumps(candidate.manifest, indent=2) + "\n"
        )
        candidate = DiskSet.load(root, project_root=owner.project_root)
        proof = candidate.build(
            Path(tmp) / "verified",
            body.get("media_paths", {}),
            vasm=owner.project_root / "tools/vasmm68k_mot.exe",
        )
        if (
            DiskSet.load(owner.root, project_root=owner.project_root).revision
            != owner.revision
        ):
            raise ValueError("disk-set state changed during member edit")
        changed = {
            r["path"]: file_at(root, r["path"]).read_bytes()
            for r in [a["metadata"], *a["state"].values()]
            if r["sha256"] is not None
        }
        source_files = validate_source_package(package)
        previous_sources = validate_source_package(owner.package)
        for name in source_files.keys() - previous_sources.keys():
            if file_at(owner.root, name).exists():
                raise ValueError(
                    f"member-generated source collides with an unowned file: {name}"
                )
        changed.update(source_files)
        changed["source-package-manifest.json"] = (
            root / "source-package-manifest.json"
        ).read_bytes()
        changed["manifest.json"] = (root / "manifest.json").read_bytes()
        obsolete = previous_sources.keys() - source_files.keys()
        old = {
            p: file_at(owner.root, p).read_bytes()
            if file_at(owner.root, p).exists()
            else None
            for p in set(changed) | obsolete
        }

        def write_file(path, data):
            with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(data)
            try:
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)

        try:
            for name, data in changed.items():
                p = file_at(owner.root, name)
                p.parent.mkdir(parents=True, exist_ok=True)
                write_file(p, data)
            for name in obsolete:
                file_at(owner.root, name).unlink()
            result = DiskSet.load(owner.root, project_root=owner.project_root)
        except BaseException:
            for name, data in old.items():
                p = file_at(owner.root, name)
                if data is None:
                    p.unlink(missing_ok=True)
                else:
                    write_file(p, data)
            raise
    return {
        **mutation,
        "revision": result.revision,
        "subject_revision": result.revision,
        "scope": {**subject(owner.manifest, analysis_member), "member_id": member},
        "verification": {
            "member_sources_exact": True,
            "all_placement_coverage": proof["coverage"]["complete"],
            "media_exact": True,
            "members": proof["members"],
            "media_sha256": {name: m["sha256"] for name, m in proof["media"].items()},
            "direct_placements": len(proof["coverage"]["direct_placements"]),
            "embedded_placements": len(proof["coverage"]["embedded_placements"]),
            "runtime": "not tested",
        },
    }

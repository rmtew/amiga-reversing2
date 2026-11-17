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

MEMBER_OPERATIONS = ("inspect", "interpret", "history", "review", "rollback")


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


def inspect_member(owner, member, body):
    """Discover a conservative subset of the normal row/element catalog."""
    from amiga_reversing.disasm.listing_context import listing_element_contexts
    from amiga_reversing.disasm.listing_projection import ListingProjectionService
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
    _, artifact = _artifact(owner, member, body.get("media_paths", {}))
    try:
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
        if name == changed:
            from amiga_reversing.disasm.disk_set import file_at

            text, profile, native = (
                listing_artifact_source_projection_with_c_backend_profile(
                    source,
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


def edit_member(owner, member, body):
    from amiga_reversing.disasm.manual_action_catalog import (
        listing_catalog_manual_payload,
    )
    from amiga_reversing.disasm.manual_actions import (
        append_manual_actions,
        manual_action_kind,
    )

    context = body.get("context", {})
    locator = context.get("locator", {})
    analysis_member, bias = owner.owner(member)
    # Reconstruct the current locator from native facts, never caller row text.
    state_context(owner, analysis_member)
    offset = locator.get("start_offset")
    if type(offset) is not int:
        raise ValueError("member edit requires an inspected locator")
    inspected = inspect_member(
        owner,
        member,
        {
            "source_offset": offset - bias,
            "row_kind": locator.get("kind"),
            "media_paths": body.get("media_paths", {}),
        },
    )
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
    row = inspected["row"]
    key = row.get("stable_key") or row.get("row_key")
    refs = evidence.get("evidence_refs", evidence.get("source_evidence_refs"))
    if refs != [key]:
        raise ValueError("member edit requires the inspected canonical row evidence")
    element = None
    if context["kind"] == "element":
        from amiga_reversing.disasm.listing_context import (
            selected_listing_element_context,
        )

        element = selected_listing_element_context(row, context)
    kind, payload = listing_catalog_manual_payload(
        row, command, element_context=element, parameters=body.get("parameters")
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
            "row_key": key,
            "command_id": command,
        },
    }

    def append(root, source):
        return {
            "actions": append_manual_actions(
                root,
                actions=[(manual_action_kind(kind), payload)],
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
        if (
            projection.review_state == "blocked"
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


def _apply_member_change(owner, member, body, append):
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
            metadata = effective_metadata_text(root, binary_source=source).encode()
        a = candidate.members[analysis_member]["analysis"]
        p = file_at(root, a["metadata"]["path"])
        p.write_bytes(metadata)
        a["metadata"]["sha256"] = digest(metadata)
        for ref in a["state"].values():
            path = file_at(root, ref["path"])
            ref["sha256"] = digest(path.read_bytes()) if path.exists() else None
        package = compose_source_package(
            candidate.manifest, _member_packages(candidate, analysis_member, source)
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

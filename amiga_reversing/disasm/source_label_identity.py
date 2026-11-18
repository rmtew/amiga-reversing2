"""Exact authored source points, independent of catalog-specific durable IDs.

This does not unify runtime aliases, ranges, local scopes or different names.
History retains each action; authoring can reuse one unambiguous point identity.
"""

from collections.abc import Mapping


def source_global_point_identity(label):
    if not isinstance(label, Mapping):
        return None
    scope = label.get("scope", "global")
    if (
        getattr(scope, "value", scope) != "global"
        or label.get("address_domain", "source") != "source"
        or any(
            label.get(k) is not None
            for k in ("owner_id", "owner_label_id", "owner_offset")
        )
    ):
        return None
    hunk, addr, name = label.get("hunk", 0), label.get("addr"), label.get("name")
    end = label.get("end")
    if (
        type(hunk) is not int
        or hunk < 0
        or type(addr) is not int
        or not 0 <= addr < 0xFFFFFFFF
        or not isinstance(name, str)
        or not name
        or (end is not None and (type(end) is not int or end != addr + 1))
    ):
        return None
    return hunk, addr, name


def reuse_source_global_point_actions(actions, labels):
    """Reuse one existing exact point; retain its optional attributes and ID."""
    current = list(labels)
    result = []
    for kind, payload in actions:
        label = payload.get("label") if kind == "create_manual_label" else None
        identity = source_global_point_identity(label)
        if identity is not None:
            matches = [
                p for p in current if source_global_point_identity(p) == identity
            ]
            if len(matches) == 1:
                prior = matches[0]
                label = {**prior, **label, "label_id": prior["label_id"]}
                payload = {**payload, "label": label}
            current = [p for p in current if p.get("label_id") != label["label_id"]]
            current.append(label)
        result.append((kind, payload))
    return result


def exact_duplicate_source_owner_undo(projection, record):
    """Only an active duplicate point label with fully attributed blockers."""
    if (
        record.get("kind") != "create_manual_label"
        or record.get("action_id") not in projection.active_action_ids
    ):
        return False
    label = record.get("label", {})
    identity = source_global_point_identity(label)
    if identity is None:
        return False
    blockers = [r for r in projection.review_items if r.get("review_blocker")]
    if not blockers:
        return False
    labels = {p["label_id"]: p for p in projection.labels}
    for item in blockers:
        ids = item.get("label_ids", [])
        if (
            item.get("kind") != "label_scope_conflict"
            or len(ids) != 2
            or len(set(ids)) != 2
            or label.get("label_id") not in ids
            or any(source_global_point_identity(labels.get(i)) != identity for i in ids)
        ):
            return False
    return True

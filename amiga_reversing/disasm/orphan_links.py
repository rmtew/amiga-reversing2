"""Read-only coverage of orphan positions under explicit entry hypotheses.

The native analysis determines decoding, byte ownership and CFG edges. Supplied
roots are assumptions, never inferred entries or authorization to promote code.
"""

from __future__ import annotations

from bisect import bisect_right
from collections import Counter, defaultdict, deque

_CONTROL_EVIDENCE = frozenset(
    {
        "direct_control_target",
        "runtime_control_target",
        "dispatch_table_control_target",
        "traced_indirect_control_target",
        "initial_record_control_target",
        "staged_record_control_target",
        "initial_pointer_control_target",
        "callback_field_control_target",
    }
)


def orphan_link_hypotheses(analysis, manifest):
    section_index = manifest.get("section_index", 0)
    if type(section_index) is not int or section_index < 0:
        raise ValueError("section_index must be a nonnegative source-section index")
    section = next(
        (s for s in analysis["sections"] if s["section_index"] == section_index), None
    )
    if section is None:
        raise ValueError("source section is absent from the native analysis")
    size = section["section_size"]

    def coordinates(values):
        if not isinstance(values, list) or any(
            type(v) is not int or v < 0 or v >= size or v & 1 for v in values
        ):
            raise ValueError(
                "coordinates must be a list of even in-range source offsets"
            )
        return sorted(set(values))

    cases = coordinates(manifest["case_source_offsets"])
    groups = manifest["entry_groups"]
    if not isinstance(groups, dict) or any(
        not isinstance(k, str) or not k.strip() for k in groups
    ):
        raise ValueError(
            "entry_groups must map nonempty family names to source offsets"
        )
    roots = {k: coordinates(v) for k, v in sorted(groups.items())}
    runs = sorted(section["accepted_code_runs"], key=lambda r: r["start_offset"])
    run_starts = [r["start_offset"] for r in runs]

    def code(at):
        i = bisect_right(run_starts, at) - 1
        return i >= 0 and at < runs[i]["end_offset"]

    blocks = section["blocks"]
    block_starts = [r["start_offset"] for r in blocks]

    def block(at):
        i = bisect_right(block_starts, at) - 1
        return i if i >= 0 and at < blocks[i]["end_offset"] and code(at) else None

    accepted = {i for i, b in enumerate(blocks) if code(b["start_offset"])}
    adjacency = defaultdict(set)
    terminals = set()
    for edge in section["edges"]:
        a, b = edge["source_block_index"], edge["target_block_index"]
        if a not in accepted:
            continue
        # Native kind 5 is a terminal boundary, including traps. It alone does
        # not establish a return mnemonic; callers retain their probe evidence.
        if edge["kind"] == 5:
            terminals.add(edge["source_offset"])
        elif edge["kind"] in (1, 2, 3, 4) and b in accepted:
            adjacency[a].add(b)
    for ref in section.get("code_start_refs", []):
        if (
            ref.get("source_section_index") != section_index
            or ref.get("evidence_kind") not in _CONTROL_EVIDENCE
        ):
            continue
        a, b = block(ref["source_offset"]), block(ref["offset"])
        if (
            a is not None
            and b is not None
            and blocks[b]["start_offset"] == ref["offset"]
        ):
            adjacency[a].add(b)

    memberships = defaultdict(list)
    group_reports = {}
    for name, values in roots.items():
        admitted, refused = [], []
        for at in values:
            i = block(at)
            # Merely pointing into code bytes, possibly an extension word, is
            # insufficient even for an assumed root in this analysis.
            (
                admitted
                if i is not None and blocks[i]["start_offset"] == at
                else refused
            ).append(at)
        reached, parents, entry_for = set(), {}, {}
        pending = deque((block(at), None, at) for at in admitted)
        while pending:
            at, parent, entry = pending.popleft()
            if at in reached:
                continue
            reached.add(at)
            parents[at], entry_for[at] = parent, entry
            pending.extend((b, at, entry) for b in sorted(adjacency[at] - reached))
        covered = [at for at in cases if block(at) in reached]
        witnesses = []
        for at in covered:
            end = block(at)
            path, cursor = [], end
            while cursor is not None:
                path.append(blocks[cursor]["start_offset"])
                cursor = parents[cursor]
            witnesses.append(
                {
                    "case_source_offset": at,
                    "assumed_entry_source_offset": entry_for[end],
                    "block_source_offsets": list(reversed(path)),
                }
            )
        for at in covered:
            memberships[at].append(name)
        group_reports[name] = {
            "assumed_roots": values,
            "accepted_roots_under_analysis": admitted,
            "roots_not_at_accepted_block_start": refused,
            "reachable_case_positions": covered,
            "reachable_native_terminal_positions": [
                at for at in covered if at in terminals
            ],
            "native_block_path_witnesses": witnesses,
        }
    records = []
    for at in cases:
        linked = memberships[at]
        terminal = code(at) and at in terminals
        status = (
            "linked_terminal_instruction"
            if terminal and linked
            else "linked_nonterminal_code_position"
            if linked
            else "accepted_terminal_without_group_link"
            if terminal
            else "accepted_code_without_group_link"
            if code(at)
            else "unaccepted_position"
        )
        records.append(
            {
                "source_offset": at,
                "status": status,
                "linked_families": linked,
                "native_terminal_boundary": terminal,
            }
        )
    return {
        "schema": "native-orphan-link-hypotheses/v1",
        "section_index": section_index,
        "hypothesis_only": True,
        "scope": "Same-section static reachability under supplied entry assumptions; not entry evidence, execution, function extents or adoption.",
        "terminal_caveat": "Native terminal edges also represent traps; mnemonic identity requires independent decoded probe evidence.",
        "groups": group_reports,
        "cases": records,
        "case_status_counts": dict(Counter(r["status"] for r in records)),
    }

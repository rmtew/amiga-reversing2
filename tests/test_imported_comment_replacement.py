"""Exact imported comments can be superseded without erasing their provenance."""

from dataclasses import asdict

import pytest

from amiga_reversing.disasm.manual_action_catalog import listing_catalog_manual_payload


def imported(text="Old interpretation", *, addr=0, hunk=0, citation="Original notebook:7"):
    return dict(hunk=hunk, addr=addr, comment=text, seed_origin="manual_analysis",
                review_status="seeded", citation=citation, source_id="fixture-import",
                source_locator="comment:7", source_path="private-original-notebook")


def row(comments):
    return dict(section_index=0, start_offset=0, end_offset=2, kind="instruction",
                row_key="s0:00000000:instruction", imported_entry_comments=comments)


def payload(selected, **params):
    return listing_catalog_manual_payload(selected, "comment.edit", parameters=params)[1]["comment"]


def test_catalog_reproduces_explicit_imported_comment_replacement():
    original = imported()
    saved = payload(row([original]), text="Corrected interpretation",
                    replace_imported_comment=original["comment"])
    assert saved["replaces_imported_comment"] == original
    assert saved["text"] == "Corrected interpretation"
    assert original["comment"] == "Old interpretation"


def test_additive_edit_remains_additive():
    saved = payload(row([imported()]), text="Another observation")
    assert "replaces_imported_comment" not in saved


@pytest.mark.parametrize("case", ["absent", "wrong_point", "wrong_hunk", "ambiguous", "manual", "empty", "object"])
def test_catalog_rejects_unidentified_or_unrelated_replacement(case):
    old = imported()
    comments = [old]
    selector = old["comment"]
    if case == "absent": comments = []
    if case == "wrong_point": comments = [imported(addr=2)]
    if case == "wrong_hunk": comments = [imported(hunk=1)]
    if case == "ambiguous": comments.append(imported(citation="Another notebook:7"))
    if case == "manual": comments[0] = {**old, "source_id": "manual_action_log"}
    if case == "empty": selector = ""
    if case == "object": selector = old
    with pytest.raises(ValueError, match="imported comment"):
        payload(row(comments), text="Correction", replace_imported_comment=selector)


def test_replay_preserves_neighbors_provenance_and_input_list():
    from amiga_reversing.disasm.imported_comments import supersede_imported_comment
    from amiga_reversing.disasm.target_metadata import EntryCommentMetadata

    old = imported()
    kept = imported("Independent same-point observation", citation="Notebook:8")
    adjacent = imported("Adjacent observation", addr=2)
    entries = [EntryCommentMetadata.from_dict(x) for x in [old, kept, adjacent]]
    saved = payload(row([old, kept]), text="Correction", replace_imported_comment=old["comment"])
    result = supersede_imported_comment(entries, saved)
    assert result == entries[1:]
    assert len(entries) == 3 and asdict(entries[0]) == old
    assert supersede_imported_comment(entries, {"text": "Additive"}) == entries
    for forged in [{**saved, "addr": 2}, {**saved, "hunk": 1},
                   {**saved, "replaces_imported_comment": {**old, "citation": "Changed source"}}]:
        with pytest.raises(ValueError, match="imported comment"):
            supersede_imported_comment(entries, forged)
    with pytest.raises(ValueError, match="imported comment"):
        supersede_imported_comment(result, saved)


def test_annotation_keeps_only_exact_source_point_imports():
    from amiga_reversing.disasm.imported_comments import annotate_imported_comments
    selected = row([])
    old = imported()
    annotate_imported_comments(selected, [old, imported(addr=2), imported(hunk=1),
                               {**old, "source_id": "manual_action_log"}])
    assert selected["imported_entry_comments"] == [old]


def test_scoped_replacement_exact_replay_undo_redo_and_revision(tmp_path, monkeypatch):
    from tests.test_disk_set_state import editable, request
    from amiga_reversing.disasm.disk_set import DiskSet

    old = imported()
    kept = imported("Independent same-point observation", citation="Notebook:8")
    adjacent = imported("Adjacent observation", addr=2)
    project, target, paths, call = editable(tmp_path, monkeypatch,
                                            entry_comments=[old, kept, adjacent])
    owner = DiskSet.load(target, project_root=project)
    original_path = target / owner.members["main"]["analysis"]["state"]["target_metadata.json"]["path"]
    original = original_path.read_bytes()
    overlay = (target / "overlay.s").read_bytes()
    before = (target / "main.s").read_text()
    selected = call("inspect", source_offset=0)
    assert old in selected["row"]["imported_entry_comments"]
    req = request(selected, "Corrected interpretation")
    req["parameters"]["replace_imported_comment"] = old["comment"]
    changed = call("interpret", **req)
    text = (target / "main.s").read_text()
    assert old["comment"] not in text and "Corrected interpretation" in text
    assert kept["comment"] in text and adjacent["comment"] in text
    assert original_path.read_bytes() == original and (target / "overlay.s").read_bytes() == overlay
    assert changed["verification"]["media_exact"] and changed["verification"]["all_placement_coverage"]
    with pytest.raises(ValueError, match="revision"):
        call("interpret", **req)
    action = changed["actions"][0]["action_id"]
    history = call("history")
    assert any(x["action_id"] == action for x in history["items"])
    undone = call("rollback", expected_revision=changed["revision"], action_id=action)
    assert (target / "main.s").read_text() == before
    redone = call("rollback", expected_revision=undone["revision"], action_id=action, redo=True)
    assert (target / "main.s").read_text() == text and redone["verification"]["media_exact"]
    assert original_path.read_bytes() == original and (target / "overlay.s").read_bytes() == overlay
    # The immutable imported identity remains inspectable for subsequent edits.
    again = call("inspect", source_offset=0)
    assert old in again["row"]["imported_entry_comments"]
    req = request(again, "Second corrected interpretation")
    req["parameters"]["replace_imported_comment"] = old["comment"]
    call("interpret", **req)
    assert old["comment"] not in (target / "main.s").read_text()
    # The embedded member starts at owner offset 2, not owner offset zero.
    view = call("inspect", member="return_view", source_offset=0)
    assert adjacent in view["row"]["imported_entry_comments"]
    req = request(view, "Corrected embedded return observation")
    req["parameters"]["replace_imported_comment"] = adjacent["comment"]
    saved = call("interpret", member="return_view", **req)
    assert saved["scope"]["analysis_member_id"] == "main"
    text = (target / "main.s").read_text()
    assert adjacent["comment"] not in text and kept["comment"] in text
    assert "Second corrected interpretation" in text
    assert original_path.read_bytes() == original and (target / "overlay.s").read_bytes() == overlay


def test_replacement_failed_build_is_atomic(tmp_path, monkeypatch):
    from tests.test_disk_set_state import editable, request
    from amiga_reversing.disasm.disk_set import DiskSet

    original = imported()
    _, target, _, call = editable(tmp_path, monkeypatch, entry_comments=[original])
    inspected = call("inspect", source_offset=0)
    req = request(inspected, "Correction")
    req["parameters"]["replace_imported_comment"] = original["comment"]
    snapshot = lambda: {p.relative_to(target): p.read_bytes() for p in target.rglob("*")
                       if p.is_file() and p.name != ".target-history.lock"}
    before = snapshot()
    def fail(*args, **kwargs):
        raise ValueError("candidate proof refused")
    monkeypatch.setattr(DiskSet, "build", fail)
    with pytest.raises(ValueError, match="candidate proof refused"):
        call("interpret", **req)
    assert snapshot() == before


def test_replacement_scope_and_missing_selector_are_atomic(tmp_path, monkeypatch):
    from tests.test_disk_set_state import editable, request

    original = imported()
    _, target, _, call = editable(tmp_path, monkeypatch, entry_comments=[original])
    inspected = call("inspect", source_offset=0)
    req = request(inspected, "Correction")
    req["parameters"]["replace_imported_comment"] = original["comment"]
    before = (target / "manifest.json").read_bytes()
    with pytest.raises(ValueError, match="subject or revision mismatch"):
        call("interpret", member="overlay", **req)
    req["parameters"]["replace_imported_comment"] = "Not the inspected original"
    with pytest.raises(ValueError, match="imported comment"):
        call("interpret", **req)
    assert (target / "manifest.json").read_bytes() == before

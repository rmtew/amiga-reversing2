"""Explicit, exact-provenance replacement of one imported entry comment.

Ordinary comment edits remain additive. The original metadata and journal stay
intact; undo removes the replacement and reveals the original interpretation.
"""

from collections.abc import Mapping
from dataclasses import asdict

from .target_metadata import EntryCommentMetadata


def _imported(value):
    return (isinstance(value, Mapping)
            and value.get("source_id") != "manual_action_log"
            and not str(value.get("citation", "")).startswith("manual_action_log:"))


def annotate_imported_comments(row, comments):
    """Expose immutable candidates at this source point, never a whole range."""
    hunk, addr = row.get("section_index", 0), row.get("start_offset")
    row["imported_entry_comments"] = [
        dict(value) for comment in comments
        if _imported(value := asdict(comment) if isinstance(comment, EntryCommentMetadata) else comment)
        and value.get("hunk", 0) == hunk and value.get("addr") == addr
    ]


def replacement_for_row(row, parameters):
    if "replace_imported_comment" not in parameters:
        return None
    text = parameters["replace_imported_comment"]
    if not isinstance(text, str) or not text.strip():
        raise ValueError("imported comment replacement requires the exact original text")
    matches = [item for item in row.get("imported_entry_comments", ())
               if _imported(item) and item.get("comment") == text
               and item.get("hunk", 0) == row.get("section_index", 0)
               and item.get("addr") == row.get("start_offset")]
    if len(matches) != 1:
        raise ValueError("imported comment replacement requires one exact inspected source identity")
    return dict(matches[0])


def supersede_imported_comment(entries, comment):
    """Replay only against the same complete original provenance record."""
    if "replaces_imported_comment" not in comment:
        return entries
    original = comment["replaces_imported_comment"]
    if (not _imported(original) or original.get("hunk", 0) != comment.get("hunk", 0)
            or original.get("addr") != comment.get("addr")):
        raise ValueError("imported comment replacement crosses its authored source point")
    matches = [entry for entry in entries if asdict(entry) == original]
    if len(matches) != 1:
        raise ValueError("imported comment replacement no longer matches its original provenance")
    return [entry for entry in entries if entry is not matches[0]]

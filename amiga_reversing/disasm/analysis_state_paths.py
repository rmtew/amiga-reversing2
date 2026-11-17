"""Scope the existing annotation/journal store to an analysis member.

The formats and replay rules remain those of ordinary target state. This
context-local binding changes file locations only; it never registers a child
project or changes the lock domain (the owning target directory).
"""

from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

STATE_FILES = frozenset(
    {
        "target_metadata.json",
        "target_seeded_metadata.json",
        "target_corrections.json",
        "manual_actions.jsonl",
        "decision_journal.jsonl",
    }
)
_BOUND = ContextVar("analysis_member_state_paths", default=None)


def state_path(directory: Path, filename: str) -> Path:
    bound = _BOUND.get()
    if bound is not None and Path(directory).resolve() == bound[0]:
        return bound[1][filename]
    return directory / filename


@contextmanager
def bind_state_paths(directory: Path, paths: dict[str, Path]):
    if set(paths) != STATE_FILES:
        raise ValueError("member state must bind the complete existing state file set")
    root = Path(directory).resolve()
    if any(
        not p.resolve().is_relative_to(root)
        or any(q.is_symlink() for q in (p, *p.parents))
        for p in paths.values()
    ):
        raise ValueError("member state files must belong to their owner")
    token = _BOUND.set((root, dict(paths)))
    try:
        yield
    finally:
        _BOUND.reset(token)

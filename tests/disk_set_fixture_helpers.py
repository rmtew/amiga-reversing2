"""Read committed member projections for source-only reconstruction tests."""

import json
from pathlib import Path

from amiga_reversing.disasm.disk_set import DiskSet
from amiga_reversing.disasm.disk_set_state import _member_packages
from amiga_reversing.disasm.target_metadata import TargetMetadata

ROOT = Path(__file__).resolve().parents[1]
OWNER = ROOT / "targets/amiga_raw_foft"


def member_package(member):
    owner = DiskSet.load(OWNER, project_root=ROOT)
    return _member_packages(owner, None, None)[member]


def member_metadata(member):
    owner = DiskSet.load(OWNER, project_root=ROOT)
    return OWNER / owner.members[member]["analysis"]["metadata"]["path"]


def original_main_metadata(_):
    return TargetMetadata.from_dict(
        json.loads((OWNER / "analysis/main.original-target_metadata.json").read_bytes())
    )

"""Restore exact authored fact files from pinned templates and local member bytes."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tempfile

TOKEN = re.compile(rb'\{"\$media_integer":(\{[^{}]+\})\}')
def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def safe_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or "\\" in name or any(p in {"", ".", ".."} for p in name.split("/")):
        raise ValueError("unsafe fact path")
    return path

def encoded_cell_width(reference: dict) -> int:
    """Use the recorded reference schema instead of guessing table cell widths."""
    if reference.get('reference_kind') == 'base_displacement_range':
        width = reference.get('entry_width', 2)
    else:
        width = reference.get('width', reference.get('size'))
    if type(width) is not int or width not in {1, 2, 4}:
        raise ValueError('invalid encoded reference cell width')
    return width

def materialize(bundle: Path, destination: Path, members: dict[str, Path], expected_manifest: str) -> dict:
    raw = (bundle / "bundle-manifest.json").read_bytes()
    if digest(raw) != expected_manifest:
        raise ValueError("bundle manifest identity mismatch")
    manifest = json.loads(raw)
    if manifest["schema"] != "private-proposed-fact-template-v1":
        raise ValueError("unsupported fact template schema")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("fact staging destination must be new")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if any(p.is_symlink() for p in (destination.parent, *destination.parent.parents)):
        raise ValueError("fact destination traverses symlink")
    verified = {}
    for name, identity in manifest["members"].items():
        data = members[name].read_bytes()
        if len(data) != identity["size"] or digest(data) != identity["sha256"]:
            raise ValueError("member identity mismatch: " + name)
        verified[name] = data
    restored = {}
    for record in manifest["files"]:
        name = str(safe_path(record["path"]))
        if name in restored:
            raise ValueError("duplicate fact path")
        source = bundle / name
        if any(p.is_symlink() for p in (source, *source.parents)):
            raise ValueError("fact template traverses symlink")
        data = source.read_bytes()
        if digest(data) != record["template_sha256"]:
            raise ValueError("fact template identity mismatch")
        count = 0
        def resolve(match):
            nonlocal count
            ref = json.loads(match[1])
            if set(ref) != {"member", "offset", "length", "signed", "slice_sha256"}:
                raise ValueError("invalid media integer reference")
            offset, length = ref["offset"], ref["length"]
            if type(offset) is not int or offset < 0 or type(length) is not int or length not in {1, 2, 4} or type(ref["signed"]) is not bool:
                raise ValueError("invalid media integer bounds")
            member = verified[ref["member"]]
            if offset > len(member) or length > len(member) - offset:
                raise ValueError("media integer exceeds member")
            chunk = member[offset:offset+length]
            if digest(chunk) != ref["slice_sha256"]:
                raise ValueError("media integer slice identity mismatch")
            count += 1
            return str(int.from_bytes(chunk, "big", signed=ref["signed"])).encode()
        data = TOKEN.sub(resolve, data)
        if count != record["references"] or digest(data) != record["restored_sha256"]:
            raise ValueError("restored fact identity mismatch")
        restored[name] = data
    # Nothing is installed until all members, templates, slices and restored files validate.
    with tempfile.TemporaryDirectory(prefix=".fact-stage-", dir=destination.parent) as temp:
        stage = Path(temp) / "facts"
        stage.mkdir()
        for name, data in restored.items():
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        if destination.exists() or destination.is_symlink():
            raise FileExistsError("fact destination appeared")
        stage.rename(destination)
    return {"files": len(restored), "restored_sha256_exact": True, "references": sum(r["references"] for r in manifest["files"])}

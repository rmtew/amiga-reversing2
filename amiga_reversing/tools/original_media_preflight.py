"""Read-only original-media input contracts; never launch or handoff admission.

An input report cannot replace live loaded-byte verification or register a game
recipe. Public contracts are fixed here; callers cannot supply hashes/mappings.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from amiga_reversing.disasm.disk_set import DiskSet


@dataclass(frozen=True)
class FileIdentity:
    size: int | None
    hashes: tuple[str, ...]


@dataclass(frozen=True)
class SourceIdentity:
    member: str
    size: int
    sha256: str
    load_address: int
    phase: str


@dataclass(frozen=True)
class InputContract:
    target: str
    media: tuple[tuple[str, FileIdentity], ...]
    rom: FileIdentity
    runtime: FileIdentity
    sources: tuple[SourceIdentity, ...]


PREFLIGHT_NAMES = ("foft",)


def selected_contract(name, target):
    from .foft_original_media_inputs import CONTRACT

    declared = {"foft": CONTRACT}
    contract = declared.get(name)
    if contract is None or target != contract.target:
        raise ValueError(
            "Original-media input preflight is not declared for this target"
        )
    return contract


def inspect_file(path: Path | None, identity: FileIdentity):
    """Fresh bounded bytes, not a claimed digest or a filename-only check."""
    result = {"status": "missing", "size": None, "sha256": None}
    if path is None:
        return result
    try:
        if not path.is_file():
            return result
        size = path.stat().st_size
        result["size"] = size
        if size > 128 * 1024 * 1024 or (
            identity.size is not None and size != identity.size
        ):
            return {**result, "status": "size_mismatch"}
        h = hashlib.sha256()
        count = 0
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                count += len(chunk)
                if count > 128 * 1024 * 1024:
                    return {**result, "status": "size_changed"}
                h.update(chunk)
        result.update(size=count, sha256=h.hexdigest())
        if count != size:
            return {**result, "status": "size_changed"}
        return {
            **result,
            "status": "verified"
            if h.hexdigest() in identity.hashes
            else "hash_mismatch",
        }
    except OSError:
        return {**result, "status": "unreadable"}


def preflight_inputs(
    contract: InputContract,
    *,
    target_dir: Path,
    project_root: Path,
    rom_path: Path,
    media_paths: dict[str, Path],
    binary_path: Path | None,
):
    """Authenticate host inputs and recover members only after all files match.

    Uses normal DiskSet validation/recovery; no runtime views, receipts, files,
    state directories, guest writes, processes or launch permissions are created.
    """
    owner = DiskSet.load(target_dir, project_root=project_root)
    if owner.manifest["id"] != contract.target:
        raise ValueError("Input contract target differs from canonical owner")
    declared = {m["id"]: m for m in owner.manifest["media"]}
    if set(declared) != dict(contract.media).keys() or set(media_paths) != set(
        declared
    ):
        raise ValueError("Input contract requires exact declared media bindings")
    for name, identity in contract.media:
        if (
            declared[name]["size"] != identity.size
            or declared[name]["sha256"] not in identity.hashes
        ):
            raise ValueError("Canonical media differs from pinned input contract")
    if any(
        Path(path).resolve().is_relative_to(owner.root.resolve())
        for path in media_paths.values()
    ):
        raise ValueError(
            "Private original media must remain outside the owned source directory"
        )
    views = []
    for source in contract.sources:
        member = owner.members.get(source.member)
        if (
            member is None
            or owner.owner(source.member) != (source.member, 0)
            or member["size"] != source.size
            or member["sha256"] != source.sha256
            or member["context"]
            != {
                "address_model": "runtime_absolute",
                "load_address": source.load_address,
                "entrypoint": source.load_address,
                "code_start_offset": 0,
                "phase": source.phase,
            }
        ):
            raise ValueError(
                "Canonical source identity/context differs or is not an independent owner"
            )
        views.append(
            {
                "member_id": source.member,
                "section_index": 0,
                "source_start": 0,
                "source_end": source.size,
                "runtime_base": source.load_address,
                "sha256": source.sha256,
                "live_mapping_verified": False,
            }
        )
    files = {
        "rom": inspect_file(rom_path, contract.rom),
        "runtime": inspect_file(binary_path, contract.runtime),
        **{
            "media:" + name: inspect_file(media_paths[name], identity)
            for name, identity in contract.media
        },
    }
    result = {
        "kind": "original_media_input_preflight",
        "scope": "host_inputs_only",
        "target_id": contract.target,
        "revision": owner.revision,
        "files": files,
        "source_contracts": views,
        "recovered_members": [],
        "status": "blocked",
        "input_contract_satisfied": False,
        "runtime_executed": False,
        "launch_admitted": False,
        "live_handoff_verified": False,
        "media_rebuild_verified": False,
        "all_placement_coverage": None,
        "required_runtime": "copperline 1.0.0 / authenticated protocol 1",
        "next_gate": "A qualified original-media recipe and live loaded-byte verification are still required",
    }
    if any(f["status"] != "verified" for f in files.values()):
        return result
    values, _, _ = owner.recover(
        {name: str(path) for name, path in media_paths.items()}
    )
    for source in contract.sources:
        data = values[source.member]
        if (
            len(data) != source.size
            or hashlib.sha256(data).hexdigest() != source.sha256
        ):
            raise ValueError("Recovered member differs from pinned source identity")
        result["recovered_members"].append(
            {"member_id": source.member, "size": len(data), "sha256": source.sha256}
        )
    return {**result, "status": "inputs_verified", "input_contract_satisfied": True}


def cli_preflight(args, *, project_root: Path, binary_path: Path | None):
    contract = selected_contract(args.preflight_original_media, args.target)
    if (
        args.run
        or args.original_media_prefix
        or args.scenario
        or args.direct_payload_contract
        or args.derived_artifact
        or args.host_directory
        or args.state_directory
        or args.checkpoint_load
        or args.checkpoint_save
        or args.loadseg_watch_seconds
        or args.breakpoint_stable_key
        or args.observation_memory_address is not None
        or args.observation_memory_equals is not None
        or args.observation_memory_write_watch
        or args.continue_seconds != 60
        or args.breakpoint_wait_seconds != 60
    ):
        raise ValueError(
            "Input preflight cannot launch, compile, inject, capture, checkpoint or create runtime state"
        )
    if len(contract.media) != 1:
        raise ValueError(
            "This CLI preflight requires a single explicit original medium"
        )
    if args.floppy0 is None:
        raise ValueError("Input preflight requires an explicit original --floppy0 path")
    return preflight_inputs(
        contract,
        target_dir=project_root / "targets" / args.target,
        project_root=project_root,
        rom_path=args.rom,
        media_paths={contract.media[0][0]: args.floppy0},
        binary_path=binary_path,
    )

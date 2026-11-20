"""Read-only input checks do not grant original-media execution or live identity."""

import hashlib
import json
from pathlib import Path

import pytest

from amiga_reversing.disasm.disk_set import DiskSet
from amiga_reversing.tools import copperline_session as session
from amiga_reversing.tools import original_media_preflight as check
from amiga_reversing.tools.original_media_prefix import validate_prefix_target
from tests.test_disk_set import fixture


def identity(data):
    return check.FileIdentity(len(data), (hashlib.sha256(data).hexdigest(),))


@pytest.fixture
def inputs(tmp_path):
    project, target, paths, _ = fixture(tmp_path)
    owner = DiskSet.load(target, project_root=project)
    rom = tmp_path / "user.rom"
    rom.write_bytes(b"synthetic supplied rom")
    binary = tmp_path / "runtime"
    binary.write_bytes(b"synthetic pinned runtime")
    contract = check.InputContract(
        "amiga_disk_fixture",
        tuple(
            (m["id"], identity(Path(paths[m["id"]]).read_bytes()))
            for m in owner.manifest["media"]
        ),
        identity(rom.read_bytes()),
        identity(binary.read_bytes()),
        tuple(
            check.SourceIdentity(
                name,
                owner.members[name]["size"],
                owner.members[name]["sha256"],
                0x1000,
                "decoded_resource",
            )
            for name in ("main", "overlay")
        ),
    )
    return project, target, paths, rom, binary, contract


def run(inputs, **kwargs):
    project, target, paths, rom, binary, contract = inputs
    return check.preflight_inputs(
        contract,
        target_dir=target,
        project_root=project,
        rom_path=rom,
        media_paths={k: Path(v) for k, v in paths.items()},
        binary_path=binary,
        **kwargs,
    )


def test_independent_dos_ndos_owner_recovers_exact_inputs_without_runtime_authority(
    inputs,
):
    p = run(inputs)
    assert p["input_contract_satisfied"] and p["status"] == "inputs_verified"
    assert [s["member_id"] for s in p["recovered_members"]] == ["main", "overlay"]
    assert (
        p["source_contracts"][0]["runtime_base"]
        == p["source_contracts"][1]["runtime_base"]
        == 0x1000
    )
    assert not any(
        p[k]
        for k in (
            "runtime_executed",
            "launch_admitted",
            "live_handoff_verified",
            "media_rebuild_verified",
        )
    )
    assert p["all_placement_coverage"] is None
    assert all(not v["live_mapping_verified"] for v in p["source_contracts"])
    with pytest.raises(ValueError, match="not registered"):
        validate_prefix_target("foft", "amiga_raw_foft")


@pytest.mark.parametrize("role", ["rom", "runtime", "media"])
def test_same_size_wrong_bytes_do_not_recover_members_or_supply_a_reported_match(
    inputs, monkeypatch, role
):
    _, _, paths, rom, binary, _ = inputs
    path = rom if role == "rom" else binary if role == "runtime" else Path(paths["dos"])
    data = bytearray(path.read_bytes())
    data[0] ^= 1
    path.write_bytes(data)
    monkeypatch.setattr(
        DiskSet, "recover", lambda *_: pytest.fail("wrong input reached extraction")
    )
    p = run(inputs)
    assert not p["input_contract_satisfied"] and not p["recovered_members"]
    assert (
        p["files"]["media:dos" if role == "media" else role]["status"]
        == "hash_mismatch"
    )


def test_missing_inputs_are_all_reported_without_creating_files_or_mutating_owner(
    inputs, monkeypatch
):
    project, target, paths, rom, binary, _ = inputs
    before = {
        str(p.relative_to(target)): p.read_bytes()
        for p in target.rglob("*")
        if p.is_file()
    }
    rom.unlink()
    binary.unlink()
    Path(paths["dos"]).unlink()
    monkeypatch.setattr(
        DiskSet, "recover", lambda *_: pytest.fail("missing input reached extraction")
    )
    p = run(inputs)
    assert sum(x["status"] == "missing" for x in p["files"].values()) == 3
    assert not p["recovered_members"] and not p["launch_admitted"]
    assert before == {
        str(p.relative_to(target)): p.read_bytes()
        for p in target.rglob("*")
        if p.is_file()
    }
    assert not (project / "runtime").exists()


@pytest.mark.parametrize(
    "change", ["base", "member_hash", "member_size", "media_hash", "target"]
)
def test_wrong_canonical_source_contract_fails_closed_before_runtime(inputs, change):
    from dataclasses import replace

    project, target, paths, rom, binary, c = inputs
    if change == "base":
        c = replace(c, sources=(replace(c.sources[0], load_address=0x2000),))
    elif change == "member_hash":
        c = replace(c, sources=(replace(c.sources[0], sha256="0" * 64),))
    elif change == "member_size":
        c = replace(c, sources=(replace(c.sources[0], size=1),))
    elif change == "media_hash":
        c = replace(
            c,
            media=(
                (c.media[0][0], check.FileIdentity(c.media[0][1].size, ("0" * 64,))),
                *c.media[1:],
            ),
        )
    else:
        c = replace(c, target="other")
    with pytest.raises(ValueError, match="contract|Canonical"):
        check.preflight_inputs(
            c,
            target_dir=target,
            project_root=project,
            rom_path=rom,
            media_paths={k: Path(v) for k, v in paths.items()},
            binary_path=binary,
        )


def test_embedded_child_cannot_replace_independent_owner_even_with_correct_hash(inputs):
    from dataclasses import replace

    project, target, paths, rom, binary, c = inputs
    owner = DiskSet.load(target, project_root=project)
    m = owner.members["return_view"]
    c = replace(
        c,
        sources=(
            check.SourceIdentity(
                "return_view", m["size"], m["sha256"], 0x1002, "decoded_resource"
            ),
        ),
    )
    with pytest.raises(ValueError, match="independent owner"):
        check.preflight_inputs(
            c,
            target_dir=target,
            project_root=project,
            rom_path=rom,
            media_paths={k: Path(v) for k, v in paths.items()},
            binary_path=binary,
        )


def test_recovery_failure_is_not_converted_into_verified_inputs(inputs, monkeypatch):
    def fail(*_):
        raise ValueError("independent decode failed")

    monkeypatch.setattr(DiskSet, "recover", fail)
    with pytest.raises(ValueError, match="decode failed"):
        run(inputs)


def test_file_check_requires_actual_bounded_bytes(tmp_path):
    p = tmp_path / "input"
    p.write_bytes(b"wrong size")
    assert check.inspect_file(p, identity(b"123"))["status"] == "size_mismatch"
    assert check.inspect_file(None, identity(b"123"))["status"] == "missing"
    assert check.inspect_file(tmp_path, identity(b"123"))["status"] == "missing"


def test_public_preflight_is_read_only_and_does_not_resolve_an_injected_entry(
    monkeypatch, capsys
):
    seen = []

    def fake(args, **kwargs):
        seen.append((args.target, args.rom, args.floppy0, kwargs))
        return {
            "input_contract_satisfied": False,
            "runtime_executed": False,
            "launch_admitted": False,
        }

    monkeypatch.setattr(check, "cli_preflight", fake)
    monkeypatch.setattr(
        session,
        "resolve_project_paths",
        lambda *_: pytest.fail("created source runtime view"),
    )
    monkeypatch.setattr(
        session, "run_session", lambda *_: pytest.fail("launched emulator")
    )
    assert (
        session.main(
            [
                "--preflight-original-media",
                "foft",
                "--target",
                "amiga_raw_foft",
                "--rom",
                "missing.rom",
                "--floppy0",
                "missing.ipf",
                "--copperline",
                "candidate",
            ]
        )
        == 1
    )
    assert seen[0][:3] == ("amiga_raw_foft", Path("missing.rom"), Path("missing.ipf"))
    assert not json.loads(capsys.readouterr().out)["launch_admitted"]


@pytest.mark.parametrize(
    "extra",
    [
        ["--run"],
        ["--original-media-prefix", "starglider2"],
        ["--scenario", "x.json"],
        ["--direct-payload-contract", "x"],
        ["--host-directory", "x"],
        ["--state-directory", "x"],
        ["--checkpoint-load", "x"],
        ["--derived-artifact", "x"],
        ["--observation-memory-address", "0x800"],
        ["--continue-seconds", "1"],
        ["--breakpoint-wait-seconds", "1"],
    ],
)
def test_preflight_cannot_be_combined_with_execution_or_other_admission(
    extra, tmp_path
):
    args = session.build_parser().parse_args(
        [
            "--preflight-original-media",
            "foft",
            "--target",
            "amiga_raw_foft",
            "--rom",
            "x",
            "--floppy0",
            "y",
            *extra,
        ]
    )
    with pytest.raises(ValueError, match="cannot launch"):
        check.cli_preflight(args, project_root=tmp_path, binary_path=None)


def test_preflight_contract_cannot_select_other_targets_or_user_hashes():
    with pytest.raises(ValueError, match="not declared"):
        check.selected_contract("foft", "other")
    with pytest.raises(ValueError, match="not declared"):
        check.selected_contract("other", "amiga_raw_foft")
    p = session.build_parser()
    with pytest.raises(SystemExit):
        p.parse_args(
            [
                "--target",
                "amiga_raw_foft",
                "--rom",
                "x",
                "--preflight-original-media",
                "foft",
                "--expected-sha256",
                "0" * 64,
            ]
        )


def test_owned_source_directory_cannot_become_private_original_media_storage(inputs):
    _, target, paths, _, _, _ = inputs
    bad = target / "private-original.adf"
    bad.write_bytes(Path(paths["dos"]).read_bytes())
    paths["dos"] = str(bad)
    with pytest.raises(ValueError, match="outside the owned source"):
        run(inputs)

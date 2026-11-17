"""The resource target builds from its published source and narrow PCM assets."""

import json
import struct
from pathlib import Path

import pytest

from amiga_reversing.disasm.source_package import validate_source_package
from amiga_reversing.disasm.source_package_publish import load_published_source_package
from tools import foft_baseline, foft_disk

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "targets/amiga_raw_foft_music_bank9_sps0613"
EXPECTED = "29792eedbaf4c3105f7a7812f378f9fbb7f9302e814956c6c9a49393b149aa50"


@pytest.mark.parametrize(
    ("target", "expected", "size", "load", "asset_count", "asset_bytes"),
    [
        (TARGET, EXPECTED, 50000, 0x58000, 10, 44046),
        (
            ROOT / "targets/amiga_raw_foft_boot_loader_sps0613",
            "b52575d366313c1648976925c368e7a990d30477e7a099301dcabb031a3939a1",
            4000,
            0x78000,
            0,
            0,
        ),
    ],
)
def test_source_build_has_no_hidden_original_and_only_proven_assets(
    tmp_path, target, expected, size, load, asset_count, asset_bytes
):
    package = load_published_source_package(target)
    files = validate_source_package(package)
    assets = [f for f in package["manifest"]["files"] if f["kind"] == "asset"]
    assert len(assets) == asset_count and sum(f["size"] for f in assets) == asset_bytes
    assert all(f["path"].startswith("assets/audioInstrument") for f in assets)
    assert not any(
        "binary.bin" in name or name.endswith((".ipf", ".rom")) for name in files
    )
    stage = tmp_path / "source-only"
    stage.mkdir()
    for name, data in files.items():
        path = stage / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    manifest = "source-package-manifest.json"
    (stage / manifest).write_bytes((target / manifest).read_bytes())
    vasm = ROOT / "tools/vasmm68k_mot.exe"
    if not vasm.is_file():
        pytest.skip("build the vasm oracle first")
    result = foft_baseline.build(
        tmp_path / "assembled",
        vasm,
        target=stage,
        expected=expected,
        size=size,
        load_address=load,
        stem="bank9",
    )
    assert result["native"] == result["vasm"]
    assert result["native"]["sha256"] == expected
    assert result["native"]["end_exclusive"] == hex(load + size)


def test_disk_outputs_require_a_fresh_private_directory(tmp_path):
    directory = foft_disk.private_directory(tmp_path / "fresh")
    assert directory.is_dir()
    with pytest.raises(FileExistsError):
        foft_disk.private_directory(directory)
    with pytest.raises(ValueError, match="private scratch"):
        foft_disk.private_directory(ROOT / "untracked-media-output")


def test_original_loader_records_prove_the_two_adjacent_main_program_transfers(
    tmp_path,
):
    from tools.foft_music_menu_probe import nominal_copy_chunks

    target = ROOT / "targets/amiga_raw_foft_boot_loader_sps0613"
    plan = json.loads(foft_disk.RECIPE.read_bytes())
    vasm = ROOT / "tools/vasmm68k_mot.exe"
    if not vasm.is_file():
        pytest.skip("build the vasm oracle first")
    foft_baseline.build(
        tmp_path,
        vasm,
        target=target,
        expected="b52575d366313c1648976925c368e7a990d30477e7a099301dcabb031a3939a1",
        size=4000,
        load_address=0x78000,
        stem="loader",
    )
    loader = (tmp_path / "loader-native.bin").read_bytes()
    descriptors = [struct.unpack_from(">4I", loader, 0x8EA + 16 * n) for n in range(3)]
    assert descriptors == [
        (0x58000, 85, 0, 32000),
        (0x800, 3, 0, 456000),
        (0x6FD40, 79, 0, 33472),
    ]
    chunks = []
    for descriptor in descriptors[1:]:
        chunks.extend(nominal_copy_chunks(*descriptor))
    spans = [
        {
            "track": c["track"] // 2,
            "side": (c["track"] ^ 1) & 1,
            "offset": c["track_offset"],
            "length": c["end"] - c["start"],
        }
        for c in chunks
    ]
    program = next(a for a in plan["actions"] if a["resource"]["id"] == "boot-program")
    assert spans == program["spans"]
    assert chunks[0]["start"] == 0x800 and chunks[-1]["end"] == 0x78000

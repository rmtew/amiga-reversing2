"""The resource target builds from its published source and narrow PCM assets."""

from pathlib import Path

import pytest

from amiga_reversing.disasm.source_package import validate_source_package
from amiga_reversing.disasm.source_package_publish import load_published_source_package
from tools import foft_baseline, foft_disk

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "targets/amiga_raw_foft_music_bank9_sps0613"
EXPECTED = "29792eedbaf4c3105f7a7812f378f9fbb7f9302e814956c6c9a49393b149aa50"


def test_bank_build_has_no_hidden_original_and_only_proven_pcm_assets(tmp_path):
    package = load_published_source_package(TARGET)
    files = validate_source_package(package)
    assets = [f for f in package["manifest"]["files"] if f["kind"] == "asset"]
    assert len(assets) == 10 and sum(f["size"] for f in assets) == 44046
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
    (stage / manifest).write_bytes((TARGET / manifest).read_bytes())
    vasm = ROOT / "tools/vasmm68k_mot.exe"
    if not vasm.is_file():
        pytest.skip("build the vasm oracle first")
    result = foft_baseline.build(
        tmp_path / "assembled",
        vasm,
        target=stage,
        expected=EXPECTED,
        size=50000,
        load_address=0x58000,
        stem="bank9",
    )
    assert result["native"] == result["vasm"]
    assert result["native"]["sha256"] == EXPECTED
    assert result["native"]["end_exclusive"] == "0x64350"


def test_disk_outputs_require_a_fresh_private_directory(tmp_path):
    directory = foft_disk.private_directory(tmp_path / "fresh")
    assert directory.is_dir()
    with pytest.raises(FileExistsError):
        foft_disk.private_directory(directory)
    with pytest.raises(ValueError, match="private scratch"):
        foft_disk.private_directory(ROOT / "untracked-media-output")

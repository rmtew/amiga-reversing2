"""The committed F.O.F.T. package builds without the private input or Ghidra."""

import json
import re
from pathlib import Path

import pytest

from amiga_reversing.disasm.source_package import materialize_source_package
from amiga_reversing.disasm.source_package_publish import (
    PUBLISH_MANIFEST,
    load_published_source_package,
)
from amiga_reversing.disasm.target_metadata import load_target_metadata
from tools import foft_baseline

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "targets/amiga_raw_foft"


@pytest.mark.c_backend
def test_clean_package_only_assembly_matches_whole_original_handoff(
    tmp_path, monkeypatch
):
    package = load_published_source_package(TARGET)
    stage = tmp_path / "committed-only"
    stage.mkdir()
    materialize_source_package(package, stage)
    (stage / "manifest.json").unlink()
    (stage / PUBLISH_MANIFEST).write_bytes((TARGET / PUBLISH_MANIFEST).read_bytes())
    assert not (stage / "binary.bin").exists()
    monkeypatch.setattr(foft_baseline, "TARGET", stage)
    vasm = ROOT / "tools/vasmm68k_mot.exe"
    if not vasm.is_file():
        pytest.skip("Build vasm oracle first")
    result = foft_baseline.build(tmp_path / "built", vasm)
    assert result["native"] == result["vasm"]
    assert result["native"]["whole_file_exact"]
    assert (tmp_path / "built/foft-native.bin").read_bytes() == (
        tmp_path / "built/foft-vasm.bin"
    ).read_bytes()


def test_imported_scopes_have_named_global_owners_and_real_bare_locals():
    metadata = load_target_metadata(TARGET)
    labels = metadata.seeded_code_labels
    globals_by_name = {l.name: l.addr for l in labels if "\\." not in l.name}
    locals_ = [l for l in labels if "\\." in l.name]
    assert len(locals_) >= 100
    for l in locals_:
        owner, local = l.name.split("\\.", 1)
        assert re.fullmatch("[A-Za-z_][A-Za-z_0-9]*", local)
        assert globals_by_name[owner] < l.addr and len(l.name.encode()) <= 63
    text = (TARGET / "source.s").read_text()
    assert "DrawSelectedKeyboardMarker:\n" in text and "\n.loop_y:\n" in text
    assert "\tdbf.w d7,.loop_y" in text


def test_rendered_references_use_the_materialized_load_view():
    text = (TARGET / "source.s").read_text()
    assert "\tclr.w abs_0_0004E37C.l\n" in text
    assert "\tjsr BumpSounds80.l\n" in text
    assert "-2646.l" not in text


def test_import_is_provenance_bound_and_does_not_promote_generic_auto_names():
    metadata = load_target_metadata(TARGET)
    for r in (
        *metadata.seeded_code_labels,
        *metadata.seeded_code_entrypoints,
        *metadata.seeded_entities,
        *metadata.entry_comments,
    ):
        assert r.source_id == "foft-sps-ghidra" and r.source_locator and r.source_path
        assert r.review_status == "seeded"
        if getattr(r, "name", None):
            assert not re.fullmatch(r"(?:FUN|LAB|DAT|WORD_ARRAY)_[0-9a-fA-F]+", r.name)
    source = json.loads((TARGET / "source_binary.json").read_text())
    assert source["load_address"] == source["entrypoint"] == 0x800
    assert source["path"] == "targets/amiga_raw_foft/binary.bin"


def test_changed_asset_is_refused_before_assembly(tmp_path, monkeypatch):
    package = load_published_source_package(TARGET)
    stage = tmp_path / "modified"
    stage.mkdir()
    materialize_source_package(package, stage)
    (stage / "manifest.json").unlink()
    (stage / PUBLISH_MANIFEST).write_bytes((TARGET / PUBLISH_MANIFEST).read_bytes())
    asset = next(
        row["path"] for row in package["manifest"]["files"] if row["kind"] == "asset"
    )
    (stage / asset).write_bytes(b"changed")
    monkeypatch.setattr(foft_baseline, "TARGET", stage)
    with pytest.raises(ValueError, match="modified|invalid"):
        foft_baseline.build(tmp_path / "built")


def test_wrong_private_payload_is_not_bound(tmp_path, monkeypatch):
    data = tmp_path / "wrong.bin"
    data.write_bytes(bytes(489472))
    target = tmp_path / "target"
    target.mkdir()
    monkeypatch.setattr(foft_baseline, "TARGET", target)
    with pytest.raises(ValueError, match="Whole program differs"):
        foft_baseline.bind(data)
    assert not (target / "binary.bin").exists()

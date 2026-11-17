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


@pytest.mark.parametrize(
    ("typ", "size", "unit"),
    [
        ("/word", 2, "word"),
        ("/undefined4", 4, "long"),
        ("/word[16]", 32, "word"),
        ("/dword[4]", 16, "long"),
    ],
)
def test_saved_scalar_types_do_not_imply_lookup_semantics(typ, size, unit):
    from tools.import_foft_reference import scalar_declaration

    assert scalar_declaration(typ, size) == {"unit": unit, "subtype": None}


def test_saved_scalar_extent_mismatch_is_refused():
    from tools.import_foft_reference import scalar_declaration

    with pytest.raises(ValueError, match="extent"):
        scalar_declaration("/word[16]", 2)
    assert scalar_declaration("/pointer", 4) is None


def test_saved_pointer_declarations_do_not_assert_mapped_addresses():
    metadata = json.loads((TARGET / "target_metadata.json").read_text())
    declarations = [
        r
        for r in metadata["seeded_entities"]
        if r.get("source_locator", "").endswith(("/pointer", "/undefined *"))
    ]
    assert len(declarations) > 100
    for row in declarations:
        assert row["unit"] == "long" and row["subtype"] is None
        assert row.get("value_kind") is None


def test_collection_classification_is_not_an_authored_comment():
    from amiga_reversing.disasm.effective_metadata import _data_block_element_entity
    from amiga_reversing.disasm.target_metadata import (
        DataBlockElementKind,
        DataBlockElementMetadata,
        DataBlockLayoutMetadata,
        TargetMetadataReviewStatus,
        TargetMetadataSeedOrigin,
    )

    provenance = {
        "seed_origin": TargetMetadataSeedOrigin.MANUAL_ANALYSIS,
        "review_status": TargetMetadataReviewStatus.SEEDED,
        "citation": "consumer proof",
    }
    element = DataBlockElementMetadata(
        layout_id="test",
        offset=0,
        width=8,
        kind=DataBlockElementKind.ARRAY,
        array_count=2,
        array_stride=4,
        **provenance,
    )
    layout = DataBlockLayoutMetadata(
        layout_id="test",
        hunk=0,
        source_start=0,
        source_end=8,
        name="pointers",
        role="pointer_table",
        default_unit="long",
        elements=(element,),
        **provenance,
    )
    entity = _data_block_element_entity(layout, element)
    assert entity.subtype == "pointer_table" and entity.comment is None


def test_vetted_collections_preserve_complete_geometry_and_named_handlers():
    from amiga_reversing.disasm.effective_metadata import effective_target_metadata

    metadata = effective_target_metadata(TARGET)
    layouts = {item.layout_id: item for item in metadata.data_block_layouts}
    expected = {
        "region_codes": (0x1B28, 12, 2),
        "selection_pointers": (0x1B48, 4, 4),
        "triplet_pointers": (0x1CD2, 18, 4),
        "ship_word_lookup": (0x198C0, 32, 2),
        "rawkey_characters": (0x36888, 158, 1),
        "ship_callbacks": (0x2B684, 32, 4),
        "ship_text": (0x12A56, 32, 4),
        "audio_records": (0x4F482, 15, 4),
    }
    for name, (address, count, stride) in expected.items():
        layout = layouts["foft-collection-" + name]
        assert layout.source_start == address - 0x800
        assert layout.source_end - layout.source_start == count * stride
        (element,) = layout.elements
        assert element.array_count == count and element.array_stride == stride
        assert element.type_binding is None
    assert [e.array_count for e in layouts["foft-edi_commands"].elements] == [11, 2]
    assert layouts["foft-scp_key_commands"].elements[0].array_count == 11
    assert layouts["foft-scp-instructions"].elements[0].array_count == 31
    text = (TARGET / "source.s").read_text()
    assert "tableConvHandler:\n\tbra.w fConvHandleEnd\n" in text
    assert "\tdc.l fEditCommand\t; handler\n" in text
    assert "\tdc.l fShipIntimidator\n" in text


def test_declared_table_owns_plain_scalars_without_erasing_independent_evidence():
    from amiga_reversing.disasm.effective_metadata import _declared_table_scalar_labels
    from amiga_reversing.disasm.target_metadata import (
        SeededEntityMetadata,
        TargetMetadataReviewStatus,
        TargetMetadataSeedOrigin,
    )

    def row(addr, **changes):
        return SeededEntityMetadata(
            **{
                "addr": addr,
                "end": addr + 4,
                "type": "data",
                "unit": "long",
                "seed_origin": TargetMetadataSeedOrigin.MANUAL_ANALYSIS,
                "review_status": TargetMetadataReviewStatus.SEEDED,
                "citation": "saved declaration",
                **changes,
            }
        )

    owner = row(0, end=16, name="pointers", subtype="pointer_table")
    named = row(0, name="old_name", source_id="saved_reference")
    anonymous = row(4)
    independent = [
        row(8, struct_name="Record", field_name="field"),
        row(12, comment="Independent authored evidence"),
        row(14),
        row(4, hunk=1),
        row(8, type="code"),
        row(8, value_kind="target_pointer"),
        row(8, name="independent_owner", source_owner_start=8, source_owner_size=4),
        row(8, source_evidence_id="independent-value-proof"),
    ]
    result = _declared_table_scalar_labels([named, anonymous, *independent], [owner])
    assert result[0].name == "old_name" and result[0].source_id == "saved_reference"
    assert result[0].end is None and result[0].unit is None
    assert result[1:] == independent

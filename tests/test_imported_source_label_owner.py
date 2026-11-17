"""Restating an imported source label can own locals without hiding collisions."""

import json
from dataclasses import replace

import pytest

from amiga_reversing.disasm import c_backend
from amiga_reversing.disasm.assembler_profiles import VASM_PROFILE
from amiga_reversing.disasm.binary_source import (
    BinarySourceKind,
    RawAddressModel,
    RawBinarySource,
)
from amiga_reversing.disasm.effective_metadata import (
    effective_metadata_file,
    effective_target_metadata,
)
from amiga_reversing.disasm.manual_action_catalog import target_catalog_manual_payload
from amiga_reversing.disasm.manual_actions import (
    ManualActionKind,
    ManualLabelScope,
    _manual_label_conflict_items,
    append_manual_actions,
)
from amiga_reversing.disasm.target_metadata import (
    SeededCodeLabelMetadata,
    SeededEntityMetadata,
    TargetMetadata,
    TargetMetadataReviewStatus,
    TargetMetadataSeedOrigin,
    write_target_metadata,
)
from tests.test_scoped_source_labels import assemble_both


def imported_label(**changes):
    return SeededEntityMetadata(
        addr=0,
        hunk=0,
        name="entry",
        seed_origin=TargetMetadataSeedOrigin.MANUAL_ANALYSIS,
        review_status=TargetMetadataReviewStatus.SEEDED,
        citation="Synthetic imported bare label",
        **changes,
    )


def test_imported_bare_label_restatement_owns_local_through_render_and_both_assemblers(
    tmp_path,
):
    raw = bytes.fromhex("60024e714e75")
    path = tmp_path / "input.bin"
    path.write_bytes(raw)
    source = RawBinarySource(
        kind=BinarySourceKind.RAW_BINARY,
        path=path,
        address_model=RawAddressModel.RUNTIME_ABSOLUTE,
        load_address=0x1000,
        entrypoint=0x1000,
        code_start_offset=0,
        display_path=str(path),
        analysis_cache_path=tmp_path / "analysis",
    )
    (tmp_path / "source_binary.json").write_text(
        json.dumps(
            {
                "kind": "raw_binary",
                "path": str(path),
                "address_model": "runtime_absolute",
                "load_address": 0x1000,
                "entrypoint": 0x1000,
                "code_start_offset": 0,
            }
        )
    )
    write_target_metadata(
        tmp_path,
        TargetMetadata(
            target_type="program",
            seeded_entities=(imported_label(),),
            entry_register_seeds=(),
        ),
    )
    actions = []
    for params in [
        {"hunk": 0, "addr": 0, "name": "entry"},
        {"hunk": 0, "addr": 4, "name": ".done", "scope": "local", "owner_offset": 0},
    ]:
        kind, payload = target_catalog_manual_payload("target.code_label.add", params)
        actions.append((ManualActionKind(kind), payload))
    append_manual_actions(tmp_path, binary_source=source, actions=actions)
    metadata = effective_target_metadata(tmp_path, binary_source=source)
    assert [v.name for v in metadata.seeded_code_labels] == ["entry", "entry\\.done"]
    assert not metadata.seeded_code_entrypoints
    with effective_metadata_file(tmp_path) as config:
        artifact = c_backend.build_listing_artifact_profile_from_binary_source(
            source, metadata_path=config
        )[2]
    try:
        text = artifact.inline_source_text_with_profile()[0]
        assert (
            text.count("entry:\n") == 1
            and "entry\\.done:\n" in text
            and "bra.b entry\\.done" in text
        )
        assert "dc.b $4E,$71" in text  # A label did not admit the skipped NOP as code.
        assemble_both(tmp_path, text, raw)
    finally:
        artifact.close()


@pytest.mark.parametrize(
    "case",
    [
        "address",
        "section",
        "typed_data",
        "extent",
        "runtime",
        "homonym",
        "runtime_alias",
        "field_type",
        "c_type",
        "label_extent",
    ],
)
def test_restatement_does_not_hide_other_address_domain_or_data_collisions(case):
    item = imported_label()
    label = {
        "label_id": "explicit",
        "hunk": 0,
        "addr": 0,
        "name": "entry",
        "address_domain": "source",
        "scope": ManualLabelScope.GLOBAL,
    }
    extra = {}
    if case == "address":
        item = replace(item, addr=2)
    elif case == "section":
        item = replace(item, hunk=1)
    elif case == "typed_data":
        item = replace(item, type="data")
    elif case == "extent":
        item = replace(item, end=2)
    elif case == "runtime":
        label["address_domain"] = "runtime"
    elif case == "field_type":
        item = replace(item, field_type="word")
    elif case == "c_type":
        item = replace(item, c_type="short")
    elif case == "label_extent":
        label["end"] = 2
    elif case == "homonym":
        extra["seeded_code_labels"] = (
            SeededCodeLabelMetadata(
                addr=2,
                hunk=0,
                name="entry",
                seed_origin=item.seed_origin,
                review_status=item.review_status,
                citation=item.citation,
            ),
        )
    elif case == "runtime_alias":
        from amiga_reversing.disasm.target_metadata import AbsoluteCodeLabelMetadata

        extra["absolute_code_labels"] = (
            AbsoluteCodeLabelMetadata(
                addr=0,
                name="entry",
                seed_origin=item.seed_origin,
                review_status=item.review_status,
                citation=item.citation,
            ),
        )
    metadata = TargetMetadata(
        target_type="program", seeded_entities=(item,), entry_register_seeds=(), **extra
    )
    conflicts = _manual_label_conflict_items(
        {"explicit": label},
        stronger_metadata=metadata,
        assembler_profile=VASM_PROFILE,
    )
    assert len(conflicts) == 1 and conflicts[0]["item_id"].endswith(
        ":metadata-collision"
    )

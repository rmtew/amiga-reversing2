"""A correction filters only its selected source declarations."""

from dataclasses import fields

import pytest

from amiga_reversing.disasm.target_metadata import (
    AbsoluteCodeLabelMetadata,
    AbstractRegionMetadata,
    RssetUseSiteBindingMetadata,
    SeededCodeEntrypointMetadata,
    SeededCodeLabelMetadata,
    SeededEntityMetadata,
    SuppressedSeededItemKind,
    SuppressedSeededItemMetadata,
    TargetMetadata,
    TargetMetadataReviewStatus,
    TargetMetadataSeedOrigin,
    apply_suppressed_seeded_items,
)


@pytest.mark.parametrize("kind", list(SuppressedSeededItemKind))
def test_suppression_preserves_every_unrelated_metadata_field(kind):
    provenance = {
        "seed_origin": TargetMetadataSeedOrigin.MANUAL_ANALYSIS,
        "review_status": TargetMetadataReviewStatus.SEEDED,
        "citation": "Synthetic source proof",
    }
    metadata = TargetMetadata(
        target_type="program",
        entry_register_seeds=(),
        absolute_code_labels=(
            AbsoluteCodeLabelMetadata(addr=0x1000, name="runtimeEntry", **provenance),
        ),
        abstract_regions=(AbstractRegionMetadata("work", 0, 16, 8),),
        rsset_use_site_bindings=(
            RssetUseSiteBindingMetadata(
                hunk=0,
                addr=2,
                operand_index=0,
                base_register="a0",
                displacement=2,
                layout_name="record",
                base_symbol="recordBase",
                base_evidence_id="proof",
                **provenance,
            ),
        ),
        seeded_entities=tuple(
            SeededEntityMetadata(
                addr=at, end=at + 4, hunk=0, type="data", unit="long", **provenance
            )
            for at in (4, 8)
        ),
        seeded_code_labels=tuple(
            SeededCodeLabelMetadata(addr=at, hunk=0, name=f"label{at}", **provenance)
            for at in (4, 8)
        ),
        seeded_code_entrypoints=tuple(
            SeededCodeEntrypointMetadata(
                addr=at, hunk=0, name=f"entry{at}", **provenance
            )
            for at in (4, 8)
        ),
    )
    suppression = SuppressedSeededItemMetadata(
        kind, 0, 4, 8 if kind is SuppressedSeededItemKind.SEEDED_ENTITY else None
    )
    result = apply_suppressed_seeded_items(metadata, (suppression,))
    selected = {
        SuppressedSeededItemKind.SEEDED_ENTITY: "seeded_entities",
        SuppressedSeededItemKind.SEEDED_CODE_LABEL: "seeded_code_labels",
        SuppressedSeededItemKind.SEEDED_CODE_ENTRYPOINT: "seeded_code_entrypoints",
    }[kind]
    assert (
        len(getattr(result, selected)) == 1 and getattr(result, selected)[0].addr == 8
    )
    for field in fields(metadata):
        if field.name not in {selected, "suppressed_seeded_items"}:
            assert getattr(result, field.name) == getattr(metadata, field.name), (
                field.name
            )
    assert apply_suppressed_seeded_items(metadata, ()) is metadata

"""Subview imports preserve source coordinates, widths and proven lexical owners."""

import json

import pytest

from amiga_reversing.disasm.metadata_slice import slice_raw_metadata
from amiga_reversing.disasm.target_metadata import (
    TargetMetadata,
    target_metadata_json_payload,
)


def fixture():
    payload = json.loads(
        json.dumps(
            target_metadata_json_payload(
                TargetMetadata(target_type="raw_binary", entry_register_seeds=())
            )
        )
    )
    provenance = {
        "seed_origin": "manual_analysis",
        "review_status": "seeded",
        "citation": "synthetic source evidence",
    }
    payload["seeded_entities"] = [
        dict(
            addr=110,
            end=118,
            hunk=0,
            name="samples",
            type="data",
            subtype="sound_sample",
            unit="byte",
            **provenance,
        ),
        dict(addr=1, end=2, hunk=0, name="outside", type="data", **provenance),
    ]
    payload["seeded_code_labels"] = [
        dict(
            addr=104,
            name=r"Entry\.loop",
            source_locator="import;scope_owner=s0:00000064:label",
            **provenance,
        )
    ]
    payload["seeded_code_entrypoints"] = [dict(addr=100, name="Entry", **provenance)]
    payload["entry_register_seeds"] = [
        {
            "entry_offset": 100,
            "register": "A1",
            "kind": "struct_ptr",
            "struct_name": "Voice",
            "note": "synthetic",
            "library_name": None,
            "context_name": None,
        }
    ]
    payload["custom_structs"] = [
        dict(
            name="Voice",
            size=4,
            fields=[],
            source="fixture",
            base_offset=0,
            base_struct=None,
            available_since="1.0",
            **provenance,
        ),
        dict(
            name="Unused",
            size=2,
            fields=[],
            source="fixture",
            base_offset=0,
            base_struct=None,
            available_since="1.0",
            **provenance,
        ),
    ]
    payload["source_output_policy"] = {"mode": "binary_assets", "minimum_asset_size": 1}
    return payload


def test_selected_source_facts_are_rebased_but_literal_values_and_widths_are_preserved():
    metadata, counts = slice_raw_metadata(
        TargetMetadata.from_dict(fixture()), start=100, size=20
    )
    assert metadata.seeded_entities[0].addr == 10
    assert metadata.seeded_entities[0].end == 18
    assert metadata.seeded_entities[0].subtype == "sound_sample"
    assert len(metadata.seeded_entities) == 1
    assert metadata.seeded_code_entrypoints[0].addr == 0
    assert metadata.entry_register_seeds[0].entry_offset == 0
    assert metadata.seeded_code_labels[0].name == r"Entry\.loop"
    assert metadata.seeded_code_labels[0].source_locator.endswith(
        "scope_owner=s0:00000000:label"
    )
    assert [s.name for s in metadata.custom_structs] == ["Voice"]
    assert metadata.source_output_policy.mode == "binary_assets"
    assert not metadata.execution_views and counts["seeded_entities"] == 1


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p["seeded_entities"][0].update(end=121),
        lambda p: p["seeded_entities"][0].update(
            source_owner_start=110, source_owner_size=20
        ),
        lambda p: p["seeded_code_labels"][0].update(
            source_locator="scope_owner=s0:00000001:label"
        ),
    ],
)
def test_partial_or_outside_ownership_is_not_clipped_or_promoted(mutation):
    payload = fixture()
    mutation(payload)
    with pytest.raises(ValueError, match="outside"):
        slice_raw_metadata(TargetMetadata.from_dict(payload), start=100, size=20)


@pytest.mark.parametrize(
    ("start", "size"), [(True, 20), (100, False), (-1, 20), (100, 0)]
)
def test_invalid_slice_extent(start, size):
    with pytest.raises(ValueError, match="extent"):
        slice_raw_metadata(TargetMetadata.from_dict(fixture()), start=start, size=size)


def test_runtime_container_facts_are_not_silently_imported():
    payload = fixture()
    payload["suppressed_seeded_items"] = [
        {"kind": "seeded_entity", "hunk": 0, "addr": 110}
    ]
    metadata = TargetMetadata.from_dict(payload)
    with pytest.raises(ValueError, match="unsupported fact family"):
        slice_raw_metadata(metadata, start=100, size=20)


def test_layout_and_relative_reference_coordinates_move_together_without_value_rebasing():
    payload = fixture()
    proof = {
        "seed_origin": "manual_analysis",
        "review_status": "seeded",
        "citation": "fixture",
    }
    reference = {
        "base_locator": {"hunk": 0, "offset": 110},
        "target_locator": {"hunk": 0, "offset": 114},
        "target_hunk": 0,
        "target_offset": 114,
        "reference_kind": "base_displacement_range",
        "entry_width": 4,
        "width": 4,
        "offset": 0,
        "signed": False,
        "scale": 1,
        "source_value": 4,
        "data_block_ref_id": "ref",
        "layout_id": "layout",
        "xref_generation_mode": "bidirectional",
    }
    payload["data_block_layouts"] = [
        dict(
            layout_id="layout",
            hunk=0,
            source_start=110,
            source_end=114,
            elements=[
                dict(
                    layout_id="layout",
                    offset=0,
                    width=4,
                    kind="scalar",
                    reference_interpretation=reference,
                    **proof,
                )
            ],
            **proof,
        )
    ]
    payload["manual_data_references"] = [
        dict(
            addr=110,
            size=4,
            hunk=0,
            base_hunk=0,
            base_offset=110,
            target_hunk=0,
            target_offset=114,
            reference_kind="base_displacement_range",
            entry_width=4,
            owner_kind="data_block_interpreted_ref",
            owner_id="ref",
            owner_layout_id="layout",
            owner_element_offset=0,
            xref_generation_mode="bidirectional",
            signed=False,
            scale=1,
            source_value=4,
            **proof,
        )
    ]
    metadata, _ = slice_raw_metadata(
        TargetMetadata.from_dict(payload), start=100, size=20
    )
    layout = metadata.data_block_layouts[0]
    assert (layout.source_start, layout.source_end) == (10, 14)
    transformed = layout.elements[0].reference_interpretation
    assert transformed["base_locator"]["offset"] == 10
    assert transformed["target_locator"]["offset"] == transformed["target_offset"] == 14
    assert transformed["source_value"] == 4 and transformed["width"] == 4
    assert metadata.manual_data_references[0].base_offset == 10
    assert metadata.manual_data_references[0].target_offset == 14
    reference["target_locator"]["offset"] = 200
    with pytest.raises(ValueError, match="outside"):
        slice_raw_metadata(TargetMetadata.from_dict(payload), start=100, size=20)


def test_an_owner_crossing_into_the_slice_is_not_silently_discarded():
    payload = fixture()
    payload["seeded_entities"][0].update(addr=99, end=118)
    with pytest.raises(ValueError, match="partially overlaps"):
        slice_raw_metadata(TargetMetadata.from_dict(payload), start=100, size=20)

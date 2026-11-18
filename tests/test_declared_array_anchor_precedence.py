"""An authored array can restate its imported anchor without losing its width."""

import json

import pytest

from amiga_reversing.disasm import c_backend
from amiga_reversing.disasm.effective_metadata import effective_metadata_file
from amiga_reversing.disasm.manual_actions import MANUAL_ACTION_LOG_FILE_NAME
from amiga_reversing.disasm.project_paths import PROJECT_ROOT
from tests.test_declared_scalar_opaque_precedence import fixture, policy


def named_fixture(tmp_path, protection=None, matching=True, unit=4):
    source, raw, _ = fixture(
        tmp_path,
        opaque=(4, 4 + unit),
        arrays=((4, 20),),
        stride=4,
        protection=protection,
    )
    path = tmp_path / "target_metadata.json"
    m = json.loads(path.read_text())
    leaf = m["seeded_entities"][0]
    leaf.update(
        subtype=None, unit={1: "byte", 2: "word", 4: "long"}[unit], name="dispatchSlots"
    )
    if protection == "field":
        leaf["field_type"] = "long"
    m["seeded_entities"] = [leaf]
    m["entry_comments"] = []
    path.write_text(json.dumps(m))
    journal = tmp_path / MANUAL_ACTION_LOG_FILE_NAME
    rows = [json.loads(x) for x in journal.read_text().splitlines()]
    rows[1]["data_block_layout"]["default_unit"] = {1: "byte", 2: "word", 4: "long"}[
        unit
    ]
    rows[2]["data_block_element"].update(array_count=16 // unit, array_stride=unit)
    rows[1]["data_block_layout"]["name"] = (
        "dispatchSlots" if matching else "differentArray"
    )
    journal.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return source, raw


@pytest.mark.parametrize("unit", [1, 2, 4])
def test_named_scalar_restates_identical_array_anchor_without_owning_its_first_cell(
    tmp_path,
    unit,
):
    source, raw = named_fixture(tmp_path, unit=unit)
    before = (tmp_path / "target_metadata.json").read_bytes()
    active = [
        (x["offset"], x["size"])
        for x in policy(source, tmp_path)
        if x["size"] and x["kind"] == {1: "bytes", 2: "words", 4: "longs"}[unit]
    ]
    assert active == [(4, 16)]
    with effective_metadata_file(tmp_path) as meta:
        text = c_backend.render_project_source_with_c_backend(
            source, metadata_path=meta, project_root=PROJECT_ROOT
        )
    values = ",".join(
        f"${int.from_bytes(raw[i : i + unit], 'big'):0{unit * 2}X}"
        for i in range(4, 20, unit)
    )
    assert (
        "dispatchSlots:\n\tdc." + {1: "b", 2: "w", 4: "l"}[unit] + " " + values in text
    )
    rebuilt, _ = c_backend.assemble_platform_source_text_with_c_backend(
        "amiga-raw", text, project_root=PROJECT_ROOT
    )
    assert rebuilt == raw
    assert (tmp_path / "target_metadata.json").read_bytes() == before


@pytest.mark.parametrize(
    "protection",
    ["comment", "manual", "validated", "owner", "evidence", "parents", "field"],
)
def test_independent_named_contract_is_not_reduced(tmp_path, protection):
    source, _ = named_fixture(tmp_path, protection)
    assert any(x["offset"] == 4 and x["size"] == 4 for x in policy(source, tmp_path))


def test_different_name_does_not_establish_one_anchor_identity(tmp_path):
    source, _ = named_fixture(tmp_path, matching=False)
    assert any(x["offset"] == 4 and x["size"] == 4 for x in policy(source, tmp_path))


def byte_fixture(tmp_path, protection=None):
    source, raw, _ = fixture(
        tmp_path, opaque=(4, 20), arrays=((5, 13),), protection=protection
    )
    journal = tmp_path / MANUAL_ACTION_LOG_FILE_NAME
    rows = [json.loads(x) for x in journal.read_text().splitlines()]
    rows[1]["data_block_layout"]["default_unit"] = "byte"
    rows[2]["data_block_element"].update(array_count=8, array_stride=1)
    journal.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return source, raw


def test_odd_byte_array_subtracts_only_its_authored_extent_from_weak_opaque_span(
    tmp_path,
):
    source, raw = byte_fixture(tmp_path)
    paths = [tmp_path / "target_metadata.json", tmp_path / MANUAL_ACTION_LOG_FILE_NAME]
    before = [p.read_bytes() for p in paths]
    actual = [
        (x["offset"], x["size"])
        for x in policy(source, tmp_path)
        if x["size"] and x.get("semantic_role") == "opaque_data"
    ]
    assert actual == [(4, 1), (13, 7)]
    with effective_metadata_file(tmp_path) as meta:
        text = c_backend.render_project_source_with_c_backend(
            source, metadata_path=meta, project_root=PROJECT_ROOT
        )
    for name in [
        "opaqueStart",
        "arrayStart",
        "arrayInterior",
        "arrayEnd",
        "opaqueInterior",
        "opaqueEnd",
    ]:
        assert name + ":" in text
    rebuilt, _ = c_backend.assemble_platform_source_text_with_c_backend(
        "amiga-raw", text, project_root=PROJECT_ROOT
    )
    assert rebuilt == raw
    assert [p.read_bytes() for p in paths] == before


@pytest.mark.parametrize(
    "protection",
    [
        "comment",
        "named",
        "manual",
        "validated",
        "owner",
        "parents",
        "evidence",
        "typed",
    ],
)
def test_byte_array_does_not_shadow_protected_or_different_unit_facts(
    tmp_path, protection
):
    source, _ = byte_fixture(tmp_path, protection)
    assert any(x["offset"] == 4 and x["size"] == 16 for x in policy(source, tmp_path))

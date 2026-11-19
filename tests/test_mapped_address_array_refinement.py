"""Explicit mapped addresses preserve retained LONG cells without code admission."""

import copy

import pytest

from amiga_reversing.disasm.disk_set import DiskSet
from amiga_reversing.disasm.disk_set_state import _artifact
from amiga_reversing.disasm.record_arrays import validate_record_array
from tests.test_disk_set_state import data_request, editable
from tests.test_scoped_record_arrays import metadata
from tests.test_scoped_scalar_arrays import array_request, snapshot


def field(kind="APTR", **updates):
    return {"name": "entry", "type": kind, "offset": 0, "size": 4,
            "value_kind": "target_pointer", "pointer_address_domain": "mapped_source", **updates}


def setup(tmp_path, monkeypatch, *, representation=None, target_label=True, values=None):
    values = values or [0x1002, 0x1020, 0x1020, 0, 0xDEADBEEF, 0x1020, 0x1020]
    data = b"".join(x.to_bytes(4, "big") for x in values) + bytes.fromhex("4e75123456789abc")
    project, target, paths, call = editable(tmp_path, monkeypatch, record_data=data,
        record_label=(32, "rawCallbackBytes") if target_label else None, record_scalar_label=(8, "savedAddressSlot", 4))
    selected = call("inspect", source_offset=4, end_offset=32, row_kind="data")
    call("interpret", **data_request(selected, "range.data_block.layout.create",
                                    {"name": "cells", "default_unit": "long"}))
    options = {"representation": representation} if representation else {}
    call("interpret", **array_request(call, end=32, stride=4, count=7,
                                      name="retainedCells", **options))
    return project, target, paths, call


def declare(call, *, end=32, address=None):
    selected = call("inspect", source_offset=4, end_offset=end, row_kind="data")
    return data_request(selected, "range.data_block.records.declare", {
        "record_type": "AddressCell", "record_size": 4, "record_stride": 4,
        "record_count": (end - 4) // 4, "fields": [address or field()],
        "field_presentation": True,
    })


def code_runs(project, target, paths):
    owner = DiskSet.load(target, project_root=project)
    _, artifact = _artifact(owner, "main", paths)
    try:
        code = artifact.analysis_payload()[0]["sections"][0]["accepted_code_runs"]
        assert not artifact.query_payload("instructions", section_index=0,
            source_offset=32, end_offset=34)["items"]
        return code
    finally:
        artifact.close()


@pytest.mark.parametrize("kind", ["APTR", "LONG", "ULONG"])
def test_complete_long_grid_maps_addresses_without_changing_code_or_history(tmp_path, monkeypatch, kind):
    project, target, paths, call = setup(tmp_path, monkeypatch)
    prior = copy.deepcopy(metadata(target)["data_block_layouts"][-1]["elements"][0])
    before_code = code_runs(project, target, paths)
    before_source = (target / "main.s").read_bytes()
    log = target / "analysis/main.manual_actions.jsonl"
    prefix = log.read_bytes()
    saved = call("interpret", **declare(call, address=field(kind)))
    assert log.read_bytes().startswith(prefix)
    element = metadata(target)["data_block_layouts"][-1]["elements"][0]
    assert element["provenance"]["primitive_array_refinement"] == prior
    assert element["name"] == "retainedCells"
    assert code_runs(project, target, paths) == before_code
    text = (target / "main.s").read_bytes()
    assert b"dc.l finish" in text and b"dc.l rawCallbackBytes" in text
    assert b"savedAddressSlot:" in text and b"dc.l $DEADBEEF" in text
    assert b"dc.l $00000000" in text
    assert saved["verification"]["media_exact"]
    undone = call("rollback", expected_revision=saved["revision"], action_id=saved["actions"][0]["action_id"])
    assert (target / "main.s").read_bytes() == before_source
    redone = call("rollback", expected_revision=undone["revision"], action_id=saved["actions"][0]["action_id"], redo=True)
    assert (target / "main.s").read_bytes() == text
    call("regenerate", expected_revision=redone["revision"])
    assert metadata(target)["data_block_layouts"][-1]["elements"][0]["provenance"] == element["provenance"]


@pytest.mark.parametrize("change", [
    {"pointer_address_domain": "runtime_only", "pointer_symbol_group": "runtime"},
    {"pointer_address_domain": None}, {"value_kind": "scalar"},
    {"size": 2, "type": "WORD"},
])
def test_long_refinement_requires_explicit_same_width_mapped_address_contract(tmp_path, monkeypatch, change):
    _, target, _, call = setup(tmp_path, monkeypatch)
    before = snapshot(target)
    with pytest.raises(ValueError, match="grid|address|pointer"):
        call("interpret", **declare(call, address=field(**change)))
    assert snapshot(target) == before


@pytest.mark.parametrize(("partial", "representation"), [(True, None), (False, "decimal")])
def test_pointer_refinement_preserves_full_extent_and_prior_representation(tmp_path, monkeypatch, partial, representation):
    _, target, _, call = setup(tmp_path, monkeypatch, representation=representation)
    before = snapshot(target)
    with pytest.raises(ValueError, match="primitive array grid"):
        call("interpret", **declare(call, end=28 if partial else 32))
    assert snapshot(target) == before


def test_mapped_refinement_replay_rechecks_prior_long_grid():
    shape = {"name": "Cell", "size": 4, "fields": [field()]}
    prior = {"layout_id": "owner", "offset": 0, "width": 8, "kind": "array",
             "array_count": 2, "array_stride": 4, "type_binding": None}
    binding = {"binding_kind": "custom_struct", "bound_type_id": "Cell", "record_contract": shape,
               "array_count": 2, "element_offset": 0, "element_width": 8, "layout_id": "owner"}
    element = {"layout_id": "owner", "offset": 0, "width": 8, "kind": "array",
               "array_count": 2, "array_stride": 4, "type_binding": binding}
    layout = {"source_start": 4, "source_end": 12, "elements": [prior]}
    validate_record_array(element, shape, layout)
    element["provenance"]["primitive_array_refinement"]["array_stride"] = 2
    with pytest.raises(ValueError, match="provenance differs"):
        validate_record_array(element, shape, layout)

def test_mixed_long_grid_keeps_equal_looking_scalar_column_numeric(tmp_path, monkeypatch):
    values = [0x1002, 0x101C, 0x101C, 0x1002, 0, 0x101C]
    data = b"".join(x.to_bytes(4, "big") for x in values) + bytes.fromhex("4e751234")
    _, target, _, call = editable(tmp_path, monkeypatch, record_data=data,
                                  record_label=(28, "rawTail"))
    selected = call("inspect", source_offset=4, end_offset=28, row_kind="data")
    call("interpret", **data_request(selected, "range.data_block.layout.create",
                                    {"name": "mixedCells", "default_unit": "long"}))
    call("interpret", **array_request(call, end=28, stride=4, count=6))
    selected = call("inspect", source_offset=4, end_offset=28, row_kind="data")
    saved = call("interpret", **data_request(selected, "range.data_block.records.declare", {
        "record_type": "MixedCell", "record_size": 8, "record_count": 3, "record_stride": 8,
        "fields": [field(), {"name": "scalarBits", "type": "LONG", "offset": 4, "size": 4}],
        "field_presentation": True,
    }))
    text = (target / "main.s").read_text()
    assert "dc.l finish" in text and "dc.l rawTail" in text
    assert "dc.l $0000101C" in text and "dc.l $00001002" in text
    assert 'rawTail:\n\tdc.b $4E,$75,$12,$34' in text
    assert saved["verification"]["media_exact"]


def test_unowned_mapped_field_gets_source_anchor_without_code_admission(tmp_path, monkeypatch):
    project, target, paths, call = setup(tmp_path, monkeypatch, target_label=False)
    before = code_runs(project, target, paths)
    saved = call("interpret", **declare(call))
    text = (target / "main.s").read_text()
    longs = [line.strip().split(";", 1)[0].strip()[5:] for line in text.splitlines()
             if line.strip().startswith("dc.l ")]
    anchor = longs[1]
    assert not anchor.startswith("$") and anchor + ":" in text
    assert longs[1] == longs[2] == longs[5] == longs[6]
    assert code_runs(project, target, paths) == before
    assert saved["verification"]["media_exact"]


def test_mapped_field_does_not_split_an_accepted_instruction(tmp_path, monkeypatch):
    project, target, paths, call = setup(tmp_path, monkeypatch, target_label=False,
        values=[0x1001, 0x1020, 0x1020, 0, 0xDEADBEEF, 0x1020, 0x1020])
    before = code_runs(project, target, paths)
    call("interpret", **declare(call))
    text = (target / "main.s").read_text()
    assert "dc.l $00001001" in text
    assert code_runs(project, target, paths) == before

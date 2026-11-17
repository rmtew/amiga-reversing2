import pytest

from amiga_reversing.disasm.manual_action_catalog import (
    target_action_catalog, target_catalog_manual_payload,
)


def test_target_data_seed_uses_existing_required_data_fact():
    assert any(a["action_id"] == "target.data.seed" for a in target_action_catalog())
    kind, payload = target_catalog_manual_payload("target.data.seed", {
        "hunk": 0, "addr": 32, "end": 64, "name": "offset_table", "unit": "word"})
    assert kind == "create_manual_seed"
    assert payload["seed"] == {
        "seed_id": "catalog-data-seed-h0-00000020-00000040",
        "kind": "data", "mode": "required", "hunk": 0,
        "addr": 32, "end": 64, "name": "offset_table", "unit": "word", "data_role": "raw"}


@pytest.mark.parametrize("change", [
    {"end": 32}, {"end": 31}, {"end": 33}, {"addr": -1},
    {"hunk": -1}, {"hunk": True}, {"addr": "32"},
    {"name": " "}, {"unit": "quad"}, {"unit": []},
])
def test_target_data_seed_rejects_invalid_range_or_unit(change):
    with pytest.raises(ValueError):
        target_catalog_manual_payload("target.data.seed", {
            "hunk": 0, "addr": 32, "end": 64, "name": "offset_table", "unit": "word", **change})


def test_target_code_seed_remains_code():
    _, payload = target_catalog_manual_payload("target.code.seed", {
        "hunk": 0, "addr": 32, "name": "routine"})
    assert payload["seed"]["kind"] == "code"


@pytest.mark.parametrize("data_role", ["bitmap", "sound_sample", "opaque_data"])
def test_target_binary_classification_covers_the_explicit_whole_range(data_role):
    _, payload = target_catalog_manual_payload("target.data.seed", {
        "hunk": 0, "addr": 32, "end": 544, "name": "raw_asset", "unit": "byte",
        "data_role": data_role, "role": "authored purpose"})
    seed = payload["seed"]
    assert (seed["addr"], seed["end"], seed["data_role"], seed["unit"]) == (32, 544, data_role, "byte")
    assert seed["role"] == "authored purpose" and "row_indexes" not in seed


@pytest.mark.parametrize("change", [
    {"data_role": "code"}, {"data_role": "string"}, {"data_role": []},
    {"data_role": None}, {"unit": "word"}, {"unit": "long"},
])
def test_binary_classification_rejects_other_kinds_and_nonbyte_storage(change):
    with pytest.raises(ValueError):
        target_catalog_manual_payload("target.data.seed", {
            "hunk": 0, "addr": 32, "end": 544, "name": "raw_asset", "unit": "byte",
            "data_role": "sound_sample", **change})


def test_target_string_seed_uses_existing_ascii_fact_without_listing_rows():
    action = next(a for a in target_action_catalog() if a["action_id"] == "target.string.seed")
    assert action["parameter_schema"]["required"] == ["hunk", "addr", "end", "name"]
    kind, payload = target_catalog_manual_payload("target.string.seed", {
        "hunk": 0, "addr": 33, "end": 44, "name": " view_front ",
        "role": "Original view-direction text"})
    assert kind == "create_manual_seed"
    assert payload["seed"] == {
        "seed_id": "catalog-string-seed-h0-00000021-0000002C",
        "kind": "data", "mode": "required", "hunk": 0,
        "addr": 33, "end": 44, "name": "view_front", "unit": "byte",
        "data_role": "string", "encoding": "ascii",
        "role": "Original view-direction text"}


@pytest.mark.parametrize("change", [
    {"end": 32}, {"end": 31}, {"addr": -1}, {"hunk": -1},
    {"addr": True}, {"end": "64"}, {"name": " "},
    {"encoding": "utf-8"}, {"encoding": []}, {"unit": "word"},
])
def test_target_string_seed_rejects_invalid_admission(change):
    with pytest.raises(ValueError):
        target_catalog_manual_payload("target.string.seed", {
            "hunk": 0, "addr": 32, "end": 64, "name": "message", **change})

"""The closure audit rejects incomplete or contradictory native witnesses."""

import copy

import pytest

from tools.foft_record_closure_audit import check_native


def fixture():
    particle = []
    for i in range(12):
        particle.append(
            {
                "source_offset": 20 + i * 2,
                "typed_accesses": [
                    {
                        "operand_index": 0,
                        "field_name": "field" + str(i),
                        "displacement": 0,
                        "field_size": 2,
                        "root_struct_name": "HyperspaceParticleRecord",
                        "record_cursor_loop": {
                            "header_offset": 0x57FC,
                            "tail_offset": 0x5870,
                            "iteration_count": 100,
                            "iteration_stride": 18,
                            "record_count": 100,
                            "base_record_index": 0,
                            "counter_register": 0,
                            "body_only": True,
                        },
                    }
                ],
            }
        )
    mesh = [
        {
            "typed_accesses": [
                {
                    "base_register": "A6",
                    "root_struct_name": "ProjectedVertexRecord",
                    "field_name": name,
                    "field_size": 2,
                    "displacement": row * 10 + field,
                }
                for row in range(15)
                for field, name in [(0, "x"), (2, "y"), (4, "z")]
            ]
        }
    ]
    mapping = {
        "particle_bindings": [
            dict(
                source_offset=r["source_offset"],
                **{
                    k: a[k]
                    for k in [
                        "operand_index",
                        "field_name",
                        "displacement",
                        "field_size",
                    ]
                },
            )
            for r in particle
            for a in r["typed_accesses"]
        ]
    }
    return {"particles": particle, "mesh": mesh}, mapping


def test_complete_native_field_proofs_leave_source_index_and_runtime_open():
    windows, mapping = fixture()
    before = copy.deepcopy((windows, mapping))
    result = check_native(windows, mapping)
    assert (
        result["particle_body_fields"] == 12 and result["projection_xyz_fields"] == 45
    )
    assert not result["mesh_source_index_proved"] and not result["guest_execution"]
    assert (windows, mapping) == before


@pytest.mark.parametrize(
    "change",
    [
        "counter",
        "stride",
        "extent",
        "word_index",
        "field",
        "projection",
        "missing",
        "source",
    ],
)
def test_incomplete_proofs_do_not_close_the_static_milestone(change):
    w, m = fixture()
    field = w["particles"][0]["typed_accesses"][0]
    if change == "counter":
        field["record_cursor_loop"]["counter_register"] = 1
    if change == "stride":
        field["record_cursor_loop"]["iteration_stride"] = 16
    if change == "extent":
        field["record_cursor_loop"]["record_count"] = 99
    if change == "word_index":
        field["word_index"] = {}
    if change == "field":
        field["field_name"] = "different"
    if change == "projection":
        w["mesh"][0]["typed_accesses"][-1]["displacement"] = 146
    if change == "missing":
        w["mesh"][0]["typed_accesses"].pop()
    if change == "source":
        w["mesh"][0]["typed_accesses"].append({"base_register": "A0"})
    with pytest.raises(
        ValueError,
        match={
            "counter": "counter/cursor",
            "stride": "counter/cursor",
            "extent": "counter/cursor",
            "word_index": "WORD index",
            "field": "source/field",
            "projection": "projection rows",
            "missing": "projection rows",
            "source": "unproved frame-index",
        }[change],
    ):
        check_native(w, m)

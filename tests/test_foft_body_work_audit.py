"""Copy-protocol checks over synthetic accepted facts; no original bytes."""

import copy

import pytest

from tools.foft_render_contract_audit import body_work_chain


def memory(base, access, update=0, displacement=0, indexed=False, width=4):
    return {
        "memory": True,
        "base_register": base,
        "access": access,
        "ea_update": update,
        "displacement": displacement,
        "displacement_known": True,
        "indexed": indexed,
        "width_bytes": width,
        "index_register": "D0" if indexed else None,
        "index_width_bytes": 2,
        "index_scale": 1,
    }


def register():
    return {"memory": False, "direct_register": "D1", "width_bytes": 4}


def protocol():
    rows = []

    def add(at, size, operands):
        rows.append(
            {
                "source_offset": at - 0x800,
                "size": size,
                "mnemonic": "move",
                "provenance": "accepted_instruction",
                "operand_facts": operands,
            }
        )

    for i in range(9):
        at = 0xF4F0 + 6 * i
        add(at, 2, [memory("A0", "memory_read"), register()])
        add(at + 2, 2, [memory("A1", "memory_read"), memory("A0", "memory_write", 1)])
        add(at + 4, 2, [register(), memory("A1", "memory_write", 1)])
    at = 0xF52C
    for offset, width in [
        (6, 2),
        (8, 2),
        (10, 2),
        (12, 4),
        (16, 4),
        (20, 4),
        (24, 4),
        (28, 4),
    ]:
        add(at, 8, [memory("A0", "memory_read", displacement=offset, width=width), {}])
        at += 8
    for i in range(8):
        add(
            0xF582 + 4 * i,
            4,
            [
                memory("A0", "memory_read", displacement=32, indexed=True),
                memory("A0", "memory_write", 1),
            ],
        )
    return rows


def test_body_exchange_removal_and_immediate_draw_contract():
    receipt = body_work_chain(protocol())
    assert receipt["exchange_bytes"] == 36
    assert receipt["row_stride_bytes"] == 32
    assert receipt["draw_input_extent"] == [6, 32]
    assert not receipt["intent_or_global_alias_closure"]


@pytest.mark.parametrize(
    "change",
    [
        "gap",
        "unaccepted",
        "width",
        "reverse",
        "index",
        "displacement",
        "draw",
        "operation",
    ],
)
def test_body_contract_rejects_different_or_incomplete_native_facts(change):
    rows = copy.deepcopy(protocol())
    if change == "gap":
        rows.pop(0)
    if change == "unaccepted":
        rows[0]["provenance"] = "candidate"
    if change == "width":
        rows[0]["operand_facts"][0]["width_bytes"] = 2
    if change == "reverse":
        rows[1]["operand_facts"][1]["ea_update"] = -1
    if change == "index":
        rows[-1]["operand_facts"][0]["index_register"] = "D1"
    if change == "displacement":
        rows[-1]["operand_facts"][0]["displacement"] = 36
    if change == "draw":
        rows[27]["operand_facts"][0]["displacement"] = 0
    if change == "operation":
        rows[0]["mnemonic"] = "add"
    with pytest.raises(ValueError, match="differs|contiguous"):
        body_work_chain(rows)

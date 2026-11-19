"""Direct encoded glyph references remain distinct from dynamic closure."""

import pytest

from tools.foft_render_contract_audit import glyph_stream_inventory


def fact(at, mnemonic, address, access="address", width=4):
    return {
        "source_offset": at - 0x800,
        "provenance": "accepted_instruction",
        "mnemonic": mnemonic,
        "operand_facts": [
            {"absolute_address": address, "access": access, "width_bytes": width}
        ],
    }


def test_glyph_inventory_retains_calls_tails_and_separate_sign_writes():
    rows = [
        fact(0x1000, "jsr", 0x1B0E2),
        fact(0x1006, "jmp", 0x1B0E2),
        fact(0x1010, "jsr", 0x1B24C),
        fact(0x1016, "lea", 0x1B0E2),
        fact(0x1020, "move", 0x1B2D8, "memory_write", 2),
    ]
    r = glyph_stream_inventory(rows)
    assert [i["mnemonic"] for i in r["five_row_draw_transfers"]] == ["jsr", "jmp"]
    assert len(r["numeric_preparation_calls"]) == 1
    assert r["encoded_sign_cell_uses"] == [
        {"runtime": 0x1020, "access": "memory_write", "width": 2}
    ]
    assert not r["indirect_alias_or_input_range_closure"]


def test_glyph_inventory_does_not_use_symbol_text_as_an_address():
    r = fact(0x1000, "jsr", None)
    r["text"] = "jsr DrawFiveRowGlyphRun.l"
    assert not glyph_stream_inventory([r])["five_row_draw_transfers"]


def test_glyph_inventory_rejects_unaccepted_facts():
    r = fact(0x1000, "jsr", 0x1B0E2)
    r["provenance"] = "candidate"
    with pytest.raises(ValueError, match="accepted"):
        glyph_stream_inventory([r])

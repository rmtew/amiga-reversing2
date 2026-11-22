"""Small MC68000 nominal timing model; physical trace timing stays separate.

See Motorola MC68000 User's Manual, chapter 8. Decode/export is an
independent precondition. Encoding fields here select timing variants;
an unmodelled form is deliberately not assigned a default cost.
"""

import json
from pathlib import Path


TIMING_KB = json.loads(Path(__file__).with_name("timing_rules.json").read_text())
RULES = TIMING_KB["rules"]


def exact(clocks, reads, writes=0, rule=None):
    return dict(kind="exact", min_cpu_clocks=clocks, max_cpu_clocks=clocks,
                bus_reads=reads, bus_writes=writes, rule=rule)


def varying(low, high, rule, reads=None, writes=None, *, kind="range"):
    return dict(kind=kind, min_cpu_clocks=low, max_cpu_clocks=high,
                bus_reads=reads, bus_writes=writes, rule=rule)


def m68k_timing(mnemonic, raw):
    """Return nominal clocks and bus totals for supported decoded encodings.

    Bus totals include instruction fetches. Exception service and DMA
    wait are not included; divide maxima describe non-trapping divides.
    """
    name = mnemonic.lower().split(".")[0]
    op = int.from_bytes(raw[:2], "big")
    ext = int.from_bytes(raw[2:4], "big")
    ea = op & 63
    data_reg = ea < 8
    immediate = ea == 60
    if name in ("muls", "mulu", "divs", "divu") and (
        (data_reg and len(raw) == 2) or (immediate and len(raw) == 4)
    ):
        table = RULES["divide_max" if name.startswith("div") else "multiply"]
        cycles, reads = table["immediate_ea"] if immediate else (0, 0)
        reads += table["source_register_reads"]
        if name.startswith("div"):
            return varying(None, table[name] + cycles,
                           "operand-dependent; non-trapping CPU maximum",
                           reads, 0, kind="upper_bound")
        base = table["base"]
        bits = table["source_word_bits"]
        per_bit = table["per_bit"]
        if data_reg:
            return varying(base, base + bits * per_bit, "value of source word", reads, 0)
        ones = ext if name == "mulu" else (ext ^ (ext << 1)) & ((1 << bits) - 1)
        return exact(base + cycles + per_bit * ones.bit_count(), reads,
                     rule="immediate source word")
    if name in ("asl", "asr", "lsl", "lsr", "rol", "ror", "roxl", "roxr") and (
        len(raw) == 2 and op >> 12 == 14 and ((op >> 6) & 3) != 3
    ):
        table = RULES["register_shift"]
        base = table["long" if ((op >> 6) & 3) == 2 else "byte_word"]
        step, reads = table["per_count"], table["bus_reads"]
        if op & 0x20:
            return varying(base, base + step * (table["register_modulus"] - 1),
                           "register count modulo 64", reads, 0)
        count = ((op >> 9) & 7) or table["zero_immediate_means"]
        return exact(base + step * count, reads, rule="immediate shift count")
    if op >> 12 == 6 and len(raw) in (2, 4):
        condition = (op >> 8) & 15
        table = RULES["branch"]
        kind = "short" if len(raw) == 2 else "word"
        taken, reads, writes = table[kind + "_taken"]
        if condition == 0 and name == "bra":
            return exact(taken, reads, writes)
        if condition == 1 and name == "bsr":
            return exact(*table["bsr"])
        if condition >= 2 and name.startswith("b"):
            other, other_reads, _ = table[kind + "_not_taken"]
            return varying(min(taken, other), max(taken, other),
                           f"taken: {taken}; not taken: {other}",
                           reads if reads == other_reads else None, writes)
    if name.startswith("db") and len(raw) == 4 and op & 0xF0F8 == 0x50C8:
        table = RULES["branch"]
        return varying(table["db_taken"][0], table["db_expired"][0],
                       "depends on condition and counter expiry", None, 0)
    if name in ("addq", "subq") and len(raw) == 2 and op >> 12 == 5:
        size = (op >> 6) & 3
        if size < 3 and data_reg:
            return exact(*RULES["register_quick"]["long" if size == 2 else "byte_word"])
    if name in ("add", "sub") and len(raw) == 2 and data_reg:
        mode = (op >> 6) & 7
        if mode in (0, 1, 2):
            return exact(*RULES["register_add_sub"]["long" if mode == 2 else "byte_word"])
    if name in ("cmpi", "addi", "subi") and data_reg:
        size = (op >> 6) & 3
        if size < 2 and len(raw) == 4:
            return exact(*RULES["immediate_data"]["byte_word"])
        if size == 2 and len(raw) == 6:
            return exact(*RULES["immediate_data"]["long_compare" if name == "cmpi" else "long_add_sub"])
    if name in ("move", "movea") and op >> 12 in (1, 2, 3) and ((op >> 6) & 7) in (0, 1):
        if len(raw) == 2 and ea < 16:
            return exact(*RULES["move_to_register"]["from_register"])
        if immediate and len(raw) == (6 if op >> 12 == 2 else 4):
            return exact(*RULES["move_to_register"]["immediate_long" if len(raw) == 6 else "immediate_byte_word"])
    if name in ("tst", "ext", "swap", "moveq", "nop") and len(raw) == 2:
        if name != "tst" or data_reg:
            return exact(*RULES["single_register"]["clocks_reads_writes"])
    if name == "rts" and len(raw) == 2 and op == 0x4E75:
        return exact(*RULES["rts"]["clocks_reads_writes"])
    return varying(None, None, "unsupported decoded form", kind="unknown")

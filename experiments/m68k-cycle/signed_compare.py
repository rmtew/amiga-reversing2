"""Recognise a deliberately small, auditable signed-compare narrowing."""
from liveness import prove_dead_after_branch

def _dreg(operand):
    if operand["kind"] == "dn":
        return operand["register"]
    if operand["kind"] == "ea" and operand["ea_mode"] == 0:
        return operand["ea_reg"]
    return None


def _direct_control(row):
    raw = bytes.fromhex(row["bytes"])
    op = int.from_bytes(raw[:2], "big")
    return (op >> 12 == 6 or op & 0xf0f8 == 0x50c8)


def _branch_target(row):
    raw = bytes.fromhex(row["bytes"])
    if not _direct_control(row) or len(raw) not in (2, 4):
        return None
    displacement = (int.from_bytes(raw[1:2], "big", signed=True) if len(raw) == 2 else
                    int.from_bytes(raw[2:4], "big", signed=True))
    if not row["operands"]:
        return None
    label = row["operands"][-1]
    if label["kind"] != "label" or label["value"] & 0xffffffff != displacement & 0xffffffff:
        return None
    return row["section"], row["offset"] + 2 + displacement


def _fallthrough(row):
    return row["section"], row["offset"] + row["byte_count"]


def _previous(rows, key):
    # All supported predecessor forms below are one word.
    return rows.get((key[0], key[1] - 2))


def _signed(x, bits):
    high = 1 << (bits - 1)
    return (x ^ high) - high


def _audited_compare_flags(dst, src, bits):
    mask = (1 << bits) - 1
    sign = 1 << (bits - 1)
    result = (dst - src) & mask
    return (bool(result & sign), bool((dst ^ src) & (dst ^ result) & sign),
            result == 0, src > dst)


def infer_narrow_compare(rows, key, entries=(), *, routine=None, assume_normal_flow=False):
    row = rows[key]
    raw = bytes.fromhex(row["bytes"])
    fail = lambda reason: (dict(status="unverified", reason=reason), None)
    if len(raw) != 6 or int.from_bytes(raw[:2], "big") & 0xfff8 != 0x0c80:
        return fail("only the long immediate-to-data-register form is supported")
    register = raw[1] & 7
    literal = int.from_bytes(raw[2:], "big", signed=True)
    if not -32768 <= literal <= 32767:
        return fail("immediate is not a sign-extended word")
    prefix = _previous(rows, key)
    gap = None
    if prefix and prefix["mnemonic"] == "moveq" and _dreg(prefix["operands"][-1]) != register:
        gap = prefix
        prefix = _previous(rows, (prefix["section"], prefix["offset"]))
    if not prefix or prefix["bytes"] != f"{0x48c0 + register:04x}" or prefix["mnemonic"] != "ext":
        return fail("no supported EXT.L predecessor on the compared register")
    entry = (prefix["section"], prefix["offset"])
    automatic = entry not in entries
    if automatic and not routine:
        return fail("the sign-extension prefix needs an admitted single entry")
    dependent = {key}
    if gap:
        dependent.add((gap["section"], gap["offset"]))
    if dependent.intersection(entries):
        return fail("an admitted entry bypasses the sign extension")
    for other in rows.values():
        if automatic and other["mnemonic"] in ("jmp", "jsr", "rte", "rtr", "trap", "trapv"):
            return fail("routine has unresolved control transfer")
        if _direct_control(other):
            target = _branch_target(other)
            if not target:
                return fail("routine has inconsistent direct target information")
            if target in dependent:
                return fail("another decoded branch enters after the sign extension")

    branch_key = _fallthrough(row)
    branch = rows.get(branch_key)
    signed_branches = {"bge": 12, "blt": 13, "bgt": 14, "ble": 15}
    if not branch or branch["mnemonic"] not in signed_branches:
        return fail("the compared N/V flags must first feed a signed branch")
    condition = signed_branches[branch["mnemonic"]]
    if int(branch["bytes"][:2], 16) != 0x60 + condition:
        return fail("conditional decode and encoding disagree")
    target = _branch_target(branch)
    if target is None:
        return fail("unknown conditional target")

    after = prove_dead_after_branch(rows, branch_key, pending=("N", "V"),
                                   assume_normal_flow=assume_normal_flow)
    if after["status"] != "verified":
        return dict(status="unverified", reason=after["reason"], evidence=after["evidence"]), None

    src_word = literal & 0xffff
    for dst_word in range(65536):
        dst_long = _signed(dst_word, 16) & 0xffffffff
        wn, wv, wz, wc = _audited_compare_flags(dst_word, src_word, 16)
        ln, lv, lz, lc = _audited_compare_flags(dst_long, literal & 0xffffffff, 32)
        if (wn ^ wv, wz, wc) != (ln ^ lv, lz, lc):
            raise AssertionError("signed comparison differs")
    key_offset = key[1]
    return dict(
        status="verified",
        baseline_assembly=[f"cmpi.l #{literal},d{register}"],
        candidate_assembly=[f"cmpi.w #{literal},d{register}"],
        baseline_cost={"cpu_clocks": 14, "bytes": 6},
        candidate_cost={"cpu_clocks": 8, "bytes": 4},
        evidence=dict(prefix_entry=entry, named_routine_entry=routine if automatic else None,
                      checked_incoming_edges=True, branch_offset=branch_key[1], compare_offset=key_offset,
                      after_branch=after["evidence"], normal_flow_only=assume_normal_flow),
        proof=dict(method="exhaustive 16-bit input; signed condition plus flag kills",
                   input_values=65536, equal=["N xor V", "Z", "C", "X", "all GPRs"],
                   not_equated_individually=["N", "V"]),
    ), f"{0x0c40 + register:04x}{literal & 0xffff:04x}"

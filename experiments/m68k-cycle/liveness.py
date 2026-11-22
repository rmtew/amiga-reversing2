"""Narrow local MC68000 normal-flow proof for CMP.I.W #-1,D2.

Only trusted decoder rows are input; no instruction or data discovery occurs.
A positive result applies only to the stated nonexceptional direct CFG.
"""
from collections.abc import Mapping


_Z = frozenset("Z")
_NZVC = frozenset("NZVC")
_ALL_CCR = frozenset("XNZVC")
_BRANCH = (
    ("bra", ""), ("bsr", ""), ("bhi", "CZ"), ("bls", "CZ"),
    ("bcc", "C"), ("bcs", "C"), ("bne", "Z"), ("beq", "Z"),
    ("bvc", "V"), ("bvs", "V"), ("bpl", "N"), ("bmi", "N"),
    ("bge", "NV"), ("blt", "NV"), ("bgt", "NZV"), ("ble", "NZV"),
)
_WIDTH = {"b": 1, "w": 3, "l": 15}
_SCOPE = "local direct MC68000 control flow; nonexceptional execution only"


class _Unsupported(Exception):
    pass


def _need(ok, message):
    if not ok:
        raise _Unsupported(message)


def _signed(value, width):
    sign = 1 << (width - 1)
    return (value ^ sign) - sign


def _site(key):
    return {"section": key[0], "offset": key[1]}


def _bytes(row, key):
    _need(isinstance(row, Mapping), "missing decoded instruction")
    _need((row.get("section"), row.get("offset")) == key, "inconsistent row address")
    _need(isinstance(row.get("bytes"), str), "missing instruction bytes")
    try:
        raw = bytes.fromhex(row["bytes"])
    except ValueError as exc:
        raise _Unsupported("invalid instruction encoding") from exc
    _need(len(raw) >= 2 and len(raw) % 2 == 0 and len(raw) == row.get("byte_count"),
          "invalid or truncated instruction encoding")
    return raw


def _ops(row, quantity):
    operands = row.get("operands")
    _need(isinstance(operands, list) and len(operands) == quantity
          and all(isinstance(o, Mapping) for o in operands), "unsupported typed operand list")
    return operands


def _reg(operand):
    """Data-register number, or None for another known operand kind."""
    kind = operand.get("kind")
    if kind == "dn":
        n = operand.get("register")
    elif kind == "ea" and operand.get("ea_mode") == 0:
        n = operand.get("ea_reg")
    else:
        return None
    _need(type(n) is int and 0 <= n <= 7, "invalid data register")
    return n


def _ea_index(operand, tracked):
    """D2 byte mask read by computing a classic 68000 effective address."""
    m, r = operand.get("ea_mode"), operand.get("ea_reg")
    _need(type(m) is int and type(r) is int and 0 <= m <= 7 and 0 <= r <= 7,
          "invalid effective address")
    _need(m != 7 or r <= 4, "unsupported effective address extension")
    if m != 6 and (m, r) != (7, 3):
        return 0
    i = operand.get("index_register")
    isa, long = operand.get("index_is_address"), operand.get("index_long")
    _need(type(i) is int and 0 <= i <= 7 and isa in (0, 1) and long in (0, 1),
          "unknown index register")
    return (15 if long else 3) if i == tracked and not isa else 0


def _read(operand, width, tracked):
    kind = operand.get("kind")
    reg = _reg(operand)
    if reg is not None:
        return width if reg == tracked else 0
    if kind in ("imm", "an"):
        return 0
    _need(kind == "ea", "unsupported data operand kind")
    return _ea_index(operand, tracked)


def _dest(operand, width, tracked):
    reg = _reg(operand)
    if reg is not None:
        return 0, width if reg == tracked else 0
    _need(operand.get("kind") in ("ea", "an"), "unsupported destination")
    return (_ea_index(operand, tracked) if operand.get("kind") == "ea" else 0), 0


def _direct_branch(row, raw, key):
    _need(raw[0] >> 4 == 6, "not a simple direct branch")
    cond = raw[0] & 15
    name, flags = _BRANCH[cond]
    _need(name != "bsr", "subroutine not proven")
    mn = row.get("mnemonic")
    aliases = {"bcc": "bhs", "bcs": "blo"}
    _need(mn == name or mn == aliases.get(name), "branch encoding disagrees with mnemonic")
    op, = _ops(row, 1)
    _need(op.get("kind") == "label" and type(op.get("value")) is int, "branch target not typed")
    if raw[1] == 0:
        _need(len(raw) == 4 and row.get("size") == "w", "invalid word branch")
        delta = int.from_bytes(raw[2:], "big", signed=True)
    else:
        _need(len(raw) == 2 and row.get("size") in ("b", "s"), "invalid byte branch")
        delta = _signed(raw[1], 8)
    val = op["value"]
    _need(val == delta or val == (delta & 0xffffffff),
          "encoded and typed branch displacements disagree")
    target = key[0], key[1] + 2 + delta  # architectural base also for .W
    _need(target[1] >= 0 and target[1] % 2 == 0, "branch target is not an even offset")
    return name, frozenset(flags), target


def _effects(row, tracked=2):
    """Tracked register read/write byte masks, then read and unconditionally written CCR."""
    mn = row.get("mnemonic")
    sz = row.get("size")
    none = frozenset()
    width = _WIDTH.get(sz)
    _need(mn in ("nop", "moveq", "move", "movea", "tst", "cmp", "cmpi", "add", "addi",
                 "addq", "sub", "subi", "subq", "adda", "suba", "lsl", "lsr", "asl", "asr",
                 "ext", "swap", "divs", "divu", "addx", "subx", "roxl", "roxr"),
          f"unsupported instruction {mn!r} before all differences were killed")
    if mn == "nop":
        _ops(row, 0)
        return 0, 0, none, none
    if mn in ("ext", "swap"):
        a, = _ops(row, 1)
        n = _reg(a)
        _need(n is not None, "register required")
        if mn == "swap":
            reads, writes = 15, 15
        else:
            _need(sz in ("w", "l"), "invalid EXT width")
            reads, writes = (3, 15) if sz == "l" else (1, 3)
        return (reads, writes, none, _NZVC) if n == tracked else (0, 0, none, _NZVC)
    if mn == "tst":
        a, = _ops(row, 1)
        _need(width is not None, "invalid test width")
        return _read(a, width, tracked), 0, none, _NZVC
    a, b = _ops(row, 2)
    _need(width is not None, "unknown data width")
    if mn == "moveq":
        _need(a.get("kind") == "imm" and _reg(b) is not None and sz == "l", "invalid MOVEQ")
    reads, writes = _dest(b, width, tracked)
    reads |= _read(a, width, tracked)
    if mn in ("moveq", "move", "movea"):
        return reads, writes, none, none if mn == "movea" else _NZVC
    if mn in ("cmp", "cmpi"):
        return reads | _read(b, width, tracked), 0, none, _NZVC
    if mn in ("divs", "divu"):
        # No flag kills claimed: overflow does not define every bit.
        # Divide-by-zero exceptions are outside this normal-flow proof.
        _need(sz == "w" and _reg(b) is not None, "invalid word division")
        return reads | _read(b, 15, tracked), 0, none, none
    if mn in ("adda", "suba") or (mn in ("addq", "subq") and (
        b.get("kind") == "an" or (b.get("kind") == "ea" and b.get("ea_mode") == 1)
    )):
        return reads, writes, none, none
    if mn in ("lsl", "lsr", "asl", "asr", "roxl", "roxr"):
        _need(_reg(b) is not None, "unsupported nonregister shift")
        fixed = a.get("kind") == "imm" and a.get("value") in range(1, 9)
        uses = frozenset("X") if mn in ("roxl", "roxr") else none
        # Register count may be zero; X could survive.
        return _read(a, 15, tracked) | _read(b, width, tracked), writes, uses, _ALL_CCR if fixed else _NZVC
    uses = frozenset("XZ") if mn in ("addx", "subx") else none
    return reads | _read(b, width, tracked), writes, uses, _ALL_CCR


def _may_fault(row):
    if row.get("mnemonic") in ("divs", "divu"):
        return "division exception is unresolved"
    for op in row.get("operands", ()):
        if isinstance(op, Mapping) and op.get("kind") == "ea":
            mode, reg = op.get("ea_mode"), op.get("ea_reg")
            if mode not in (0, 1) and (mode, reg) != (7, 4):
                return "memory exception is unresolved"
    return None


def _validate_map(rows, key):
    _need(isinstance(rows, Mapping), "need decoded row mapping")
    _need(isinstance(key, tuple) and len(key) == 2 and all(type(i) is int and i >= 0 for i in key)
          and key[1] % 2 == 0, "invalid starting section/offset")
    end = -1
    for k in sorted(k for k in rows if isinstance(k, tuple) and len(k) == 2 and k[0] == key[0]):
        _need(type(k[1]) is int and k[1] >= end and k[1] % 2 == 0, "overlapping or invalid row boundaries")
        end = k[1] + len(_bytes(rows[k], k))


def prove_dead_after_branch(rows, branch_key, *, pending, d2_low_bytes=(), assume_normal_flow=False):
    """M2 API: the caller separately proves the common branch outcome."""
    return _live_proof(rows, branch_key, pending, d2_low_bytes, 2, True, assume_normal_flow)


def prove_dead_after_instruction(rows, key, *, pending, register, low_bytes=(),
                                 assume_normal_flow=False):
    """Prove the pending effects from the next contiguous instruction onward.

    The caller must already prove both instructions have the same successor.
    """
    return _live_proof(rows, key, pending, low_bytes, register, False, assume_normal_flow)


def _live_proof(rows, branch_key, pending, low_bytes, tracked, branch_mode, assume_normal_flow):
    """Prove no pending differences survive either arm of a shared direct predicate.

    The caller must separately prove that the initial branch chooses the same
    outcome for both implementations. Only subsequent flag reads are checked.
    pending is an iterable of CCR names, d2_low_bytes uses indices 0 (LSB), 1.
    """
    scope = "local direct MC68000 synchronous control flow"
    if assume_normal_flow:
        scope += "; exceptions excluded by caller opt-in"
    evidence = {"scope": scope, "assume_normal_flow": assume_normal_flow, "paths": []}
    where = branch_key
    trail = ()
    try:
        _validate_map(rows, branch_key)
        _need(type(assume_normal_flow) is bool, "normal-flow option must be explicit boolean")
        flags = frozenset(pending)
        indices = frozenset(low_bytes)
        _need(type(tracked) is int and tracked in range(8), "need a tracked data register")
        which = f"D{tracked}"
        _need(flags <= _ALL_CCR and indices <= {0, 1}
              and all(type(i) is int for i in indices) and (flags or indices),
              "need typed pending CCR and low-byte differences")
        mask = sum(1 << i for i in indices)
        evidence["tracked_register"] = which
        evidence[f"initial_d{tracked}_low_bytes"] = sorted(indices)
        evidence["initial_ccr"] = sorted(flags)
        branch = rows.get(branch_key)
        br_raw = _bytes(branch, branch_key)
        fallthrough = branch_key[0], branch_key[1] + len(br_raw)
        if branch_mode:
            name, _, target = _direct_branch(branch, br_raw, branch_key)
            _need(name != "bra", "initial predicate must be conditional")
            evidence["predicate"] = dict(_site(branch_key), mnemonic=name, taken=_site(target),
                                         fallthrough=_site(fallthrough))
            work = [(fallthrough, mask, flags, (), frozenset(), "fallthrough"),
                    (target, mask, flags, (), frozenset(), "taken")]
        else:
            evidence["successor"] = _site(fallthrough)
            work = [(fallthrough, mask, flags, (), frozenset(), "fallthrough")]
        visits = 0
        while work:
            where, mask, flags, trail, seen, arm = work.pop()
            visits += 1
            _need(visits <= 512 and len(trail) <= 96, "local CFG proof budget exhausted")
            _need(where not in seen, "cycle with live differences")
            row = rows.get(where)
            raw = _bytes(row, where)
            fall = where[0], where[1] + len(raw)
            step = dict(_site(where), mnemonic=row["mnemonic"])
            if raw[0] >> 4 == 6:
                name2, used2, to2 = _direct_branch(row, raw, where)
                _need(not (flags & used2), "branch uses a live differing CCR flag")
                successors = (("taken", to2),) if name2 == "bra" else (("taken", to2), ("fallthrough", fall))
                for edge, to in successors:
                    work.append((to, mask, flags, trail + (dict(step, edge=edge),), seen | {where}, arm))
                continue
            rd, wr, flag_rd, flag_wr = _effects(row, tracked)
            _need(not (mask & rd), f"{which}.W is read before its differing bits are killed")
            _need(not (flags & flag_rd), "instruction reads a live differing CCR flag")
            fault = _may_fault(row)
            if fault:
                _need(assume_normal_flow, fault + " while differences remain")
                step["excluded_exception"] = fault
            killed_bytes = mask & wr
            killed_flags = flags & flag_wr
            if killed_bytes:
                step[f"killed_d{tracked}_low_bytes"] = [i for i in range(2) if killed_bytes & (1 << i)]
            if killed_flags:
                step["killed_ccr"] = sorted(killed_flags)
            mask &= ~wr
            flags -= flag_wr
            trail += (step,)
            if not mask and not flags:
                evidence["paths"].append({"initial_arm": arm, "steps": list(trail)})
            else:
                work.append((fall, mask, flags, trail, seen | {where}, arm))
        return {"status": "verified", "evidence": evidence}
    except (_Unsupported, KeyError, TypeError, ValueError) as exc:
        return {"status": "unverified", "reason": str(exc),
                "evidence": dict(evidence, failed_at=list(where) if isinstance(where, tuple) else None,
                                 prefix=list(trail))}


def infer_cmp_contract(rows, key, *, assume_normal_flow=False):
    """Infer the narrow CMP.W #-1,D2 rewrite on both immediate EQ/NE arms."""
    where = key
    try:
        _validate_map(rows, key)
        row = rows.get(key)
        raw = _bytes(row, key)
        _need(raw == bytes.fromhex("0c42ffff") and row.get("mnemonic") == "cmpi"
              and row.get("size") == "w", "not the exact CMP.I.W #-1,D2 encoding")
        a, b = _ops(row, 2)
        _need(a.get("kind") == "imm" and a.get("value") in (-1, 65535, 0xffffffff)
              and _reg(b) == 2, "compare operand mismatch")
        where = key[0], key[1] + len(raw)
        branch = rows.get(where)
        name, used, _ = _direct_branch(branch, _bytes(branch, where), where)
        _need(name in ("beq", "bne") and used == _Z, "immediate successor must be EQ/NE")
        # Conservatively keep N/V among the differences along with C and X.
        result = prove_dead_after_branch(rows, where, pending=_ALL_CCR - _Z,
                                         d2_low_bytes=(0, 1), assume_normal_flow=assume_normal_flow)
        if result["status"] == "verified":
            result["contract"] = {"following_branch": name, "d2_low_word_dead": True, "live_ccr": ["Z"]}
        return result
    except (_Unsupported, KeyError, TypeError, ValueError) as exc:
        return {"status": "unverified", "reason": str(exc),
                "evidence": {"scope": _SCOPE, "assume_normal_flow": assume_normal_flow,
                             "failed_at": list(where) if isinstance(where, tuple) else None}}

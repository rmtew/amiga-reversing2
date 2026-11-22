"""Read-only MC68000 rewrite calibrations; no arbitrary code search."""
from collections.abc import Mapping
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory


_CCR = frozenset("XNZVC")
_MULU40 = ["mulu.w #40,d1"]
_MULU40_LOW = ["move.w d1,d0", "add.w d1,d1", "add.w d1,d1",
               "add.w d0,d1", "lsl.w #3,d1"]


def prove_mulu40(contract=None):
    """Verify the fixed rewrite for an explicit bounded liveness contract.

    d1_domain refers to unsigned D1.W on input. The only permitted unrelated
    clobber is D0.W. This fixture is always register-only on MC68000.
    """
    result = {"status": "unverified", "baseline_assembly": _MULU40.copy()}
    if not isinstance(contract, Mapping):
        return dict(result, reason="explicit input range and liveness required")

    domain = contract.get("d1_domain")
    output = contract.get("result")
    flags = contract.get("live_ccr")
    if (not isinstance(domain, (list, tuple)) or len(domain) != 2
            or any(type(x) is not int for x in domain)
            or not 0 <= domain[0] <= domain[1] <= 200):
        return dict(result, reason="need an inclusive D1.W domain contained in 0..200")
    if output not in ("d1_low_word", "d1_full"):
        return dict(result, reason="need the observed result width")
    if contract.get("d0_low_word_dead") is not True:
        return dict(result, reason="D0.W is changed and must be known dead")
    if (not isinstance(flags, (list, tuple)) or not all(isinstance(x, str) and x in _CCR for x in flags)):
        return dict(result, reason="need explicit live CCR bits")

    full = output == "d1_full"
    result.update(
        candidate_assembly=_MULU40_LOW + (["ext.l d1"] if full else []),
        baseline_cost={"cpu_clocks": 46, "bytes": 4},
        candidate_cost={"cpu_clocks": 32 if full else 28, "bytes": 12 if full else 10},
        contract={"d1_domain": list(domain), "result": output,
                  "d0_low_word_dead": True, "live_ccr": list(flags)},
    )
    if "X" in flags:
        return dict(result, status="rejected",
                    reason="MULU preserves X but the final LSL sets it to zero",
                    counterexample={"d1_word": domain[0], "incoming_x": 1,
                                    "baseline_x": 1, "candidate_x": 0})

    for x in range(domain[0], domain[1] + 1):
        expected = x * 40
        add1 = (x + x) & 0xffff
        add2 = (add1 + add1) & 0xffff
        add3 = (add2 + x) & 0xffff
        shifted = add3 << 3
        word = shifted & 0xffff
        extended = word - 0x10000 if word & 0x8000 else word
        candidate = extended & 0xffffffff if full else word
        if candidate != expected:
            raise AssertionError("multiply values differ", x)
        baseline_ccr = {"N": bool(expected & 0x80000000), "Z": expected == 0,
                        "V": False, "C": False}
        candidate_ccr = {"N": bool(candidate & (0x80000000 if full else 0x8000)),
                         "Z": candidate == 0, "V": False,
                         "C": False if full else bool(shifted & 0x10000)}
        if any(baseline_ccr[bit] != candidate_ccr[bit] for bit in flags):
            raise AssertionError("live CCR differs", x)
    return dict(result, status="verified", proof={
        "method": "exhaustive bounded low word, with width and CCR invariants",
        "input_values": domain[1] - domain[0] + 1,
        "all_incoming_ccr_states": True,
        "detail": "No input high half or old CCR is read by the observed outputs. "
                  "Low-only preserves D1.HI without claiming it matches MULU; "
                  "EXT.L supplies the full result when requested. D0.HI is untouched.",
    })


def prove_cmp_minus_one(contract=None):
    """Check the fixed EQ/NE sentinel rewrite, never inferred from a lone PC."""
    orig = dict(status="unverified", baseline_assembly=["cmpi.w #-1,d2"])
    if not isinstance(contract, Mapping):
        return dict(orig, reason="explicit branch and liveness contract required")
    branch = contract.get("following_branch")
    if branch not in ("beq", "bne"):
        return dict(orig, reason="the immediate successor must be BEQ or BNE")
    dead = contract.get("d2_low_word_dead")
    flags = contract.get("live_ccr")
    if type(dead) is not bool or not isinstance(flags, (list, tuple)) or not flags:
        return dict(orig, reason="need explicit D2.W liveness and live CCR")
    if not all(isinstance(x, str) and x in _CCR for x in flags):
        return dict(orig, reason="unknown CCR bits")
    if not dead:
        return dict(orig, status="rejected", reason="ADDQ changes D2.W")
    if set(flags) != {"Z"}:
        return dict(orig, status="rejected", reason="this narrow rule proves only Z")
    for d2 in range(65536):
        before = d2 == 0xffff
        after = ((d2 + 1) & 0xffff) == 0
        if before != after:
            raise AssertionError("sentinel branch is not equivalent", d2)
    return dict(orig, status="verified", candidate_assembly=["addq.w #1,d2"],
                baseline_cost={"cpu_clocks": 8, "bytes": 4},
                candidate_cost={"cpu_clocks": 4, "bytes": 2},
                contract={"following_branch": branch, "d2_low_word_dead": True, "live_ccr": ["Z"]},
                proof={"method": "exhaustive word inputs plus untouched high word",
                       "input_values": 65536, "observed": ["D2.HI", "Z"],
                       "detail": "All upper halves and prior flags are arbitrary. The EQ/NE "
                                 "branch tests the same Z; preserve the branch itself."})


def _assemble(vasm, lines, *, no_opt):
    with TemporaryDirectory(prefix="m68k-rewrite-") as tmp:
        tmp = Path(tmp)
        src = tmp / "fixture.s"
        out = tmp / "fixture.bin"
        src.write_text("".join("        " + line + "\n" for line in lines), encoding="ascii")
        args = [vasm, "-m68000", "-Fbin", "-quiet"]
        if no_opt:
            args.append("-no-opt")
        subprocess.run(args + ["-o", str(out), str(src)], check=True,
                       capture_output=True, timeout=15)
        return out.read_bytes()


def calibrate():
    """Return the supported read-only fixtures as JSON-safe data."""
    common = dict(d1_domain=[0, 200], d0_low_word_dead=True, live_ccr=["N", "Z", "V", "C"])
    return {
        "mulu40_bounded_full": prove_mulu40(dict(common, result="d1_full")),
        "mulu40_bounded_low_word": prove_mulu40(dict(common, result="d1_low_word")),
        "mulu40_x_live": prove_mulu40(dict(common, result="d1_full", live_ccr=["X"])),
        "mulu40_unknown_contract": prove_mulu40(),
        "cmp_minus_one_z_only": prove_cmp_minus_one(
            dict(following_branch="beq", d2_low_word_dead=True, live_ccr=["Z"])),
    }

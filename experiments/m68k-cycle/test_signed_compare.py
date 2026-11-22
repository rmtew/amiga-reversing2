"""Tests for a signed branch's compound predicate and explicit entry scope."""
import unittest

from signed_compare import infer_narrow_compare


def make_rows(target="move"):
    rows = {}
    put = lambda at, **row: rows.update({(0, at): dict(
        section=0, offset=at, byte_count=len(row["bytes"])//2, **row)})
    put(0, bytes="48c2", mnemonic="ext", operands=[dict(kind="dn", register=2)])
    put(2, bytes="7000", mnemonic="moveq", operands=[dict(kind="imm", value=0), dict(kind="dn", register=0)])
    put(4, bytes="0c8200000200", mnemonic="cmpi", operands=[])
    put(10, bytes="6c02", mnemonic="bge", size="b", operands=[dict(kind="label", value=2)])
    put(12, bytes="7001", mnemonic="moveq", size="l", operands=[dict(kind="imm", value=1), dict(kind="dn", register=0)])
    put(14, bytes="3210", mnemonic=target, size="w",
        operands=[dict(kind="ea", ea_mode=2, ea_reg=0), dict(kind="dn", register=1)])
    return rows


class NarrowCompareTests(unittest.TestCase):
    def test_bge_proof_uses_compound_flags(self):
        out, encoding = infer_narrow_compare(make_rows(), (0,4), [(0,0)], assume_normal_flow=True)
        self.assertEqual((out["status"], encoding), ("verified", "0c420200"))
        self.assertEqual(out["proof"]["not_equated_individually"], ["N", "V"])

    def test_explicit_entry_and_nonexceptional_scope(self):
        for entries, normal, match in [((), True, "entry"),
                                       ([(0,0),(0,4)], True, "entry"),
                                       ([(0,0)], False, "memory exception")]:
            out, _ = infer_narrow_compare(make_rows(), (0,4), entries, assume_normal_flow=normal)
            self.assertEqual(out["status"], "unverified")
            self.assertIn(match, out["reason"])

    def test_unknown_or_flag_read_after_branch(self):
        out, _ = infer_narrow_compare(make_rows("bvs"), (0,4), [(0,0)], assume_normal_flow=True)
        self.assertEqual(out["status"], "unverified")
        self.assertIn("unsupported instruction", out["reason"])


if __name__ == "__main__":
    unittest.main()

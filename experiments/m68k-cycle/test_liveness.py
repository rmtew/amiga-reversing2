import unittest

from liveness import infer_cmp_contract, prove_dead_after_branch
from rewrite import prove_cmp_minus_one


def row(off, raw, mnemonic, size, *operands):
    return (0, off), dict(section=0, offset=off, bytes=raw, byte_count=len(raw)//2,
                         mnemonic=mnemonic, size=size, operands=list(operands))


def imm(x):
    return dict(kind="imm", value=x)


def dn(x):
    return dict(kind="dn", register=x)


def label(x):
    return dict(kind="label", value=x & 0xffffffff)


def ead(x):
    return dict(kind="ea", ea_mode=0, ea_reg=x)


def fixture(*extra):
    return dict([
        row(0, "0c42ffff", "cmpi", "w", imm(65535), ead(2)),
        row(4, "6704", "beq", "b", label(4)),  # target 10; fallthrough 6
        row(6, "7400", "moveq", "l", imm(0), dn(2)),
        row(8, "5243", "addq", "w", imm(1), ead(3)),
        row(10, "7400", "moveq", "l", imm(0), dn(2)),
        row(12, "5243", "addq", "w", imm(1), ead(3)),
        *extra,
    ])


class LivenessTest(unittest.TestCase):
    def infer(self, table):
        return infer_cmp_contract(table, (0, 0))

    def test_both_arms_and_moveq_preserves_x(self):
        result = self.infer(fixture())
        self.assertEqual(result["status"], "verified")
        self.assertEqual(prove_cmp_minus_one(result["contract"])["status"], "verified")
        paths = result["evidence"]["paths"]
        self.assertEqual({p["initial_arm"] for p in paths}, {"taken", "fallthrough"})
        for p in paths:
            a, b = p["steps"]
            self.assertEqual(a["killed_d2_low_bytes"], [0, 1])
            self.assertEqual(a["killed_ccr"], ["C", "N", "V"])
            self.assertEqual(b["killed_ccr"], ["X"])

    def test_reads_x_even_after_moveq(self):
        r = self.infer(fixture(row(12, "d141", "addx", "w", dn(1), dn(0))))
        self.assertEqual(r["status"], "unverified")
        self.assertIn("CCR", r["reason"])
        self.assertEqual(r["evidence"]["failed_at"], [0, 12])

    def test_reads_pending_branch_flag(self):
        r = self.infer(fixture(row(10, "6502", "bcs", "b", label(2))))
        self.assertEqual(r["status"], "unverified")
        self.assertIn("branch uses", r["reason"])

    def test_live_d2_word_read(self):
        r = self.infer(fixture(row(10, "3202", "move", "w", ead(2), ead(1))))
        self.assertEqual(r["status"], "unverified")
        self.assertIn("D2.W", r["reason"])

    def test_byte_stores_only_kill_low_byte(self):
        r = self.infer(fixture(
            row(10, "1401", "move", "b", ead(1), ead(2)),
            row(12, "4a02", "tst", "b", ead(2)),
            row(14, "4a42", "tst", "w", ead(2)),
        ))
        self.assertEqual(r["status"], "unverified")
        self.assertEqual(r["evidence"]["failed_at"], [0, 14])
        self.assertEqual(r["evidence"]["prefix"][0]["killed_d2_low_bytes"], [0])

    def test_unknown_effect_and_missing_target(self):
        r = self.infer(fixture(row(10, "4ed0", "jmp", None, dict(kind="ea", ea_mode=2, ea_reg=0))))
        self.assertEqual(r["status"], "unverified")
        self.assertIn("unsupported instruction", r["reason"])
        rows = fixture()
        del rows[0, 10]
        r = self.infer(rows)
        self.assertIn("missing decoded", r["reason"])
        self.assertEqual(r["evidence"]["failed_at"], [0, 10])

    def test_noncontiguous_and_branch_to_middle(self):
        rows = fixture()
        del rows[0, 8]
        self.assertIn("missing decoded", self.infer(rows)["reason"])
        rows = fixture(row(2, "4e71", "nop", None))
        self.assertIn("overlapping", self.infer(rows)["reason"])

    def test_cycle_still_pending(self):
        r = self.infer(fixture(row(10, "60fe", "bra", "b", label(-2))))
        self.assertEqual(r["status"], "unverified")
        self.assertIn("cycle", r["reason"])

    def test_word_branch_pc_plus_two_and_direct_predicate(self):
        rows = dict([
            row(0, "6c000006", "bge", "w", label(6)),  # target 8, not 10
            row(4, "7000", "moveq", "l", imm(0), dn(0)),
            row(8, "7000", "moveq", "l", imm(0), dn(0)),
        ])
        r = prove_dead_after_branch(rows, (0, 0), pending=("N", "V"))
        self.assertEqual(r["status"], "verified")
        self.assertEqual(r["evidence"]["predicate"]["taken"]["offset"], 8)
        self.assertEqual(r["evidence"]["predicate"]["fallthrough"]["offset"], 4)

    def test_pending_divisor_exception_requires_opt_in(self):
        rows = fixture(
            row(10, "81c1", "divs", "w", ead(1), dn(0)),
            row(12, "7400", "moveq", "l", imm(0), dn(2)),
            row(14, "5243", "addq", "w", imm(1), ead(3)),
        )
        self.assertIn("division exception", self.infer(rows)["reason"])
        r = infer_cmp_contract(rows, (0, 0), assume_normal_flow=True)
        self.assertEqual(r["status"], "verified")
        self.assertTrue(r["evidence"]["assume_normal_flow"])
        self.assertIn("excluded_exception", r["evidence"]["paths"][0]["steps"][0])

    def test_index_is_register_read_and_memory_may_fault(self):
        addr = dict(kind="ea", ea_mode=6, ea_reg=0, index_is_address=0,
                    index_register=2, index_long=0)
        rows = fixture(row(10, "30302000", "move", "w", addr, ead(0)))
        del rows[0, 12]
        r = self.infer(rows)
        self.assertIn("D2.W", r["reason"])
        addr["index_register"] = 1
        rows.update([row(10, "30301000", "move", "w", addr, ead(0))])
        r = self.infer(rows)
        self.assertIn("memory exception", r["reason"])

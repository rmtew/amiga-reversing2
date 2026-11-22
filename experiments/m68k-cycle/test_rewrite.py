import json
import unittest

from rewrite import calibrate, prove_cmp_minus_one, prove_mulu40


class RewriteTest(unittest.TestCase):
    def test_multiply_both_widths(self):
        contract = dict(d1_domain=[0, 200], d0_low_word_dead=True, live_ccr=list("NZVC"))
        low = prove_mulu40(dict(contract, result="d1_low_word"))
        full = prove_mulu40(dict(contract, result="d1_full"))
        for r in (low, full):
            self.assertEqual(r["status"], "verified")
            self.assertEqual(r["proof"]["input_values"], 201)
            self.assertEqual(r["baseline_cost"], {"cpu_clocks": 46, "bytes": 4})
        self.assertEqual(low["candidate_cost"], {"cpu_clocks": 28, "bytes": 10})
        self.assertEqual(full["candidate_cost"], {"cpu_clocks": 32, "bytes": 12})
        self.assertEqual(full["candidate_assembly"][-1], "ext.l d1")

    def test_multiply_requires_explicit_contract(self):
        good = dict(d1_domain=[0, 200], result="d1_full", d0_low_word_dead=True, live_ccr=[])
        cases = [None, {}, dict(good, d1_domain=[0, 201]), dict(good, d1_domain=[False, 1]),
                 dict(good, d1_domain=[100, 50]), dict(good, result="unknown"),
                 dict(good, d0_low_word_dead=False), dict(good, live_ccr=None),
                 dict(good, live_ccr=[{}]), dict(good, live_ccr=["Q"])]
        for case in cases:
            self.assertEqual(prove_mulu40(case)["status"], "unverified")
            self.assertNotIn("candidate_assembly", prove_mulu40(case))
        self.assertEqual(prove_mulu40(dict(good, d1_domain=[200, 200]))["status"], "verified")

    def test_multiply_x_counterexample(self):
        r = prove_mulu40(dict(d1_domain=[0, 200], result="d1_full",
                              d0_low_word_dead=True, live_ccr=["X"]))
        self.assertEqual(r["status"], "rejected")
        self.assertEqual((r["counterexample"]["baseline_x"], r["counterexample"]["candidate_x"]), (1, 0))

    def test_sentinel_branch(self):
        for branch in ("beq", "bne"):
            case = dict(following_branch=branch, d2_low_word_dead=True, live_ccr=["Z"])
            r = prove_cmp_minus_one(case)
            self.assertEqual(r["status"], "verified")
            self.assertEqual(r["proof"]["input_values"], 65536)
            self.assertEqual(r["candidate_cost"], {"cpu_clocks": 4, "bytes": 2})
            self.assertEqual(prove_cmp_minus_one(dict(case, d2_low_word_dead=False))["status"], "rejected")
            self.assertEqual(prove_cmp_minus_one(dict(case, live_ccr=["Z", "C"]))["status"], "rejected")
        self.assertEqual(prove_cmp_minus_one()["status"], "unverified")
        self.assertEqual(prove_cmp_minus_one(dict(case, following_branch="bpl"))["status"], "unverified")

    def test_calibration_json(self):
        self.assertEqual(calibrate()["cmp_minus_one_z_only"]["status"], "verified")
        json.dumps(calibrate())

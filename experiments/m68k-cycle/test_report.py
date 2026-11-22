"""Timing algebra, trace identity, and fail-closed report joins."""
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest

from report import code_range, compare, explain, join_hunk_profile
from timing import m68k_timing


class TimingTests(unittest.TestCase):
    def test_actual_assembler_forms(self):
        cases = [
            ("mulu", "c2fc0028", 46, 46), ("asl", "e383", 10, 10),
            ("add", "d683", 8, 8), ("swap", "4843", 4, 4),
            ("cmpi", "0c42ffff", 8, 8), ("addq", "5242", 4, 4),
            ("lsl", "e749", 12, 12), ("move", "3001", 4, 4),
            ("muls", "c1fc5555", 74, 74), ("muls", "c1c0", 38, 70),
            ("bne", "6602", 8, 10), ("bne", "66000004", 10, 12),
            ("dbra", "51c8fffc", 10, 14), ("divs", "81c1", None, 158),
            ("divu", "80fc0030", None, 144), ("movem", "48e78001", None, None),
        ]
        for name, raw, low, high in cases:
            with self.subTest(raw=raw):
                item = m68k_timing(name, bytes.fromhex(raw))
                self.assertEqual((item["min_cpu_clocks"], item["max_cpu_clocks"]), (low, high))
        self.assertIsNone(m68k_timing("bne", bytes.fromhex("6602"))["bus_reads"])


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.profile = {
            "binary_sha256": "0" * 64, "config_sha256": "1" * 64,
            "machine_args": ["--cpu", "68000"], "windows": [{"frame": 24}],
            "sites": [{"pc": "10", "hits": 4, "core": 16, "wait": 2, "total": 18,
                       "asm": "source spelling isn't decoded"},
                      {"pc": "20", "hits": 1, "core": 4, "wait": 0, "total": 4}],
        }

    def test_trace_gate_and_partial_range(self):
        rows = {(0, 16): {"mnemonic": "add"}}
        joined = join_hunk_profile(rows, self.profile, "0" * 64)
        self.assertEqual((joined["joined_sites"], joined["profile_sites"]), (1, 2))
        self.assertEqual(rows[0, 16]["mnemonic"], "add")
        self.assertEqual(rows[0, 16]["measured"]["elapsed_cck"], 18)
        with self.assertRaisesRegex(ValueError, "hash"):
            join_hunk_profile(rows, self.profile, "2" * 64)
        self.profile["machine_args"][-1] = "68020"
        with self.assertRaisesRegex(ValueError, "68000"):
            join_hunk_profile(rows, self.profile, "0" * 64)

    def test_invalid_trace(self):
        self.profile["sites"][0]["total"] = 1
        with self.assertRaisesRegex(ValueError, "totals"):
            join_hunk_profile({}, self.profile, "0" * 64)

    def test_compare_reports_observation_not_proof(self):
        row = {"baseline_sha": "a" * 64, "candidate_sha": "b" * 64,
               "same_full_pages": 3, "machine": "PAL", "emulator": "Copperline",
               "saved_mean_active_ms": 0.08, "saved_median_active_ms": 0.07,
               "software_flips_per_second": [5, 5], "loaded_bytes": [100, 98]}
        self.assertIsNone(compare(row, frames=3)["semantic_equivalence"])
        with self.assertRaises(ValueError):
            compare(row, frames=4)

    def test_contract_requires_identity_site_and_successor(self):
        report = {"artifact_sha256": "0" * 64, "sites": [
            {"section": 0, "offset": 0, "bytes": "0c42ffff", "mnemonic": "cmpi",
             "byte_count": 4, "site_id": "h:0:0"},
            {"section": 0, "offset": 4, "bytes": "6702", "mnemonic": "beq", "byte_count": 2},
        ]}
        self.assertEqual(explain(report, None)[0]["status"], "unverified")
        with tempfile.TemporaryDirectory() as tmp:
            k = Path(tmp) / "contract.json"
            item = dict(section=0, offset=0, evidence="Audited both branch exits",
                        following_branch="beq", d2_low_word_dead=True, live_ccr=["Z"])
            content = dict(artifact_sha256="0" * 64, sites=[item])
            k.write_text(json.dumps(content))
            self.assertEqual(explain(report, k)[0]["status"], "verified")
            item["following_branch"] = "bne"
            k.write_text(json.dumps(content))
            with self.assertRaisesRegex(ValueError, "successor"):
                explain(report, k)
            content["artifact_sha256"] = "9" * 64
            k.write_text(json.dumps(content))
            with self.assertRaisesRegex(ValueError, "artifact"):
                explain(report, k)

    def test_range_syntax(self):
        self.assertEqual(code_range("0:0x10:4:edge"), (0, 16, 4, "edge"))


class NativeReportTests(unittest.TestCase):
    @unittest.skipUnless(os.getenv("M68K_TIMING_DECODER"), "set M68K_TIMING_DECODER for native smoke")
    def test_annotate_synthetic_raw(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "synthetic.bin"
            artifact.write_bytes(bytes.fromhex("4e714e75"))  # NOP, RTS
            result = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("report.py")), "annotate",
                 "--decoder", os.environ["M68K_TIMING_DECODER"], "--artifact", str(artifact),
                 "--input-format", "raw", "--code", "0:0:4:smoke", "--json"],
                check=True, capture_output=True, text=True, timeout=20,
            )
            report = json.loads(result.stdout)
            self.assertEqual([row["mnemonic"] for row in report["sites"]], ["nop", "rts"])
            self.assertEqual(report["sites"][1]["nominal"]["min_cpu_clocks"], 16)
            self.assertIsNone(report["trace"])


if __name__ == "__main__":
    unittest.main()

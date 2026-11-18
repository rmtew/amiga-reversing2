"""Exact states upgraded in confidence consume one bounded variant."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_exact_context_budget_preserves_live_state_and_provenance(tmp_path):
    compiler = shutil.which("cc")
    backend = Path(
        os.environ.get("AMIGA_TEST_BACKEND", ROOT / "src/build/libamiga_backend.so")
    )
    if not compiler or not backend.exists():
        pytest.skip("native backend and host compiler required")
    driver = tmp_path / "context-budget"
    built = subprocess.run(
        [
            compiler,
            "-Isrc",
            "-std=c11",
            "-D_POSIX_C_SOURCE=200809L",
            "-O1",
            str(ROOT / "tests/native/dispatch_context_budget_fixture.c"),
            str(backend),
            f"-Wl,-rpath,{backend.parent}",
            "-lm",
            "-lcrypto",
            "-o",
            str(driver),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert built.returncode == 0, built.stderr
    checked = subprocess.run([str(driver)], capture_output=True, text=True, timeout=30)
    assert checked.returncode == 0, checked.stdout + checked.stderr

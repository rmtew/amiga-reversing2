"""Known incoming register values through a preaccepted branching helper."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "mode",
    [
        "resolved",
        "unknown",
        "indexed",
        "clobbered",
        "opaque_call",
        "trap_barrier",
        "caller_opaque",
        "redefined",
        "resolved_long",
        "confidence_duplicates",
    ],
)
def test_branching_register_dispatch(tmp_path, mode):
    compiler = shutil.which("cc")
    backend = Path(
        os.environ.get("AMIGA_TEST_BACKEND", ROOT / "src/build/libamiga_backend.so")
    )
    vasm = ROOT / "tools/vasmm68k_mot.exe"
    if not compiler or not backend.exists() or not vasm.exists():
        pytest.skip("native backend, host compiler and vasm required")
    driver = tmp_path / "dispatch"
    result = subprocess.run(
        [
            compiler,
            "-Isrc",
            "-std=c11",
            str(ROOT / "tests/native/dispatch_register_fixture.c"),
            str(backend),
            f"-Wl,-rpath,{backend.parent}",
            "-o",
            str(driver),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    incoming = {"unknown": "movea.l (a0),a6", "indexed": "movea.l $0(a0,d0.w),a6"}.get(
        mode, "lea.l selected(pc),a6"
    )
    change = {
        "clobbered": "movea.l (a1),a6",
        "opaque_call": "bsr.w opaque",
        "trap_barrier": "trap #0",
    }.get(mode, "nop")
    source = f""" SECTION code,code
 ORG 0
 {incoming}
 {"bsr.w opaque" if mode in ("caller_opaque", "redefined") else "nop"}
 {"lea.l selected(pc),a6" if mode == "redefined" else "nop"}
 bsr.w dispatch
 rts
 dcb.b 32-*,0
dispatch:
 lea.l buffer(pc),a0
 moveq #2,d7
scan:
 tst.w (a0)+
 beq.w transfer
 dbf d7,scan
 rts
transfer:
 {change}
 {(chr(10) + " ").join(["nop"] * 10) if mode == "resolved_long" else "nop"}
 jmp (a6)
opaque:
 movea.l (a1),a6
 rts
 dcb.b 128-*,0
selected:
 moveq #7,d0
 rts
buffer:
 dc.w $ffff,$ffff,$ffff
"""
    if mode == "confidence_duplicates":
        calls = "\n".join(
            f" lea.l selected{i}(pc),a6\n moveq #{i + 1},d7\n bsr.w dispatch"
            for i in range(6)
        )
        targets = "\n".join(f"selected{i}:\n moveq #{i},d0\n rts" for i in range(6))
        source = f""" SECTION code,code
 ORG 0
{calls}
 rts
 dcb.b 64-*,0
dispatch:
 lea.l buffer(pc),a0
scan:
 tst.w (a0)+
 beq.w transfer
 dbf d7,scan
 rts
transfer:
 jmp (a6)
 dcb.b 128-*,0
{targets}
buffer:
 dc.w $ffff,$ffff,$ffff
"""
    original = tmp_path / "original.bin"
    input_asm = tmp_path / "input.s"
    input_asm.write_text(source)
    flags = [str(vasm), "-quiet", "-Fbin", "-m68000", "-no-opt"]
    result = subprocess.run(
        [*flags, "-o", str(original), str(input_asm)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    rendered = tmp_path / "rendered.s"
    result = subprocess.run(
        [
            str(driver),
            str(original),
            str(
                2
                if mode == "confidence_duplicates"
                else int(mode in ("resolved", "redefined", "resolved_long"))
            ),
            str(rendered),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    rebuilt = tmp_path / "rebuilt.bin"
    result = subprocess.run(
        [*flags, "-o", str(rebuilt), str(rendered)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert rebuilt.read_bytes() == original.read_bytes()

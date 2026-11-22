# Cycle-aware 68000 report

Report nominal timing and bounded rewrite evidence for caller-selected MC68000
instruction ranges. The framework's native decoder supplies the actual
instruction bytes. The tool is read-only: it does not apply rewrites, move
code, or infer code boundaries. Nominal CPU clocks do not measure bus waits.

Build the decoder with `make src/build/m68k_timing_decode.exe` on Linux or WSL,
or `src\build.bat build-timing-decode` with MSVC x64 on Windows. Run the
standard-library-only tests from the repository root:

```sh
python src/tests/test_timing_decode.py src/build/m68k_timing_decode.exe
python -m unittest discover -s experiments/m68k-cycle
```

Synthetic example (two instructions: NOP and RTS):

```sh
python -c "from pathlib import Path; Path('timing-demo.bin').write_bytes(bytes.fromhex('4e714e75'))"
python experiments/m68k-cycle/report.py annotate --decoder src/build/m68k_timing_decode.exe --artifact timing-demo.bin --input-format raw --code 0:0:4:demo --json
python experiments/m68k-cycle/report.py calibrate
```

## Optional inputs

- For a caller-supplied Amiga Hunk executable, use `--input-format hunk`
  (the default), then provide explicit CODE ranges (`--code SECTION:OFFSET:LENGTH:LABEL`)
  or symbol bounds (`--routine START:END`). Caller-supplied ranges must be
  contiguous instructions, not inline data. Boundaries and external ingress are
  not proven by the tool.
- `hot` and `rank` accept `--profile` with offset-based Hunk 0 timing data.
  The input JSON includes `binary_sha256`, `config_sha256`, `machine_args`
  (including `--cpu 68000`), `windows` with frame numbers, and `sites` with
  hexadecimal `pc`, `hits`, `core`, `wait`, and `total` counters. The
  artifact SHA must match and totals must reconcile. A join covers only the
  selected ranges. These measured counters are separate from nominal clocks.
- `explain` accepts an explicit per-site `--contract` bound to the input hash
  or an inferred contract via `--infer`; inference can require a trusted
  `--entry`. `--normal-flow` narrows proof to nonexceptional execution and
  can exclude synchronous faults. Neither asynchronous observation nor layout
  and relocation are proven. Optional `--vasm` verifies emitted encodings
  separately from proof.
- `compare` summarizes a caller-supplied `--receipt`; matching observed
  outputs does not prove semantic equivalence. Use `--help` for all options.

# C99 Assembler Scaffold

Isolated C-side generator, corpus, and tests live under `src/`.

## Commands

Generate the C subset tables:

```powershell
uv run python src/scripts/generate_c99_assembler_subset.py --output-dir src
```

Generate the oracle corpus files:

```powershell
uv run python src/scripts/generate_c99_assembler_corpus.py --output-dir src/tests/generated
```

Build the C subset tools with MSVC:

```powershell
src\build.bat
```

Run corpus verification with the built C tool:

```powershell
src\build.bat verify-corpus
```

```powershell
src\build.bat verify-manifest src\tests\generated\full_ext_cases.txt
```

Assemble one generated corpus case to stdout:

```powershell
src\build.bat assemble-case src\tests\generated\all_cases.txt bra_b_sample
```

Assemble the full generated manifest to a binary:

```powershell
src\build.bat assemble-manifest src\tests\generated\all_cases.txt src\tests\generated\all_cases.rebuilt.bin
```

Assemble one line of supported source text:

```powershell
src\build.bat assemble-line "clr.b d0"
```

Assemble a simple source file to binary:

```powershell
src\build.bat assemble-file input.s out.bin
```

`assemble-line` currently supports the generated subset and numeric branch displacements.

`assemble-file` now supports file-level labels with two-pass branch resolution for the generated subset.

Indexed EA text also supports internal full-extension options like:

```powershell
lea.l $10(a0,d1.w){full,bdw=$1234,odw=$5678,iis=3},a0
```

Run the isolated `unittest` suite:

```powershell
uv run python -m unittest discover -s src/tests -p "test_*.py"
```

Run lint on the isolated Python support files:

```powershell
uv run ruff check src/scripts/generate_c99_assembler_subset.py src/scripts/generate_c99_assembler_corpus.py src/tests/test_c99_assembler_codegen.py src/tests/test_c99_assembler_corpus.py
```

## Generated Files

Corpus output:

- `src/tests/generated/all_cases.s`
- `src/tests/generated/all_cases.json`
- `src/tests/generated/all_cases.txt` — generic encoded instruction-sequence verifier manifest
- `src/tests/generated/all_cases.bin`
- `src/tests/generated/full_ext_cases.txt`

C subset output:

- `src/generated/m68k_asm_tables.h`
- `src/generated/m68k_asm_tables.c`
- `src/generated/m68k_disassembler_tables.h`
- `src/generated/m68k_simulator_tables.h`

Static runtime:

- `src/m68k_asm_metadata.h`
- `src/m68k_assembler.h`
- `src/m68k_assembler.c`
- `src/m68k_disassembler.h`
- `src/m68k_disassembler.c`

## 68000 timing instruction export

On Linux, build with `make src/build/m68k_timing_decode.exe` and run:

```sh
src/build/m68k_timing_decode.exe hunk game.hunk 0 0x120 0x38 > instructions.jsonl
src/build/m68k_timing_decode.exe raw section.bin 0 0x120 0x38 > instructions.jsonl
```

Arguments after the file are zero-based section index, original section byte
offset, and byte length (decimal or `0x` hexadecimal). In raw mode, the input
must start at section offset zero; the section index is the caller's identifier.
Hunk mode also requires an actual CODE section and refuses to read beyond its
stored bytes. **Provide a range already established as contiguous code.** A
Hunk CODE section can still contain inline data, and valid-looking encodings do
not establish code membership. This first slice does not traverse control flow
or discover accepted ranges; neither format automatically scans an entire file.

One JSON record per instruction reports `section`, `offset`, `byte_count`,
`bytes` (lowercase hex), `mnemonic`, `size` (or null), `form` (the generated
canonical ID), and typed `operands`. Operand fields are the native decoder's
values, not a reparse of rendered source: for example, the immediate effective
address in `mulu.w #40,d1` is `kind=ea, ea_mode=7, ea_reg=4, value=40`.
Only fields applicable to the operand kind/mode carry meaning. There is no
fallback to guessed lengths or other CPU models; a failed decode does not
publish a partial stream. This command neither times nor modifies the binary.

Run the encoding and admission smoke test with a local vasm:

```sh
python src/tests/test_timing_decode.py src/build/m68k_timing_decode.exe /path/to/vasmm68k_mot
```

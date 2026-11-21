"""Smoke test a native m68k_timing_decode, optionally with live vasm encoding."""

import argparse
import json
from pathlib import Path
import struct
import subprocess
from tempfile import TemporaryDirectory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoder", type=Path)
    parser.add_argument("vasm", type=Path, nargs="?")
    args = parser.parse_args()
    decoder = str(args.decoder.resolve())
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = root / "encoding.s"
        executable = root / "encoding.hunk"
        raw = root / "encoding.bin"
        # Independently fixed opcode bytes from the vasm encoding test:
        # NOP, ADD.L (vasm's normal encoding for ASL.L #1,D4), MULU.W #40,D1,
        # RTS. Hunk storage rounds up to a long; the admitted range does not.
        code = bytes.fromhex("4e71 d884 c2fc0028 4e75 0000")
        data = bytes.fromhex("4e71 4e75")

        def longs(*values):
            return struct.pack(f">{len(values)}I", *values)

        def symbol(name, value):
            text = name.encode("ascii")
            words = (len(text) + 3) // 4
            return longs(words) + text.ljust(words * 4, b"\0") + longs(value)

        if args.vasm is None:
            executable.write_bytes(
                longs(0x3F3, 0, 2, 0, 1, 3, 1)      # HUNK_HEADER, empty names, two sections
                + longs(0x3E9, len(code) // 4) + code  # HUNK_CODE
                + longs(0x3F0) + symbol("fixture_start", 2) + symbol("fixture_end", 10) + longs(0)
                + longs(0x3F2, 0x3EA, len(data) // 4) + data  # HUNK_END, HUNK_DATA
                + longs(0x3F0) + symbol("fixture_data", 0) + longs(0, 0x3F2)
            )
        else:
            source.write_text(
                "        section timing,code\n"
                "        nop\n"
                "fixture_start:\n"
                "        asl.l #1,d4\n"
                "        mulu.w #40,d1\n"
                "        rts\n"
                "fixture_end:\n"
                "        section table,data\n"
                "fixture_data:\n"
                "        dc.w $4e71,$4e75\n",
                encoding="ascii",
            )
            subprocess.run(
                [str(args.vasm.resolve()), "-quiet", "-m68000", "-Fhunkexe", "-o", executable, source],
                check=True,
            )

        def decode(fmt, path, section, offset, length, success=True):
            result = subprocess.run(
                [decoder, fmt, path, str(section), str(offset), str(length)],
                capture_output=True,
                text=True,
            )
            if not success:
                assert result.returncode != 0 and not result.stdout, result
                return []
            assert result.returncode == 0, result.stderr
            return [json.loads(line) for line in result.stdout.splitlines()]

        def bounds(first, limit, success=True):
            found = subprocess.run([decoder, "bounds", executable, first, limit],
                                   capture_output=True, text=True)
            if not success:
                assert found.returncode != 0 and not found.stdout, found
                return
            assert found.returncode == 0, found.stderr
            return json.loads(found.stdout)

        assert bounds("fixture_start", "fixture_end") == {"section": 0, "start": 2, "length": 8}
        bounds("fixture_end", "fixture_start", success=False)
        bounds("fixture_start", "fixture_data", success=False)
        bounds("missing", "fixture_end", success=False)

        rows = decode("hunk", executable, 0, 2, 8)
        assert [(r["section"], r["offset"], r["byte_count"], r["bytes"], r["mnemonic"], r["size"])
                for r in rows] == [
            (0, 2, 2, "d884", "add", "l"),
            (0, 4, 4, "c2fc0028", "mulu", "w"),
            (0, 8, 2, "4e75", "rts", None),
        ]
        assert (rows[0]["operands"][0]["kind"], rows[0]["operands"][0]["ea_reg"],
                rows[0]["operands"][1]["register"]) == ("ea", 4, 4)
        assert (rows[1]["operands"][0]["kind"], rows[1]["operands"][0]["ea_mode"],
                rows[1]["operands"][0]["ea_reg"], rows[1]["operands"][0]["value"]) == ("ea", 7, 4, 40)
        assert len({r["form"] for r in rows}) == 3 and all(r["form"] > 0 for r in rows)

        raw.write_bytes(bytes.fromhex("4e71 d884 c2fc0028 4e75 49c0"))
        assert decode("raw", raw, 17, 2, 8) == [dict(row, section=17) for row in rows]
        decode("raw", raw, 0, 2, 4, success=False)  # ADD then truncated MULU extension.
        decode("raw", raw, 0, 10, 2, success=False)  # EXTB.L, 68020+.
        decode("raw", raw, 0, 0, 100, success=False)
        decode("raw", raw, 0, 1, 2, success=False)
        decode("hunk", executable, 0, 2, 4, success=False)
        decode("hunk", executable, 1, 0, 4, success=False)  # Valid-looking opcodes, DATA.
        decode("hunk", executable, 2, 0, 2, success=False)
    fixture = "vasm encoding" if args.vasm else "fixed byte fixture"
    print(f"68000 timing decode: raw/Hunk, {fixture}, typed operands and admission checks passed")


if __name__ == "__main__":
    main()

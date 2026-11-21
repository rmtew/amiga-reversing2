"""Native smoke test; supply a built m68k_timing_decode and vasm with M68k/MOT support."""

import argparse
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoder", type=Path)
    parser.add_argument("vasm", type=Path)
    args = parser.parse_args()
    decoder, vasm = (str(path.resolve()) for path in (args.decoder, args.vasm))
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = root / "encoding.s"
        executable = root / "encoding.hunk"
        raw = root / "encoding.bin"
        source.write_text(
            "        section timing,code\n"
            "        nop\n"
            "        asl.l #1,d4\n"
            "        mulu.w #40,d1\n"
            "        rts\n"
            "        section table,data\n"
            "        dc.w $4e71,$4e75\n",
            encoding="ascii",
        )
        subprocess.run(
            [vasm, "-quiet", "-m68000", "-Fhunkexe", "-o", executable, source],
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
    print("68000 timing decode: raw/Hunk, vasm encoding, typed operands and admission checks passed")


if __name__ == "__main__":
    main()

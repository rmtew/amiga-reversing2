"""LEA reads its input record coordinate before overwriting the same register."""

import subprocess
from contextlib import closing

import pytest

from amiga_reversing.disasm import c_backend
from amiga_reversing.disasm.binary_source import (
    BinarySourceKind,
    RawAddressModel,
    RawBinarySource,
)
from amiga_reversing.disasm.effective_metadata import effective_metadata_file
from amiga_reversing.disasm.manual_action_catalog import target_catalog_manual_payload
from amiga_reversing.disasm.manual_actions import (
    ManualActionKind,
    append_manual_actions,
)
from amiga_reversing.disasm.target_metadata import TargetMetadata, write_target_metadata


def render(
    tmp_path, *, selected=32, delta=18, destination="a0", before="", access=2, count=2
):
    code, _ = c_backend.assemble_platform_source_text_with_c_backend(
        "amiga-raw",
        f"TABLE EQU {selected}\n SECTION code,code\n lea.l TABLE(pc),a0\n"
        + before
        + f" lea.l {delta}(a0),{destination}\n move.w {access}({destination}),d0\n rts\n",
    )
    assert len(code) <= 32
    binary = tmp_path / "input.bin"
    original = code + bytes(32 + 18 * count - len(code))
    binary.write_bytes(original)
    source = RawBinarySource(
        kind=BinarySourceKind.RAW_BINARY,
        path=binary,
        address_model=RawAddressModel.LOCAL_OFFSET,
        load_address=0,
        entrypoint=0,
        code_start_offset=0,
        display_path=str(binary),
        analysis_cache_path=tmp_path / "analysis",
    )
    write_target_metadata(
        tmp_path, TargetMetadata(target_type="program", entry_register_seeds=())
    )
    actions = []

    def add(command, parameters):
        kind, payload = target_catalog_manual_payload(command, parameters)
        actions.append((ManualActionKind(kind), payload))
        return payload

    add(
        "target.custom_struct.add",
        {
            "name": "Particle",
            "size": 18,
            "fields": [
                {"name": "word" + str(i), "type": "WORD", "offset": 2 * i, "size": 2}
                for i in range(7)
            ]
            + [{"name": "relative", "type": "LONG", "offset": 14, "size": 4}],
        },
    )
    owner = add(
        "target.data_block.layout.create",
        {
            "hunk": 0,
            "source_start": 32,
            "source_end": 32 + 18 * count,
            "name": "particles",
            "role": "data",
            "default_unit": "word",
        },
    )
    add(
        "target.data_block.element.set",
        {
            "layout_id": owner["data_block_layout"]["layout_id"],
            "offset": 0,
            "width": 18 * count,
            "kind": "struct",
            "array_count": count,
            "array_stride": 18,
            "binding_kind": "custom_struct",
            "type_id": "Particle",
        },
    )
    append_manual_actions(tmp_path, binary_source=source, actions=actions)
    with effective_metadata_file(tmp_path) as path:
        artifact = c_backend.build_listing_artifact_profile_from_binary_source(
            source, metadata_path=path
        )[2]
    with closing(artifact):
        text = artifact.inline_source_text_with_profile()[0]
    asm = tmp_path / "rendered.s"
    asm.write_text(text)
    rebuilt, _ = c_backend.assemble_platform_source_path_with_c_backend(
        "amiga-raw", asm
    )
    assert rebuilt == original
    output = tmp_path / "oracle.bin"
    run = subprocess.run(
        [
            str(c_backend.PROJECT_ROOT / "tools/vasmm68k_mot.exe"),
            "-quiet",
            "-no-opt",
            "-Fbin",
            "-o",
            str(output),
            str(asm),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert run.returncode == 0, run.stderr
    assert output.read_bytes() == original
    return text


@pytest.mark.parametrize(
    ("selected", "delta", "access", "field"),
    [
        (32, 18, 2, "word1"),
        (50, -18, 2, "word1"),
        (32, 0, 14, "relative"),
        (32, 1, 1, "word1"),
    ],
)
def test_self_lea_preserves_proved_array_or_interior_coordinate(
    tmp_path, selected, delta, access, field
):
    text = render(tmp_path, selected=selected, delta=delta, access=access)
    assert "move.w Particle_" + field in text


def test_separate_destination_keeps_the_existing_source_type_contract(tmp_path):
    assert "Particle_word1(a1)" in render(tmp_path, destination="a1")


@pytest.mark.parametrize("before", [" movea.l d1,a0\n", " jsr (a1)\n"])
def test_unknown_base_or_call_does_not_recover_type_from_self_lea(tmp_path, before):
    text = render(tmp_path, before=before)
    assert "move.w $0002(a0),d0" in text
    assert "move.w Particle_" not in text


@pytest.mark.parametrize(("delta", "access"), [(36, 2), (-18, 2), (0, 1)])
def test_one_past_outside_or_cross_field_access_remains_untyped(
    tmp_path, delta, access
):
    text = render(tmp_path, delta=delta, access=access)
    assert "move.w Particle_" not in text


def test_backwards_two_record_stride_retains_negative_symbolic_sign(tmp_path):
    text = render(tmp_path, selected=68, delta=-36, count=3)
    assert "Particle_word0-2*Particle_SIZEOF(a0)" in text
    assert "move.w Particle_word1(a0),d0" in text

"""Synthetic custom sectors: independent clocks/checksum oracle and refusal cases."""

import copy
import json
import struct
import zlib

import pytest

from amiga_reversing.disasm.ipf_resources import (
    CODEC,
    PROJECT_ROOT,
    _encode_foft_sector,
    decode_foft_block,
    digest,
    rebuild_resources,
    recover_resources,
    validate_plan,
)
from src.tests.test_platform_ipf import chunk, mfm, sample


def sector_block(
    sector, *, header_track=3, payload=None, bad_checksum=False, prefix_kind=3
):
    payload = bytes([sector + 1]) * 2000 if payload is None else payload
    header = bytes([255, header_track, sector])
    raw = mfm(header + payload)
    checksum = 0
    for word in struct.unpack(">2000H", raw[6:]):
        checksum ^= word
    checksum ^= int(bad_checksum)
    data = header + payload + checksum.to_bytes(2, "big")
    # Include last payload bit when encoding the checksum.
    return (
        sample(prefix_kind, b"\0" * 13)
        + sample(1, bytes.fromhex("44894489"))
        + sample(2, data)
        + b"\0"
    ), data


def media_fixture(*, duplicate=False, bad_checksum=False, prefix_kind=3):
    blocks = [
        sector_block(
            0 if duplicate and n == 1 else n,
            bad_checksum=bad_checksum and n == 2,
            prefix_kind=prefix_kind,
        )[0]
        for n in range(3)
    ]
    offset = 96
    descriptors = bytearray()
    for block in blocks:
        descriptors += struct.pack(">8I", 32320, 0, 4040, 0, 1, 0, 0, offset)
        offset += len(block)
    payload = descriptors + b"".join(blocks)
    info = [1, 1, 1, 0, 1, 0, 0, 1, 0, 0] + [0] * 11
    image = [1, 0, 2, 1, 0, 0, 0, 96960, 0, 96960, 3, 0, 0, 1, 0, 0, 0]
    return (
        chunk(b"CAPS")
        + chunk(b"INFO", struct.pack(">21I", *info))
        + chunk(b"IMGE", struct.pack(">17I", *image))
        + chunk(
            b"DATA",
            struct.pack(">4I", len(payload), len(payload) * 8, zlib.crc32(payload), 1),
            payload,
        )
    )


def plan_for(image):
    expected = b"\1" * 1000 + b"\2" * 2000 + b"\3" * 123
    return {
        "schema_version": 1,
        "kind": "ipf_resource_recovery",
        "image_sha256": digest(image),
        "geometry": {"cylinders": 2, "sides": 1, "records": 1},
        "codec": CODEC,
        "evidence": {"reader": "synthetic independent checksum oracle"},
        "actions": [
            {
                "op": "capture",
                "file": "mixed_bank.bin",
                "size": len(expected),
                "sha256": digest(expected),
                "spans": [
                    {"track": 1, "side": 0, "offset": 1000, "length": len(expected)}
                ],
                "resource": {
                    "id": "bank",
                    "kind": "mixed",
                    "destination": 0x58000,
                    "trigger": "fixture",
                    "reader": "fixture",
                    "analysis_target": "fixture",
                },
            }
        ],
    }


def test_partial_resource_crosses_sectors_and_exact_template_rebuild():
    image = media_fixture()
    plan = plan_for(image)
    receipt, outputs = recover_resources(image, plan)
    assert outputs == {"mixed_bank.bin": b"\1" * 1000 + b"\2" * 2000 + b"\3" * 123}
    assert [s["sector"] for s in receipt["captures"][0]["spans"][0]["sectors"]] == [
        0,
        1,
        2,
    ]
    rebuilt, proof = rebuild_resources(image, plan, outputs)
    assert rebuilt == image
    assert proof["regenerated_sectors"] == 3 and proof["untouched_bytes_preserved"]
    assert proof["encoded_write_sectors"] == [[0, 0], [0, 1], [0, 2]]
    assert proof["write_coverage"] == [
        {
            "file": "mixed_bank.bin",
            "sha256": plan["actions"][0]["sha256"],
            "size": 3123,
            "spans": [
                {
                    "source_offset": 0,
                    "length": 3123,
                    "storage": {"track": 1, "side": 0, "offset": 1000},
                }
            ],
        }
    ]
    assert proof["scope"].endswith("boot and playback not tested")
    assert digest(image) == plan["image_sha256"]


def test_omitted_ipf_placement_cannot_pass_using_unchanged_template():
    from amiga_reversing.disasm.disk_codecs import IpfResources, verify_write_coverage

    image = media_fixture()
    plan = plan_for(image)
    # A second placement is required even though both payloads already occur
    # in the immutable template. Coverage comes from the actual write loop.
    other = copy.deepcopy(plan["actions"][0])
    other.update(
        file="second.bin",
        size=100,
        sha256=digest(b"\1" * 100),
        spans=[{"track": 1, "side": 0, "offset": 0, "length": 100}],
    )
    other["resource"].pop("analysis_target")
    plan["actions"].append(other)
    _, outputs = IpfResources.extract(image, plan, project_root=PROJECT_ROOT)
    rebuilt, receipt = IpfResources.rebuild(
        image, plan, outputs, project_root=PROJECT_ROOT
    )
    verify_write_coverage(
        IpfResources.required_coverage(plan), receipt["write_coverage"]
    )
    assert rebuilt == image
    reduced = copy.deepcopy(plan)
    reduced["actions"].pop()
    rebuilt, receipt = IpfResources.rebuild(
        image,
        reduced,
        {"mixed_bank.bin": outputs["mixed_bank.bin"]},
        project_root=PROJECT_ROOT,
    )
    assert rebuilt == image
    with pytest.raises(ValueError, match="placement write coverage"):
        verify_write_coverage(
            IpfResources.required_coverage(plan), receipt["write_coverage"]
        )


def test_sector_encoder_changes_bytes_and_checksums_against_independent_oracle():
    for sector in range(3):
        payload = bytes((i * 37 + sector) & 255 for i in range(2000))
        _, oracle = sector_block(sector, payload=payload)
        encoded = _encode_foft_sector(bytes([255, 3, sector]), payload)
        assert encoded == oracle
        raw = mfm(b"\0" * 13, previous=0) + bytes.fromhex("44894489") + mfm(encoded)
        assert decode_foft_block(raw, track=1, side=0)[0:2] == (sector, payload)
    with pytest.raises(ValueError, match="FOFT|resource|recipe|unsigned"):
        _encode_foft_sector(b"bad", b"too short")


@pytest.mark.parametrize(
    "mutation", ["clock", "checksum", "side", "duplicate_sync", "short"]
)
def test_independent_block_validation_refuses_corruption(mutation):
    _, data = sector_block(0, bad_checksum=mutation == "checksum")
    raw = bytearray(mfm(b"\0" * 13, previous=0) + bytes.fromhex("44894489") + mfm(data))
    side = 1 if mutation == "side" else 0
    if mutation == "clock":
        raw[40] ^= 128
    elif mutation == "duplicate_sync":
        raw[:4] = bytes.fromhex("44894489")
    elif mutation == "short":
        raw.pop()
    with pytest.raises(ValueError, match="FOFT|resource|recipe|unsigned"):
        decode_foft_block(bytes(raw), track=1, side=side)


@pytest.mark.parametrize("kwargs", [{"duplicate": True}, {"bad_checksum": True}])
def test_all_three_sectors_must_verify_even_for_a_partial_resource(kwargs):
    image = media_fixture(**kwargs)
    plan = plan_for(image)
    plan["actions"][0].update(
        size=1,
        sha256=digest(b"\1"),
        spans=[{"track": 1, "side": 0, "offset": 0, "length": 1}],
    )
    with pytest.raises(ValueError, match="FOFT|resource|recipe|unsigned"):
        recover_resources(image, plan)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p.update(schema_version=True),
        lambda p: p.update(codec="guess"),
        lambda p: p["geometry"].update(cylinders=0),
        lambda p: p["actions"][0].update(file="../escape.bin"),
        lambda p: p["actions"][0].update(size=1),
        lambda p: p["actions"][0]["spans"][0].update(track=True),
        lambda p: p["actions"][0]["spans"][0].update(side=1),
        lambda p: p["actions"][0]["spans"][0].update(offset=5000),
        lambda p: p["actions"][0]["spans"].append(
            {"track": 1, "side": 0, "offset": 1000, "length": 1}
        ),
    ],
)
def test_bad_resource_contracts_are_refused(mutation):
    plan = plan_for(media_fixture())
    mutation(plan)
    with pytest.raises(ValueError, match="resource|recipe|unsigned"):
        validate_plan(plan)


def test_bound_identities_geometry_and_exact_rebuild_input():
    image = media_fixture()
    plan = plan_for(image)
    with pytest.raises(ValueError, match="source identity"):
        recover_resources(image + b"\0", plan)
    wrong = copy.deepcopy(plan)
    wrong["geometry"]["records"] = 2
    with pytest.raises(ValueError, match="geometry"):
        recover_resources(image, wrong)
    wrong = copy.deepcopy(plan)
    wrong["actions"][0]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="output identity"):
        recover_resources(image, wrong)
    with pytest.raises(ValueError, match="assembled resource"):
        rebuild_resources(image, plan, {"mixed_bank.bin": b"wrong"})


def test_readable_but_unreviewed_literal_template_shape_is_not_rewritten():
    image = media_fixture(prefix_kind=2)
    plan = plan_for(image)
    _, outputs = recover_resources(image, plan)
    with pytest.raises(ValueError, match="unsupported literal"):
        rebuild_resources(image, plan, outputs)


def test_explicit_multitrack_order_and_partial_sector_preservation():
    images, containers = [], []
    expected = b"\x0d" * 50 + b"\x01" * 50
    for side in range(2):
        blocks = [
            sector_block(
                n, header_track=3 ^ side, payload=bytes([side * 10 + n + 1]) * 2000
            )[0]
            for n in range(3)
        ]
        at = 96
        descriptors = bytearray()
        for block in blocks:
            descriptors.extend(struct.pack(">8I", 32320, 0, 4040, 0, 1, 0, 0, at))
            at += len(block)
        payload = descriptors + b"".join(blocks)
        images.append(
            chunk(
                b"IMGE",
                struct.pack(
                    ">17I",
                    1,
                    side,
                    2,
                    1,
                    0,
                    0,
                    0,
                    96960,
                    0,
                    96960,
                    3,
                    0,
                    0,
                    side + 1,
                    0,
                    0,
                    0,
                ),
            )
        )
        containers.append(
            chunk(
                b"DATA",
                struct.pack(
                    ">4I", len(payload), len(payload) * 8, zlib.crc32(payload), side + 1
                ),
                payload,
            )
        )
    info = [1, 1, 1, 0, 1, 0, 0, 1, 0, 1] + [0] * 11
    image = (
        chunk(b"CAPS")
        + chunk(b"INFO", struct.pack(">21I", *info))
        + b"".join(images + containers)
    )
    plan = plan_for(image)
    plan["geometry"].update(sides=2, records=2)
    plan["actions"][0].update(
        size=100,
        sha256=digest(expected),
        spans=[
            {"track": 1, "side": 1, "offset": 5950, "length": 50},
            {"track": 1, "side": 0, "offset": 0, "length": 50},
        ],
    )
    _, outputs = recover_resources(image, plan)
    assert outputs["mixed_bank.bin"] == expected
    rebuilt, proof = rebuild_resources(image, plan, outputs)
    assert rebuilt == image and proof["regenerated_sectors"] == 2


def test_catalog_materializes_a_resource_identity_independent_of_runtime_address(
    tmp_path,
):
    from amiga_reversing.disasm import game_catalog as catalog

    image = media_fixture()
    plan = plan_for(image)
    action = plan["actions"][0]
    (tmp_path / "games").mkdir()
    recipe = tmp_path / "recipe.json"
    recipe.write_text(json.dumps(plan))
    media, resource = digest(image), action["sha256"]
    context = {
        "kind": "raw",
        "address_model": "runtime_absolute",
        "load_address": 0x58000,
        "entrypoint": 0x58000,
        "code_start_offset": 0,
        "phase": "decoded_resource",
    }
    family = {
        "schema_version": 1,
        "id": "fixture",
        "name": "Fixture",
        "releases": {
            "amiga": {"platform": "amiga", "edition": "synthetic", "media": [media]}
        },
        "artifacts": {
            media: {"size": len(image), "role": "media"},
            resource: {"size": action["size"], "role": "mixed resource"},
        },
        "sources": {media: {"kind": "private_media", "format": "ipf"}},
        "derivations": {
            "read": {
                "kind": "ipf_resource_recovery",
                "input": media,
                "recipe": "recipe.json",
                "recipe_sha256": digest(recipe.read_bytes()),
                "outputs": {action["file"]: resource},
            }
        },
        "targets": {
            "bank": {"release": "amiga", "artifact": resource, "context": context}
        },
        "correspondences": [],
    }
    (tmp_path / "games/fixture.json").write_text(json.dumps(family))
    source = tmp_path / "original.ipf"
    source.write_bytes(image)
    catalog.bind_source(tmp_path, "fixture", media, source)
    path = catalog.materialize(tmp_path, "fixture", resource)
    assert digest(path.read_bytes()) == resource
    assert path.parent == tmp_path / ".amiga_reversing/artifacts"
    changed = copy.deepcopy(family)
    changed["targets"]["bank"]["context"].update(
        load_address=0x60000, entrypoint=0x60000
    )
    catalog.validate(changed, tmp_path)
    assert catalog.binding_revision(changed, "bank") != catalog.binding_revision(
        family, "bank"
    )
    assert changed["targets"]["bank"]["artifact"] == resource
    recipe.write_text(recipe.read_text() + "\n")
    with pytest.raises(ValueError, match="stale recovery recipe"):
        catalog.load_family(tmp_path, "fixture")

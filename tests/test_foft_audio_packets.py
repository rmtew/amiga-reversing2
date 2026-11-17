import pytest

from tools.foft_audio_layout_probe import (
    decode_order,
    decode_order_prefix,
    decode_pattern,
    decode_pattern_prefix,
    probe,
)


def test_pattern_packet_boundaries_preserve_parameters_and_note_variants():
    # FF inside a slide parameter is data, while the final FF ends the stream.
    data = bytes([0x80, 0xC0, 0xFF, 2, 0xFE, 0x20, 12, 0x7F, 3, 0x21, 0, 5, 0xFF])
    events = decode_pattern(data, 0, len(data))
    assert [(r["kind"], r["width"]) for r in events] == [
        ("instrument_select", 1),
        ("slide_command", 4),
        ("note", 2),
        ("rest", 2),
        ("held_note", 3),
        ("end", 1),
    ]
    assert sum(r["width"] for r in events) == len(data)


@pytest.mark.parametrize(
    "data",
    [
        bytes([0xC7, 0xFF]),
        bytes([0xC0, 1, 2]),
        bytes([0x20]),
        bytes([0x20, 0]),
        bytes([0x7F]),
        bytes([0x80]),
        bytes([0xFF, 0]),
    ],
)
def test_pattern_refuses_unsupported_truncated_or_wrong_extent(data):
    with pytest.raises(ValueError, match="pattern|Pattern|note"):
        decode_pattern(data, 0, len(data))


def test_orders_do_not_treat_parameter_ff_as_a_terminator():
    data = bytes([0xD8, 0, 0xFE, 0xFF, 0xFD, 0x14, 0xF0, 4, 0xFF])
    events, indices = decode_order(data, 0, len(data), 17)
    assert indices == [0]
    assert [r["width"] for r in events] == [1, 1, 2, 2, 2, 1]


@pytest.mark.parametrize(
    "data", [bytes([17, 0xFF]), bytes([0xFE]), bytes([0xFF, 0]), bytes([0])]
)
def test_order_refuses_absent_pattern_truncation_or_wrong_extent(data):
    with pytest.raises(ValueError, match="order|Order|pattern"):
        decode_order(data, 0, len(data), 17)


def test_profile_and_packet_bounds_are_explicit():
    with pytest.raises(ValueError, match="verified"):
        probe(bytes(489472))
    for start, end in [(-1, 1), (0, 0), (0, 2)]:
        with pytest.raises(ValueError, match="outside"):
            decode_pattern(bytes([0xFF]), start, end)


def test_bounded_prefixes_do_not_classify_container_tails_as_packets_or_padding():
    data = bytes([0x20, 1, 0xFF, 0, 0xC7])
    events, end = decode_pattern_prefix(data, 0, len(data))
    assert end == 3 and sum(e["width"] for e in events) == 3
    with pytest.raises(ValueError, match="precedes"):
        decode_pattern(data, 0, len(data))
    events, indices, end = decode_order_prefix(
        bytes([1, 0xFE, 0xFF, 0xFF, 0xAB]), 0, 5, 2
    )
    assert end == 4 and indices == [1]
    assert [e["width"] for e in events] == [1, 2, 1]


def test_consumer_verified_pattern_profiles_preserve_parameter_ff_and_default_refusal():
    data = bytes([0xC6, 0xFF, 0, 0xC7, 0xC7, 0xFF])
    profile = {0xC6: 3, 0xC7: 0}
    events = decode_pattern(data, 0, len(data), command_parameters=profile)
    assert [e["width"] for e in events] == [4, 1, 1]
    assert profile == {0xC6: 3, 0xC7: 0}
    with pytest.raises(ValueError, match="Unsupported"):
        decode_pattern(data, 0, len(data))


@pytest.mark.parametrize(
    "profile", [{True: 0}, {0xFF: 0}, {0xC0: -1}, {0xC0: True}, {0xC0: 256}, []]
)
def test_bad_pattern_profiles_do_not_admit_guessed_commands(profile):
    with pytest.raises(ValueError, match="profile"):
        decode_pattern_prefix(bytes([0xFF]), 0, 1, command_parameters=profile)

import pytest

from tools.foft_music_menu_probe import nominal_copy_chunks, probe


def test_nominal_copy_covers_bytes_once_and_resets_track_offset():
    chunks = nominal_copy_chunks(0x58000, 124, 5998, 6005)
    assert [(r["track"], r["track_offset"], r["end"]-r["start"]) for r in chunks] == [
        (124, 5998, 2), (125, 0, 6000), (126, 0, 3)]
    assert chunks[0]["start"] == 0x58000
    assert chunks[-1]["end"] == 0x58000+6005
    assert all(a["end"] == b["start"] for a, b in zip(chunks, chunks[1:], strict=False))


@pytest.mark.parametrize("args", [(-1, 1, 0, 1), (1, -1, 0, 1), (1, 1, 6000, 1),
                                  (1, 1, 0, 0), (0xFFFFFFFF, 1, 0, 2), (True, 1, 0, 1)])
def test_unsupported_descriptors_do_not_claim_a_write_span(args):
    with pytest.raises(ValueError, match="Descriptor|descriptor"):
        nominal_copy_chunks(*args)


def test_probe_requires_exact_initial_input():
    with pytest.raises(ValueError, match="verified"):
        probe(bytes(489472))

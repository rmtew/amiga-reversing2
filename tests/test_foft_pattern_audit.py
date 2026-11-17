import pytest

from tools.foft_pattern_audit import pattern_shape


def test_matcher_shapes_preserve_adjacent_star_and_empty_alternatives():
    result = pattern_shape(b"(everyone/nobody)*= (is/) useful")
    assert [token["kind"] for token in result["tokens"]] == [
        "alternatives",
        "capture",
        "alternatives",
        "literal",
    ]
    assert result["tokens"][2]["empty_branches"] == 1
    assert result["complete_match_semantics"] is False
    # The machine scanner only recognizes a star at an operation boundary.
    assert pattern_shape(b"word*=")["tokens"][0]["kind"] == "literal"


@pytest.mark.parametrize(
    ("pattern", "reason"),
    [
        (b"(nested/(group))", "nested"),
        (b"(unclosed", "unterminated"),
        (b"word ", "trailing"),
        (b"a" * 24, "literal"),
        (b"(" + b"a " * 32 + b")", "alternative"),
        (b"bad\x80", "unsupported"),
    ],
)
def test_unproved_or_out_of_reservation_shapes_refuse(pattern, reason):
    with pytest.raises(ValueError, match=reason):
        pattern_shape(pattern)

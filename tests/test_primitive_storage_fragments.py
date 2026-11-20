"""A narrower authored owner must not demote intact surrounding storage cells."""

import pytest

from tests.test_structural_record_views import fixture


def test_word_storage_remains_word_on_both_sides_of_a_typed_record(tmp_path):
    text, _ = fixture(tmp_path, raw=(124, 28, 'word'),
                      raw_properties={'comment': 'Original WORD storage'})
    prefix = text.split('retained_view:\n', 1)[1].split('points:\n', 1)[0]
    suffix = text.rsplit('\t; z\n', 1)[1]
    assert '\tdc.w ' in prefix or '\tdcb.w ' in prefix
    assert suffix.lstrip().startswith(('dc.w ', 'dcb.w '))
    assert 'Original WORD storage' in text
    assert 'dcb.b $28,' in suffix  # Forty bytes outside the imported span stay raw.


def test_long_storage_keeps_only_complete_remaining_long_cells(tmp_path):
    text, _ = fixture(tmp_path, raw=(124, 28, 'long'), code=' lea.l TABLE(pc),a6\n rts')
    prefix = text.split('retained_view:\n', 1)[1].split('points:\n', 1)[0]
    suffix = text.rsplit('\t; z\n', 1)[1]
    assert '\tdc.l ' in prefix or '\tdcb.l ' in prefix
    assert suffix.lstrip().startswith(('dc.b ', 'dc.w '))  # Never a LONG across the two-byte edge.
    assert '\tdc.l ' in suffix or '\tdcb.l ' in suffix
    assert 'dcb.b $28,' in suffix


@pytest.mark.parametrize('kind', ['word', 'long'])
def test_explicit_value_type_is_not_reinterpreted_as_a_storage_fragment(tmp_path, kind):
    text, _ = fixture(tmp_path, raw=(124, 28, kind), raw_properties={'c_type': kind.upper()})
    prefix = text.split('retained_view:\n', 1)[1].split('points:\n', 1)[0]
    assert '\tdc.b ' in prefix or '\tdcb.b ' in prefix
    assert '\tdc.' + ('w' if kind == 'word' else 'l') + ' ' not in prefix


@pytest.mark.parametrize('at', [125, 126])
def test_interior_labels_preserve_complete_cells_without_crossing_partial_ones(tmp_path, at):
    text, _ = fixture(tmp_path, raw=(124, 28, 'word'), labels=[(at, 'keptLabel')],
                      raw_properties={'comment': 'Original WORD storage'})
    prefix = text.split('retained_view:\n', 1)[1].split('points:\n', 1)[0]
    assert 'keptLabel:\n' in prefix
    assert text.count('Original WORD storage') == 1
    if at == 125:
        before, after = prefix.split('keptLabel:\n')
        assert before.lstrip().startswith('dc.b ')
        assert after.lstrip().startswith('dc.b ')
        assert '\tdc.w ' in after
    else:
        assert '\tdc.b ' not in prefix and '\tdcb.b ' not in prefix
        assert '\tdc.w ' in prefix


def test_decoded_code_conflict_keeps_existing_invalid_overlap_guard(tmp_path):
    text, _ = fixture(tmp_path, raw=(124, 28, 'word'),
        code=' bra.w protected\n dcb.b 120,0\nprotected:\n rts')
    prefix = text.split('retained_view:\n', 1)[1].split('points:\n', 1)[0]
    assert 'invalid overlap: decoded code' in prefix
    assert '\trts' not in prefix

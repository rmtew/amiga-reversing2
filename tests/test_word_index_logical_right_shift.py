"""Zero-fill WORD right shifts retain existing scalar bounds, never pointees."""

import pytest

from tests.test_base_candidates import candidate_artifact
from tests.test_masked_word_index_fields import metadata
from tests.test_typed_index_symbol_compensation import exact


@pytest.mark.parametrize(('setup', 'shift', 'middle', 'count', 'wanted'), [
    ('move.w #8,d0', 'lsr.w #1,d0', '', 2, True),
    ('move.w #4,d0\n moveq #0,d1', 'lsr.w d1,d0', '', 2, True),
    ('move.w #$8000,d0\n moveq #15,d1', 'lsr.w d1,d0', 'add.w d0,d0\n add.w d0,d0', 2, True),
    ('', 'lsr.w #8,d0', 'add.w d0,d0\n add.w d0,d0\n cmp.w #32,d0\n ble.s selected\n moveq #32,d0\nselected:', 9, True),
    ('move.w #$8008,d0\n moveq #13,d1', 'lsr.w d1,d0', '', 2, True),
    ('move.w #8,d0\n moveq #1,d1', 'lsr.w d1,d0', '', 2, True),
    ('andi.w #$0F00,d0', 'lsr.w #8,d0', 'add.w d0,d0\n add.w d0,d0\n cmp.w #32,d0\n ble.s selected\n moveq #32,d0\nselected:', 9, True),
    ('andi.w #$0F00,d0', 'lsr.w #8,d0', 'add.w d0,d0\n add.w d0,d0', 9, False),
    ('andi.w #$0F00,d0', 'lsr.w #8,d0', 'add.w d0,d0\n add.w d0,d0\n cmp.w #32,d0\n ble.s selected\n moveq #32,d0\nselected:', 8, False),
    ('move.w #8,d0', 'lsr.l #1,d0', '', 2, False),
    ('move.w #8,d0', 'lsr.b #1,d0', '', 2, False),
    ('move.w #$8008,d0\n moveq #13,d1', 'asr.w d1,d0', '', 2, False),
    ('move.w #8,d0', 'ror.w #1,d0', '', 2, False),
    ('move.w #8,d0', 'lsr.w d1,d0', '', 2, False),
    ('move.w #8,d0\n moveq #16,d1', 'lsr.w d1,d0', '', 2, False),
    ('move.w #8,d0', 'lsr.w #1,d0', 'move.w d3,d0', 2, False),
    ('move.w #8,d0', 'lsr.w #1,d0', 'jsr (a2)', 2, False),
    ('move.w #8,d0', 'lsr.w #1,d0', 'tst.w d7\n beq.s selected\n move.w d3,d0\nselected:', 2, False),
])
def test_logical_right_shift_reuses_word_domain(tmp_path, setup, shift, middle, count, wanted):
    code = f'{setup}\n {shift}\n {middle}\n move.l 0(a0,d0.w),d2\n rts\n'
    with candidate_artifact(tmp_path, code, [], metadata(count=count,size=4,offset=0,width=4)) as (a, raw):
        analysis = a.analysis_payload()[0]
        assert not analysis['incomplete_analysis']
        fields = [r for r in analysis['sections'][0]['recovered_platform_typed_accesses']
                  if r['field_name'] == 'value']
        assert bool(fields) == wanted
        if fields:
            assert fields[0]['word_index']['record_count'] == count
        exact(a, raw, tmp_path)


def test_clamped_selector_names_a_source_record_field_without_reading_its_pointer(tmp_path):
    from tests.test_structural_record_views import fixture

    text, rows = fixture(tmp_path, record_size=4, count=9, code=(
        ' lea.l TABLE(pc),a4\n andi.w #$0F00,d0\n lsr.w #8,d0\n'
        ' add.w d0,d0\n add.w d0,d0\n cmp.w #32,d0\n ble.s selected\n'
        ' moveq #32,d0\nselected:\n move.l 0(a4,d0.w),(a0)+\n'
        ' movea.l 0(a4,d0.w),a6\n rts\n'))
    reads = [t for row in rows for t in row['typed_accesses']
             if t.get('root_struct_name') == 'Point']
    assert len(reads) == 2
    assert 'Point_pointer(a4,d0.w)' in text
    assert all(t['word_index']['record_count'] == 9 for t in reads)
    # Null initial table bytes do not become pointer values or callable targets.
    assert not any(row['mnemonic'] == 'jsr' for row in rows)


@pytest.mark.parametrize(('prefix', 'branch', 'wanted'), [
    ('andi.w #$00FC,d0', 'ble', True),
    ('andi.w #$80FC,d0', 'ble', False),
    ('ori.w #$8000,d0\n andi.w #$80FC,d0', 'ble', False),
    ('andi.w #$00FC,d0\n move.w d3,d0', 'ble', False),
    ('andi.w #$80FC,d0', 'bls', True),
])
def test_modular_bounds_require_an_independently_impossible_arm(tmp_path,prefix,branch,wanted):
    code = (f'{prefix}\n cmp.w #32,d0\n {branch}.s selected\n'
            ' moveq #32,d0\nselected:\n move.l 0(a0,d0.w),d2\n rts\n')
    with candidate_artifact(tmp_path,code,[],metadata(count=9,size=4,offset=0,width=4)) as (a,raw):
        analysis=a.analysis_payload()[0]
        assert not analysis['incomplete_analysis']
        fields=analysis['sections'][0]['recovered_platform_typed_accesses']
        assert bool(fields)==wanted
        exact(a,raw,tmp_path)

"""A structural DBF induction needs an exact stack position, not saved values."""

import pytest

from tests.test_structural_record_views import fixture


def check(tmp_path, stack, *, conditional=False):
    if conditional:
        stack = ' tst.w d3\n beq.w joined\n' + stack + 'joined:\n'
    code = (
        ' lea.l TABLE(pc),a0\n move.w #149,d7\nagain:\n'
        ' move.w (a0)+,d0\n move.w (a0)+,d1\n move.w (a0)+,d2\n'
        + stack + ' dbf.w d7,again\n move.w (a0),d3\n rts\n'
    )
    text, rows = fixture(tmp_path, code=code, record_size=6, count=150)
    fields = [a for r in rows for a in r['typed_accesses'] if a.get('record_cursor_loop')]
    return text, rows, fields


@pytest.mark.parametrize('width', ['b', 'w', 'l'])
@pytest.mark.parametrize('conditional', [False, True])
def test_balanced_arithmetic_stack_read_preserves_record_induction(tmp_path, width, conditional):
    _, rows, fields = check(tmp_path,
        f' move.{width} d1,-(a7)\n add.{width} (a7)+,d1\n', conditional=conditional)
    assert [f['field_name'] for f in fields] == ['x', 'y', 'z']
    assert all(f['record_cursor_loop']['iteration_count'] == 150 for f in fields)
    assert all(f['record_cursor_loop']['iteration_stride'] == 6 for f in fields)
    assert not next(r for r in rows if r['text'] == 'move.w (a0),d3')['typed_accesses']


@pytest.mark.parametrize('stack', [
    ' link a6,#-8\n',
    ' unlk a6\n',
    ' move.w d1,-(a7)\n',  # A real two-byte leak on every trip.
    ' move.l d1,-(a7)\n add.w (a7)+,d1\n',
    ' move.w d1,-(a7)\n movea.l a1,a7\n add.w (a7)+,d1\n',
    ' move.w d1,-(a7)\n movea.l (a7)+,a7\n',
    ' move.l d1,-(a7)\n movea.l (a7)+,a7\n',
    ' cmpm.w (a7)+,(a7)+\n subq.l #4,a7\n',  # Repeated updating EA remains unsupported.
    ' tst.w d3\n beq.w joined\n move.w d1,-(a7)\njoined:\n',
])
def test_unbalanced_replaced_or_ambiguous_stack_cannot_certify_loop(tmp_path, stack):
    assert not check(tmp_path, stack)[2]


@pytest.mark.parametrize(('push', 'pop'), [('b', 'w'), ('w', 'b')])
def test_byte_and_word_stack_accesses_share_the_two_byte_position_step(tmp_path, push, pop):
    assert len(check(tmp_path, f' move.{push} d1,-(a7)\n add.{pop} (a7)+,d1\n')[2]) == 3


def test_arithmetic_pop_does_not_restore_the_saved_pointer_value(tmp_path):
    _, rows, fields = check(tmp_path,
        ' move.l a0,-(a7)\n add.l (a7)+,d1\n movea.l d1,a1\n move.w (a1),d4\n')
    assert len(fields) == 3
    selected = next(r for r in rows if r['text'] == 'move.w (a1),d4')
    assert not selected['typed_accesses']

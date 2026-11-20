"""Copy-linked callback may-values keep their four bytes and row identity."""

import pytest

from tests.test_base_candidates import candidate_artifact
from tests.test_typed_index_symbol_compensation import exact


def program(*, middle='', second='move.l 8(a0,d6.w),8(a0)', prefix='', suffix='', stored=True):
    # A real nine-MOVE exchange. The field at +6 straddles the +4/+8 LONGs.
    return (' lea.l rows(pc),a0\n lea.l callback(pc),a1\n'
            + (' move.l a1,18(a0)\n' if stored else '')
            + prefix + ''' move.l (a0),d2
 move.l 0(a0,d6.w),(a0)
 move.l d2,0(a0,d6.w)
 move.l 4(a0),d2
 move.l 4(a0,d6.w),4(a0)
 move.l d2,4(a0,d6.w)
 move.l 8(a0),d2
''' + middle + ' ' + second + '\n move.l d2,8(a0,d6.w)\n' + suffix
            + ''' movea.l 6(a0),a1
 jsr (a1)
 rts
callback: moveq #7,d0
 rts
rows: dcb.b 36,0
''')


def resolved_calls(a):
    edges = a.query_payload('edges', limit=100)['items']
    sites={r['source_offset'] for r in a.query_payload('instructions',limit=100)['items'] if r['mnemonic']=='jsr'}
    return [e for e in edges if e['kind']=='call' and e['status']=='resolved' and e['source_offset'] in sites]


@pytest.mark.parametrize('prefix', ['', ' moveq #12,d6\n'])
def test_reloaded_selector_resolves_after_complete_exchange(tmp_path, prefix):
    with candidate_artifact(tmp_path, program(prefix=prefix), []) as (a, raw):
        calls = resolved_calls(a)
        assert len(calls)==1
        edges=a.query_payload('edges',source_offset=calls[0]['source_offset'],direction='outgoing',limit=100)['items']
        assert any(e['kind']=='call' and e['status']=='unresolved' for e in edges)
        summary=[s for s in a.analysis_payload()[0]['sections'][0]['function_summaries']
                 if s['entry_offset']==calls[0]['target_offset']]
        assert len(summary)==1 and summary[0]['terminal_reason']=='none'
        exact(a, raw, tmp_path)


@pytest.mark.parametrize('change', [
    {'second':'move.l 12(a0,d6.w),8(a0)'},  # other row/field
    {'second':'move.l 8(a0,d5.w),8(a0)'},   # unrelated selector
    {'second':'move.w 8(a0,d6.w),8(a0)'},   # only one byte of this half is replaced
    {'second':'move.l 8(a0,d6.w),10(a0)'},  # gap in destination
    {'second':'move.l 8(a0,d6.l),8(a0)'},   # different index extension
    {'middle':' moveq #12,d6\n'},           # changes index between fragments
    {'middle':' lea.l other(pc),a0\n'},    # changes owner
    {'middle':' move.l d0,(a3)\n'},         # unknown alias
    {'middle':' move.l d0,6(a0)\n'},        # overwrites already copied half
    {'middle':' move.l d0,8(a0,d6.w)\n'},   # overwrites unread source half
    {'middle':' bsr.w helper\n'},           # no invented memory/ABI preservation
    {'middle':' tst.w d7\n beq.w join\njoin:\n'},  # not a single straight-line path
    {'middle':' move.l (a0)+,d0\n'},         # owner update
    {'prefix':' moveq #0,d6\n'},            # known index cannot select row 1
    {'stored':False},                       # pointer-looking initial bytes are not a store
])
def test_incomplete_or_unproved_fragments_do_not_resolve(tmp_path, change):
    code=program(**change)+'other: dcb.b 36,0\nhelper: rts\n'
    with candidate_artifact(tmp_path, code, []) as (a, raw):
        assert not resolved_calls(a)
        exact(a, raw, tmp_path)


def test_alternate_entry_into_second_half_is_not_a_complete_copy(tmp_path):
    code=program(prefix=' tst.w d7\n beq.w second_half\n',middle='second_half:\n')
    with candidate_artifact(tmp_path,code,[]) as (a,raw):
        assert not resolved_calls(a)
        exact(a,raw,tmp_path)


def test_disjoint_store_does_not_destroy_the_copy_witness(tmp_path):
    with candidate_artifact(tmp_path,program(middle=' move.l d0,30(a0)\n'),[]) as (a,raw):
        assert len(resolved_calls(a))==1
        exact(a,raw,tmp_path)


def test_two_rows_keep_separate_values_not_cross_products_of_halves(tmp_path):
    code=program(prefix=' lea.l callback2(pc),a2\n move.l a2,30(a0)\n')+'callback2: moveq #9,d0\n rts\n'
    with candidate_artifact(tmp_path,code,[]) as (a,raw):
        calls=resolved_calls(a)
        assert len(calls)==2 and len({e['target_offset'] for e in calls})==2
        assert all(e['source_offset']==calls[0]['source_offset'] for e in calls)
        exact(a,raw,tmp_path)


def test_source_long_reads_must_fit_even_when_pointer_itself_fits(tmp_path):
    code=program().replace('dcb.b 36,0','dcb.b 22,0')
    with candidate_artifact(tmp_path,code,[]) as (a,raw):
        assert not resolved_calls(a)
        exact(a,raw,tmp_path)


def test_first_copy_cannot_destroy_its_unread_source_half(tmp_path):
    code=(program().replace('move.l 4(a0,d6.w),4(a0)','move.l 4(a0,d6.w),18(a0)')
          .replace('move.l 8(a0,d6.w),8(a0)','move.l 8(a0,d6.w),22(a0)')
          .replace('movea.l 6(a0),a1','movea.l 20(a0),a1'))
    with candidate_artifact(tmp_path,code,[]) as (a,raw):
        assert not resolved_calls(a)
        exact(a,raw,tmp_path)


def test_independently_registered_second_half_is_an_entry_barrier(tmp_path):
    with candidate_artifact(tmp_path,program(),[],
                            {'seeded_code_entrypoints':[{'hunk':0,'addr':40,'name':'separate_entry'}]}) as (a,raw):
        assert not resolved_calls(a)
        exact(a,raw,tmp_path)


def indexed_program(*,prefix='',middle='',source='d5',destination='d6'):
    return (' lea.l rows(pc),a0\n lea.l callback(pc),a1\n move.l a1,18(a0)\n'+prefix
            +f' move.l 0(a0,{source}.w),0(a0,{destination}.w)\n'
             f' move.l 4(a0,{source}.w),4(a0,{destination}.w)\n'+middle
            +f' move.l 8(a0,{source}.w),8(a0,{destination}.w)\n'
            +' movea.l 6(a0),a1\n jsr (a1)\n rts\ncallback: moveq #7,d0\n rts\nrows: dcb.b 36,0\n')


@pytest.mark.parametrize('prefix',['',' moveq #12,d5\n moveq #0,d6\n'])
def test_two_index_record_compaction_keeps_complete_pointer_origin(tmp_path,prefix):
    with candidate_artifact(tmp_path,indexed_program(prefix=prefix),[]) as (a,raw):
        assert len(resolved_calls(a))==1
        exact(a,raw,tmp_path)


@pytest.mark.parametrize('updates',[
    {'source':'d5','destination':'d5'},
    {'prefix':' moveq #0,d5\n moveq #0,d6\n'},
    {'prefix':' moveq #12,d5\n moveq #0,d6\n','middle':' move.l d2,d6\n'},
    {'prefix':' moveq #12,d5\n moveq #0,d6\n','middle':' move.l d2,d5\n'},
])
def test_index_identity_and_version_are_not_independent_numeric_choices(tmp_path,updates):
    with candidate_artifact(tmp_path,indexed_program(**updates),[]) as (a,raw):
        assert not resolved_calls(a)
        exact(a,raw,tmp_path)


@pytest.mark.parametrize('prefix',['',' moveq #12,d6\n'])
def test_reverse_exchange_through_successive_register_fragments(tmp_path,prefix):
    code=(program(prefix=prefix).replace('move.l a1,18(a0)','move.l a1,6(a0)')
          .replace('movea.l 6(a0),a1','movea.l 18(a0),a1'))
    with candidate_artifact(tmp_path,code,[]) as (a,raw):
        assert len(resolved_calls(a))==1
        exact(a,raw,tmp_path)


@pytest.mark.parametrize('middle',[
    ' move.l d3,d2\n',
    ' move.l d3,8(a0)\n',
    ' bsr.w helper\n',
])
def test_register_or_unread_memory_kills_prevent_half_recomposition(tmp_path,middle):
    code=(program(prefix=' moveq #12,d6\n').replace('move.l a1,18(a0)','move.l a1,6(a0)')
          .replace('movea.l 6(a0),a1','movea.l 18(a0),a1')
          .replace(' move.l d2,4(a0,d6.w)',middle+' move.l d2,4(a0,d6.w)'))
    code+='helper: rts\n'
    with candidate_artifact(tmp_path,code,[]) as (a,raw):
        assert not resolved_calls(a)
        exact(a,raw,tmp_path)


def test_register_to_register_byte_transport_retains_one_origin(tmp_path):
    code=(program(prefix=' moveq #12,d6\n').replace('move.l a1,18(a0)','move.l a1,6(a0)')
          .replace('movea.l 6(a0),a1','movea.l 18(a0),a1')
          .replace(' move.l d2,4(a0,d6.w)',' move.l d2,d3\n move.l d3,4(a0,d6.w)'))
    with candidate_artifact(tmp_path,code,[]) as (a,raw):
        assert len(resolved_calls(a))==1
        exact(a,raw,tmp_path)


def test_halves_from_distinct_rows_do_not_form_a_new_numeric_pointer(tmp_path):
    code=''' lea.l rows(pc),a0
 lea.l callback(pc),a1
 move.l a1,6(a0)
 lea.l other(pc),a1
 move.l a1,30(a0)
 move.l 4(a0),d2
 move.l d2,16(a0)
 move.l 32(a0),d2
 move.l d2,20(a0)
 movea.l 18(a0),a1
 jsr (a1)
 rts
callback: moveq #7,d0
 rts
other: moveq #9,d0
 rts
rows: dcb.b 36,0
'''
    with candidate_artifact(tmp_path,code,[]) as (a,raw):
        assert not resolved_calls(a)
        exact(a,raw,tmp_path)


def test_aligned_whole_pointer_and_data_register_use_the_same_byte_domain(tmp_path):
    code=''' lea.l rows(pc),a0
 lea.l callback(pc),a1
 move.l a1,(a0)
 move.l (a0),d2
 move.l d2,0(a0,d6.w)
 movea.l 12(a0),a1
 jsr (a1)
 rts
callback: moveq #7,d0
 rts
rows: dcb.b 24,0
'''
    with candidate_artifact(tmp_path,code,[]) as (a,raw):
        assert len(resolved_calls(a))==1
        exact(a,raw,tmp_path)


@pytest.mark.parametrize(('body', 'memory'), [
    ('move.w #0,count.l', 'explicit'),
    ('move.w #0,0(a3,d2.w)', 'unknown'),
])
def test_fragment_target_effects_do_not_imply_post_return_count_preservation(tmp_path, body, memory):
    code=indexed_program().replace('callback: moveq #7,d0\n rts\n',
                                  'callback: moveq #0,d7\n '+body+'\n rts\ncount: dc.w 0\n')
    with candidate_artifact(tmp_path,code,[]) as (a,raw):
        call,=resolved_calls(a)
        summaries=a.analysis_payload()[0]['sections'][0]['function_summaries']
        summary,=[s for s in summaries if s['entry_offset']==call['target_offset']]
        assert summary['terminal_reason']=='none'
        effects=summary['effects']
        assert effects['memory']['state']==memory
        if memory=='explicit':assert effects['memory']['effects']
        assert any(r['location']['register']=='D7' and r['effect']=='clobbered'
                   for r in effects['registers']['locations'])
        edges=a.query_payload('edges',source_offset=call['source_offset'],direction='outgoing',limit=100)['items']
        assert any(e['kind']=='call'and e['status']=='unresolved'for e in edges)
        exact(a,raw,tmp_path)

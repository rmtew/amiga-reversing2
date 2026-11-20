"""Accepted indirect-call entries share the ordinary body solver, not closure."""

import pytest

from tests.test_base_candidates import candidate_artifact
from tests.test_typed_index_symbol_compensation import exact


def entry_summary(analysis, entry):
    return [s for s in analysis['sections'][0]['function_summaries']
            if s['callable_kind']=='direct' and s['entry_offset']==entry]


def test_accepted_indirect_leaf_gets_an_individual_effect_summary(tmp_path):
    with candidate_artifact(tmp_path,' lea.l callback(pc),a1\n jsr (a1)\n rts\ncallback: moveq #7,d0\n rts\n',[]) as (a,raw):
        analysis=a.analysis_payload()[0]
        summary,=entry_summary(analysis,8)
        assert summary['terminal_reason']=='none'
        effects=summary['effects']
        regs={r['location']['register']:r['effect'] for r in effects['registers']['locations']}
        assert regs['D0']=='clobbered' and regs['A0']=='preserved'
        assert effects['memory']=={'state':'explicit','effects':[]}
        assert effects['escapes']=={'state':'explicit','escapes':[]}
        uses=analysis['sections'][0]['function_summary_uses']
        assert any(u['function_summary_id']==summary['function_summary_id'] and u['caller_offset']==4 for u in uses)
        exact(a,raw,tmp_path)


@pytest.mark.parametrize(('body','memory'),[
    ('move.w d0,cell.l\n rts\ncell: dc.w 0','explicit'),
    ('move.w d0,(a0)\n rts','explicit'),
    ('move.w d0,0(a0,d1.w)\n rts','unknown'),
])
def test_callback_writes_use_existing_effect_subjects(tmp_path,body,memory):
    with candidate_artifact(tmp_path,' lea.l callback(pc),a1\n jsr (a1)\n rts\ncallback: '+body+'\n',[]) as (a,raw):
        summary,=entry_summary(a.analysis_payload()[0],8)
        assert summary['terminal_reason']=='none'
        assert summary['effects']['memory']['state']==memory
        if memory=='explicit':assert summary['effects']['memory']['effects']
        exact(a,raw,tmp_path)


def test_duplicate_sites_deduplicate_entry_without_losing_uses(tmp_path):
    code=' lea.l callback(pc),a1\n jsr (a1)\n lea.l callback(pc),a1\n jsr (a1)\n rts\ncallback: rts\n'
    with candidate_artifact(tmp_path,code,[]) as (a,raw):
        analysis=a.analysis_payload()[0];summary,=entry_summary(analysis,14)
        uses=[u for u in analysis['sections'][0]['function_summary_uses']
              if u['function_summary_id']==summary['function_summary_id']]
        assert {u['caller_offset']for u in uses}=={4,10}
        exact(a,raw,tmp_path)


def test_known_target_does_not_close_other_unknown_calls(tmp_path):
    code=' lea.l callback(pc),a1\n jsr (a1)\n jsr (a3)\n rts\ncallback: rts\n'
    with candidate_artifact(tmp_path,code,[]) as (a,raw):
        analysis=a.analysis_payload()[0];assert len(entry_summary(analysis,10))==1
        edges=a.query_payload('edges',source_offset=6,direction='outgoing',limit=100)['items']
        assert any(e['kind']=='call'and e['status']=='unresolved'for e in edges)
        assert not any(e['kind']=='call'and e['status']=='resolved'for e in edges)
        exact(a,raw,tmp_path)


@pytest.mark.parametrize('body',['jsr (a3)\n rts','trap #0\n rts','rte','rtr'])
def test_unsupported_target_body_does_not_gain_effect_guarantees(tmp_path,body):
    with candidate_artifact(tmp_path,' lea.l callback(pc),a1\n jsr (a1)\n rts\ncallback: '+body+'\n',[]) as (a,raw):
        summary,=entry_summary(a.analysis_payload()[0],8)
        assert summary['terminal_reason']!='none'
        assert summary['effects']['memory']['state']!='explicit'
        exact(a,raw,tmp_path)


@pytest.mark.parametrize('prefix',['lea.l callback(pc),a1','jmp (a1)'])
def test_address_taken_or_unresolved_jump_alone_is_not_a_call_entry(tmp_path,prefix):
    with candidate_artifact(tmp_path,prefix+'\n rts\ncallback: rts\n',[]) as (a,raw):
        assert not a.analysis_payload()[0]['sections'][0]['function_summaries']
        exact(a,raw,tmp_path)


def test_callback_direct_helper_reuses_existing_call_graph(tmp_path):
    code=' lea.l callback(pc),a1\n jsr (a1)\n rts\ncallback: bsr.w helper\n rts\nhelper: moveq #3,d2\n rts\n'
    with candidate_artifact(tmp_path,code,[]) as (a,raw):
        analysis=a.analysis_payload()[0];summary,=entry_summary(analysis,8)
        assert summary['terminal_reason']=='none'
        regs={r['location']['register']:r['effect']for r in summary['effects']['registers']['locations']}
        assert regs['D2']=='clobbered'and regs['A0']=='preserved'
        exact(a,raw,tmp_path)


def test_known_indirect_jump_is_not_misclassified_as_a_call(tmp_path):
    with candidate_artifact(tmp_path,' lea.l callback(pc),a1\n jmp (a1)\ncallback: rts\n',[]) as (a,raw):
        assert not a.analysis_payload()[0]['sections'][0]['function_summaries']
        exact(a,raw,tmp_path)


def test_configured_entry_summary_keeps_precedence_and_use_identity(tmp_path):
    from amiga_reversing.disasm.manual_action_catalog import (
        target_catalog_manual_payload,
    )
    _,payload=target_catalog_manual_payload('target.function_summary.add',
        {'hunk':0,'callable_kind':'direct','entry_offset':8,'inputs':[],
         'note':'Deliberately unknown effects'})
    configured=payload['function_summary'];identity=configured['function_summary_id']
    with candidate_artifact(tmp_path,' lea.l callback(pc),a1\n jsr (a1)\n rts\ncallback: rts\n',[],
                            {'function_summaries':[configured]}) as (a,raw):
        analysis=a.analysis_payload()[0];summary,=entry_summary(analysis,8)
        assert summary['function_summary_id']==identity
        assert summary['effects']['memory']['state']=='unknown'
        assert any(u['function_summary_id']==identity and u['caller_offset']==4
                   for u in analysis['sections'][0]['function_summary_uses'])
        exact(a,raw,tmp_path)


def test_two_known_targets_have_separate_effects_without_call_closure(tmp_path):
    code=(' tst.w d7\n beq.s other\n lea.l first(pc),a1\n bra.s dispatch\n'
          'other: lea.l second(pc),a1\ndispatch: jsr (a1)\n rts\n'
          'first: moveq #1,d0\n rts\nsecond: move.w d0,(a0)\n rts\n')
    with candidate_artifact(tmp_path,code,[]) as (a,raw):
        analysis=a.analysis_payload()[0]
        first,=entry_summary(analysis,18);second,=entry_summary(analysis,22)
        assert first['effects']['memory']=={'state':'explicit','effects':[]}
        assert second['effects']['memory']['effects']
        edges=a.query_payload('edges',source_offset=14,direction='outgoing',limit=100)['items']
        assert {e['target_offset']for e in edges if e['kind']=='call'and e['status']=='resolved'}=={18,22}
        assert any(e['kind']=='call'and e['status']=='unresolved'for e in edges)
        # There is no summary whose identity means the writable dispatch is closed.
        assert all(s['callable_kind']=='direct' for s in analysis['sections'][0]['function_summaries'])
        exact(a,raw,tmp_path)


@pytest.mark.parametrize('body',['rte','rtr'])
def test_direct_entries_use_the_same_ordinary_return_contract(tmp_path,body):
    with candidate_artifact(tmp_path,' bsr.w helper\n rts\nhelper: '+body+'\n',[]) as (a,raw):
        summary,=entry_summary(a.analysis_payload()[0],6)
        assert summary['terminal_reason']!='none'
        assert summary['effects']['memory']['state']!='explicit'
        exact(a,raw,tmp_path)

"""Only provenance-marked inherited opaque bytes coexist with proved records."""

import pytest

from tests.test_structural_record_views import fixture


def check(tmp_path,protection=None):
 properties={'name':None,'subtype':'opaque_data','source_id':'fixture-import',
             'citation':'Inherited preliminary opaque classification'}
 if protection=='named':properties['name']='ownedBytes'
 if protection=='comment':properties['comment']='Independent interpretation'
 if protection=='validated':properties['review_status']='validated'
 if protection=='manual':properties.update(source_id='manual_action_log',citation='manual_action_log:owned')
 if protection=='owner':properties['owner_action_id']='prior-owner'
 if protection=='parents':properties['parent_evidence_ids']=['prior-evidence']
 if protection=='evidence':properties['source_evidence_id']='confirmed-evidence'
 if protection=='typed':properties['c_type']='BYTE'
 code=' lea.l TABLE(pc),a6\n andi.w #1,d0\n mulu.w #6,d0\n move.w 2(a6,d0.w),d1\n rts'
 return fixture(tmp_path,unsigned=True,raw=(126,24,'byte'),raw_properties=properties,code=code)


def test_weak_opaque_crossing_keeps_the_checked_array_root(tmp_path):
 text,rows=check(tmp_path)
 uses=[a for r in rows for a in r['typed_accesses']]
 assert len(uses)==1 and uses[0]['field_name']=='y'
 assert uses[0]['word_index']['record_count']==3
 assert 'Point_y'in text


@pytest.mark.parametrize('protection',['named','comment','validated','manual','owner','parents','evidence','typed'])
def test_stronger_opaque_fact_is_not_discarded(tmp_path,protection):
 _,rows=check(tmp_path,protection)
 assert not [a for r in rows for a in r['typed_accesses']]

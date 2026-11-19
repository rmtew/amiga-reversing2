"""An untyped directive's width is not a conflicting signed-value contract."""

import pytest

from tests.test_structural_record_views import fixture


@pytest.mark.parametrize(('size','width','raw','field'),[
 (6,'w',(128,18,'word'),'y'),
 (6,'w',(126,20,'word'),'y'),
 (4,'l',(124,16,'long'),'value'),
])
def test_complete_unsigned_fields_preserve_raw_primitive_views(tmp_path,size,width,raw,field):
 displacement=2 if size==6 else 0
 code=f' lea.l TABLE(pc),a6\n andi.w #1,d0\n mulu.w #{size},d0\n move.{width} {displacement}(a6,d0.w),d1\n rts'
 text,rows=fixture(tmp_path,unsigned=True,record_size=size,raw=raw,code=code,scalar_long=size==4)
 fields=[a for r in rows for a in r['typed_accesses']if a['field_name']==field]
 assert len(fields)==1
 assert f'Point_{field}'in text


@pytest.mark.parametrize(('raw','conflict'),[
 ((129,18,'word'),False),
 ((128,16,'long'),False),
 ((128,18,'word'),True),
])
def test_width_alignment_and_independent_typed_conflicts_still_refuse(tmp_path,raw,conflict):
 code=' lea.l TABLE(pc),a6\n andi.w #1,d0\n mulu.w #6,d0\n move.w 2(a6,d0.w),d1\n rts'
 _,rows=fixture(tmp_path,unsigned=True,raw=raw,conflict=conflict,code=code)
 assert not [a for r in rows for a in r['typed_accesses']]


def test_explicit_signed_type_is_not_treated_as_an_untyped_width(tmp_path):
 code=' lea.l TABLE(pc),a6\n andi.w #1,d0\n mulu.w #6,d0\n move.w 2(a6,d0.w),d1\n rts'
 _,rows=fixture(tmp_path,unsigned=True,raw=(126,20,'word'),raw_properties={'c_type':'WORD'},code=code)
 assert not [a for r in rows for a in r['typed_accesses']]

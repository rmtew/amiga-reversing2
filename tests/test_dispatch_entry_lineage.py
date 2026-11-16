"""A proved dispatch path retains entry lineage through absolute tail bridges."""
import pytest
from tests.test_app_cursor_propagation import cursor_artifact
from amiga_reversing.disasm import c_backend

BODY='''move.w offsets(pc,d0.w),d0
 jmp offsets(pc,d0.w)
offsets:
 dc.w bridge-offsets,done-offsets
bridge:
 bra.w tail
done:
 rts
tail:
 jmp destination.l
destination:
 moveq #42,d1
 rts'''

@pytest.mark.parametrize('preknown',((),(12,),(18,),(12,18)))
def test_word_dispatch_keeps_established_lineage_through_absolute_bridge(tmp_path,preknown):
 # Table starts at8, relative bridge at12 and absolute tail at18.
 artifact,original=cursor_artifact(tmp_path,BODY,regions=False,metadata_extra={'seeded_code_entrypoints':[dict(hunk=0,addr=at,name='preknown_'+str(at))for at in preknown]})
 try:
  analysis=artifact.analysis_payload()[0]['sections'][0]
  target=original.index(bytes.fromhex('722a4e75'))
  assert any(r['start_offset']<=target<r['end_offset']for r in analysis['accepted_code_runs']),analysis['accepted_code_runs']
  text=artifact.inline_source_text_with_profile()[0]
  rebuilt,_=c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',text)
  assert rebuilt==original
 finally:artifact.close()


def test_source_only_dispatch_roots_bind_code_without_runtime_entry_lineage(tmp_path):
 artifact,original=cursor_artifact(tmp_path,'rts\n'+BODY,regions=False,metadata_extra={'seeded_code_entrypoints':[dict(hunk=0,addr=2,name='unphased_dispatch'),dict(hunk=0,addr=20,name='unphased_tail')]})
 try:
  section=artifact.analysis_payload()[0]['sections'][0];target=original.index(bytes.fromhex('722a4e75'))
  assert any(r['start_offset']<=target<r['end_offset']for r in section['accepted_code_runs'])
  refs=[r for r in section['code_start_refs'] if r['offset']==target]
  assert refs and all(r['runtime_address'] is None for r in refs)
  assert {r['evidence_kind'] for r in refs}=={'direct_control_target'}
  text=artifact.inline_source_text_with_profile()[0]
  rebuilt,_=c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',text)
  assert rebuilt==original
 finally:artifact.close()


@pytest.mark.parametrize('body,extra,target',[
 ('rts\n jmp $1009.l\n move.l #$12345678,d0\n rts',
  {'seeded_code_entrypoints':[dict(hunk=0,addr=2,name='bridge'),dict(hunk=0,addr=8,name='known')]},9),
 ('rts\n jmp $1008.l\n dc.w $FFFF\n rts',
  {'seeded_code_entrypoints':[dict(hunk=0,addr=2,name='bridge')]},8),
 ('rts\n jmp $1008.l\n moveq #42,d1\n rts',
  {'seeded_code_entrypoints':[dict(hunk=0,addr=2,name='bridge')],
   'seeded_entities':[dict(type='data',hunk=0,addr=8,end=12,unit='byte',name='opaque')]},8),
])
def test_source_bound_control_preserves_ownership_and_decode_guards(tmp_path,body,extra,target):
 artifact,original=cursor_artifact(tmp_path,body,regions=False,metadata_extra=extra)
 try:
  section=artifact.analysis_payload()[0]['sections'][0]
  assert not any(r['offset']==target for r in section['code_start_refs'])
  if target%2==0:
   assert not any(r['start_offset']<=target<r['end_offset']for r in section['accepted_code_runs'])
  text=artifact.inline_source_text_with_profile()[0]
  rebuilt,_=c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',text)
  assert rebuilt==original
 finally:artifact.close()


def test_source_bound_absolute_target_cannot_split_a_known_instruction(tmp_path):
 artifact,original=cursor_artifact(tmp_path,'rts\n jmp $100A.l\n move.l #$12345678,d0\n rts',regions=False,
  metadata_extra={'seeded_code_entrypoints':[dict(hunk=0,addr=8,name='known_instruction'),dict(hunk=0,addr=2,name='bridge')]})
 try:
  section=artifact.analysis_payload()[0]['sections'][0]
  assert all(r['start_offset']!=10 for r in section['blocks'])
  assert not [r for r in section['code_start_refs'] if r['offset']==10]
  text=artifact.inline_source_text_with_profile()[0]
  assert 'move.l #$12345678,d0' in text
  assert c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',text)[0]==original
 finally:artifact.close()

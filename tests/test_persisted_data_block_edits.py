"""Committed owners remain editable; projected facts retain their contracts."""
import json
from dataclasses import replace
import pytest
from amiga_reversing.disasm.effective_metadata import effective_metadata_text,_merge_seeded_entity_projection
from amiga_reversing.disasm.manual_actions import append_manual_action,load_manual_projection,ManualActionKind
from amiga_reversing.disasm.manual_action_catalog import target_catalog_manual_payload
from amiga_reversing.disasm.binary_source import resolve_target_binary_source
from amiga_reversing.disasm.target_metadata import SeededEntityMetadata
from tests.test_manual_action_log import _write_raw_source


def seed(**extra):
 return SeededEntityMetadata.from_dict(dict(addr=0,end=4,hunk=0,name='directory',type='data',unit='long',seed_origin='manual_analysis',review_status='seeded',citation='original',**extra))

@pytest.mark.parametrize('domain,group',[('mapped_source',None),('runtime_only','buffers')])
def test_partial_projection_retains_pointer_owner_and_evidence_contracts(domain,group):
 original=seed(value_kind='struct_pointer',pointer_struct='Header',pointer_address_domain=domain,pointer_symbol_group=group,source_owner_start=0,source_owner_size=8,owner_action_id='binding-a',source_evidence_id='proof-a',parent_evidence_ids=['parent-a'])
 result=_merge_seeded_entity_projection(original,seed())
 assert result==replace(original,citation='original')
 updated=replace(original,name='expanded',source_owner_size=12,owner_action_id='binding-b',source_evidence_id='proof-b',parent_evidence_ids=('parent-b',))
 assert _merge_seeded_entity_projection(original,updated)==updated


def test_scalar_reinterpretation_clears_the_previous_pointer_domain():
 original=seed(value_kind='struct_pointer',pointer_struct='Header',pointer_address_domain='mapped_source')
 result=_merge_seeded_entity_projection(original,seed(value_kind='scalar',c_type='LONG'))
 assert result.value_kind=='scalar' and result.pointer_struct is None and result.pointer_address_domain is None


def persisted_owner(path):
 _write_raw_source(path,path/'binary.bin',bytes.fromhex('0000001000000014000000184e714e71')+b'Alpha\0Beta\0Gamma\0'+bytes(16))
 source=resolve_target_binary_source(path)
 def append(command,parameters):
  kind,payload=target_catalog_manual_payload(command,parameters)
  return append_manual_action(path,kind=ManualActionKind(kind),binary_source=source,payload=payload)
 append('target.custom_struct.add',dict(name='Ref',size=4,fields=[dict(name='text',offset=0,size=4,type='APTR',value_kind='target_pointer',pointer_address_domain='mapped_source')]))
 append('target.data_block.layout.create',dict(layout_id='directory',hunk=0,source_start=0,source_end=8,name='first_two',default_unit='long'))
 append('target.data_block.element.set',dict(layout_id='directory',offset=0,width=8,kind='array',array_count=2,array_stride=4,binding_kind='custom_struct',type_id='Ref'))
 (path/'target_metadata.json').write_text(effective_metadata_text(path))
 (path/'manual_actions.jsonl').unlink()
 return source,append


def test_committed_owner_resize_rename_rebind_and_undo_preserve_its_fields(tmp_path):
 source,append=persisted_owner(tmp_path)
 changes=[append('target.data_block.layout.resize',dict(layout_id='directory',expected_source_end=8,source_end=12)),
 append('target.data_block.layout.rename',dict(layout_id='directory',name='all_three')),
 append('target.data_block.element.set',dict(layout_id='directory',offset=0,width=12,kind='array',array_count=3,array_stride=4,binding_kind='custom_struct',type_id='Ref'))]
 value=json.loads(effective_metadata_text(tmp_path));layout=value['data_block_layouts'][0]
 assert (layout['name'],layout['source_end'],layout['elements'][0]['array_count'])==('all_three',12,3)
 pointers=[e for e in value['seeded_entities']if e.get('field_name')=='text']
 assert len(pointers)==3 and all(e['value_kind']=='target_pointer' and e['pointer_address_domain']=='mapped_source'for e in pointers)
 assert pointers[0]['source_owner_size']==12 and pointers[0]['name']=='all_three'
 projection=load_manual_projection(tmp_path,binary_source=source)
 assert len(projection.data_block_layouts)==1
 for action in reversed(changes):
  append_manual_action(tmp_path,kind=ManualActionKind.UNDO_ACTION,payload={'undoes_action_id':action['action_id']},binary_source=source)
 restored=json.loads(effective_metadata_text(tmp_path))['data_block_layouts'][0]
 assert (restored['name'],restored['source_end'],restored['elements'][0]['array_count'])==('first_two',8,2)
 for action in changes:
  append_manual_action(tmp_path,kind=ManualActionKind.REDO_ACTION,payload={'redoes_action_id':action['action_id']},binary_source=source)
 assert json.loads(effective_metadata_text(tmp_path))['data_block_layouts'][0]['source_end']==12


def test_committed_owner_refuses_stale_or_truncating_resize_without_a_log_write(tmp_path):
 source,append=persisted_owner(tmp_path)
 for end,expected in ((12,9),(4,8)):
  with pytest.raises(ValueError):append('target.data_block.layout.resize',dict(layout_id='directory',expected_source_end=expected,source_end=end))
 assert not(tmp_path/'manual_actions.jsonl').exists()


def test_committed_neighbors_and_duplicate_creation_are_checked_before_writing(tmp_path):
 source,append=persisted_owner(tmp_path)
 value=json.loads((tmp_path/'target_metadata.json').read_text())
 other=dict(value['data_block_layouts'][0]);other.update(layout_id='neighbor',source_start=8,source_end=12,name='neighbor',elements=[])
 value['data_block_layouts'].append(other);(tmp_path/'target_metadata.json').write_text(json.dumps(value))
 with pytest.raises(ValueError,match='overlap'):
  append('target.data_block.layout.resize',dict(layout_id='directory',expected_source_end=8,source_end=12))
 with pytest.raises(ValueError,match='already uses'):
  append('target.data_block.layout.create',dict(layout_id='directory',hunk=0,source_start=0,source_end=8,name='duplicate'))
 assert not(tmp_path/'manual_actions.jsonl').exists()


def test_unrelated_edit_does_not_duplicate_committed_reference_presentations(tmp_path):
 from tests.test_absolute_array_data_refs import _actions
 from amiga_reversing.disasm.effective_metadata import effective_target_metadata
 from amiga_reversing.disasm.target_metadata import write_target_metadata
 _actions(tmp_path,4)
 original=effective_target_metadata(tmp_path)
 write_target_metadata(tmp_path,original)
 records=[{'record':'manual_action_log_header','version':1,'target_identity':{}},
 {'record':'manual_action','action_id':'unrelated','sequence':1,'created_at':'2026-11-15T00:00:00+00:00',
 'kind':'create_manual_data_block_layout','data_block_layout':dict(layout_id='other',hunk=0,source_start=100,source_end=104,default_unit='long')}]
 (tmp_path/'manual_actions.jsonl').write_text('\n'.join(json.dumps(x)for x in records)+'\n')
 actual=effective_target_metadata(tmp_path)
 assert actual.manual_representations==original.manual_representations
 assert len(actual.manual_representations)==8

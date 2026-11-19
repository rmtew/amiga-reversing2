import pytest

from tests.test_base_candidates import candidate_artifact
from tests.test_typed_index_symbol_compensation import exact


def metadata(fields=None,count=8):
 return {'custom_structs':[{'name':'Patterns','size':16,'fields':fields or [{'name':f'w{i}','type':'UWORD','offset':2*i,'size':2}for i in range(8)]}], 'entry_register_seeds':[{'hunk':0,'entry_offset':0,'register':'A0','kind':'struct_ptr','struct_name':'Patterns','array_length':count,'note':'Bounded synthetic array'}]}

@pytest.mark.parametrize('prefix',['andi.w #7,d0\n lsl.w #4,d0','move.w #16,d0','andi.w #31,d0\n lsl.w #4,d0'])
def test_compound_word_pair_is_an_address_anchor_only(tmp_path,prefix):
 with candidate_artifact(tmp_path,prefix+'\n move.l 4(a0,d0.w),d1\n rts',[],metadata(count=32 if '#31' in prefix else 8))as(a,raw):
  refs=a.analysis_payload()[0]['sections'][0]['recovered_platform_typed_accesses']
  assert len(refs)==1
  proof=refs[0]['word_index']
  assert proof['address_anchor_only'] and proof['primitive_span_fields']==2
  assert proof['access_width']==4 and refs[0]['field_size']==2
  assert 'Patterns_w2' in exact(a,raw,tmp_path)


@pytest.mark.parametrize('middle',['', 'move.w d0,d2\n move.w d2,d0', 'bsr.w keep'])
def test_mask_domain_and_preserved_index_keep_complete_span(tmp_path,middle):
 code='andi.w #31,d0\n lsl.w #4,d0\n'+middle+'\n move.l 4(a0,d0.w),d1\n rts\nkeep: rts'
 with candidate_artifact(tmp_path,code,[],metadata(count=32))as(a,raw):
  refs=a.analysis_payload()[0]['sections'][0]['recovered_platform_typed_accesses']
  assert len(refs)==1 and refs[0]['word_index']['evidence']=='bounded_cfg_mask'
  assert refs[0]['word_index']['primitive_span']==[{'offset':4,'size':2},{'offset':6,'size':2}]
  query=a.query_payload('instructions',limit=100)
  use=next(r for r in query['items']if r['mnemonic']=='move'and r['text'].endswith(',d1'))
  assert use['typed_accesses'][0]['word_index']['address_anchor_only']
  fields=a.query_payload('fields',struct_name='Patterns',field_offset=6,limit=100)
  assert fields['total']==1 and fields['items'][0]['field_name']=='w3'
  assert fields['items'][0]['component_of_primitive_span']
  assert fields['items'][0]['address_anchor_field_offset']==4
  first=a.query_payload('fields',struct_name='Patterns',offset=0,limit=1)
  second=a.query_payload('fields',struct_name='Patterns',offset=1,limit=1)
  assert first['total']==second['total']==2 and first['has_more'] and not second['has_more']
  assert [first['items'][0]['field_offset'],second['items'][0]['field_offset']]==[4,6]
  assert 'Patterns_w2' in exact(a,raw,tmp_path)


@pytest.mark.parametrize('bad',['gap','pointer_tail','nested_tail','overlap','partial','end','extent','index','call'])
@pytest.mark.parametrize('finite',[False,True])
def test_nonpartition_or_unproved_domain_has_no_span(tmp_path,bad,finite):
 fields=metadata()['custom_structs'][0]['fields']
 access=4;count=32;middle=''
 if bad=='gap':fields=[f for f in fields if f['offset']!=6]
 if bad=='pointer_tail':
  fields=[f for f in fields if f['offset']not in(6,8)]
  fields.append({'name':'pointer','type':'APTR','offset':6,'size':4,'value_kind':'target_pointer','pointer_address_domain':'mapped_source'})
 if bad=='nested_tail':fields[3].update(type='WORD',struct='Nested')
 if bad=='overlap':fields.append({'name':'overlay','type':'LONG','offset':4,'size':4})
 if bad=='partial':access=5
 if bad=='end':access=14
 if bad=='extent':count=31 if not finite else 1
 if bad=='index':middle='move.w d7,d0'
 if bad=='call':middle='jsr $4000.l'
 prefix='move.w #16,d0'if finite else'andi.w #31,d0\n lsl.w #4,d0'
 extra=metadata(fields,count)
 if bad=='nested_tail':extra['custom_structs'].append({'name':'Nested','size':2,'fields':[{'name':'value','type':'WORD','offset':0,'size':2}]})
 with candidate_artifact(tmp_path,prefix+'\n'+middle+f'\n move.l {access}(a0,d0.w),d1\n rts',[],extra)as(a,raw):
  refs=a.analysis_payload()[0]['sections'][0]['recovered_platform_typed_accesses']
  assert not refs
  exact(a,raw,tmp_path)


def test_four_byte_fields_form_a_complete_long_address_span(tmp_path):
 fields=[{'name':f'b{i}','type':'UBYTE','offset':i,'size':1}for i in range(16)]
 with candidate_artifact(tmp_path,'andi.w #31,d0\n lsl.w #4,d0\n move.l 4(a0,d0.w),d1\n rts',[],metadata(fields,32))as(a,raw):
  r=a.analysis_payload()[0]['sections'][0]['recovered_platform_typed_accesses'][0]
  assert r['word_index']['primitive_span_fields']==4
  assert r['field_size']==1
  exact(a,raw,tmp_path)


def test_loaded_compound_bits_do_not_establish_a_pointee_type(tmp_path):
 with candidate_artifact(tmp_path,'move.w #0,d0\n movea.l 4(a0,d0.w),a1\n move.w 2(a1),d2\n rts',[],metadata())as(a,raw):
  rows=a.query_payload('instructions',limit=100)['items']
  load=next(r for r in rows if r['mnemonic']=='movea')
  assert load['typed_accesses'][0]['word_index']['address_anchor_only']
  following=next(r for r in rows if r['mnemonic']=='move')
  assert not following['typed_accesses']
  exact(a,raw,tmp_path)


def test_single_pointer_field_retains_its_existing_noncompound_contract(tmp_path):
 fields=[f for f in metadata()['custom_structs'][0]['fields']if f['offset']not in(4,6)]
 fields.append({'name':'pointer','type':'APTR','offset':4,'size':4,'value_kind':'target_pointer','pointer_address_domain':'mapped_source'})
 with candidate_artifact(tmp_path,'andi.w #31,d0\n lsl.w #4,d0\n move.l 4(a0,d0.w),d1\n rts',[],metadata(fields,32))as(a,raw):
  r=a.analysis_payload()[0]['sections'][0]['recovered_platform_typed_accesses'][0]
  assert r['field_name']=='pointer' and r['field_size']==4
  assert 'address_anchor_only'not in r['word_index']
  exact(a,raw,tmp_path)


def test_another_operand_cannot_auto_update_the_span_base(tmp_path):
 with candidate_artifact(tmp_path,'andi.w #31,d0\n lsl.w #4,d0\n move.l (a0)+,4(a0,d0.w)\n rts',[],metadata(count=32))as(a,raw):
  refs=a.analysis_payload()[0]['sections'][0]['recovered_platform_typed_accesses']
  assert not [r for r in refs if r.get('word_index',{}).get('address_anchor_only')]
  exact(a,raw,tmp_path)


def test_compound_write_names_an_address_without_one_wider_field(tmp_path):
 with candidate_artifact(tmp_path,'andi.w #31,d0\n lsl.w #4,d0\n move.l d1,4(a0,d0.w)\n rts',[],metadata(count=32))as(a,raw):
  r=a.analysis_payload()[0]['sections'][0]['recovered_platform_typed_accesses'][0]
  assert r['operand_index']==1 and r['field_size']==2
  assert r['word_index']['address_anchor_only'] and r['word_index']['access_width']==4
  exact(a,raw,tmp_path)


@pytest.mark.parametrize(('access','wanted'),[(4,True),(6,False)])
def test_inherited_span_keeps_one_declaration_owner(tmp_path,access,wanted):
 extra=metadata(count=32)
 fields=extra['custom_structs'][0]['fields']
 extra['custom_structs']=[{'name':'Prefix','size':8,'fields':fields[:4]},
                         {'name':'Patterns','size':16,'base_struct':'Prefix','base_offset':8,'fields':fields[4:]}]
 with candidate_artifact(tmp_path,f'andi.w #31,d0\n lsl.w #4,d0\n move.l {access}(a0,d0.w),d1\n rts',[],extra)as(a,raw):
  refs=a.analysis_payload()[0]['sections'][0]['recovered_platform_typed_accesses']
  assert bool(refs)==wanted
  if wanted:
   assert refs[0]['owner_struct_name']=='Prefix' and refs[0]['root_struct_name']=='Patterns'
   assert refs[0]['word_index']['address_anchor_only']
   used=a.query_payload('fields',struct_name='Patterns',field_offset=6,limit=100)
   assert used['items'][0]['owner_struct_name']=='Prefix'and used['items'][0]['field_name']=='w3'
  exact(a,raw,tmp_path)

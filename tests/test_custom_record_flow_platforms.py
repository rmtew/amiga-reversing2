"""Declared custom-record flow is portable; Amiga hardware inference is not."""
import json,os
from pathlib import Path
import pytest
from amiga_reversing.disasm import c_backend
from amiga_reversing.disasm.binary_source import RawBinarySource,RawAddressModel,BinarySourceKind

class STRaw(RawBinarySource):
 @property
 def backend_name(self):return 'atari-st-raw'

FIXTURES={
 'fields':'btst #4,2(a4)\nmove.w 22(a4),d1\nmove.w 24(a4),d2\nmove.w 26(a4),d3',
 'cursor':'movea.l a4,a0\nlea.l 22(a0),a1\nmove.w (a1),d0',
 'hardware':'lea.l $00DFF000.l,a5\nmove.w $0180(a5),d0\nmovea.l 4.w,a6\naddq.b #1,$127(a6)\nmove.w 22(a4),d1',
}

def artifact(tmp_path,platform,body,seed=True,builtin=False):
 tmp_path.mkdir(parents=True,exist_ok=True)
 raw,_=c_backend.assemble_platform_source_text_with_c_backend('amiga-raw','section code,code\norg $1000\n'+body+'\nrts\n')
 binary=tmp_path/'synthetic.bin';binary.write_bytes(raw)
 fields=[dict(name='kind',type='UWORD',offset=0,size=2),dict(name='flags',type='UBYTE',offset=2,size=1),dict(name='x',type='WORD',offset=22,size=2),dict(name='y',type='WORD',offset=24,size=2),dict(name='z',type='WORD',offset=26,size=2)]
 seeds=[dict(hunk=0,entry_offset=0,register='A4',kind='struct_ptr',struct_name='Record',note='Explicit original input contract')] if seed else []
 if builtin:seeds.append(dict(hunk=0,entry_offset=0,register='A6',kind='struct_ptr',struct_name='ExecBase',note='Platform-specific seed'))
 meta=tmp_path/'metadata.json';meta.write_text(json.dumps(dict(custom_structs=[dict(name='Record',size=28,fields=fields)],entry_register_seeds=seeds)))
 cls=RawBinarySource if platform=='amiga' else STRaw
 source=cls(kind=BinarySourceKind.RAW_BINARY,path=binary,address_model=RawAddressModel.RUNTIME_ABSOLUTE,load_address=4096,entrypoint=4096,code_start_offset=0,display_path=str(binary),analysis_cache_path=tmp_path/'cache')
 a=c_backend.build_listing_artifact_profile_from_binary_source(source,metadata_path=meta)[2]
 return a,raw

@pytest.mark.parametrize('platform',['amiga','st'])
@pytest.mark.parametrize('name',FIXTURES)
def test_declared_record_fields_and_cursors_are_rendered_without_changing_bytes(tmp_path,platform,name):
 a,raw=artifact(tmp_path,platform,FIXTURES[name])
 try:
  text=a.inline_source_text_with_profile()[0];assert 'Record_x(' in text
  if name=='fields':
   for field in ['flags','x','y','z']:assert 'Record_'+field+'(a4)' in text
  if platform=='st':
   assert 'COLOR00' not in text and 'color(a5)' not in text and 'app_0127(a6)' not in text and 'TDNestCnt' not in text
   s=a.analysis_payload()[0]['sections'][0]
   assert not s['recovered_platform_effects'] and not s['app_slot_refs']
   assert any(r['field_name']=='x' for r in s['recovered_platform_typed_accesses'])
  assembled,_=c_backend.assemble_platform_source_text_with_c_backend(platform+'-raw' if platform=='amiga' else 'atari-st-raw',text,include_dir=c_backend.PROJECT_ROOT/'ext/amiga_includes/ndk_2.0/include')
  assert assembled==raw
  baseline=os.getenv('AMIGA_TYPED_BASELINE_DIRECTORY')
  if platform=='amiga' and baseline:assert text==(Path(baseline)/(name+'.s')).read_text()
 finally:a.close()

@pytest.mark.parametrize('body,seed',[('move.w 22(a4),d0',False),('movea.l a1,a4\nmove.w 22(a4),d0',True),('move.l 1(a4),d0',True),('move.w 4(a4),d0',True)])
def test_st_unknown_changed_or_overlapping_access_is_not_named(tmp_path,body,seed):
 a,_=artifact(tmp_path,'st',body,seed)
 try:
  s=a.analysis_payload()[0]['sections'][0];assert not s['recovered_platform_typed_accesses']
  text=a.inline_source_text_with_profile()[0]
  if body in ('move.l 1(a4),d0','move.w 4(a4),d0'):assert s['recovered_platform_unresolved_typed_accesses']
  assert not any('Record_'+field+'(a4)' in text for field in ['kind','flags','x','y','z'])
 finally:a.close()

def test_st_builtin_os_seed_does_not_acquire_amiga_fields(tmp_path):
 a,_=artifact(tmp_path,'st','addq.b #1,$127(a6)\nmove.w 22(a4),d1',builtin=True)
 try:
  text=a.inline_source_text_with_profile()[0]
  assert 'Record_x(a4)' in text and 'TDNestCnt' not in text
  s=a.analysis_payload()[0]['sections'][0]
  assert all(r['root_struct_name']=='Record' for r in s['recovered_platform_typed_accesses'])
 finally:a.close()

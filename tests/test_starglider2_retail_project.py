"""A discoverable shared project, explicit platform bindings, no shipped media."""
import json
import shutil
from pathlib import Path
from amiga_reversing.disasm.game_catalog import load_family,available
from amiga_reversing.disasm.projects import get_project,list_projects
from tools.build_starglider2_retail_pair import load_shared_program,ROOT,EXPECTED


def test_shared_project_has_one_annotation_owner_and_two_platform_bindings():
 manifest=load_shared_program();family=load_family(ROOT,'starglider2')
 assert manifest['analysis_target']=='starglider2_retail'
 assert {family['targets'][v['target']]['artifact'] for v in manifest['bindings'].values()}==set(EXPECTED.values())
 assert {v['platform'] for v in manifest['bindings'].values()}=={'amiga','atari-st'}
 assert not (ROOT/'targets/starglider2_retail_amiga/target_metadata.json').exists()
 assert not (ROOT/'targets/starglider2_retail_atari_st/target_metadata.json').exists()
 # Existing independent origins remain catalogued, rather than overwritten.
 assert family['targets']['amiga_raw_starglider2_game']['release']=='amiga_ua_wow'
 assert family['targets']['atari_st_starglider2_main']['release']=='atari_st_1_05_supplied'


def test_clean_checkout_discovers_shared_target_without_private_inputs(tmp_path):
 paths=['games/starglider2.json','targets/starglider2_retail']
 for name in paths:
  source=ROOT/name;dest=tmp_path/name;dest.parent.mkdir(parents=True,exist_ok=True)
  if source.is_dir():shutil.copytree(source,dest,ignore=shutil.ignore_patterns('*.s','*.bin','.target-history.lock','__pycache__'))
  else:shutil.copyfile(source,dest)
 # Place legacy recipe dependencies outside targets so they do not create
 # fake discoverable projects in this deliberately minimal fixture.
 catalog=tmp_path/'games/starglider2.json';family=json.loads(catalog.read_text())
 for d in family['derivations'].values():
  if not (tmp_path/d['recipe']).exists():
   destination=tmp_path/'recipes'/Path(d['recipe']).name;destination.parent.mkdir(exist_ok=True)
   shutil.copyfile(ROOT/d['recipe'],destination);d['recipe']=destination.relative_to(tmp_path).as_posix()
 catalog.write_text(json.dumps(family))
 project=get_project('starglider2_retail',tmp_path)
 assert not project.ready and project.game_family=='starglider2'
 assert [p.id for p in list_projects(tmp_path)]==['starglider2_retail']
 assert not available(tmp_path,'starglider2',EXPECTED['amiga'])
 assert not (tmp_path/'.amiga_reversing/artifacts').exists()

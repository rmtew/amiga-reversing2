"""Private runtime receipts must describe real inputs and live output files."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import pytest

spec=importlib.util.spec_from_file_location('retail_execution',Path(__file__).resolve().parents[1]/'tools/check_starglider2_retail_execution.py')
checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)

@pytest.fixture
def receipt(tmp_path,monkeypatch):
 raw=tmp_path/'rebuilt.raw';raw.write_bytes(bytes(419308));state=tmp_path/'handoff.state';state.write_bytes(b'known handoff')
 monkeypatch.setitem(checker.EXPECTED,'st',checker.digest(raw))
 log=tmp_path/'native.log';log.write_text(f'00001000 entry\n> loadbin {raw} $1000\nRead 0x665ec bytes.\n')
 image=tmp_path/'capture.bmp';image.write_bytes(b'BMfixture')
 smoke={n:dict(mode=4 if n=='outside' else 0,image=str(image),file_sha256=checker.digest(image)) for n in checker.STAGES}
 smoke['question_record']=7
 args=['--memstate',str(state),'--machine','st','--memsize','1','--monitor','rgb','--tos','rom.img']
 case=dict(args=args,actions=[dict(frame=10,key=2)],state_sha256=checker.digest(state),smoke=smoke)
 a=copy.deepcopy(case);a['host_memory_write']=False
 b=copy.deepcopy(case);b.update(host_memory_write=True,injection=dict(file=str(raw),address=4096,size=419308,sha256=checker.digest(raw),debugger_log=str(log)))
 r=dict(status='passed',platform='st',monitor='rgb',checkpoint=dict(state_sha256=checker.digest(state)),cases=dict(original=a,rebuilt=b))
 return r


def write_check(tmp_path,r):
 p=tmp_path/'receipt.json';p.write_text(json.dumps(r));return checker.check(p,'st','rgb')


def test_live_fixture_accepts_consistent_runtime_evidence(tmp_path,receipt):
 assert write_check(tmp_path,receipt)['screen_checkpoints']==7


@pytest.mark.parametrize('fault,message',[
 ('original-write','original-only'),('no-injection','not inserted'),('view','transition'),('timeline','timelines'),
 ('different-machine','machine profile'),('changed-output','stale or wrong'),('missing-native-read','file-read witness'),('stale-capture','capture changed'),
])
def test_changed_or_unsupported_evidence_is_rejected(tmp_path,receipt,fault,message):
 a,b=receipt['cases']['original'],receipt['cases']['rebuilt']
 if fault=='original-write':a['host_memory_write']=True
 elif fault=='no-injection':b['host_memory_write']=False
 elif fault=='view':b['smoke']['outside']['mode']=0
 elif fault=='timeline':b['actions']=[dict(frame=11,key=2)]
 elif fault=='different-machine':b['args'][b['args'].index('--memsize')+1]='4'
 elif fault=='changed-output':Path(b['injection']['file']).write_bytes(b'wrong')
 elif fault=='missing-native-read':Path(b['injection']['debugger_log']).write_text('00001000 entry only')
 elif fault=='stale-capture':Path(b['smoke']['cockpit']['image']).write_bytes(b'BMchanged')
 with pytest.raises(ValueError,match=message):write_check(tmp_path,receipt)


@pytest.mark.skipif(not os.getenv('SGII_RETAIL_DIFFERENTIAL_DIRECTORY'),reason='private original/rebuilt emulator evidence')
def test_all_three_actual_private_contexts_remain_valid():
 p=Path(os.environ['SGII_RETAIL_DIFFERENTIAL_DIRECTORY'])
 assert checker.check(p/'amiga3/receipt.json','amiga')['screen_checkpoints']==7
 for mode in ('rgb','mono'):assert checker.check(p/f'st/{mode}/receipt.json','st',mode)['screen_checkpoints']==7

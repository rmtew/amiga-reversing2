import copy
import hashlib
import pytest
from amiga_reversing.disasm.byte_projection import recover_projection


def plan(data,result):
 return dict(schema_version=1,kind='byte_projection',source_sha256=hashlib.sha256(data).hexdigest(),evidence='synthetic flag word',actions=[dict(op='replace',offset=2,before='0000',after='8001'),dict(op='capture',file='variant.bin',size=len(result),sha256=hashlib.sha256(result).hexdigest())])


def test_bounded_header_projection_checks_the_complete_source_and_result():
 data=b'AB\0\0CD';out=b'AB\x80\x01CD';receipt,files=recover_projection(data,plan(data,out))
 assert files=={'variant.bin':out} and receipt['changed_positions']==[2,3]


@pytest.mark.parametrize('fault',['source','before','result','overlap','budget','large-literal','order','path'])
def test_projection_refuses_corruption_or_unbounded_payloads(fault):
 data=b'AB\0\0CD';p=plan(data,b'AB\x80\x01CD')
 if fault=='source':data=b'wrong'
 elif fault=='before':p['actions'][0]['before']='0001'
 elif fault=='result':p['actions'][-1]['sha256']='0'*64
 elif fault=='overlap':p['actions'].insert(1,copy.deepcopy(p['actions'][0]))
 elif fault=='large-literal':p['actions'][0].update(before='00'*9,after='11'*9)
 elif fault=='order':p['actions'].reverse()
 elif fault=='path':p['actions'][-1]['file']='../variant.bin'
 elif fault=='budget':
  data=bytes(24);p['source_sha256']=hashlib.sha256(data).hexdigest();p['actions']=[dict(op='replace',offset=i*8,before='00'*8,after='01'*8) for i in range(3)]+[p['actions'][-1]]
 with pytest.raises(ValueError):recover_projection(data,p)

"""Separate retail platform contexts from the same source disk.

Opt-in private handoffs. These are CPU slices, not emulator smoke tests.
"""
import hashlib
import os
from pathlib import Path
import pytest
from amiga_reversing.disasm.mapped_execution import MappedExecution

pytestmark=pytest.mark.skipif(not os.getenv('SGII_RETAIL_DIRECTORY'),reason='requires private same-disk retail handoffs')
IDENTITIES={
 'st':('main_at_st_handoff.bin.private.bin','20c19400180d7e846b78aa615b68446293f8ca54015c4f4a42a77f03b24e8260',0x0001,0x61668,0x3ccc0),
 'amiga':('amiga-retail-handoff.private.bin','334f83ec3bdb30e36b2e5c741b7788e4a3489ee15811d11e1e52ef83bd28a938',0x8001,0x69668,0xcc68),
}

def image(platform):
 name,digest,*_=IDENTITIES[platform]
 data=(Path(os.environ['SGII_RETAIL_DIRECTORY'])/name).read_bytes()
 assert len(data)==419308 and hashlib.sha256(data).hexdigest()==digest
 return data


def prefix(platform,register_seed):
 _,_,flags,workspace,entry=IDENTITIES[platform]
 data=image(platform);cpu=MappedExecution(0x80000,register_seed=register_seed);cpu.seed(0x1000,data)
 for start,size in [(0xe144,2),(0x27be,4),(workspace,0x6598),(0x3300,0x86)]:cpu.allow_write(start,size)
 result=cpu.run(0x1000,entry,27000)
 assert cpu.read(0x1002,2)==flags.to_bytes(2,'big')
 assert cpu.read(0x27be,4)==workspace.to_bytes(4,'big')
 assert cpu.read(workspace,0x6598)==bytes(0x6598)
 return cpu,result


def test_retail_handoffs_share_all_stored_bytes_except_platform_flag():
 st,amiga=image('st'),image('amiga')
 assert [i for i,(a,b) in enumerate(zip(st,amiga)) if a!=b]==[2]
 assert st[2:4]==b'\0\1' and amiga[2:4]==b'\x80\1'


@pytest.mark.parametrize('platform',['st','amiga'])
@pytest.mark.parametrize('seed',[0,0xdeadbeef])
def test_real_flag_selects_workspace_and_platform_initializer(platform,seed):
 cpu,result=prefix(platform,seed)
 assert result['stop_pc']==IDENTITIES[platform][4]
 assert cpu.cpu.a[7]==0x337e


@pytest.mark.parametrize('seed',[0,0xdeadbeef])
def test_amiga_loader_flag_skips_os_calls_then_stops_before_palette_io(seed):
 cpu,_=prefix('amiga',seed)
 result=cpu.run(0xcc68,0xcc9a,20)
 assert result['steps']==6
 assert cpu.cpu.a[6]==0x69668 and cpu.cpu.a[5]==0xdff000
 # No OS base at address 4 or hardware registers were seeded. A false
 # assumption about supervisor entry or first I/O would fail this witness.
 with pytest.raises(ValueError,match='native CPU witness failed'):
  cpu.run(0xcc9a,0xcca0,1)

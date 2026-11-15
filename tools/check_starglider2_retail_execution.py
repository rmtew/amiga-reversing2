"""Check private original/rebuilt retail execution receipts against live files.

No game bytes or captures are written to the repository. Each platform/monitor
is compared only with its own original run. Byte-equal PNG/BMP files are a
stronger requirement than equal decoded pixels; no cross-platform image test.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re

EXPECTED={
 'amiga':'334f83ec3bdb30e36b2e5c741b7788e4a3489ee15811d11e1e52ef83bd28a938',
 'st':'20c19400180d7e846b78aa615b68446293f8ca54015c4f4a42a77f03b24e8260',
}
STAGES=('first-picture','options','language','question','cockpit','outside','cockpit-return')

def require(condition,message):
    if not condition:raise ValueError(message)


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def option(args,name):
    require(name in args,'missing machine option '+name)
    return args[args.index(name)+1]


def check(receipt_path: Path,platform: str,monitor: str | None=None) -> dict:
    r=json.loads(receipt_path.read_text());require(r.get('status')=='passed','execution did not pass')
    require(r.get('platform')==platform,'wrong platform context')
    if platform=='st':require(r.get('monitor')==monitor,'wrong ST monitor context')
    original,rebuilt=(r['cases'][v] for v in ('original','rebuilt'))
    require(original['host_memory_write'] is False,'original-only run contains an insertion')
    require(rebuilt['host_memory_write'] is True,'rebuilt file was not inserted')
    injection=rebuilt['injection'];file=Path(injection['file'])
    require(injection['address']==0x1000 and injection['size']==419308,'wrong insertion extent')
    require(file.stat().st_size==419308 and digest(file)==injection['sha256']==EXPECTED[platform],
            'rebuilt output missing, stale or wrong')
    require(original['smoke']['question_record']==rebuilt['smoke']['question_record'],
            'runs did not use the same novella question/input')
    if platform=='amiga':
        require(injection['reply']['written']==419308,'native mem.write did not confirm the insertion')
        require(rebuilt['readback_sha256']==EXPECTED[platform],'insertion readback differs')
        paths=[option(c['args'],'--load-state') for c in (original,rebuilt)]
        require(all(digest(p)==r['checkpoint']['sha256'] for p in paths),'handoff state changed')
        for key in ('--model','--cpu','--chip','--slow','--fast','--floppy-speed'):
            require(option(original['args'],key)==option(rebuilt['args'],key),'machine profile differs: '+key)
    else:
        require(all(c['state_sha256']==r['checkpoint']['state_sha256'] for c in (original,rebuilt)),
                'runs claim different handoff states')
        for c in (original,rebuilt):
            require(digest(option(c['args'],'--memstate'))==r['checkpoint']['state_sha256'],'handoff state changed')
        require(original['actions']==rebuilt['actions'],'ST input/frame timelines differ')
        for key in ('--machine','--memsize','--monitor','--tos'):
            require(option(original['args'],key)==option(rebuilt['args'],key),'machine profile differs: '+key)
        log=Path(injection['debugger_log']).read_text()
        require(f'> loadbin {file} $1000' in log and 'Read 0x665ec bytes.' in log,
                'native loadbin file-read witness is missing')
        require(re.search(r'^00001000\s',log,re.M) is not None,'insertion was not observed at entry')
    for case in (original,rebuilt):
        require([case['smoke'][k]['mode'] for k in ('cockpit','outside','cockpit-return')]==[0,4,0],
                'cockpit/outside/cockpit transition did not occur')
    for name in STAGES:
        a,b=(c['smoke'][name] for c in (original,rebuilt))
        pa,pb=(Path(x['image']) for x in (a,b))
        require(digest(pa)==a['file_sha256'] and digest(pb)==b['file_sha256'],'capture changed: '+name)
        image=pa.read_bytes();require(image.startswith(b'\x89PNG\r\n\x1a\n') or image.startswith(b'BM'),
                                    'capture is not a PNG/BMP: '+name)
        require(image==pb.read_bytes() and a['mode']==b['mode'],'screen/state mismatch: '+name)
        if platform=='amiga':
            require(all(a['event'][k]==b['event'][k] for k in ('frame','cck','pc')),
                    'emulated position differs: '+name)
    return dict(platform=platform,monitor=monitor,screen_checkpoints=len(STAGES),view_modes=[0,4,0],
                insertion='rebuilt file at original-media handoff',status='passed')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--amiga',type=Path,required=True)
    parser.add_argument('--st-colour',type=Path,required=True)
    parser.add_argument('--st-mono',type=Path,required=True)
    args=parser.parse_args()
    result=[check(args.amiga,'amiga'),check(args.st_colour,'st','rgb'),check(args.st_mono,'st','mono')]
    print(json.dumps(dict(status='passed',contexts=result,total_screen_checkpoints=21,
                         rebuilt_disk_boot=False),indent=2))


if __name__=='__main__':main()

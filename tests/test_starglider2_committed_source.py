"""The committed retail source is complete, current and independent of media."""
import hashlib,json,os,re,shutil,subprocess,sys
from pathlib import Path
import pytest
from tools.build_starglider2_retail_pair import ROOT,EXPECTED,package_files

def copy_source_checkout(destination):
    target=destination/'targets/starglider2_retail';target.mkdir(parents=True)
    original=ROOT/'targets/starglider2_retail'
    shutil.copyfile(original/'target_metadata.json',target/'target_metadata.json')
    shutil.copytree(original/'rendered',target/'rendered')
    tools=destination/'tools';tools.mkdir()
    shutil.copyfile(ROOT/'tools/build_starglider2_retail_pair.py',tools/'build_starglider2_retail_pair.py')
    return target

def rewrite_manifest(target,edit):
    path=target/'rendered/source-package-manifest.json';envelope=json.loads(path.read_text());edit(envelope['manifest'])
    envelope['sha256']=hashlib.sha256((json.dumps(envelope['manifest'],sort_keys=True,indent=2,ensure_ascii=True)+'\n').encode()).hexdigest()
    path.write_text(json.dumps(envelope,sort_keys=True,indent=2)+'\n')

def test_committed_package_has_exactly_the_required_include_data():
    directory,manifest,files=package_files()
    shared=files[manifest['source']].decode()
    references=set(re.findall(r'(?im)^\s*INCBIN\s+"([^"]+)"',shared))
    assets={r['path'] for r in manifest['files'] if r['kind']=='asset'}
    assert references==assets
    assert {manifest['source'],*manifest['application']['wrappers'].values(),*assets}==files.keys()
    assert len(assets)==2 and sum(len(files[p]) for p in assets)==27339
    assert '/workspace/' not in shared and '/home/' not in shared
    assert manifest['application']['expected_sha256']==EXPECTED

def test_stale_annotations_require_regeneration(tmp_path):
    target=copy_source_checkout(tmp_path);(target/'target_metadata.json').write_text('{}\n')
    with pytest.raises(ValueError,match='annotations changed'):package_files(tmp_path)

def test_changed_include_is_rejected_before_assembly(tmp_path):
    target=copy_source_checkout(tmp_path);asset=next((target/'rendered/assets').glob('*.bin'));data=bytearray(asset.read_bytes());data[0]^=1;asset.write_bytes(data)
    with pytest.raises(ValueError,match='changed generated'):package_files(tmp_path)

def test_missing_platform_is_not_a_successful_pair(tmp_path):
    target=copy_source_checkout(tmp_path);rewrite_manifest(target,lambda m:m['application']['wrappers'].pop('amiga'))
    with pytest.raises(ValueError,match='both platform'):package_files(tmp_path)

def test_manifest_cannot_read_an_external_private_file(tmp_path):
    target=copy_source_checkout(tmp_path);rewrite_manifest(target,lambda m:m['files'][0].update(path='../outside.bin'))
    with pytest.raises(ValueError,match='invalid package path'):package_files(tmp_path)

@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='external vasm is the only build dependency')
def test_source_only_checkout_builds_under_isolated_system_python(tmp_path):
    checkout=tmp_path/'checkout';copy_source_checkout(checkout)
    vasm=tmp_path/'vasmm68k_mot';shutil.copyfile(os.environ['SGII_RETAIL_VASM'],vasm);vasm.chmod(0o755)
    env={k:v for k,v in os.environ.items() if not k.startswith(('AMIGA_','SGII_','UV_','PYTHON'))}
    env['AMIGA_C_BACKEND_DLL_ROOT']=str(tmp_path/'no-native-backend')
    result=subprocess.run([sys.executable,'-I',str(checkout/'tools/build_starglider2_retail_pair.py'),'--vasm',str(vasm),'--output',str(tmp_path/'built')],cwd=checkout,env=env,capture_output=True,text=True,check=True)
    assert {k:v['sha256'] for k,v in json.loads(result.stdout).items()}==EXPECTED
    assert not (checkout/'.amiga_reversing').exists()

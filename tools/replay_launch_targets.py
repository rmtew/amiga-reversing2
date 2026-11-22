"""Private end-to-end recipe rehearsal from pinned, locally supplied originals."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,subprocess,sys,zipfile
MEDIA={'FederationOfFreeTraders.ipf':'da33fc1e068d73078094fc4cb6f72ab69a9c2f30f4094b8321033aedb6237b93','Conqueror.ipf':'4f8b5ec7b59d0a6a89873d37ae52feb5b4ed53335ab1ff5dba96eb82fb72b9fb','StarGlider2.ipf':'34ad554ee97e3e7ebb9f227cfbf8d5c45251640f4c0e999175d4b56d5ed8d55f','Starglider 2 (1988)(Rainbird).stx':'6a25ccb01084c666241556e5f98fdfec260415bd9ca259ac688fddcaf99a2d22'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--framework',type=Path,default=Path(__file__).resolve().parents[1])
 for name in ['media-dir','output','vasm','sdk-root']:p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();root=a.framework.resolve();out=a.output.resolve();repo=root/'recipes/launch-targets';contract=json.loads((repo/'recipe-contract.json').read_text())
 for name,want in MEDIA.items():
  if sha(a.media_dir/name)!=want:raise ValueError('original media identity mismatch: '+name)
 head=subprocess.check_output(['git','--no-replace-objects','-C',root,'rev-parse','HEAD'],text=True).strip()
 manifest_file=repo/'framework-source-manifest.json'
 if sha(manifest_file)!=contract['framework_source_manifest_sha256']:raise ValueError('framework source manifest identity mismatch')
 inventory=json.loads(manifest_file.read_text())
 for record in inventory['files']:
  file=root/record['path']
  if file.stat().st_size!=record['size'] or sha(file)!=record['sha256']:raise ValueError('framework source identity mismatch: '+record['path'])
 if os.environ.get('AMIGA_C_BACKEND_DLL_ROOT'):raise ValueError('external native backend override is not allowed for clean replay')
 subprocess.run(['git','-C',root,'diff','--exit-code','HEAD','--'],stdout=subprocess.DEVNULL,check=True)
 if (root/'targets').exists() or (root/'.amiga_reversing').exists() or out.exists():raise ValueError('fresh checkout and new output required')
 out.mkdir(parents=True);(out/'replay-input-identity.json').write_text(json.dumps({'framework_commit':head,'framework_tree':subprocess.check_output(['git','-C',root,'rev-parse','HEAD^{tree}'],text=True).strip(),'framework_source_manifest_sha256':contract['framework_source_manifest_sha256'],'fact_manifest_sha256':contract['fact_manifest_sha256']},indent=2));env=os.environ.copy();env['PYTHONPATH']=str(root);commands=[]
 def run(argv,log,cwd=root):
  commands.append({'argv':[str(x) for x in argv],'cwd':str(cwd)});(out/'commands.json').write_text(json.dumps(commands,indent=2))
  with (out/log).open('w') as f:subprocess.run([str(x) for x in argv],cwd=cwd,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
  print(log+' PASS',flush=True)
 shutil.copytree(a.sdk_root,root/'ext');shutil.copy2(a.vasm,root/'tools/vasmm68k_mot.exe');run(['make','-j4','all'],'native-build.log')
 sys.path.insert(0,str(root));sys.path.insert(0,str(repo))
 from amiga_reversing.disasm.media_fact_templates import materialize,digest
 from amiga_reversing.disasm.launch_fact_checkpoints import derive
 from amiga_reversing.disasm.ipf_resources import recover_resources
 from amiga_reversing.disasm.game_catalog import bind_source,materialize as recover
 from amiga_reversing.disasm.disk_set import DiskSet
 from amiga_reversing.disasm.disk_set_state import verify_journal_snapshots
 from amiga_reversing.disasm.source_package import materialize_source_package
 members={};store=out/'members';store.mkdir()
 for recipe in ['sps0613-resources.json','sps0613-music-resource5.json']:
  _,outputs=recover_resources((a.media_dir/'FederationOfFreeTraders.ipf').read_bytes(),json.loads((root/'recipes/foft'/recipe).read_bytes()),project_root=root)
  for name,data in outputs.items():
   key={'foft-program.bin':'foft-main','foft-boot-loader.bin':'foft-boot','foft-music-bank5.bin':'foft-music-5'}.get(name)
   if key:members[key]=store/(key+'.bin');members[key].write_bytes(data)
 bind_source(root,'starglider2',MEDIA['StarGlider2.ipf'],a.media_dir/'StarGlider2.ipf');members['sgii-st']=recover(root,'starglider2','20c19400180d7e846b78aa615b68446293f8ca54015c4f4a42a77f03b24e8260')
 facts=out/'restored-facts';bundle=repo/'facts';pin=contract['fact_manifest_sha256'];result=materialize(bundle,facts,members,pin);result['derived']=derive(bundle,facts,members,pin);(out/'fact-restoration.json').write_text(json.dumps(result,indent=2));shutil.copytree(facts/'targets',root/'targets')
 for name in ['decode_resident.py','inspect_media.py']:shutil.copy2(root/'recipes/conqueror_sps1275'/name,root/'targets/amiga_disk_conqueror_sps1275'/name)
 run([sys.executable,'targets/amiga_disk_conqueror_sps1275/bootstrap_analysis.py',a.media_dir/'Conqueror.ipf'],'conqueror-bootstrap.log')
 run([sys.executable,'-m','amiga_reversing.tools.source_export','amiga_disk_conqueror_sps1275__amiga_raw_gameplay','--binary-assets','--verify-package','--output',out/'conqueror.zip'],'conqueror-export.log')
 reader=out/'conqueror';reader.mkdir()
 with zipfile.ZipFile(out/'conqueror.zip') as z:z.extractall(reader)
 entry=next(reader.glob('*.s'));vasm=root/'tools/vasmm68k_mot.exe';run([vasm,'-Fbin','-m68000','-no-opt','-o','rebuilt.raw',entry.name],'conqueror-reader.log',reader)
 run([sys.executable,'tools/regenerate_starglider2_retail_source.py','--vasm',vasm],'sgii-regenerate.log');run([sys.executable,'tools/build_starglider2_retail_pair.py','--vasm',vasm,'--output',out/'sgii'],'sgii-reader.log')
 owner=DiskSet.load(root/'targets/amiga_raw_foft',project_root=root,require_source_package=False);media={'game-disc':str(a.media_dir/'FederationOfFreeTraders.ipf')};(out/'foft-journals.json').write_text(json.dumps(verify_journal_snapshots(owner,media),indent=2))
 for name in ['boot','music-5','main']:
  package=owner.recover_member_package(name,media);directory=out/('foft-'+name);entry=materialize_source_package(package,directory);run([vasm,'-Fbin','-m68000','-no-opt','-o','rebuilt.raw',entry.name],'foft-'+name+'-reader.log',directory)
 expected={'conqueror/rebuilt.raw':'6428d23379667b19c7397721ed31a2a90369be99865440692ba95c6bf265f24c','sgii/retail-amiga.raw':'334f83ec3bdb30e36b2e5c741b7788e4a3489ee15811d11e1e52ef83bd28a938','sgii/retail-st.raw':'20c19400180d7e846b78aa615b68446293f8ca54015c4f4a42a77f03b24e8260','foft-main/rebuilt.raw':'85e2684b03badc7308e7eaa059b7c717441808798f55b4642e1d8b1895914c9b','foft-boot/rebuilt.raw':'b52575d366313c1648976925c368e7a990d30477e7a099301dcabb031a3939a1','foft-music-5/rebuilt.raw':'3fa229a343d5fa6e050abc696911c36e55d5ee96cc7b2d852dbdd4404b299190'}
 payloads={}
 for path,want in expected.items():
  actual=sha(out/path)
  if actual!=want:raise ValueError('rebuilt payload differs: '+path)
  payloads[path]={'size':(out/path).stat().st_size,'sha256':actual,'exact':True}
 (out/'payloads.json').write_text(json.dumps(payloads,indent=2));print('ALL SIX PAYLOADS EXACT',flush=True)
if __name__=='__main__':main()

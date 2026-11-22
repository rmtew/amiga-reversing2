import hashlib,json
from src.scripts.project_amiga_hardware_facts import project,FUNCTION_TERMS
from src.scripts.generate_amiga_os_runtime import hardware_register_semantic_flags,hardware_register_runtime_target_role

def test_projection_omits_prose_and_retains_existing_semantic_predicates():
 row={'name':'SYNTHETIC','address':'0x0000','address_68k':'0x1000','access':'W','dma_only':False,'pointer_pair':True,'function':'Synthetic audio channel location description.','notes':'A private evidence note.','detail_page':'local.html','bits':[{'bit':2,'name':'SYNTH','description':'Private bit explanation.'}]}
 data={'base_address':'0x1000','chapters':[{'title':'Private chapter text'}],'registers':[row]};sha=hashlib.sha256(json.dumps(data).encode()).hexdigest();out=project(data,sha);got=out['registers'][0]
 assert 'chapters' not in out and not {'notes','detail_page'}&got.keys()
 assert 'description' not in got['bits'][0]
 assert hardware_register_semantic_flags(row)==hardware_register_semantic_flags(got)
 assert hardware_register_runtime_target_role(row)==hardware_register_runtime_target_role(got)
 assert all((term in row['function'].lower())==(term in got['function']) for term in FUNCTION_TERMS)
 assert out['fact_projection']['source_sha256']==sha

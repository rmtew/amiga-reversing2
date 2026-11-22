"""Project hardware facts without manual prose, preserving current reader predicates.

The vocabulary is the union of predicates in generate_amiga_os_runtime and
amiga_hardware_usage. A pipe delimiter prevents accidental phrase formation.
This records observed categories; it does not infer new hardware behavior.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
FUNCTION_TERMS=('pointer','location','coprocessor','disk pointer','blitter pointer','destination','source','bitplane','sprite','audio channel','copper','audio','dma','interrupt','disk','display','window','color','beam','modulo')
def project(payload:dict,source_sha256:str)->dict:
 result={k:v for k,v in payload.items() if k in ('base_address','base_address_68k','schema','version')}
 result['fact_projection']={'schema':'amiga-hardware-facts-v1','source_sha256':source_sha256,'function_encoding':'canonical-reader-predicate-vocabulary'}
 result['registers']=[]
 for row in payload['registers']:
  item={k:v for k,v in row.items() if k not in ('function','notes','detail_page','bits')}
  item['function']=' | '.join(term for term in FUNCTION_TERMS if term in str(row.get('function','')).lower())
  item['bits']=[{k:v for k,v in bit.items() if k!='description'} for bit in row.get('bits',[])]
  result['registers'].append(item)
 return result

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('input',type=Path);p.add_argument('output',type=Path);a=p.parse_args();raw=a.input.read_bytes();result=project(json.loads(raw),hashlib.sha256(raw).hexdigest());a.output.write_text(json.dumps(result,indent=2)+'\n')
if __name__=='__main__':main()

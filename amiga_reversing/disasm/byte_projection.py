"""Small hash-bound stored-variant projections, separate from CPU execution.

This describes a few proven header/state bytes. It cannot embed an asset or
replace loader recovery, original execution or whole-output identity checks.
"""
import hashlib
from .mapped_recipe import keys,integer


def recover_projection(data,plan,**_):
 keys(plan,'schema_version kind source_sha256 evidence actions')
 if type(plan['schema_version']) is not int or plan['schema_version']!=1 or plan['kind']!='byte_projection':raise ValueError('invalid projection schema')
 if not 0<len(data)<=32*1024*1024 or hashlib.sha256(data).hexdigest()!=plan['source_sha256']:raise ValueError('projection source identity mismatch')
 if not isinstance(plan['evidence'],str) or not isinstance(plan['actions'],list) or not 2<=len(plan['actions'])<=9:raise ValueError('invalid projection actions')
 result=bytearray(data);touched=set();outputs={}
 for index,action in enumerate(plan['actions']):
  if not isinstance(action,dict):raise ValueError('invalid projection action')
  if action.get('op')=='replace' and index<len(plan['actions'])-1:
   keys(action,'op offset before after');at=integer(action['offset'])
   try:before=bytes.fromhex(action['before']);after=bytes.fromhex(action['after'])
   except (TypeError,ValueError):raise ValueError('invalid projection byte literal') from None
   if not 0<len(before)==len(after)<=8 or before==after or at+len(before)>len(result):raise ValueError('invalid projection extent')
   span=set(range(at,at+len(before)))
   if span&touched or len(span|touched)>16:raise ValueError('projection overlap or byte budget exceeded')
   if result[at:at+len(before)]!=before:raise ValueError('projection expected bytes differ')
   result[at:at+len(after)]=after;touched|=span
  elif action.get('op')=='capture' and index==len(plan['actions'])-1:
   keys(action,'op file size sha256');name=action['file']
   if not isinstance(name,str) or '/' in name or '\\' in name or not name.endswith('.bin') or len(result)!=action['size']:raise ValueError('invalid projection capture')
   if hashlib.sha256(result).hexdigest()!=action['sha256']:raise ValueError('projection output identity mismatch')
   outputs[name]=bytes(result)
  else:raise ValueError('invalid projection action order')
 if len(outputs)!=1:raise ValueError('projection needs one final capture')
 return dict(kind='byte_projection_result',changed_positions=sorted(i for i in touched if result[i]!=data[i]),scope='Proven stored variant only; not original loader execution'),outputs

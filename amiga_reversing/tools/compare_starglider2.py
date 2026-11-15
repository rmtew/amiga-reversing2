"""Recheck the earned SGII correspondences and current native classifications.

This is a target workflow, not a fuzzy diff framework. It reads the normal game
catalogue and native facts. Reports contain coordinates/counts, never game bytes.
Private native-fact caches invalidate when inputs, annotations or backend change.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import time
import tempfile

ROOT=Path(__file__).resolve().parents[2]
TARGETS=('amiga_raw_starglider2_game','starglider2_retail')
SNAPSHOT_SCHEMA=1
INSTRUCTION_FIELDS=('section_index','source_offset','mnemonic','text','size','bytes','operand_facts')
ST_NATIVE_SECTIONS=('table_descriptors','recovered_indirect_sites')

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def face_stream(data: bytes,start: int,count: int,vertices: int,*,extra: bool=False) -> dict:
    """Parse stored count-bounded records, not the renderer's terminated output.

    The main consumer uses three arity bits; the extra-face consumer uses four.
    Vertex values are byte offsets into eight-byte reference/transformed records.
    This describes initial source storage, not every possible runtime mutation.
    """
    if not (0<=start<=len(data) and start%2==0 and 0<=count<=65535 and 1<=vertices<=65536):
        raise ValueError('Invalid face-stream bounds')
    pos=start;records=[]
    for _ in range(count):
        if pos+2>len(data):raise ValueError('Truncated face header')
        header=int.from_bytes(data[pos:pos+2],'big');arity=(header>>8)&(15 if extra else 7)
        if arity<2:raise ValueError('Unsupported zero/one-vertex face record')
        end=pos+2+2*arity
        if end>len(data):raise ValueError('Truncated face vertices')
        refs=[int.from_bytes(data[p:p+2],'big') for p in range(pos+2,end,2)]
        if any(v%8 or v>=vertices*8 or v>=32768 for v in refs):raise ValueError('Invalid face vertex offset')
        records.append({'offset':pos,'header':header,'vertices':refs});pos=end
    return {'start':start,'end':pos,'count':count,'extra':extra,'records':records}

def model_streams(data: bytes,directory: int) -> list[dict]:
    """Follow the 104-entry directory, retaining aliases and optional streams."""
    def word(p):return int.from_bytes(data[p:p+2],'big')
    def pointer(p):
        if not 0<=p<=len(data)-4:raise ValueError('Pointer field outside image')
        value=int.from_bytes(data[p:p+4],'big')-4096
        if value<0 or value>=len(data) or value%2:raise ValueError('Pointer target outside image or unaligned')
        return value
    result=[];seen={}
    for ordinal in range(104):
        h=pointer(directory+ordinal*4)
        if h in seen:seen[h]['ordinals'].append(ordinal);continue
        if h+24>len(data):raise ValueError('Truncated model header')
        vertices=word(h)+1
        item={'ordinals':[ordinal],'header':h,'vertices':vertices,
              'main':face_stream(data,pointer(h+6),word(h+2),vertices)}
        if word(h+22):
            item['extra']=face_stream(data,pointer(h+24),word(h+22),vertices,extra=True)
        if int.from_bytes(data[h+18:h+22],'big'):
            table=pointer(h+18);view=pointer(table);refs=pointer(h+10)
            offsets=[word(refs+8*i+6) for i in range(vertices) if word(refs+8*i+6)<32768]
            if not offsets or any(v%2 for v in offsets):raise ValueError('Invalid variant vertex offsets')
            # Only selector 1 is covered here. There is no local table length
            # guard; do not infer a complete table from a run of plausible PTRs.
            end=view+max(offsets)+6
            if end>len(data):raise ValueError('Variant read footprint outside image')
            item['variant_first']={'table':table,'start':view,'end':end,'offsets':sorted(set(offsets))}
        seen[h]=item;result.append(item)
    return result

def variant_cycle_step(control: bytes,state: tuple[int,int],*,reverse: bool=False) -> tuple[int,int]:
    """One model-viewer step, including the signed second-leg enable marker.

    State is (selector, leg byte offset). This is a producer-context bound, not
    a guard in the renderer or a bound on arbitrary actor/editor memory writes.
    """
    selector,leg=state
    if len(control)!=4 or leg not in (0,2) or control[0]>=128:
        raise ValueError('Disabled or invalid variant-cycle state')
    a,b=control[leg:leg+2]
    stop=b if reverse else a
    if selector==stop:
        if leg or control[2]>=128:return (control[0] if reverse else control[1],0)
        return (control[2] if reverse else control[3],2)
    delta=(1 if b>=a else -1) if reverse else (1 if a>=b else -1)
    return ((selector+delta)&255,leg)

def bounded_variants(data: bytes,model: dict,controls: int) -> dict:
    """Recover selectors from actual four-byte viewer controls, not PTR scans."""
    states_by_ordinal={};selectors=set()
    for ordinal in model['ordinals']:
        record=data[controls+4*ordinal:controls+4*ordinal+4]
        if len(record)!=4:raise ValueError('Truncated variant-cycle control')
        if record[0]>=128:states_by_ordinal[ordinal]=[];continue
        todo=[(0,0)];seen=set()
        while todo:
            state=todo.pop()
            if state in seen:continue
            seen.add(state)
            todo.extend(variant_cycle_step(record,state,reverse=reverse) for reverse in (False,True))
            if len(seen)>512:raise ValueError('Unbounded variant-cycle state')
        states_by_ordinal[ordinal]=sorted(seen);selectors.update(s for s,leg in seen)
    positive=sorted(selectors-{0})
    if positive!=list(range(1,max(positive,default=0)+1)):
        raise ValueError('Non-contiguous variant selectors need sparse treatment')
    if not positive:return {'states':states_by_ordinal,'selectors':sorted(selectors),'views':[]}
    if 'variant_first' not in model:raise ValueError('Viewer selectors lack a model variant pointer')
    first=model['variant_first'];table=first['table'];views=[]
    coordinate_bytes=2*int.from_bytes(data[model['header']+4:model['header']+6],'big')
    for selector in positive:
        field=table+4*(selector-1)
        if field+4>len(data):raise ValueError('Variant pointer outside image')
        view=int.from_bytes(data[field:field+4],'big')-4096
        end=view+max(first['offsets'])+6
        if not 0<=view<end<=len(data) or view%2:raise ValueError('Variant reference footprint outside image')
        for offset in first['offsets']:
            for delta in (0,2,4):
                index=int.from_bytes(data[view+offset+delta:view+offset+delta+2],'big')&32767
                if index%2 or index>=coordinate_bytes:raise ValueError('Variant coordinate reference outside pool')
        views.append({'selector':selector,'pointer_offset':field,'start':view,'end':end,'offsets':first['offsets']})
    return {'states':states_by_ordinal,'selectors':sorted(selectors),'views':views}

def annotation_identity(root: Path,target: str) -> str:
    """Key the declared fact/projection dependencies; timestamps are irrelevant."""
    paths=[root/'targets'/target/n for n in ('source_binary.json','target_metadata.json','manual_actions.jsonl','decision_journal.jsonl')]
    paths+=sorted((root/'amiga_reversing/disasm').glob('*.py'))
    backend_root=Path(os.environ.get('AMIGA_C_BACKEND_DLL_ROOT',root)).resolve()
    paths+=[backend_root/'src/build/platform_file_lib.dll']
    h=hashlib.sha256()
    for p in paths:
        h.update(str(p.relative_to(root) if p.is_relative_to(root) else p).encode())
        h.update(b'\0');h.update(p.read_bytes() if p.exists() else b'<absent>');h.update(b'\0')
    h.update(json.dumps([SNAPSHOT_SCHEMA,INSTRUCTION_FIELDS]).encode())
    if target==TARGETS[1]:h.update(json.dumps(ST_NATIVE_SECTIONS).encode())
    return h.hexdigest()

def snapshot(root: Path,target: str,path: Path,expected: str,cache_dir: Path) -> tuple[dict,bool]:
    from amiga_reversing.disasm.c_backend import CListingArtifact,_CBackendSourceFile
    from amiga_reversing.disasm.effective_metadata import effective_metadata_file
    key=digest((expected+annotation_identity(root,target)).encode())
    cache=cache_dir/(target+'.private.json')
    if cache.exists():
        try:saved=json.loads(cache.read_text())
        except (OSError,json.JSONDecodeError):saved={}
        if saved.get('key')==key:return saved,True
    started=time.perf_counter();platform='atari-st-raw' if target.startswith('atari') else 'amiga-raw'
    with effective_metadata_file(root/'targets'/target) as metadata:
        a=CListingArtifact.create(_CBackendSourceFile(path,platform,0,4096),metadata_text=str(metadata) if metadata else '',
            include_dir=str(root/'ext/amiga_includes/ndk_2.0/include'),project_root=root)
        try:
            result={'key':key,'payload_sha256':expected,'target':target,'backend':a.loaded_backend_identity()}
            for kind in ('instructions','references','edges'):
                rows=[]
                while True:
                    page=a.query_payload(kind,offset=len(rows),limit=100);part=page['items'];rows.extend(part)
                    if len(rows)>=page['total']:break
                if kind=='instructions':
                    rows=[{k:i[k] for k in INSTRUCTION_FIELDS} for i in rows]
                result[kind]=rows
            analysis,_=a.analysis_payload()
            if analysis['incomplete_analysis']:raise ValueError('Native analysis is incomplete: '+target)
            result['ownership']=analysis['sections'][0]['range_ownerships']
            if target==TARGETS[1]:
                for name in ST_NATIVE_SECTIONS:result[name]=analysis['sections'][0][name]
            result['export_seconds']=time.perf_counter()-started
        finally:a.close()
    if digest((expected+annotation_identity(root,target)).encode())!=key:
        raise ValueError('Annotations or backend changed during native export; do not cache this snapshot')
    cache_dir.mkdir(parents=True,exist_ok=True)
    with tempfile.NamedTemporaryFile('w',dir=cache_dir,delete=False) as f:
        json.dump(result,f);temporary=Path(f.name)
    temporary.replace(cache)
    return result,False

def masks(data: bytes,facts: dict) -> tuple[bytearray,bytearray,bytearray]:
    code=bytearray(len(data));classified=bytearray(len(data));padding=bytearray(len(data))
    for row in facts['instructions']:
        s,n=row['source_offset'],row['size']
        if row['section_index']!=0 or data[s:s+n].hex()!=row['bytes']:raise ValueError('Stale native instruction bytes')
        code[s:s+n]=b'\1'*n
    for row in facts['ownership']:
        if row['status_name']=='accepted' and row['kind_name']!='code':
            s,e=row['start_offset'],row['end_offset'];classified[s:e]=b'\1'*(e-s)
    if any(c and d for c,d in zip(code,classified)):raise ValueError('Native code/data ownership overlap')
    s=0
    while s<len(data):
        e=s+1
        while e<len(data) and data[e]==data[s]:e+=1
        if e-s>=16 and data[s] in (0,255):padding[s:e]=b'\1'*(e-s)
        s=e
    return code,classified,padding

def window_index(data: bytes,width: int=32) -> dict:
    result={}
    for i in range(len(data)-width+1):
        k=data[i:i+width]
        result[k]=(result[k][0],result[k][1]+1) if k in result else (i,1)
    return result

def periodic(k: bytes) -> bool:
    return any(k==(k[:p]*((len(k)+p-1)//p))[:len(k)] for p in (1,2,4,8))

def unique_ranges(a: bytes,b: bytes,ca: bytearray,cb: bytearray) -> tuple[list,dict]:
    ia,ib=window_index(a),window_index(b);rows=[];last=-1;repeated=0;low=0
    for x in range(0,len(a)-31,8):
        if x<last or any(ca[x:x+32]):continue
        k=a[x:x+32]
        if periodic(k):low+=1;continue
        target=ib.get(k)
        if target is None:continue
        if ia[k][1]!=1 or target[1]!=1:repeated+=1;continue
        y=target[0]
        if any(cb[y:y+32]):continue
        s,t=x,y;e,f=x+32,y+32
        while s and t and not ca[s-1] and not cb[t-1] and a[s-1]==b[t-1]:s-=1;t-=1
        while e<len(a) and f<len(b) and not ca[e] and not cb[f] and a[e]==b[f]:e+=1;f+=1
        rows.append((s,t,e-s));last=e
    ma=bytearray(len(a));mb=bytearray(len(b));selected=[];overlaps=0
    for x,y,n in sorted(set(rows),key=lambda q:-q[2]):
        if any(ma[x:x+n]) or any(mb[y:y+n]):overlaps+=1;continue
        ma[x:x+n]=b'\1'*n;mb[y:y+n]=b'\1'*n;selected.append((x,y,n))
    return selected,dict(repeated_seed_samples=repeated,periodic_seed_samples=low,overlap_candidates=overlaps)

def reference_index(facts: dict) -> tuple[dict,dict]:
    refs={};edges={}
    for r in facts['references']:
        if r.get('section_index')==r.get('target_section_index')==0 and r.get('provenance')=='typed_operand' and not r.get('comment_only',False):
            refs.setdefault(r['source_offset'],{})[r['operand_index']]=r['target_offset']
    for e in facts['edges']:
        if e['section_index']==e['target_section_index']==0 and e['status']=='resolved' and e['kind'] in ('branch','jump','call'):
            edges.setdefault(e['source_offset'],set()).add(e['target_offset'])
    return refs,edges

def operation_form(row: dict,refs: dict,edges: dict,mapping: dict|None) -> str:
    fields=json.loads(json.dumps(row['operand_facts']));targets=[]
    for f in fields:
        target=refs.get(row['source_offset'],{}).get(f['operand_index'])
        if f['access']=='branch_target':
            choices=edges.get(row['source_offset'],set())
            if len(choices)==1:target=next(iter(choices))
        if target is None:continue
        if not (f['access']=='branch_target' or f.get('absolute_address') is not None or f.get('pc_relative') or f.get('immediate_value')==target+4096):continue
        if mapping is not None and target not in mapping:raise ValueError('Unqualified changed target')
        value=mapping[target] if mapping is not None else target
        targets.append((f['operand_index'],value))
        if f.get('absolute_address') is not None:f['absolute_address']=value+4096
        if f.get('pc_relative'):f['displacement']='resolved_target'
        if f.get('immediate_value')==target+4096:f['immediate_value']=value+4096
    return json.dumps((row['mnemonic'],row['text'].split()[0],row['size'],fields,targets),sort_keys=True)

def check_baseline(a: bytes,b: bytes,fa: dict,fb: dict,spec: dict) -> dict:
    mapping={};inverse={};counts=Counter()
    for x,y,n,kind in spec['code_ranges']:
        counts[str(kind)]+=n
        for i in range(n):
            if mapping.get(x+i,y+i)!=y+i or inverse.get(y+i,x+i)!=x+i:raise ValueError('Baseline not one-to-one')
            mapping[x+i]=y+i;inverse[y+i]=x+i
    if sum(counts.values())!=spec['frozen']['code_bytes']:raise ValueError('Baseline count changed')
    for x,y in spec['literal_data_anchor_points']:
        k=a[x:x+32]
        if k!=b[y:y+32] or a.find(k)!=a.rfind(k) or b.find(k)!=b.rfind(k):raise ValueError('Data anchor is no longer unique/exact')
        mapping[x]=y
    ra,ea=reference_index(fa);rb,eb=reference_index(fb)
    aa={r['source_offset']:r for r in fa['instructions']};bb={r['source_offset']:r for r in fb['instructions']}
    for x,y,n,kind in spec['code_ranges']:
        s,t=x,y
        while s<x+n:
            left,right=aa.get(s),bb.get(t)
            if left is None or right is None or left['size']!=right['size']:raise ValueError('Baseline instruction boundary changed')
            if left['bytes']!=right['bytes']:
                if kind==1 or operation_form(left,ra,ea,mapping)!=operation_form(right,rb,eb,None):raise ValueError('Frozen operation/operand claim changed')
            s+=left['size'];t+=right['size']
        if s!=x+n:raise ValueError('Baseline cuts an instruction')
    for x,y,n in spec['heldout_code_ranges']:
        if a[x:x+n]!=b[y:y+n]:raise ValueError('Held-out control changed')
        if any(z in inverse for z in range(y,y+n)):raise ValueError('Held-out code entered baseline')
    return {'validated_bytes':sum(counts.values()),'kind_bytes':dict(counts),'holdouts_excluded':True}

def report(root: Path,cache: Path) -> dict:
    from amiga_reversing.disasm.game_catalog import load_family,materialize
    started=time.perf_counter();family=load_family(root,'starglider2')
    spec=json.loads((root/'targets'/TARGETS[1]/'comparison_spec.json').read_text())
    for target,expected in zip(TARGETS,spec['payloads']):
        actual=family['targets'][target]['artifact']
        if actual!=expected['sha256'] or family['artifacts'][actual]['size']!=expected['bytes']:
            raise ValueError('Comparison spec belongs to a different release; review the baseline before use')
    blobs=[];facts=[];hits=[];identities=[]
    for target in TARGETS:
        sha=family['targets'][target]['artifact'];path=materialize(root,'starglider2',sha);data=path.read_bytes()
        if digest(data)!=sha or len(data)!=family['artifacts'][sha]['size']:raise ValueError('Payload identity mismatch')
        snap,hit=snapshot(root,target,path,sha,cache);blobs.append(data);facts.append(snap);hits.append(hit)
        identities.append({'target':target,'sha256':sha,'bytes':len(data),'native_snapshot_key':snap['key']})
    a,b=blobs;fa,fb=facts;ca,da,za=masks(a,fa);cb,db,zb=masks(b,fb)
    frozen=check_baseline(a,b,fa,fb,spec)
    code_map={x+i:y+i for x,y,n,_ in spec['code_ranges'] for i in range(n)}
    exact_controls={y+i:x+i for x,y,n,kind in spec['code_ranges'] if kind==1 for i in range(n)}
    for start,end in ((0x3a7e,0x3a9c),(0x3cb4,0x3cd4)):
        if any(exact_controls.get(i)!=i-24 for i in range(start,end)):
            raise ValueError('Independent Amiga variant selector/reader control is missing')
    qualified_controls={y+i:x+i for x,y,n,kind in spec['code_ranges'] if kind in (1,2) for i in range(n)}
    for start,end in ((0xdf98,0xe054),(0xe0ec,0xe118)):
        if any(qualified_controls.get(i)!=i-76 for i in range(start,end)):
            raise ValueError('Independent Amiga model-viewer producer control is missing')
    ranges,ambiguity=unique_ranges(a,b,ca,cb);raw=0;padding=0;classes=Counter();ma=bytearray(len(a));mb=bytearray(len(b))
    for x,y,n in ranges:
        raw+=n
        for i in range(n):
            if za[x+i] or zb[y+i]:padding+=1;continue
            classes[(('classified' if da[x+i] else 'unclassified')+'__'+('classified' if db[y+i] else 'unclassified'))]+=1
            if da[x+i] and db[y+i]:ma[x+i]=mb[y+i]=1
    # Preserve the 735 already-proven extra typed bytes; no count-only shortcut.
    for x,y,n,kind in spec['typed_data_extra_ranges']:
        if kind==1 and a[x:x+n]!=b[y:y+n]:raise ValueError('Typed literal baseline changed')
        if kind==2:
            if n%4:raise ValueError('Pointer baseline cuts a field')
            for i in range(0,n,4):
                left=int.from_bytes(a[x+i:x+i+4],'big')-4096;right=int.from_bytes(b[y+i:y+i+4],'big')-4096
                if code_map.get(left)!=right:raise ValueError('Frozen pointer target correspondence changed')
        for i in range(n):
            if ca[x+i] or cb[y+i] or not da[x+i] or not db[y+i]:raise ValueError('Typed baseline classification changed')
            ma[x+i]=mb[y+i]=1
    assets=json.loads((root/'targets'/TARGETS[0]/'rendered-manifest.json').read_text())['assets'];full_assets=0;asset_bytes=0
    for item in assets:
        x,n=item['source_offset'],item['size'];k=a[x:x+n];y=b.find(k)
        if y>=0 and a.find(k)==a.rfind(k)==x and b.rfind(k)==y and not any(ca[x:x+n]) and not any(cb[y:y+n]):full_assets+=1;asset_bytes+=n
    # ST consumers establish these initial-source extents independently. The
    # corresponding Amiga selector/reader operations are frozen exact code
    # controls; compare complete consumed streams, not plausible PTR prefixes.
    models_a,models_b=model_streams(a,96628),model_streams(b,102964)
    streams=Counter();variant_prefix_bytes=0;pointer_fields=0;pointer_added=0
    if len(models_a)!=len(models_b):raise ValueError('Model directory alias structure changed')
    for left,right in zip(models_a,models_b):
        if left['ordinals']!=right['ordinals'] or left['vertices']!=right['vertices']:
            raise ValueError('Model ordinal/vertex roles differ')
        for kind in ('main','extra'):
            if (kind in left)!=(kind in right):raise ValueError('Optional face-stream roles differ')
            if kind not in right:continue
            x,y=left[kind],right[kind]
            if x['count']!=y['count'] or a[x['start']:x['end']]!=b[y['start']:y['end']]:
                raise ValueError('Complete counted face stream differs')
            streams[kind+'_streams']+=1;streams[kind+'_records']+=y['count']
            streams[kind+'_bytes']+=y['end']-y['start']
        if ('variant_first' in left)!=('variant_first' in right):raise ValueError('Variant pointer roles differ')
        if 'variant_first' not in right:continue
        x,y=left['variant_first'],right['variant_first']
        if x['offsets']!=y['offsets'] or a[x['start']:x['end']]!=b[y['start']:y['end']]:
            raise ValueError('First variant read footprint differs')
        variant_prefix_bytes+=y['end']-y['start'];pointer_fields+=1
        for i in range(4):
            u,v=x['table']+i,y['table']+i
            if ca[u] or cb[v] or not da[u] or not db[v]:raise ValueError('Variant prefix is not classified data in both targets')
            if ma[u]!=mb[v]:raise ValueError('Asymmetric typed correspondence overlap')
            pointer_added+=not ma[u];ma[u]=mb[v]=1
    # Extend beyond selector one only through the independently tested viewer
    # producer. These role-qualified bytes may be repeated or padding-like;
    # retain the exact nonpadding scan unchanged as a separate tier.
    control_a,control_b=spec['viewer_variant_control_offsets']
    if a[control_a:control_a+416]!=b[control_b:control_b+416]:raise ValueError('Viewer cycle controls differ')
    viewer_before=sum(ma);viewer_added=Counter();views_count=0;view_bytes=0;table_bytes=0
    def claim_role(x,y,n,kind):
        for i in range(n):
            u,v=x+i,y+i
            if ca[u] or cb[v] or not da[u] or not db[v]:raise ValueError('Viewer role overlaps code or unclassified data')
            if ma[u]!=mb[v]:raise ValueError('Asymmetric viewer role overlap')
            viewer_added[kind]+=not ma[u];ma[u]=mb[v]=1
    claim_role(control_a,control_b,416,'cycle_controls')
    for left,right in zip(models_a,models_b):
        if 'variant_first' not in right:continue
        va,vb=bounded_variants(a,left,control_a),bounded_variants(b,right,control_b)
        if va['states']!=vb['states'] or len(va['views'])!=len(vb['views']):raise ValueError('Viewer selector roles differ')
        for x,y in zip(va['views'],vb['views']):
            n=x['end']-x['start']
            if x['selector']!=y['selector'] or x['offsets']!=y['offsets'] or a[x['start']:x['end']]!=b[y['start']:y['end']]:
                raise ValueError('Viewer variant reference footprint differs')
            claim_role(x['start'],y['start'],n,'reference_footprints')
            claim_role(x['pointer_offset'],y['pointer_offset'],4,'pointer_storage')
            views_count+=1;view_bytes+=n;table_bytes+=4
    current=[]
    for code,data in ((ca,da),(cb,db)):
        current.append({'known_code_bytes':sum(code),'classified_noncode_bytes':sum(data),'unclassified_bytes':sum(not x and not y for x,y in zip(code,data))})
    relation=spec['reviewed_counter_relation'];left_entry,right_entry=relation['initializer_entries']
    for payload,table,entry in zip((a,b),relation['initializer_table_offsets'],(left_entry,right_entry)):
        slot=table+4*relation['initializer_table_index']
        if int.from_bytes(payload[slot:slot+4],'big')!=entry+4096:
            raise ValueError('Reviewed initializer-table slot changed')
    if a[left_entry:left_entry+10]!=b[right_entry:right_entry+10]:raise ValueError('Reviewed initializer prefix changed')
    counter_a,counter_b=relation['source_offsets']
    accesses=[]
    for f,address in ((fa,counter_a+4096),(fb,counter_b+4096)):
        accesses.append(Counter(i['mnemonic'] for i in f['instructions'] if any(o.get('absolute_address')==address and o['width_bytes']==2 for o in i['operand_facts'])))
    if accesses[0]!=accesses[1] or accesses[0]!=Counter({'clr':1,'addq':1,'cmp':1}):raise ValueError('Counter access/lifetime contract changed')
    # This is a review-backed entry pairing, kept distinct from the 147 frozen
    # primitive code-target pairs. It does not assert whole-function behavior.
    reviewed_pointer_bytes=4
    reviewed_added=0
    for i in range(4):
        x=relation['initializer_table_offsets'][0]+4*relation['initializer_table_index']+i
        y=relation['initializer_table_offsets'][1]+4*relation['initializer_table_index']+i
        if ma[x]!=mb[y]:raise ValueError('Asymmetric reviewed pointer overlap')
        reviewed_added+=not ma[x]
    retained=spec['retained_checkpoint_40110']
    retained_streams=spec['retained_checkpoint_57078']
    retained_producers=spec['retained_checkpoint_92794']
    actor_dispatch=[]
    for start,end in ((0x703e,0x7166),(0x7230,0x7358)):
        tables=[t for t in fb['table_descriptors'] if t['start_offset']==start and t['end_offset']==end]
        if len(tables)!=1 or tables[0]['entry_count']!=148 or tables[0]['table_kind']!='relative_code_dispatch' or tables[0]['conflict_state']:
            raise ValueError('Qualified native actor dispatch table changed')
        actor_dispatch.append(tables[0])
    return {'schema_version':1,'kind':'source-bound-SGII-comparison-not-exhaustive-equivalence','inputs':identities,'cache_hits':hits,
        'frozen_baseline':spec['frozen'],'code_baseline':frozen,'current_native':current,'code_denominators_unchanged':[current[i]['known_code_bytes']==spec['frozen']['code_denominators'][i] for i in range(2)],
        'exact_noncode':{'ranges':len(ranges),'anchored_bytes':raw,'zero_ff_padding_like_bytes':padding,'nonpadding_bytes':raw-padding,'classification_pairs':dict(classes),'ambiguity':ambiguity},
        'typed_data_correspondence_lower_bound':sum(ma),'typed_data_gain_vs_frozen':sum(ma)-spec['frozen']['typed_data_correspondence_bytes'],
        'delta_since_retained_checkpoint_40110':{
            'st_classified_noncode_bytes':current[1]['classified_noncode_bytes']-retained['st_classified_noncode_bytes'],
            'typed_data_correspondence_bytes':sum(ma)-retained['typed_data_correspondence_bytes'],
            'code_bytes_per_target':frozen['validated_bytes']-retained['code_bytes_per_target']},
        'delta_since_retained_checkpoint_57078':{
            'st_classified_noncode_bytes':current[1]['classified_noncode_bytes']-retained_streams['st_classified_noncode_bytes'],
            'typed_data_correspondence_bytes':sum(ma)-retained_streams['typed_data_correspondence_bytes'],
            'code_bytes_per_target':frozen['validated_bytes']-retained_streams['code_bytes_per_target']},
        'delta_since_retained_checkpoint_92794':{
            'st_classified_noncode_bytes':current[1]['classified_noncode_bytes']-retained_producers['st_classified_noncode_bytes'],
            'st_known_code_bytes':current[1]['known_code_bytes']-retained_producers['st_known_code_bytes'],
            'typed_data_correspondence_bytes':sum(ma)-retained_producers['typed_data_correspondence_bytes'],
            'code_correspondence_bytes_per_target':frozen['validated_bytes']-retained_producers['code_bytes_per_target']},
        'actor_dispatch':{'native_tables':actor_dispatch,'stored_domain_checked':[0,147],
            'universal_id_guard_claimed':False,'word_index_wrap_aliases':True,
            'semantic_regressions':'tests/test_starglider2_actor_dispatch.py'},
        'review_backed_pointer_storage_bytes':reviewed_pointer_bytes,'review_backed_pointer_unique_increment':reviewed_added,
        'typed_data_including_reviewed_pointer':sum(ma)+reviewed_added,
        'model_streams':dict(streams),'variant_first_prefixes':{'count':pointer_fields,'read_footprint_bytes':variant_prefix_bytes,
            'pointer_storage_bytes':4*pointer_fields,'unique_typed_pointer_increment':pointer_added,'full_variant_table_extents_claimed':False},
        'viewer_bounded_variants':{'context':'model viewer; not arbitrary actor state','views':views_count,
            'reference_footprint_bytes':view_bytes,'pointer_storage_bytes':table_bytes,'cycle_control_bytes':416,
            'unique_role_bytes_added':sum(ma)-viewer_before,'unique_role_increment_by_kind':dict(viewer_added),
            'universal_renderer_guard_claimed':False,'whole_frame_storage_claimed':False},
        'initializer_table_targets':{'frozen_primitive_code_pairs':147,'review_backed_entry_pair':1,'whole_function_equivalence_claimed':False},
        'full_unique_assets':{'count':full_assets,'bytes':asset_bytes,'extra_coverage':0,'runtime_use_transferred':False},
        'tentative_matches_promoted':False,'reviewed_counter_relation':spec['reviewed_counter_relation'],'counter_scope':'See executable regression cases; no whole-function behavior equality claimed.',
        'runtime_seconds':time.perf_counter()-started}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT);parser.add_argument('--cache',type=Path);parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args();root=args.root.resolve();cache=args.cache or root/'.runtime-state/sgii-comparison'
    result=report(root,cache);args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'validated_code_bytes':result['code_baseline']['validated_bytes'],'typed_data_lower_bound':result['typed_data_correspondence_lower_bound'],
        'typed_data_gain':result['typed_data_gain_vs_frozen'],'current_native':result['current_native'],'cache_hits':result['cache_hits'],'runtime_seconds':result['runtime_seconds']}))
if __name__=='__main__':main()

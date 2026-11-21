"""Pinned sampled-cycle to view/model arithmetic contracts; no guest execution."""
import argparse
import hashlib
import json
import math
import struct
from pathlib import Path

from tools.foft_irq_write_audit import mem, require
from tools.foft_music_voice_effects_audit import ea
from tools.foft_render_contract_audit import MAIN_SHA256, composition, operand, window


def phase_pair(a,b):
    require(type(a)is int and type(b)is int and 0<=a<512 and 0<=b<512,
            'canonical model phases required')
    total=a+b
    if total>=512:total-=512
    difference=a-b
    if difference<0:difference+=512
    return total,difference


def sampled_cycles(sine,cosine):
    require(len(sine)==len(cosine)==513,'cycle needs 512 samples and endpoint')
    require(all(type(v)is int and -32768<=v<=32767 for v in [*sine,*cosine]),'signed sample differs')
    require(sine[0]==sine[512]==0 and cosine[0]==cosine[512]==32767,'cycle endpoint differs')
    require(all(cosine[i]==sine[(i+128)%512]for i in range(513)),'quarter-phase relation differs')
    require(all(sine[(i+256)%512]==-sine[i]for i in range(512)),'half-phase antisymmetry differs')
    error=max(abs(sine[i]-32768*math.sin(2*math.pi*i/512))for i in range(513))
    require(error<1.5,'samples do not fit the evidenced Q15 sine envelope')
    return {'period':512,'stored_words_per_cycle':513,'cosine_phase_shift':128,
            'sample_min':min(sine),'sample_max':max(sine),'max_q15_sine_error':error,
            'generation_rounding_rule_proved':False,'current_table_constness_proved':False}


def signed_word(v):return v-65536 if v&0x8000 else v


def q15_product_word(a,b):
    require(type(a)is int and type(b)is int and 0<=a<=65535 and 0<=b<=65535,'WORD arguments required')
    product=(signed_word(a)*signed_word(b))&0xFFFFFFFF
    swapped=((product&0xFFFF)<<16)|(product>>16)
    return ((swapped<<1)|(swapped>>31))&0xFFFF


def clamp_word(v):
    require(type(v)is int and 0<=v<=65535,'WORD argument required')
    if signed_word(v)>=0:return min(v,0x3FFF)
    magnitude=(-v)&0xFFFF
    if signed_word(magnitude)>=0x4000:magnitude=0x3FFF
    return (-magnitude)&0xFFFF


def q15_reductions(block):
    result=[]
    for i,row in enumerate(block):
        if row['mnemonic']!='muls':continue
        require(i+2<len(block),'truncated product reduction')
        swap,rotate=block[i+1:i+3]
        require(swap['mnemonic']=='swap'and rotate['mnemonic']=='rol','Q15 product sequence differs')
        reg=row['operand_facts'][1]['direct_register']
        operand(row,1,register=reg);operand(swap,0,register=reg,width=4)
        require(rotate['operand_facts'][0]['immediate_value']==1,'Q15 rotate count differs')
        operand(rotate,1,register=reg,width=4)
        result.append({'runtime':row['source_offset']+0x800,'register':reg,'low_word_shift':15})
    return result


def rotation_rows(block,first_column,second_column):
    require(len(block)==60,'rotation needs three twenty-instruction rows')
    expected=['move','muls','swap','rol','move','muls','swap','rol','sub',
              'move','muls','swap','rol','move','muls','swap','rol','add','move','move']
    result=[]
    for r in range(3):
        part=block[20*r:20*r+20]
        require([p['mnemonic']for p in part]==expected,'rotation row sequence differs')
        first=0xFCD4+2*(3*r+first_column);second=0xFCD4+2*(3*r+second_column)
        for i,address,reg in [(0,first,'D2'),(4,second,'D3'),(9,second,'D4'),(13,first,'D3')]:
            ea(part[i],0,address);operand(part[i],1,register=reg)
        for i,source,dest in [(1,'D1','D2'),(5,'D0','D3'),(10,'D1','D4'),(14,'D0','D3')]:
            operand(part[i],0,register=source);operand(part[i],1,register=dest)
        for i,dest in [(8,'D2'),(17,'D4')]:
            operand(part[i],0,register='D3');operand(part[i],1,register=dest)
        for i,address,reg in [(18,first,'D2'),(19,second,'D4')]:
            operand(part[i],0,register=reg);operand(part[i],1,address=address)
        result.append({'matrix_row':r,'first_column':first_column,'second_column':second_column,
                       'first_store_runtime':part[18]['source_offset']+0x800,
                       'second_store_runtime':part[19]['source_offset']+0x800})
    return result


def check_source(rows,analysis,data):
    require(len(data)==489472 and hashlib.sha256(data).hexdigest()==MAIN_SHA256,'main identity differs')
    require(all(r['provenance']=='accepted_instruction'and data[r['source_offset']:r['source_offset']+r['size']]==bytes.fromhex(r['bytes'])for r in rows),'accepted row bytes differ')
    at={r['source_offset']+0x800:r for r in rows}
    sine=struct.unpack_from('>513h',data,0x571EE-0x800);cosine=struct.unpack_from('>513h',data,0x575F0-0x800)
    tables=sampled_cycles(sine,cosine)
    tables['spans']=[{'runtime_start':lo,'runtime_end':hi,'sha256':hashlib.sha256(data[lo-0x800:hi-0x800]).hexdigest()}for lo,hi in [(0x571EE,0x575F0),(0x575F0,0x579F2)]]
    model=window(rows,0xEFAC,0xF16E);view=window(rows,0xFA68,0xFC24)
    require(len(model)==117 and len(view)==149 and not any(r['mnemonic']in('bsr','jsr','jmp','rts')for r in model+view),'builder framing differs')
    for pc,address in [(0xEFAC,0x571EE),(0xEFB2,0x575F0),(0xFA68,0x571EE),(0xFA6E,0x575F0)]:operand(at[pc],0,address=address,width=4)
    pitch=rotation_rows(window(rows,0xFA8C,0xFB34),1,2)
    roll=rotation_rows(window(rows,0xFB4C,0xFBF4),0,1)
    reductions=q15_reductions(model)+q15_reductions(view)
    require(len(reductions)==28,'model/view Q15 product count differs')
    for guard,mask,target in [(0xFA7A,0xFA7E,0xFB34),(0xFB3A,0xFB3E,0xFBF4)]:
        require(at[guard]['mnemonic']=='beq'and at[mask]['mnemonic']=='andi'and at[mask]['operand_facts'][0]['immediate_value']==511,'increment zero/mask order differs')
        require(any(e['source_offset']+0x800==guard and e['target_offset']+0x800==target and e['kind']==2 for e in analysis['edges']),'increment skip edge differs')
    for pc,reg in [(0xEFEC,'D3'),(0xF064,'D0'),(0xF0B2,'D0')]:
        require(at[pc]['mnemonic']=='cmp'and at[pc]['operand_facts'][0]['immediate_value']==512,'model sum wrap differs');operand(at[pc],1,register=reg)
    for pc,op,reg in [(0xEFF2,'subi','D3'),(0xF06A,'subi','D0'),(0xF0B8,'subi','D0'),(0xF004,'addi','D0'),(0xF076,'addi','D3'),(0xF0C4,'addi','D3')]:
        require(at[pc]['mnemonic']==op and at[pc]['operand_facts'][0]['immediate_value']==512,'model phase correction differs');operand(at[pc],1,register=reg)
    for pc,op,skip,correction in [(0xEFF0,'blt',0xEFF6,0xEFF2),(0xF002,'bpl',0xF008,0xF004),(0xF068,'blt',0xF06E,0xF06A),(0xF074,'bpl',0xF07A,0xF076),(0xF0B6,'blt',0xF0BC,0xF0B8),(0xF0C2,'bpl',0xF0C8,0xF0C4)]:
        require(at[pc]['mnemonic']==op and {(e['kind'],e['target_offset']+0x800)for e in analysis['edges']if e['source_offset']+0x800==pc}=={(2,skip),(1,correction)},'single-wrap signed control differs')
    for pc,base,index,op in [(0xF032,'A0','D3','movea'),(0xF036,'A0','D0','suba'),(0xF044,'A1','D0','movea'),(0xF048,'A1','D3','suba')]:
        require(at[pc]['mnemonic']==op,'half-difference operation differs')
        sample=at[pc]['operand_facts'][0]
        require(sample['memory'] and sample['access']=='memory_read' and sample['width_bytes']==2 and sample['indexed'] and sample['base_register']==base and sample['index_register']==index and sample['index_width_bytes']==2 and sample['index_scale']==1 and sample['displacement']==0 and sample['displacement_known'] and sample['ea_update']==0 and not sample['bulk_transfer'],'half-difference sample index differs')
        operand(at[pc],1,register='A2')
    for pc in (0xF03A,0xF04C):
        require(at[pc]['mnemonic']=='move','half-difference transfer differs')
        operand(at[pc],0,register='A2',width=4);operand(at[pc],1,register='D1',width=4)
        shift=at[pc+2]
        require(shift['mnemonic']=='lsr'and shift['operand_facts'][0]['immediate_value']==1,'half-difference shift differs')
        operand(shift,1,register='D1',width=4)
    for pc,address in [(0xEFD0,0xF2EE),(0xEFD8,0xF2F0),(0xF03E,0xFCBA),(0xF050,0xFCBC)]:operand(at[pc],1,address=address)
    clamp=window(rows,0xFBF4,0xFC24)
    require([r['mnemonic']for r in clamp]==['lea','moveq','move','bpl','neg','cmp','blt','move','neg','bra','cmp','ble','move','move','dbf'],'orientation clamp framing differs')
    ea(at[0xFBF4],0,0xFCD4);operand(at[0xFBF4],1,register='A0',width=4)
    require(at[0xFBF8]['operand_facts'][0]['immediate_value']==8,'clamp count differs')
    for pc,value in [(0xFC02,0x4000),(0xFC08,0x3FFF),(0xFC12,0x3FFF),(0xFC1A,0x3FFF)]:require(at[pc]['operand_facts'][0]['immediate_value']==value,'clamp threshold differs')
    mem(at[0xFC1E]['operand_facts'][1],access='memory_write',width=2,base='A0',update=1)
    require({(e['kind'],e['target_offset']+0x800)for e in analysis['edges']if e['source_offset']+0x800==0xFC20}=={(2,0xFBFA),(1,0xFC24)},'clamp/transpose handoff differs')
    product=composition(rows)
    transpose=window(rows,0xFC24,0xFC92)
    require(len(transpose)==28 and transpose[-1]['mnemonic']=='rts','existing doubled transpose framing differs')
    reset=window(rows,0xFCFE,0xFD3E)
    require(len(reset)==12 and [r['mnemonic']for r in reset]==['moveq',*(['move']*10),'bra'],'adjacent reset framing differs')
    require(reset[0]['operand_facts'][0]['immediate_value']==0 and reset[7]['operand_facts'][0]['immediate_value']==0x3FFF,'adjacent reset values differ')
    for position,cell in [(1,1),(2,2),(3,3),(4,5),(5,6),(6,7),(8,0),(9,4),(10,8)]:
        operand(reset[position],0,register='D0');operand(reset[position],1,address=0xFCD4+2*cell)
    require(any(e['source_offset']+0x800==0xFD3A and e['target_offset']+0x800==0xFC24 and e['kind']==4 for e in analysis['edges']),'reset transpose branch differs')
    reset_callers=[e['source_offset']+0x800 for e in analysis['edges']if e['kind']==3 and e['target_offset']+0x800==0xFCFE]
    require(reset_callers==[0x2F0E0],'adjacent reset caller inventory differs')
    roots=[]
    for row in rows:
        if row['mnemonic']!='lea':continue
        source=row['operand_facts'][0]
        if source.get('absolute_address')in(0x571EE,0x575F0):
            roots.append({'runtime':row['source_offset']+0x800,'cycle_runtime':source['absolute_address'],'register':row['operand_facts'][1]['direct_register']})
    callers={name:[e['source_offset']+0x800 for e in analysis['edges']if e['kind']==3 and e['target_offset']+0x800==pc]for name,pc in [('model_coefficients',0xEFAC),('view_update',0xFA68)]}
    require(len(callers['model_coefficients'])==39 and len(callers['view_update'])==19,'recognized caller inventory differs')
    return {'main_sha256':MAIN_SHA256,'cycles':tables,'typed_source_bytes':2060,
        'recognized_direct_callers':callers,'model_setup_span':[0xEFAC,0xF16E],'model_setup_instructions':len(model),
        'view_update_clamp_span':[0xFA68,0xFC24],'view_update_clamp_instructions':len(view),
        'q15_product_reductions':reductions,'pitch_column_pairs':pitch,'roll_column_pairs':roll,
        'composition_cells_rechecked':product,'existing_transpose_instructions_rechecked':len(transpose),'adjacent_reset':{'runtime_start':0xFCFE,'runtime_end':0xFD3E,'instructions':len(reset),'diagonal_word':0x3FFF,'off_diagonal_word':0,'recognized_direct_callers':reset_callers,'tail_branch_runtime':0xFC24,'post_return_freshness_proved':False},
        'existing_matrix_and_scale_contract':'foft-frame-matrix-counts.md; original member bytes unchanged',
        'direct_cycle_root_loads':roots,'clamp_word_result_domain':'[-16383,16383] plus 0x8000; no current input invariant',
        'scratch_pairs':[{'runtime_start':0xF2EE,'runtime_end':0xF2F2,'roles':['orientation-1 sine','orientation-1 cosine']},{'runtime_start':0xFCBA,'runtime_end':0xFCBE,'roles':['half sin(sum02)-sin(diff02)','half cos(diff02)-cos(sum02)']}],
        'source_requirements':['original cycle/code bytes','canonical model phases for single-wrap paths','valid current shared matrix/scratch roots','intact call/exception frames','no unaccounted alias/device writes'],
        'runtime_executed':False,'table_constness_or_matrix_freshness_proved':False,
        'global_orthogonality_or_current_angle_bounds_proved':False,'new_control_or_receiver_facts_emitted':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('main','rows','analysis','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();result=check_source(json.loads(a.rows.read_text()),json.loads(a.analysis.read_text()),a.main.read_bytes())
    a.output.write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()

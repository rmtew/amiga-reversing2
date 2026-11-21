"""Read-only flight translation/input and object handoff source contracts."""
import argparse
import hashlib
import json
from pathlib import Path

from tools.foft_irq_write_audit import mem, require
from tools.foft_music_voice_effects_audit import ea
from tools.foft_render_contract_audit import MAIN_SHA256, operand, window
from tools.foft_trig_view_audit import q15_product_word, q15_reductions, signed_word


def wrap_local(coarse,local):
    require(all(type(v)is int and 0<=v<=65535 for v in (coarse,local)),'WORD arguments required')
    value=signed_word(local)
    if value>8192:return (coarse+1)&65535,(local-16384)&65535
    if value<-8192:return (coarse-1)&65535,(local+16384)&65535
    return coarse,local


def translation_word(component,step,*,coarse=False):
    require(all(type(v)is int and 0<=v<=65535 for v in (component,step)),'WORD arguments required')
    if coarse:return ((signed_word(component)*signed_word(step))>>16)&65535
    return q15_product_word(component,step)


def local_translation(block):
    require(len(block)==21,'local translation needs three seven-instruction groups')
    result=[]
    for axis in range(3):
        part=block[7*axis:7*axis+7]
        require([r['mnemonic']for r in part]==['move','move','muls','swap','rol',*(['add','move']if axis<2 else['move','add'])],'local translation ordering differs')
        ea(part[0],0,0xC1F4+2*axis);operand(part[0],0,width=2);operand(part[0],1,register='D0')
        operand(part[1],0,register='D0');operand(part[1],1,address=0xC200+2*axis)
        operand(part[2],0,register='D1');operand(part[2],1,register='D0')
        q15_reductions(part)
        add=part[5 if axis<2 else 6];save=part[6 if axis<2 else 5]
        operand(add,0,register='D0');operand(add,1,address=0x14DE6+2*axis)
        operand(save,0,register='D0');operand(save,1,address=0xC216+2*axis)
        result.append({'component':axis,'direction_store_runtime':part[1]['source_offset']+0x800,
                       'position_add_runtime':add['source_offset']+0x800,'delta_store_runtime':save['source_offset']+0x800})
    return result


def direct_address(row,p):
    if p.get('absolute_address')is not None:return p['absolute_address']
    if p.get('pc_relative')and not p.get('indexed')and p.get('displacement_known'):
        return row['source_offset']+0x802+p['displacement']
    return None


def check_source(rows,analysis,data):
    require(len(data)==489472 and hashlib.sha256(data).hexdigest()==MAIN_SHA256,'main identity differs')
    require(all(r['provenance']=='accepted_instruction'and data[r['source_offset']:r['source_offset']+r['size']]==bytes.fromhex(r['bytes'])for r in rows),'accepted row bytes differ')
    at={r['source_offset']+0x800:r for r in rows};body=window(rows,0xBD9E,0xC1EC)
    require(len(body)==237,'flight routine framing differs')
    require([r['source_offset']+0x800 for r in body if r['mnemonic']in('jsr','bsr')]==[0xBEE2],'flight call inventory differs')
    require([r['source_offset']+0x800 for r in body if r['mnemonic']=='rts']==[0xC05C,0xC1E8,0xC1EA],'flight return inventory differs')
    callers=[e['source_offset']+0x800 for e in analysis['edges']if e['kind']==3 and e['target_offset']+0x800==0xBD9E]
    require(callers==[0xFE0,0x14B2,0xC64C,0x1DFAE],'flight callers differ')
    def edges(pc):return {(e['kind'],e['target_offset']+0x800)for e in analysis['edges']if e['source_offset']+0x800==pc}
    for pc,mnemonic,skip,fallthrough in [(0xBDA4,'bne',0xC042,0xBDA8),(0xBF0E,'bne',0xC012,0xBF12),(0xBF1A,'bne',0xC012,0xBF1E),(0xC04E,'beq',0xC05E,0xC050),(0xC066,'bne',0xC1EA,0xC06A)]:
        require(at[pc]['mnemonic']==mnemonic and edges(pc)=={(2,skip),(1,fallthrough)},'flight path split differs')
    operand(at[0xBD9E],0,address=0xC21C);operand(at[0xC042],0,address=0xC21C)
    require(at[0xC042]['mnemonic']=='clr','skip WORD clear differs')
    for pc,bit in [(0xBDA8,2),(0xBF06,4),(0xBF12,5),(0xC05E,2)]:
        require(at[pc]['mnemonic']=='btst'and at[pc]['operand_facts'][0]['immediate_value']==bit,'mode gate differs')
    operand(at[0xBEE2],0,address=0xFA68,width=4)
    for axis,pc in enumerate((0xBEE8,0xBEF2,0xBEFC)):
        operand(at[pc],0,address=0xFC92+12+2*axis);operand(at[pc],1,address=0xC1F4+2*axis)
    local=local_translation(window(rows,0xBF24,0xBF78));operand(at[0xBF1E],0,address=0xC1FE);operand(at[0xBF1E],1,register='D1')
    coarse=window(rows,0xC012,0xC042)
    require(len(coarse)==13,'coarse translation framing differs');operand(coarse[0],0,address=0xC1FE);operand(coarse[0],1,register='D1')
    for axis in range(3):
        part=coarse[1+4*axis:5+4*axis]
        require([r['mnemonic']for r in part]==['move','muls','swap','add'],'coarse extraction differs')
        ea(part[0],0,0xC1F4+2*axis);operand(part[0],0,width=2);operand(part[0],1,register='D0')
        operand(part[1],0,register='D1');operand(part[1],1,register='D0');operand(part[2],0,register='D0',width=4)
        operand(part[3],0,register='D0');operand(part[3],1,address=0xF5B6+2*axis)
    wraps=[]
    for axis,lo,hi in [(2,0xBF78,0xBFAA),(1,0xBFAA,0xBFDC),(0,0xBFDC,0xC012)]:
        block=window(rows,lo,hi);ops=['move','bmi','cmp','ble','addq','subi','bra','cmp','bge','subq','addi']+(['bra']if axis==0 else[])
        require([r['mnemonic']for r in block]==ops,'coarse/local wrap ordering differs')
        operand(block[0],0,address=0x14DE6+2*axis);operand(block[0],1,register='D0')
        for index,value in [(2,8192),(7,0xE000),(5,16384),(10,16384),(4,1),(9,1)]:require(block[index]['operand_facts'][0]['immediate_value']==value,'wrap threshold or correction differs')
        for index in (4,9):operand(block[index],1,address=0xF5B6+2*axis)
        for index in (5,10):operand(block[index],1,address=0x14DE6+2*axis)
        wraps.append({'component':axis,'runtime_start':lo,'runtime_end':hi,'local_unit_per_coarse_unit':16384,'strict_signed_thresholds':[-8192,8192],'single_correction_only':True})
    for pc,address in [(0xC050,0xC20A),(0xC056,0xC206)]:require(at[pc]['mnemonic']=='clr','suppressed turn clear differs');operand(at[pc],0,address=address)
    for counter,increment,dec_pcs,reload_pcs,increment_ops,compare_pcs,join in [(0xC208,0xC206,(0xC0C0,0xC0F6),(0xC08A,0xC0D6,0xC10C),((0xC0DC,'addq'),(0xC112,'subq')),(0xC0E2,0xC118),0xC12A),(0xC20C,0xC20A,(0xC17C,0xC1B4),(0xC144,0xC192,0xC1CA),((0xC198,'addq'),(0xC1D0,'subq')),(0xC19E,0xC1D6),0xC1E8)]:
        for pc in dec_pcs:
            require(at[pc]['mnemonic']=='subq'and at[pc]['operand_facts'][0]['immediate_value']==1,'turn countdown decrement differs');operand(at[pc],1,address=counter)
            require(at[pc+6]['mnemonic']=='bne'and (2,join)in edges(pc+6),'turn countdown zero gate differs')
        for pc in reload_pcs:require(at[pc]['mnemonic']=='move','turn reload differs');operand(at[pc],0,register='D0');operand(at[pc],1,address=counter)
        for pc,op in increment_ops:require(at[pc]['mnemonic']==op and at[pc]['operand_facts'][0]['immediate_value']==1,'turn step differs');operand(at[pc],1,address=increment)
        for pc,value in zip(compare_pcs,(15,0xFFF1),strict=True):require(at[pc]['operand_facts'][0]['immediate_value']==value,'turn clamp differs');operand(at[pc],1,address=increment)
    for axis,save,load in [(0,0x1E780,0x1EB50),(1,0x1E786,0x1EB4A),(2,0x1E78C,0x1EB44)]:
        address=0xFCF0-2*axis
        operand(at[save],0,address=address);mem(at[save]['operand_facts'][1],access='memory_write',width=2,base='A7',update=2)
        mem(at[load]['operand_facts'][0],access='memory_read',width=2,base='A7',update=1);operand(at[load],1,address=address)
    for axis,pc in enumerate((0x1E792,0x1E79C,0x1E7A6)):
        operand(at[pc],0,address=0x1E2B0+2*axis);operand(at[pc],1,address=0xFCF0-2*axis)
    require(edges(0x1EB5C)=={(4,0x1DA04)},'detail return branch differs')
    require(at[0x1DFA8]['mnemonic']=='st','map skip producer differs');operand(at[0x1DFA8],0,address=0xC21C,width=1)
    operand(at[0x1DFAE],0,address=0xBD9E,width=4)
    for index,pc in enumerate((0x1DFB4,0x1DFBE,0x1DFC8,0x1DFD2)):
        operand(at[pc],0,address=0x1FEBC+4*index,width=4);operand(at[pc],1,address=0xFCD4+4*index,width=4)
    operand(at[0x1DFDC],0,address=0x1FECC);operand(at[0x1DFDC],1,address=0xFCE4)
    for save,clear,restore,address in [(0x1DFE6,0x1DFF8,0x1E00A,0xC206),(0x1DFEC,0x1DFF2,0x1E004,0xC20A)]:
        operand(at[save],0,address=address);mem(at[save]['operand_facts'][1],access='memory_write',width=2,base='A7',update=2)
        require(at[clear]['mnemonic']=='clr','map increment zero differs');operand(at[clear],0,address=address)
        mem(at[restore]['operand_facts'][0],access='memory_read',width=2,base='A7',update=1);operand(at[restore],1,address=address)
    operand(at[0x1DFFE],0,address=0xFA68,width=4)
    require([r['mnemonic']for r in window(rows,0x1DFA8,0x1E010)]==['st','jsr',*(['move']*7),'clr','clr','jsr','move','move'],'map input/matrix ordering differs')
    overlay=window(rows,0xC622,0xC652)
    require([r['mnemonic']for r in overlay]==['jsr','jsr','jsr','jsr','jsr','jsr','move','jsr'],'overlay producer order differs')
    for row,target in zip([*overlay[:6],overlay[7]],[0xFA68,0x14DE4,0x15A36,0x2AA4C,0x2A662,0xE564,0xBD9E],strict=True):
        operand(row,0,address=target,width=4)
    operand(overlay[6],0,register='D7')
    constructor_copies=[]
    for root,source,kind in [(0x2DA5A,0xFCF0,'missile_shared_spawn'),(0x2DD62,0xC200,'type4_retained_basis'),(0x2DE18,0xC200,'fusion_retained_basis')]:
        block=window(rows,root,root+18);require(len(block)==3 and all(r['mnemonic']=='move'for r in block),'constructor triple differs')
        for axis,row in enumerate(block):
            operand(row,0,address=source+(-2 if kind=='missile_shared_spawn'else 2)*axis)
            mem(row['operand_facts'][1],access='memory_write',width=2,base='A6',update=1)
        constructor_copies.append({'runtime':root,'source_runtime':source,'kind':kind,'source_stride':-2 if kind=='missile_shared_spawn'else 2,'receiver_bound_proved':False})
    shift=window(rows,0x2B2B4,0x2B2DA)
    require([r['mnemonic']for r in shift]==['move',*(['move','asr','add']*3),'bra'],'category5 vector consumer differs')
    mem(shift[0]['operand_facts'][0],access='memory_read',width=2,base='A1',displacement=8)
    for axis in range(3):
        part=shift[1+3*axis:4+3*axis];mem(part[0]['operand_facts'][0],access='memory_read',width=2,base='A1',displacement=2*axis)
        operand(part[1],0,register='D0');operand(part[1],1,register='D1')
        mem(part[2]['operand_facts'][1],access='memory_write',width=2,base='A0',displacement=2*axis)
    roots=[(0x14DE6,6,'local_position'),(0xC1F4,6,'motion_basis_row'),(0xC200,6,'retained_direction'),(0xC216,6,'local_delta'),(0xFCEC,6,'shared_spawn_orientation'),(0x1E2B0,6,'detail_orientation_source'),(0xC20E,8,'translation_requests'),(0xC1FE,2,'translation_step'),(0xC21C,2,'translation_skip_word'),(0xC208,2,'roll_repeat_countdown'),(0xC20C,2,'pitch_repeat_countdown')]
    refs=[]
    for lo,size,name in roots:
        uses=[]
        for row in rows:
            for p in row['operand_facts']:
                address=direct_address(row,p)
                if address is not None and lo<=address<lo+size:
                    require(p['width_bytes']in (1,2),'tuple has wider direct use')
                    uses.append({'runtime':row['source_offset']+0x800,'operand_index':p['operand_index'],'field_offset':address-lo,'width':p['width_bytes'],'access':p['access']})
        refs.append({'name':name,'runtime_start':lo,'runtime_end':lo+size,'sha256':hashlib.sha256(data[lo-0x800:lo+size-0x800]).hexdigest(),'literal_uses':uses,'indirect_alias_closure_proved':False})
    return {'main_sha256':MAIN_SHA256,'flight_routine_span':[0xBD9E,0xC1EC],'flight_routine_instructions':237,'recognized_direct_callers':callers,'typed_storage_bytes':sum(x[1]for x in roots),'storage_views':refs,'local_translation':local,'coarse_translation_span':[0xC012,0xC042],'coarse_local_wraps':wraps,'constructor_copies':constructor_copies,'category5_vector_consumer_span':[0x2B2B4,0x2B2DA],'detail_save_replace_restore':{'save_order':[0,1,2],'restore_order':[2,1,0],'source_is_distinct_from_view_matrix':True,'conditional_on_intact_stack_and_preserved_shared_state':True},'overlay_producer_order_span':[0xC622,0xC652],'overlay_producer_order_instructions':len(overlay),'map_caller_handoff_span':[0x1DFA8,0x1E028],'map_matrix_copy_words':9,'zero_increment_builder_still_clamps':True,'runtime_executed':False,'global_count_or_phase_or_current_receiver_bounds_proved':False,'new_control_or_receiver_facts_emitted':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('main','rows','analysis','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();a.output.write_text(json.dumps(check_source(json.loads(a.rows.read_text()),json.loads(a.analysis.read_text()),a.main.read_bytes()),indent=2)+'\n')


if __name__=='__main__':main()

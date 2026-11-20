"""Source-bound panel receivers and conditional bank/IRQ contracts.

The helpers below check finite data contracts; they neither execute guest code
nor assert that mutable bank, descriptor, callback or interrupt state is closed.
"""
import argparse
import json
from pathlib import Path

from tools.foft_action_ownership_audit import check_source as contact_contracts
from tools.foft_irq_write_audit import mem, require
from tools.foft_render_contract_audit import (
    flag_glyph_contract,
    indexed_panel_glyph_contract,
    operand,
    window,
)


def present_bank(value):
    require(type(value)is int and 0<=value<=0xFFFFFFFF,'expected a LONG bank offset')
    following=value^0x8000
    return {'following_draw_offset':following,'programmed_display_offset':0x8000 if following==0 else 0,
            'canonical_input':value in(0,0x8000),'after_detail_extra_toggle':following^0x8000}


def normal_body_count(random_word):
    require(type(random_word)is int and 0<=random_word<=65535,'expected source WORD')
    return random_word&15 or 3


def normal_body_selection(nibble,count):
    require(type(nibble)is int and 0<=nibble<16 and type(count)is int and 1<=count<=15,'requires normal body selection inputs')
    return min(nibble,count)


def irq_branch(request):
    require(type(request)is int and 0<=request<=65535,'expected request WORD')
    relevant=request&48
    return 'coper'if relevant&16 else'vblank'if relevant else'none'


def first_free_word_slot(occupied,start):
    require(type(occupied)is int and 0<=occupied<=65535,'expected sixteen occupancy bits')
    require(type(start)is int and 0<=start<16,'expected a slot index')
    for delta in range(16):
        slot=(start+delta)%16
        if not occupied&(1<<slot):return slot
    raise ValueError('a free slot is required; no guest loop is executed')


def population_window(population):
    require(type(population)is int and 0<=population<=10,'requires completed normal population 0..10')
    value=population or 1;low=value&3
    count=4*(value//3)+low+(low==3)
    return {'leading_one':population!=0,'glyph_count':count,
            'start_runtime':0x1EEDE-2*count,'end_runtime':0x1EEDE}


def coper_prefix(phase,count):
    require(type(phase)is int and phase in range(0,48,2),'requires intact even VBlank phase 0..46')
    require(type(count)is int and 0<=count<=48,'only first 48 COPER calls are covered')
    cursor=phase;step=2;reads=[]
    for ordinal in range(1,count+1):
        if ordinal==48:step=-2
        reads.append([cursor,cursor+8]);cursor+=step
    return {'read_byte_offsets':reads,'following_cursor_offset':cursor,'following_step':step}


def plane_operation_fixture(code,mask):
    """Apply only the original four byte writes to a synthetic 14-byte fixture."""
    require(len(code)==14,'expected four bit-operation instruction fixture')
    require(type(mask)is int and 0<=mask<16,'expected four plane-mask bits')
    output=bytearray(code)
    for bit,offset in enumerate((1,3,7,11)):
        output[offset]=(output[offset]&~64)|(64 if mask&(1<<bit)else 0)
    return bytes(output)


def copper_copy_entries(template):
    require(len(template)==76,'expected the bounded nineteen-entry template')
    for index in range(19):
        if template[4*index:4*index+4]==bytes.fromhex('fffffffe'):return index+1
    raise ValueError('template sentinel is not inside the bounded view')


def direct_bank_protocol(rows,bank=0x16E2,saved=0x13BD2):
    counts={'initialize':0,'toggle':0,'save':0,'restore':0}
    for row in rows:
        for field in row['operand_facts']:
            if not field.get('memory')or 'write'not in field.get('access','')or field.get('bulk_transfer'):continue
            address=field.get('absolute_address');width=field.get('width_bytes')
            if type(address)is not int or type(width)is not int:continue
            for target in(bank,saved):
                if not(address<target+4 and target<address+width):continue
                require(address==target and width==4,'partial bank/cache write has no closed protocol')
                source=row['operand_facts'][0];op=row['mnemonic']
                if target==bank and op=='eori'and source.get('immediate_value')==0x8000:counts['toggle']+=1
                elif target==bank and op=='move'and source.get('immediate_value')==0:counts['initialize']+=1
                elif target==bank and op=='move'and source.get('absolute_address')==saved:counts['restore']+=1
                elif target==saved and op=='move'and source.get('absolute_address')==bank:counts['save']+=1
                else:raise ValueError('unknown bank/cache assignment')
    return {'ordinary_absolute_operation_counts':counts,'scope':'ordinary fixed-width absolute operands only',
            'indirect_bulk_irq_and_raw_code_writers_closed':False}


def check_source(rows,analysis,data):
    old=contact_contracts(rows,analysis,data)
    at={r['source_offset']+2048:r for r in rows}
    protocol=direct_bank_protocol(rows)
    initial_banks=[int.from_bytes(data[p-2048:p-2048+4],'big')for p in(0x16E2,0x13BD2)]
    require(initial_banks==[0,0],'initial explicit bank/cache protocol state differs')
    for pc,value in [(0xB430,0x8000),(0x1E7DC,0x8000)]:
        require(at[pc]['mnemonic']=='eori'and at[pc]['operand_facts'][0].get('immediate_value')==value,'bank toggle differs')
        operand(at[pc],1,address=0x16E2,width=4)
    for pc,value in [(0xB43C,0),(0xB444,0x2000),(0xB44C,0x4000),(0xB454,0x6000),
                     (0xB45E,0x8000),(0xB466,0xA000),(0xB46E,0xC000),(0xB476,0xE000)]:
        require(at[pc]['mnemonic']=='move'and at[pc]['operand_facts'][0].get('immediate_value')==value,'Copper low-word choice differs')
        require(at[pc]['operand_facts'][1]['width_bytes']==2,'Copper pointer store width differs')
    links={(e['source_offset']+2048,e['target_offset']+2048)for e in analysis['edges']if e.get('target_offset',-1)>=0}
    require(at[0xB43A]['mnemonic']=='beq'and(0xB43A,0xB45E)in links,'full-LONG result branch differs')
    for pc,value in [(0x10888,112),(0x10892,48),(0x1089C,16)]:
        require(at[pc]['mnemonic']=='andi'and at[pc]['operand_facts'][0].get('immediate_value')==value,'IRQ request masks differ')
    require(at[0x108A0]['mnemonic']=='bne'and(0x108A0,0x10CEA)in links,'COPER priority branch differs')
    operand(at[0x10A94],0,address=0x16E6,width=2)
    # The glyph callee is leaf code and has no explicit A3/A4/D7 write.
    glyphs=window(rows,0x1B0E2,0x1B24C)
    for r in glyphs:
        require(r['mnemonic']not in('jsr','bsr','jmp'),'glyph callee is no longer leaf')
        require(not any('write'in p.get('access','')and p.get('direct_register')in('A3','A4','D7')for p in r['operand_facts']),
                'glyph callee clobbers retained cursor')
    for lo,hi in [(0x1E948,0x1E95A),(0x1EAAC,0x1EABE)]:
        block=window(rows,lo,hi)
        require([r['mnemonic']for r in block]==['movea','move','move','move','jsr','tst','bne'],
                'literal descriptor continuation differs')
        for r,width,reg in zip(block[:4],[4,2,2,2],['A5','D5','D4','D6'],strict=True):
            mem(r['operand_facts'][0],access='memory_read',width=width,base='A3',update=1)
            operand(r,1,register=reg,width=width)
    for base,count in [(0x1ED96,9),(0x1EDF4,2)]:
        require(int.from_bytes(data[base+10*count-2048:base+10*count-2048+4],'big')==0,'literal descriptor terminator differs')
        for i in range(count):
            entry=data[base-2048+10*i:base-2048+10*(i+1)]
            pointer=int.from_bytes(entry[:4],'big');words=int.from_bytes(entry[8:10],'big')
            require(pointer >= 0x800 and pointer+2*words<=0x78000 and 0<words<=13,'literal descriptor source/count differs')
    patch_writes=[]
    for row in window(rows,0x1139A,0x113E0):
        if row['mnemonic']not in('bset','bclr'):continue
        require(row['operand_facts'][0].get('immediate_value')==6,'plane operation bit differs')
        field=row['operand_facts'][1]
        require(field.get('base_register')=='A1'and field.get('memory')and not field.get('indexed')
                and field.get('width_bytes')==1 and field.get('displacement_known'),'plane operation byte writer differs')
        patch_writes.append((row['mnemonic'],field['displacement']))
    require(sorted(patch_writes)==sorted((op,offset)for op in('bclr','bset')for offset in(1,3,7,11)),
            'plane operation write sites differ')
    operand(at[0x113E4],0,address=0x114D0,width=4);operand(at[0x113E4],1,register='A1',width=4)
    # Reuse the already established counted/flag descriptor contracts.
    flag=flag_glyph_contract(data,rows);indexed=indexed_panel_glyph_contract(data,rows)
    for pc,value in [(0x1F81A,15),(0x1F89C,7),(0x1F968,15),(0x1EA22,3),(0x1EA28,3)]:
        require(at[pc]['operand_facts'][0].get('immediate_value')==value,'panel producer or population operation differs')
    require(at[0x1EA28]['mnemonic']=='divu','population division differs')
    # Exact narrow source views; no scan-derived end or whole scratch ownership.
    radii=[int.from_bytes(data[i-2048:i-2048+2],'big')for i in range(0x1FD64,0x1FD84,2)]
    angles=[int.from_bytes(data[i-2048:i-2048+2],'big')for i in range(0x1FE84,0x1FEA4,2)]
    require(len(radii)==16 and min(radii)>0 and max(radii)==66,'radius source table differs')
    require(len(angles)==16 and all(v<512 for v in angles),'angle source indices differ')
    require(data[0x1FD84-2048:0x1FDC4-2048]==bytes(64),'initial used flags differ')
    require(data[0x1FDE4-2048:0x1FE3E-2048]==bytes(90),'initial seed view differs')
    populations=[population_window(p)for p in range(11)]
    require(min(p['start_runtime']for p in populations)>=0x1EEB6 and max(p['glyph_count']for p in populations)==14,'population receiver bound differs')
    template=data[0x10C2A-2048:0x10C76-2048];early=copper_copy_entries(template)
    extended=bytearray(template);extended[32:36]=bytes.fromhex('3d01ff00');full=copper_copy_entries(extended)
    require((early,full)==(9,19),'conditional Copper copy extents differ')
    for phase in range(0,48,2):
        proof=coper_prefix(phase,48);require(min(a for a,_ in proof['read_byte_offsets'])>=0 and max(b for _,b in proof['read_byte_offsets'])<=148,'COPER prefix envelope differs')
    spans=[('seed_producer',0x1F804,0x1F896),('population_producer',0x1F962,0x1F988),('detail',0x1E77A,0x1EB60),('circle',0x1139A,0x114E0),('present',0xB422,0xB4A6),
           ('irq_dispatch',0x10880,0x108A4),('coper',0x10CEA,0x10D30)]
    windows={n:{'start_runtime':a,'end_runtime':b,'instructions':len(window(rows,a,b))}for n,a,b in spans}
    return {'main_sha256':old['main_sha256'],'cpu':'68000','runtime_executed':False,'windows':windows,
            'accepted_instructions_checked':sum(v['instructions']for v in windows.values()),
            'bank_role':'LONG byte offset added to the draw-bank base; not active display identity',
            'canonical_bank_contract':[present_bank(v)for v in(0,0x8000)],'global_canonical_bank_invariant_proved':False,'explicit_bank_protocol':protocol,'initial_bank_and_saved_offsets':initial_banks,
            'copper_copy_entries':{'early':early,'extended':full,'COP2_is_same_copy_interior':True},
            'glyph_leaf_preserves_registers':['A3','A4','D7'],'mutable_descriptor_and_bank_closure_proved':False,
            'existing_flag_records_rechecked':flag['records'],'existing_indexed_contract_rechecked':bool(indexed),
            'body_seed_view':{'start_runtime':0x1FDE4,'end_runtime':0x1FE3E,'records':15,'stride':6,'fields':['radiusSeed','angleSeed','glyphSeed'],'following_unknown_bytes':70},
            'slot_views':{'radius_words':16,'radius_used_words':16,'angle_words':16,'angle_used_words':16,'following_angle_flag_unknown_bytes':32},
            'population_windows':populations,'coper_initial_48_envelope':{'start_runtime':0x10DFA,'end_runtime':0x10E8E,'words':74,'requires_intact_vblank_setup':True,'total_calls_per_frame_proved':False},
            'circle_self_write_bytes':[0x114D1,0x114D3,0x114D7,0x114DB],
            'auxiliary_overlap':'typed count WORD and zero terminator already have clean presentation; retained weak imported LONG is provenance',
            'selected_body_number_contract':'0 is no DBF match; selection 1..N matches row N-selection in producer and reader','new_code_admissions':0,'new_unconditional_receiver_facts':0}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in('rows','analysis','member','output'):parser.add_argument('--'+name,type=Path,required=True)
    a=parser.parse_args();result=check_source(json.loads(a.rows.read_text()),json.loads(a.analysis.read_text()),a.member.read_bytes())
    a.output.write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()

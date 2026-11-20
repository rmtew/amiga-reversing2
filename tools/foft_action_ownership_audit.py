"""Conditional emission noninterference and the separate contact-instrument view.

This checks accepted source facts and bounded arithmetic. It does not execute
68000 code or turn conditional address relationships into admitted receivers.
"""
import argparse
import json
from pathlib import Path

from tools.foft_deployment_emission_audit import collect as deployment_contracts
from tools.foft_deployment_emission_audit import word
from tools.foft_irq_write_audit import mem, require
from tools.foft_render_contract_audit import operand, window

STATE = 0x4E818
ACTION = 0x4ED18
ORIENTATION = 0x2B994


def signed_word(value):
    value=word(value)
    return value-65536 if value&32768 else value


def intersects(a,b):
    return a[0]<b[1] and b[0]<a[1]


def bounded_emission(frozen_count, row, kind):
    require(type(frozen_count)is int and 1<=frozen_count<=32,'conditional count must be 1..32')
    require(type(row)is int and 0<=row<frozen_count,'row must belong to original pass')
    require(kind in ('missile','flapper'),'unknown emitter')
    displacement=signed_word((20*frozen_count)&65535)
    state=(STATE+displacement,STATE+displacement+20)
    action=(ACTION+20*row+displacement,ACTION+20*row+displacement+(16 if kind=='missile' else 18))
    orientation=(ORIENTATION+((20*frozen_count&65535)>>1),ORIENTATION+((20*frozen_count&65535)>>1)+10)
    scanned=(ACTION,ACTION+20*frozen_count)
    old_states=(STATE,STATE+20*frozen_count)
    instrument_rows=(0xD2E2,0xD2E2+12*frozen_count)
    require(STATE<=state[0]<state[1]<=STATE+64*20,'state destination left physical source window')
    require(ACTION<=action[0]<action[1]<=ACTION+64*20,'action destination left physical source window')
    require(not any(intersects(s,scanned)for s in(state,action,orientation)),
            'explicit child writes intersect original action rows')
    require(not any(intersects(s,view)for s in(state,action,orientation)for view in(old_states,instrument_rows)),
            'explicit child writes intersect caller state/instrument rows')
    return {'state_slot':frozen_count,'action_slot':frozen_count+row,
            'same_state_action_slot':row==0,'signed_displacement':displacement,
            'source_budget':[ACTION+20*row+14,ACTION+20*row+16],
            'child_write_spans':[list(s)for s in(state,action,orientation)],
            'scanned_action_span':list(scanned),'scanned_state_span':list(old_states),'caller_instrument_span':list(instrument_rows),'explicit_child_writes_preserve_scanned_actions':True,'explicit_child_writes_preserve_caller_state_and_instrument_rows':True,
            'orientation_allocation_or_lifetime_proved':False}


def saved_offset_matches_base(saved_offset,base_count):
    word(saved_offset)
    require(type(base_count)is int and 1<=base_count<=15,'fresh encounter base must be 1..15')
    return saved_offset==20*base_count


def rng_effect_inventory(rows):
    allowed={'move','addq','add','eor','roxl','bcc','rts'}
    writes=[];registers=set()
    for row in rows:
        require(row['mnemonic']in allowed,'unsupported RNG effect')
        for field in row['operand_facts']:
            if 'write'not in field.get('access',''):continue
            if field.get('memory'):
                address=field.get('absolute_address');width=field.get('width_bytes')
                require(type(address)is int and type(width)is int and width in(2,4)
                        and address>=0x1B420 and address+width<=0x1B430
                        and not field.get('bulk_transfer'),'unknown RNG memory effect')
                writes.append([address,width])
            else:
                register=field.get('direct_register')
                require(register in('D0','D1'),'RNG clobbers carried register')
                registers.add(register)
    return {'explicit_register_writes':sorted(registers),'fixed_memory_writes':writes}


def check_source(rows,analysis,data):
    prior=deployment_contracts(rows,analysis,data)
    at={r['source_offset']+2048:r for r in rows}
    rng=rng_effect_inventory(window(rows,0x1B3CA,0x1B420))
    expected={*(f'D{k}'for k in range(1,8)),*(f'A{k}'for k in range(7))}
    for pc,access in [(0x2EDF0,'register_list_read'),(0x2EE1E,'register_list_write')]:
        require(at[pc]['mnemonic']=='movem'and any(p.get('access')==access and set(p.get('register_list',[]))==expected for p in at[pc]['operand_facts']),'view lookup register frame differs')
    require(all(r['mnemonic']not in('jsr','bsr','jmp')for r in window(rows,0x2EDF0,0x2EE2E)),'view lookup now has a call')
    operand(at[0x2A07C],0,address=0x4E6A0,width=2);require(at[0x2A07C]['mnemonic']=='clr','selected deployment invalidation differs')
    operand(at[0x2E88C],0,address=0x4E6A0,width=2);require(at[0x2E88C]['mnemonic']=='tst','deployment update gate differs')
    operand(at[0x2DF24],0,address=0x4E6A0,width=1);require(at[0x2DF24]['mnemonic']=='st','activation order differs')
    links={(e['source_offset']+2048,e['target_offset']+2048)for e in analysis['edges']if e.get('target_offset',-1)>=0}
    require(at[0x2E892]['mnemonic']=='beq'and(0x2E892,0x2E8FA)in links,'inactive update return differs')
    for pc,register,address in [(0x2E9CC,'A0',STATE),(0x2E9D2,'A2',ACTION),
        (0x2EB8C,'A3',STATE),(0x2ECA4,'A3',STATE),(0xC99E,'A6',STATE),
        (0xC9A4,'A5',0xD2E2),(0xCC72,'A6',0xD2E2)]:
        require(at[pc]['mnemonic']=='lea','cursor root differs')
        operand(at[pc],0,address=address,width=4);operand(at[pc],1,register=register,width=4)
    for pc in (0x2EB82,0x2EC9A):
        operand(at[pc],0,address=0x2F094,width=2);operand(at[pc],1,register='D6')
    for pc in (0x2EB88,0x2ECA0):
        require(at[pc]['mnemonic']=='mulu'and at[pc]['operand_facts'][0].get('immediate_value')==20,
                'frozen-count multiplication differs')
    for pc in (0x2EB92,0x2ECAA):
        require(at[pc]['mnemonic']=='adda','state index addition differs')
        operand(at[pc],0,register='D6',width=2);operand(at[pc],1,register='A3',width=2)
    for lo,hi in [(0x2EB82,0x2EBEA),(0x2EC96,0x2ED2C)]:
        require(all(r['mnemonic']not in ('jsr','bsr','jmp','bra','rts','rte')for r in window(rows,lo,hi)),
                'emitting interval contains a call or transfer')
    action_writes={}
    for kind,lo,hi,expected in [('missile',0x2EBBC,0x2EBE0,[(0,4),(4,2),(6,2),(8,4),(12,4)]),
                              ('flapper',0x2ECD4,0x2ED0A,[(offset,2)for offset in range(0,18,2)])]:
        records=[]
        for row in window(rows,lo,hi):
            destinations=[p for p in row['operand_facts']if p.get('access')=='memory_write']
            require(len(destinations)==1,'action initializer write count differs')
            field=destinations[0]
            require(field.get('memory')and field.get('indexed')and field.get('base_register')=='A2'
                    and field.get('index_register')=='D6'and field.get('displacement_known')
                    and not field.get('bulk_transfer')and not field.get('ea_update'),'action indexed writer differs')
            records.append({'runtime':row['source_offset']+2048,'offset':field['displacement'],'width':field['width_bytes']})
        require([(r['offset'],r['width'])for r in records]==expected,'action write envelope differs')
        action_writes[kind]=records
    for pc,reg in [(0x2ED2C,'A0'),(0x2ED30,'A2')]:
        require(at[pc]['mnemonic']=='lea','scan stride differs')
        mem(at[pc]['operand_facts'][0],access='address',width=4,base=reg,displacement=20)
        operand(at[pc],1,register=reg,width=4)
    for pc,src,dst,disp in [(0xCB36,'D1','A5',2),(0xCB3A,'D2','A5',4)]:
        operand(at[pc],0,register=src);mem(at[pc]['operand_facts'][1],access='memory_write',width=2,base=dst,displacement=disp)
    commits=window(rows,0xCB32,0xCB50)
    written=[]
    for r in commits:
        for p in r['operand_facts']:
            if p.get('access')=='memory_write'and p.get('base_register')=='A5':
                written.append((p['displacement'],p['width_bytes']))
    require(sorted(written)==[(0,2),(2,2),(4,2),(10,2)],'instrument committed fields differ')
    for pc in (0xCB4C,0xCBEC,0xCDAE):
        require(at[pc]['mnemonic']=='lea','instrument stride differs')
        mem(at[pc]['operand_facts'][0],access='address',width=4,base='A5'if pc==0xCB4C else'A6',displacement=12)
    require(data[0xD2E2-2048:0xD5EE-2048]==bytes(780),'initial instrument backing window differs')
    for pc in (0xB1E,0x68A4):
        operand(at[pc],0,address=0xD5EE,width=2)
    require([int.from_bytes(data[i-2048:i-2048+2],'big')for i in range(0xCE56,0xCE60,2)]==[175,120,120,110,180],
            'zoom prefix differs')
    for pc,value in [(0xD61E,70),(0xD630,5),(0x1AA66,1),(0x1AA68,3)]:
        require(at[pc]['mnemonic']=='moveq'and at[pc]['operand_facts'][0].get('immediate_value')==value,
                'fixed display loop initializer differs')
    windows={n:{'start_runtime':lo,'end_runtime':hi,'accepted_instructions':len(window(rows,lo,hi))}
             for n,lo,hi in [('instrument',0xC99E,0xCDC4),('vertical_stem',0xD23C,0xD2C0),('backdrop',0xD608,0xD662)]}
    # Exhaust all rows of the explicit bounded certificate; do not assert that
    # its count premise dominates the real entry or excludes interrupt writes.
    certificates=[bounded_emission(n,i,k)for n in range(1,33)for i in range(n)for k in('missile','flapper')]
    return {'main_sha256':prior['main_sha256'],'cpu':'68000','runtime_executed':False,
            'windows':windows,'accepted_instrument_instructions':sum(v['accepted_instructions']for v in windows.values()),
            'indexed_action_write_inventory':action_writes,'prefix_helper_rng_effects':rng,'view_lookup_restores_carried_registers':True,'helper_scope':'ordinary returns and nonaliasing stack; no asynchronous closure','conditional_cases_checked':len(certificates),'conditional_frozen_count_domain':[1,32],
            'count_premise_proved_at_real_entry':False,'new_native_receiver_facts':0,'new_code_admissions':0,
            'first_row_shares_state_action_slot':True,'later_rows_have_distinct_state_action_slots':True,
            'saved_deployment_offset_direct_writers':[0x2DE8A],
            'selected_deployment_direct_invalidation':{'active_clear':0x2A07C,'inactive_update_gate':0x2E88C,'new_offset_store':0x2DE8A,'new_active_set':0x2DF24},'recreation_rebinds_saved_offset':False,'recreation_receiver_condition':'intact saved offset equals 20 * fresh base count (1..15)',
            'first_missing_deployment_state':'equality of saved deployment slot and freshly regenerated base slot; aliases/copy writes remain separate',
            'first_missing_emission_state':'preserved frozen count in 1..32 and original A2 cursor; no invariant is inferred from physical source extents',
            'instrument_record':{'start_runtime':0xD2E2,'end_runtime':0xD5EE,'physical_source_rows':65,'stride':12,'word_fields':[0,2,4,10],'untouched_words':[6,8],'live_count_cap_proved':False},
            'backdrop':{'rows':71,'source_bytes_per_row':52,'source_bytes':3692,'destination_stride':40},
            'zoom':{'glyph_words':8,'prefix':'ZOOM ','numeric_word_offsets':[10,12,14]},
            'retained_instrument_count_path':'negative count-minus-one bypasses CB5E store; later CC7E reload remains independently gated',
            'all_asynchronous_and_alias_writes_closed':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in('rows','analysis','member','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();r=check_source(json.loads(a.rows.read_text()),json.loads(a.analysis.read_text()),a.member.read_bytes())
    a.output.write_text(json.dumps(r,indent=2)+'\n')


if __name__=='__main__':main()

"""Bounded packet and affine-domain checks do not imply runtime ownership."""
from copy import deepcopy

import pytest

from tools.foft_projectile_state_audit import can_intersect, packet, word_packet_domain


@pytest.mark.parametrize(('coefficient','width'),[(20,20),(10,10),(20,2),(65536,4)])
def test_word_packet_domain_matches_modular_integer_lattice(coefficient,width):
    base=0x100000
    starts=set()
    for n in range(65536):
        low=(coefficient*n)&65535
        starts.add(base+(low if low<32768 else low-65536))
    d=word_packet_domain(base,coefficient,width)
    assert d['first_start']==min(starts) and d['last_start']==max(starts)
    assert len(starts)==(max(starts)-min(starts))//d['start_stride']+1
    assert not d['live_count_bound_proved']
    for start,size in [(base-10,2),(base+2,2),(base+32765,4),(base+32780,2)]:
        actual=any(a<start+size and start<a+width for a in starts)
        assert can_intersect(d,start,size)==actual


def test_narrow_word_marker_keeps_alignment_holes_instead_of_a_flat_band():
    d=word_packet_domain(0x100000,20,2)
    assert can_intersect(d,0x100000,2)
    assert not can_intersect(d,0x100002,2)
    assert can_intersect(word_packet_domain(0x100000,20,4),0x100002,2)


@pytest.mark.parametrize('args',[(0,20,20),(0xFFFFFFF0,20,20),(0x100000,0,4),
                                (True,20,20),(0x100000,20,0)])
def test_packet_domain_refuses_unsupported_or_wrapping_address_ranges(args):
    with pytest.raises(ValueError,match='packet|wrapping'):word_packet_domain(*args)


def source_packet():
    rows=[]
    for i in range(9):
        def memory(access,width=2,**more):
            return dict(memory=True,access=access,width_bytes=width,base_register='A6',
                displacement=0,displacement_known=True,ea_update=1,indexed=False,
                bulk_transfer=False,absolute_address=None,**more)
        clear=i==6
        width=4 if i==8 else 2
        dest=memory('memory_write',width)
        if i==8:dest['ea_update']=0
        source=memory('memory_read') if i<6 else {'immediate_value':10 if i==7 else 0x24000,'width_bytes':width}
        rows.append({'source_offset':0x100+i*2,'size':2,'provenance':'accepted_instruction',
                     'mnemonic':'clr'if clear else'move','operand_facts':[dest]if clear else[source,dest]})
    return rows


def test_state_packet_proves_twenty_written_bytes_without_admitting_the_model():
    p=packet(source_packet(),0x900,0x912,model=0x24000,category=10)
    assert p['bytes_written']==20 and p['model_value']==0x24000


@pytest.mark.parametrize('change',['width','update','source','model','category','extra','opcode','ownership'])
def test_packet_refuses_incomplete_or_changed_native_write_contract(change):
    rows=deepcopy(source_packet())
    if change=='width':rows[8]['operand_facts'][1]['width_bytes']=2
    elif change=='update':rows[0]['operand_facts'][1]['ea_update']=0
    elif change=='source':rows[0]['operand_facts'][0]['width_bytes']=1
    elif change=='model':rows[8]['operand_facts'][0]['immediate_value']=0x25000
    elif change=='category':rows[7]['operand_facts'][0]['immediate_value']=12
    elif change=='extra':rows[3]['operand_facts'].append(rows[3]['operand_facts'][1])
    elif change=='opcode':rows[3]['mnemonic']='add'
    elif change=='ownership':rows[3]['provenance']='raw_data'
    with pytest.raises(ValueError,match='differ|count|accepted'):
        packet(rows,0x900,0x912,model=0x24000,category=10)

"""Copy containment and direct writers do not establish a live count bound."""
import pytest

from tools.foft_object_motion_count_audit import (
    absolute_count_writes,
    check_indexed_action_write,
    check_view_key_copy,
    copied_field_source,
    masked_zero_fallback,
)


@pytest.mark.parametrize(('source','dest','length','field','width','expected'),[
    (0x100,0x400,16,0x400,2,0x100),
    (0x100,0x400,16,0x40E,2,0x10E),
    (0x100,0x400,16,0x404,4,0x104),
])
def test_copy_field_translation_requires_complete_containment(source,dest,length,field,width,expected):
    assert copied_field_source(source,dest,length,field,width)==expected


@pytest.mark.parametrize('args',[
    (0x100,0x400,16,0x40F,2),(0x100,0x400,16,0x3FF,2),
    (0x100,0x400,0,0x400,2),(0x100,0x400,16,0x400,0),
    (0xFFFFFFFF,0x400,16,0x400,2),(0x100,0xFFFFFFF0,32,0xFFFFFFF0,2),
    (True,0x400,16,0x400,2),(-1,0x400,16,0x400,2),
])
def test_copy_refuses_partial_fields_invalid_or_wrapping_spans(args):
    with pytest.raises(ValueError,match='copy|field'):copied_field_source(*args)


@pytest.mark.parametrize(('mask','fallback'),[(15,3),(7,2),(0,4)])
def test_masked_initializer_domain_is_only_the_local_formula(mask,fallback):
    expected={(x&mask)or fallback for x in range(65536)}
    assert set(masked_zero_fallback(mask,fallback))==expected


@pytest.mark.parametrize('args',[(10,3),(65536,3),(15,-1),(True,3),(15,65536)])
def test_refuses_nonmask_or_nonword_initializer_contract(args):
    with pytest.raises(ValueError,match='mask'):masked_zero_fallback(*args)


def writer(offset,access='memory_write',width=2,address=0x400,provenance='accepted_instruction'):
    return {'source_offset':offset,'provenance':provenance,'mnemonic':'move',
            'operand_facts':[{'memory':True,'access':access,'width_bytes':width,
                              'absolute_address':address}]}


def test_direct_writer_inventory_keeps_overlap_widths_and_excludes_unresolved_domains():
    rows=[writer(0),writer(2,width=1,address=0x401),writer(4,width=4,address=0x3FE),
          writer(6,access='memory_read'),writer(8,address=0x402),writer(10,address=None)]
    bulk=writer(12);bulk['operand_facts'][0]['bulk_transfer']=True;rows.append(bulk)
    found=absolute_count_writes(rows,address=0x400)
    assert [x['runtime']for x in found]==[0x800,0x802,0x804]
    assert [x['width']for x in found]==[2,1,4]


def test_raw_bytes_are_not_count_writer_evidence():
    with pytest.raises(ValueError,match='accepted'):
        absolute_count_writes([writer(0,provenance='raw_data')],address=0x400)


def view_key_row():
    return {'mnemonic':'move','operand_facts':[
        {'memory':True,'access':'memory_read','width_bytes':2,'base_register':'A6',
         'displacement':10,'displacement_known':True,'ea_update':0,'indexed':False,
         'bulk_transfer':False,'absolute_address':None},
        {'memory':True,'access':'memory_write','width_bytes':2,'direct_register':None}],
        'address_evidence':[{'operand_index':1,'has_address':True,'address':0x4E720}]}


def test_view_key_copy_is_a_word_not_an_address_field():
    check_view_key_copy(view_key_row())


@pytest.mark.parametrize('change',['byte_width','pointer_width','offset','unknown','base','bulk','opcode'])
def test_view_key_copy_refuses_an_incompatible_native_field_contract(change):
    row=view_key_row();p=row['operand_facts'][0]
    if change=='byte_width':p['width_bytes']=1
    elif change=='pointer_width':p['width_bytes']=4
    elif change=='offset':p['displacement']=6
    elif change=='unknown':p['displacement_known']=False
    elif change=='base':p['base_register']='A0'
    elif change=='bulk':p['bulk_transfer']=True
    elif change=='opcode':row['mnemonic']='lea'
    with pytest.raises(ValueError,match='held-key|memory'):check_view_key_copy(row)


def indexed_action_row(width):
    return {'mnemonic':'move','operand_facts':[{'immediate_value':0},{
        'memory':True,'access':'memory_write','width_bytes':width,'indexed':True,
        'base_register':'A2','index_register':'D6','index_width_bytes':2,'index_scale':1,
        'displacement_known':True,'displacement':0,'ea_update':0,'bulk_transfer':False,
        'pc_relative':False,'absolute_address':None}]}


@pytest.mark.parametrize('width',[2,4])
def test_indexed_action_field_preserves_current_receiver_and_word_index(width):
    check_indexed_action_write(indexed_action_row(width),width)


@pytest.mark.parametrize('change',['long_index','scale','base','offset','unknown','update','bulk','access','width'])
def test_indexed_action_field_refuses_changed_native_width_or_receiver(change):
    row=indexed_action_row(4);p=row['operand_facts'][1]
    if change=='long_index':p['index_width_bytes']=4
    elif change=='scale':p['index_scale']=2
    elif change=='base':p['base_register']='A3'
    elif change=='offset':p['displacement']=20
    elif change=='unknown':p['displacement_known']=False
    elif change=='update':p['ea_update']=1
    elif change=='bulk':p['bulk_transfer']=True
    elif change=='access':p['access']='memory_read'
    elif change=='width':p['width_bytes']=2
    with pytest.raises(ValueError,match='indexed action'):check_indexed_action_write(row,4)

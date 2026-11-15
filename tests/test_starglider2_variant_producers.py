"""Model-viewer producer bounds, independently checked by the original ST CPU."""
import os
from pathlib import Path
import pytest
from amiga_reversing.tools.compare_starglider2 import bounded_variants,model_streams,variant_cycle_step
from test_starglider2_model_streams import inputs,fixtures,ROOT


def test_second_leg_marker_is_not_a_selector_maximum():
    disabled=bytes((0,1,254,0));state=(0,0);seen=set()
    for _ in range(8):
        seen.add(state);state=variant_cycle_step(disabled,state,reverse=True)
    assert seen=={(0,0),(1,0)}
    assert variant_cycle_step(bytes((0,3,3,0)),(0,0))==(0,2)
    with pytest.raises(ValueError,match='Disabled'):variant_cycle_step(b'\xff'*4,(0,0))


def cycle_cpu(data,ordinal):
    from amiga_reversing.disasm.mapped_execution import MappedExecution
    cpu=MappedExecution(0x80000,project_root=ROOT,register_seed=0xdeadbeef)
    cpu.seed(0xef98,data[0xdf98:0xe054]);address=0xecee+4*ordinal
    cpu.seed(address,data[address-4096:address-4096+4])
    cpu.seed(0x70190,ordinal.to_bytes(2,'big'));cpu.allow_write(0x60003,1);cpu.allow_write(0x707e8,1)
    cpu.seed(0x78000,(0x5f000).to_bytes(4,'big'))
    return cpu


def original_step(cpu,state,reverse):
    selector,leg=state;cpu.seed(0x60003,bytes([selector]));cpu.seed(0x707e8,bytes([leg]))
    cpu.cpu.a[4]=0x60000;cpu.cpu.a[6]=0x70000;cpu.cpu.a[7]=0x78000
    cpu.run(0xeff6 if reverse else 0xef98,0x5f000,35)
    return (cpu.read(0x60003,1)[0],cpu.read(0x707e8,1)[0])


def select_original(data,header,selector,table,count):
    from amiga_reversing.disasm.mapped_execution import MappedExecution
    cpu=MappedExecution(0x80000,project_root=ROOT,register_seed=0xdeadbeef)
    cpu.seed(0x4a7e,data[0x3a7e:0x3a9c]);cpu.seed(header+4096+18,data[header+18:header+22])
    cpu.seed(table+4096,data[table:table+4*count]);cpu.seed(0x60003,bytes([selector]))
    cpu.seed(0x70024,bytes(4));cpu.allow_write(0x70024,4)
    cpu.cpu.a[0]=header+4096+18;cpu.cpu.a[4]=0x60000;cpu.cpu.a[6]=0x70000
    cpu.run(0x4a7e,0x4a9c,20)
    return int.from_bytes(cpu.read(0x70024,4),'big')


def check_reference_footprint(data,view):
    from amiga_reversing.disasm.mapped_execution import MappedExecution
    cpu=MappedExecution(0x80000,project_root=ROOT,register_seed=0xdeadbeef)
    cpu.seed(0x4cc8,data[0x3cc8:0x3cce]);cpu.seed(view['start']+4096,data[view['start']:view['end']])
    cpu.cpu.a[1]=view['start']+4096
    for offset in view['offsets']:
        cpu.cpu.d[4]=offset;cpu.run(0x4cc8,0x4cce,2)
        assert [cpu.cpu.d[i]&65535 for i in (1,2,3)]==[int.from_bytes(data[view['start']+offset+j:view['start']+offset+j+2],'big') for j in (0,2,4)]


@fixtures
def test_viewer_producers_reach_only_the_bounded_variant_tables_and_frames():
    a,b=inputs();amiga,st=model_streams(a,96628),model_streams(b,102964)
    models=0;views=0;selector_edges=0
    for left,right in zip(amiga,st):
        if 'variant_first' not in right:continue
        models+=1;proof=bounded_variants(b,right,0xdcee);other=bounded_variants(a,left,0xdca2)
        assert proof['states']==other['states']
        for ordinal,states in proof['states'].items():
            cpu=cycle_cpu(b,ordinal);control=b[0xdcee+4*ordinal:0xdcf2+4*ordinal]
            for state in states:
                for reverse in (False,True):
                    assert original_step(cpu,state,reverse)==variant_cycle_step(control,state,reverse=reverse)
                    selector_edges+=1
        count=len(proof['views']);table=right['variant_first']['table']
        assert select_original(b,right['header'],0,table,count)==0
        for x,y in zip(other['views'],proof['views']):
            assert x['selector']==y['selector'] and x['offsets']==y['offsets']
            assert a[x['start']:x['end']]==b[y['start']:y['end']]
            assert select_original(b,right['header'],y['selector'],table,count)==y['start']+4096
            check_reference_footprint(b,y);views+=1
        with pytest.raises(ValueError,match='unknown read/fetch'):
            select_original(b,right['header'],count+1,table,count)
    assert models==33 and views==471 and selector_edges>1000
    # Alias 0's zero controls do not describe alias 1's 22 variants.
    alias=bounded_variants(b,st[0],0xdcee)
    assert {s for s,leg in alias['states'][0]}=={0}
    assert {s for s,leg in alias['states'][1]}==set(range(23))
    special=next(m for m in st if m['ordinals']==[72])
    assert bounded_variants(b,special,0xdcee)['selectors']==[0,1]
    changed=bytearray(b);view=alias['views'][0]
    position=view['start']+view['offsets'][0];changed[position:position+2]=b'\x7f\xff'
    with pytest.raises(ValueError,match='coordinate reference outside pool'):
        bounded_variants(bytes(changed),st[0],0xdcee)


@fixtures
def test_shape_selection_resets_cycle_state_and_disables_negative_controls():
    from amiga_reversing.disasm.mapped_execution import MappedExecution
    _,data=inputs()
    for ordinal in range(104):
        cpu=MappedExecution(0x80000,project_root=ROOT,register_seed=0xdeadbeef)
        cpu.seed(0xf0ec,data[0xe0ec:0xe118]);cpu.seed(0x70190,ordinal.to_bytes(2,'big'))
        cpu.seed(0xecee+4*ordinal,data[0xdcee+4*ordinal:0xdcf2+4*ordinal])
        cpu.seed(0x707e7,b'\x99\x88');cpu.seed(0x72333,b'\x77')
        cpu.allow_write(0x707e7,2);cpu.allow_write(0x72333,1);cpu.cpu.a[6]=0x70000
        cpu.run(0xf0ec,0xf118,25)
        assert cpu.read(0x72333,1)==b'\0' and cpu.read(0x707e8,1)==b'\0'
        assert cpu.read(0x707e7,1)[0]==(data[0xdcee+4*ordinal]<128)


@fixtures
def test_type90_initializer_has_a_narrower_range_than_the_viewer():
    from amiga_reversing.disasm.mapped_execution import MappedExecution
    _,data=inputs();table=100266
    assert int.from_bytes(data[table+90*4:table+90*4+4],'big')==0x19fb6
    cpu=MappedExecution(0x80000,project_root=ROOT,register_seed=0xdeadbeef)
    cpu.seed(0x19fba,data[0x18fba:0x18fcc]);cpu.allow_write(0x60003,1);cpu.cpu.a[0]=0x60000
    seen=set()
    # Low four bits and the rotated top two bits are the only retained bits.
    for low in range(16):
        for high in range(4):
            for irrelevant in (0,0x3ff0):
                value=(high<<14)|irrelevant|low;cpu.cpu.d[0]=value
                cpu.run(0x19fba,0x19fcc,8);actual=cpu.read(0x60003,1)[0]
                assert actual==low+high;seen.add(actual)
    assert seen==set(range(19))  # 0..18, whereas the viewer also reaches 19.


@fixtures
def test_extended_variant_names_are_used_by_rendered_pointer_arrays():
    source=(Path(os.environ['SGII_RETAIL_RENDERED_SOURCE'])).read_text()
    assert 'model_viewer_variant_cycle_controls:' in source
    assert 'dc.l model_type_027_variant_039_reference_prefix' in source
    assert 'dc.l model_type_090_variant_019_reference_prefix' in source

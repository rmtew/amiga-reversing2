"""Finite host contracts and a synthetic assembler oracle; no game execution."""
import subprocess
from pathlib import Path

import pytest

from tools.foft_frame_panel_audit import (
    coper_prefix,
    copper_copy_entries,
    direct_bank_protocol,
    first_free_word_slot,
    irq_branch,
    normal_body_count,
    normal_body_selection,
    plane_operation_fixture,
    population_window,
    present_bank,
)


@pytest.mark.parametrize('offset',[0,0x8000])
def test_present_programs_old_bank_and_detail_extra_toggle_restores_draw_offset(offset):
    proof=present_bank(offset)
    assert proof['canonical_input']is True
    assert proof['following_draw_offset']==offset^0x8000
    assert proof['programmed_display_offset']==offset
    assert proof['after_detail_extra_toggle']==offset


@pytest.mark.parametrize('offset',[4,0x8004,0x10000])
def test_full_long_branch_is_not_an_unconditional_old_bank_claim(offset):
    proof=present_bank(offset)
    assert proof['canonical_input']is False
    assert proof['following_draw_offset']!=0
    assert proof['programmed_display_offset']==0


@pytest.mark.parametrize('value',[-1,2**32,True,None])
def test_bank_requires_exact_long(value):
    with pytest.raises(ValueError,match='LONG'):present_bank(value)


@pytest.mark.parametrize('free',range(16))
def test_cyclic_search_reaches_a_free_word_slot_from_every_start(free):
    occupied=65535^(1<<free)
    for start in range(16):assert first_free_word_slot(occupied,start)==free


@pytest.mark.parametrize('start',range(16))
def test_fifteen_normal_rows_leave_a_slot_for_each_selection(start):
    occupied=0
    for row in range(15):
        selected=first_free_word_slot(occupied,(start+7*row)%16)
        assert not occupied&(1<<selected)
        occupied|=1<<selected
    assert occupied.bit_count()==15


@pytest.mark.parametrize(('occupied','start'),[(65535,0),(-1,0),(0,16),(True,0)])
def test_search_refuses_missing_free_slot_or_invalid_contract(occupied,start):
    with pytest.raises(ValueError,match='free slot|occupancy|slot index'):first_free_word_slot(occupied,start)


@pytest.mark.parametrize(('population','count'),list(enumerate([1,1,2,8,4,5,10,12,8,13,14])))
def test_population_window_preserves_original_low_two_bit_formula(population,count):
    proof=population_window(population)
    assert proof['glyph_count']==count and proof['leading_one']==(population!=0)
    assert proof['end_runtime']==0x1EEDE
    assert proof['start_runtime']==0x1EEDE-2*count>=0x1EEB6


@pytest.mark.parametrize('phase',range(0,48,2))
def test_initial_coper_prefix_reverses_step_before_call_48_cursor_save(phase):
    before=coper_prefix(phase,47);last=coper_prefix(phase,48)
    assert before['following_cursor_offset']==phase+94
    assert last['read_byte_offsets'][-1]==[phase+94,phase+102]
    assert last['following_cursor_offset']==phase+92 and last['following_step']==-2
    assert all(a>=0 and b<=148 for a,b in last['read_byte_offsets'])


@pytest.mark.parametrize(('phase','count'),[(1,1),(48,1),(0,49),(0,-1),(True,1)])
def test_coper_prefix_does_not_invent_wider_phase_or_total_interrupt_bounds(phase,count):
    with pytest.raises(ValueError,match='VBlank phase|first 48'):coper_prefix(phase,count)


def test_copper_copy_includes_the_early_or_final_sentinel():
    data=bytearray(76);data[32:36]=bytes.fromhex('fffffffe');data[72:76]=bytes.fromhex('fffffffe')
    assert copper_copy_entries(data)==9
    data[32:36]=bytes.fromhex('3d01ff00')
    assert copper_copy_entries(data)==19


@pytest.mark.parametrize('data',[bytes(76),bytes(72),bytes(80)])
def test_copper_copy_refuses_missing_bounded_sentinel(data):
    with pytest.raises(ValueError,match='sentinel|nineteen-entry'):copper_copy_entries(data)


def bank_row(op,dest,source,width=4):
    return {'mnemonic':op,'operand_facts':[source,{'memory':True,'access':'memory_write','absolute_address':dest,'width_bytes':width}]}


def test_bank_protocol_classifies_only_explicit_full_width_assignments():
    bank,saved=0x16E2,0x13BD2
    rows=[bank_row('move',bank,{'immediate_value':0}),bank_row('eori',bank,{'immediate_value':0x8000}),
          bank_row('move',saved,{'absolute_address':bank}),bank_row('move',bank,{'absolute_address':saved})]
    proof=direct_bank_protocol(rows)
    assert set(proof['ordinary_absolute_operation_counts'].values())=={1}
    assert proof['indirect_bulk_irq_and_raw_code_writers_closed']is False


@pytest.mark.parametrize('row',[bank_row('move',0x16E4,{'immediate_value':0},2),bank_row('move',0x16E2,{'direct_register':'D0'})])
def test_bank_protocol_refuses_partial_or_unknown_assignments(row):
    with pytest.raises(ValueError,match='partial bank|unknown bank'):direct_bank_protocol([row])


def assemble(path,operations):
    executable=Path(__file__).resolve().parents[1]/'tools/vasmm68k_mot.exe'
    if not executable.is_file():pytest.skip('repository vasm oracle unavailable')
    source=path.with_suffix('.s');source.write_text('\n'.join(operations)+'\n')
    subprocess.run([str(executable),'-quiet','-m68000','-Fbin','-no-opt','-nosym','-o',str(path),str(source)],check=True,capture_output=True)
    return path.read_bytes()


@pytest.mark.parametrize('mask',range(16))
def test_original_plane_byte_writes_match_independent_bset_bclr_assembly(tmp_path,mask):
    operands=['(a1)','$2000(a1)','$4000(a1)','$6000(a1)']
    initial=assemble(tmp_path/'initial.bin',[f' bset.b d3,{operand}'for operand in operands])
    expected=assemble(tmp_path/'expected.bin',[f' {"bset"if mask&(1<<bit)else"bclr"}.b d3,{operand}'for bit,operand in enumerate(operands)])
    assert len(initial)==14
    assert plane_operation_fixture(initial,mask)==expected
    for previous in range(16):
        assert plane_operation_fixture(plane_operation_fixture(initial,previous),mask)==expected


@pytest.mark.parametrize('low',range(16))
def test_normal_seed_count_mask_and_zero_fallback(low):
    assert normal_body_count(0xAC00|low)==(low or 3)
    assert 1<=normal_body_count(low)<=15


@pytest.mark.parametrize('count',range(1,16))
def test_selection_matches_same_reverse_dbf_row_in_producer_and_reader(count):
    for nibble in range(16):
        selected=normal_body_selection(nibble,count)
        assert 0<=selected<=count
        matches=[row for row in range(count)if count-1-row==selected-1]
        assert matches==([count-selected]if selected else[])


@pytest.mark.parametrize(('mask','branch'),[(0,'none'),(16,'coper'),(32,'vblank'),(48,'coper'),(64,'none'),(80,'coper'),(96,'vblank'),(112,'coper')])
def test_irq_coper_priority_uses_captured_request_not_wait_flag(mask,branch):
    assert irq_branch(mask)==branch

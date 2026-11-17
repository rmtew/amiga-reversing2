"""Frozen-plan symbols preserve numeric encodings and discovery provenance."""
import json,re,subprocess
from pathlib import Path
import pytest
from amiga_reversing.disasm import c_backend
from tests.test_atari_mfp_vectors import fixture
ROOT=Path(__file__).resolve().parents[1]
PROFILES=['cpu','amiga-custom','atari-st-mfp']


def verify_projection(result,raw,directory):
    assert result['status']=='ok',result
    directory.mkdir(parents=True,exist_ok=True)
    for entry in result['includes']:
        path=directory/entry['path'];path.parent.mkdir(parents=True,exist_ok=True);path.write_text(entry['source_text'])
    text=result['package']['source_text']
    assert c_backend.assemble_platform_source_text_with_c_backend('atari-st-raw',text,include_dir=directory)[0]==raw
    source=directory/'out.s';source.write_text(text);output=directory/'out.bin'
    subprocess.run([str(ROOT/'tools/vasmm68k_mot.exe'),'-m68000','-no-opt','-Fbin','-quiet','-I'+str(directory),'-o',str(output),str(source)],check=True,capture_output=True)
    assert output.read_bytes()==raw
    return text


def test_shared_namespaces_inline_headers_aliases_and_discovery_are_exact(tmp_path):
    installer='''lea.l $DFF000.l,a5
movea.l a5,a1
btst.b #6,2(a1)
move.w #$1F0,64(a5)
move.b d0,$FFFFFA13.w
move.b d0,$00FFFA13.l
move.l #$1040,$118.w
move.l #$1040,$8.w'''
    artifact,raw=fixture(tmp_path,installer)
    try:
        before=artifact.analysis_payload()[0];original=artifact.inline_source_text_with_profile()[0]
        include=artifact.platform_symbol_projection_payload(PROFILES)
        assert include==artifact.platform_symbol_projection_payload(PROFILES)
        inline=artifact.platform_symbol_projection_payload(PROFILES,inline=True)
        text=verify_projection(include,raw,tmp_path/'include')
        expanded=text
        for header in include['includes']:
            assert all(' EQU $'in line for line in header['source_text'].splitlines())
            expanded=expanded.replace('    INCLUDE "'+header['path']+'"\n',header['source_text'])
        assert expanded==inline['package']['source_text']
        assert not inline['includes']
        verify_projection(inline,raw,tmp_path/'inline')
        for spelling in ['PLAT_AMIGA_CUSTOM_DMACONR_OFFSET(a1)','PLAT_AMIGA_CUSTOM_BLTCON0_OFFSET(a5)',
                         'PLAT_ST_MFP_IMRA_ADDR.w','PLAT_ST_MFP_BUS24_IMRA_ADDR.l',
                         'PLAT_ST_MFP_VECTOR_KEYBOARD_MIDI_ADDR.w','PLAT_CPU_VECTOR_BUS_ERROR_ADDR.w']:
            assert spelling in text
        assert {r['path']for r in include['includes']}=={'platform/cpu-symbols.i','platform/amiga-custom-symbols.i','platform/st-mfp-symbols.i'}
        vector=[r for r in include['bindings']if r['profile']==4 and r['conditional']]
        assert vector and all(r['admitted']for r in vector)
        assert include['discovery_analysis_runs']==0
        assert artifact.analysis_payload()[0]==before
        assert artifact.inline_source_text_with_profile()[0]==original
        assert any(r['source_overlap_disambiguated']for r in include['bindings']if r['admitted'])
    finally:artifact.close()


@pytest.mark.parametrize('installer',[
    'lea.l $DFF000.l,a5\n tst.w d0\n beq.b joined\n lea.l $DFF040.l,a5\njoined:\n btst.b #6,2(a5)',
    'lea.l $DFF000.l,a5\n jsr $1040.l\n btst.b #6,2(a5)',
    'movea.l $DFF000.l,a5\n btst.b #6,2(a5)',
    'lea.l $1040.l,a5\n btst.b #6,2(a5)',
    'lea.l $DFF002.l,a5\n btst.b #6,0(a5)',
    'lea.l $DFF000.l,a5\n move.w #$FFFF,a5\n btst.b #6,2(a5)',
])
def test_unknown_conflicting_memory_loaded_or_rebased_values_do_not_invent_hardware(tmp_path,installer):
    artifact,raw=fixture(tmp_path,installer,handler='rts')
    try:
        result=artifact.platform_symbol_projection_payload(PROFILES,inline=True)
        text=verify_projection(result,raw,tmp_path/'verified')
        assert 'PLAT_AMIGA_CUSTOM_DMACONR_OFFSET'not in text
    finally:artifact.close()


@pytest.mark.parametrize('profiles,absent',[
    (['cpu'],'PLAT_AMIGA_CUSTOM_'),(['amiga-custom'],'PLAT_ST_MFP_'),(['atari-st-mfp'],'PLAT_AMIGA_CUSTOM_'),
])
def test_explicit_profile_selection_does_not_bleed(tmp_path,profiles,absent):
    artifact,raw=fixture(tmp_path,'lea.l $DFF000.l,a5\n btst.b #6,2(a5)\n move.b d0,$FFFFFA13.w')
    try:
        result=artifact.platform_symbol_projection_payload(profiles,inline=True)
        assert absent not in verify_projection(result,raw,tmp_path/'verified')
    finally:artifact.close()


def test_namespace_collision_preserves_numeric_operand_and_user_label(tmp_path):
    name='PLAT_CPU_VECTOR_BUS_ERROR_ADDR'
    artifact,raw=fixture(tmp_path,'move.l #$1040,$8.w',extra={'seeded_code_labels':[dict(hunk=0,addr=0,name=name.lower())]})
    try:
        result=artifact.platform_symbol_projection_payload(PROFILES,inline=True)
        text=verify_projection(result,raw,tmp_path/'verified')
        assert name+' EQU'not in text and name.lower()+':'in text
        assert any(r['reason']=='platform_namespace_collision'and not r['admitted']for r in result['bindings'])
        assert re.search(r'move\.l .*\$0*8\.w',text)
    finally:artifact.close()


def test_actual_runtime_overlap_remains_ambiguous(tmp_path):
    artifact,raw=fixture(tmp_path,'move.l #$1040,$8.w',extra={'execution_views':[
        dict(source_start=0,source_end=66,base_addr=0,name='physical_zero_alias')]})
    try:
        result=artifact.platform_symbol_projection_payload(PROFILES,inline=True)
        text=verify_projection(result,raw,tmp_path/'verified')
        assert 'PLAT_CPU_VECTOR_BUS_ERROR_ADDR'not in text
        assert any(r['reason']=='ambiguous_address_binding'for r in result['bindings'])
    finally:artifact.close()


def test_projected_headers_use_normal_owned_package_and_default_export_stays_unchanged(tmp_path):
    from amiga_reversing.disasm.source_package import collect_native_package_includes,build_source_package,materialize_source_package
    artifact,raw=fixture(tmp_path,'lea.l $DFF000.l,a5\n btst.b #6,2(a5)\n move.b d0,$FFFFFA13.w\n move.l #$1040,$118.w')
    try:
        default=artifact.source_package_payload()
        projected=artifact.source_package_payload(platform_symbol_profiles=PROFILES)
        assert artifact.source_package_payload()==default
        include_root=tmp_path/'empty-sdk';include_root.mkdir()
        includes=collect_native_package_includes(projected,include_root)
        assert includes and all(r['kind']=='include'and r['provenance']=='native-platform-symbol-contracts'for r in includes)
        package=build_source_package(dict(filename='shared.s',source_text=projected['source_text'],target='fixture',
            assembler_profile='vasm',metadata_hash='fixture',target_identity_sha256='fixture'),projected['assets'],256,includes=includes)
        exported=tmp_path/'standalone';materialize_source_package(package,exported)
        text=(exported/'shared.s').read_text()
        assert c_backend.assemble_platform_source_text_with_c_backend('atari-st-raw',text,include_dir=exported)[0]==raw
        output=exported/'assembled.bin'
        subprocess.run([str(ROOT/'tools/vasmm68k_mot.exe'),'-m68000','-no-opt','-Fbin','-quiet','-o',str(output),'shared.s'],cwd=exported,check=True,capture_output=True)
        assert output.read_bytes()==raw
    finally:artifact.close()


def test_legacy_amiga_sdk_spelling_and_default_export_are_preserved(tmp_path):
    from tests.test_app_cursor_propagation import cursor_artifact
    artifact,raw=cursor_artifact(tmp_path,'lea.l $DFF000.l,a5\n btst.b #6,2(a5)\n move.w #$1F0,64(a5)',regions=False)
    try:
        original=artifact.inline_source_text_with_profile()[0]
        result=artifact.platform_symbol_projection_payload(['cpu','amiga-custom'],inline=True)
        assert result['status']=='ok'
        text=result['package']['source_text'];sdk=ROOT/'ext/amiga_includes/ndk_2.0/include'
        assert 'PLAT_AMIGA_CUSTOM_DMACONR_OFFSET(a5)'in text
        assert c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',text,include_dir=sdk)[0]==raw
        source=tmp_path/'legacy.s';source.write_text(text);output=tmp_path/'legacy.bin'
        subprocess.run([str(ROOT/'tools/vasmm68k_mot.exe'),'-m68000','-no-opt','-Fbin','-quiet','-I'+str(sdk),'-o',str(output),str(source)],check=True,capture_output=True)
        assert output.read_bytes()==raw
        assert artifact.inline_source_text_with_profile()[0]==original
        assert 'INCLUDE "hardware/custom.i"'in original
    finally:artifact.close()


@pytest.mark.parametrize('continuation',[False,True])
def test_projected_hardware_instruction_preserves_actual_local_reference_scope(tmp_path,continuation):
    labels=[dict(hunk=0,addr=0,name='owner'),dict(hunk=0,addr=64,name='second'),
            dict(hunk=0,addr=80,name='second\\.done')]
    if continuation:labels.append(dict(hunk=0,addr=70,name='continuation'))
    artifact,raw=fixture(tmp_path,'move.l #$1040,$118.w',
        handler='lea.l $DFF000.l,a5\n move.l #$1050,$8.w\n nop\n rts',
        extra={'seeded_code_labels':labels})
    try:
        original=artifact.inline_source_text_with_profile()[0]
        references=re.findall(r'move\.l\s+(#[^,]+),',original)
        reference=references[-1]
        result=artifact.platform_symbol_projection_payload(PROFILES,inline=True)
        text=verify_projection(result,raw,tmp_path/'verified')
        assert re.findall(r'move\.l\s+(#[^,]+),',text)[-1]==reference
        assert reference==('#second\\.done'if continuation else'#.done')
    finally:artifact.close()

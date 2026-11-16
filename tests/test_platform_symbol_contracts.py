"""Sourced platform spellings have independent access/base/namespace contracts."""
import subprocess
from pathlib import Path
from amiga_reversing.disasm import c_backend
ROOT=Path(__file__).resolve().parents[1]


def test_generated_platform_contracts_are_deterministic():
    from src.scripts.generate_platform_symbol_contracts import generate
    assert generate()==(ROOT/'src/generated/platform_symbol_contracts.h').read_text()


def test_native_symbol_contracts_refuse_wrong_profiles_access_bases_and_collisions(tmp_path):
    code=tmp_path/'contracts.c'
    code.write_text(r'''
#include "m68k_platform_symbols.h"
#include "m68k_simulator.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(void) {
 M68kPlatformSymbolBinding b[5];char *first=NULL,*again=NULL;
 assert(m68k_platform_symbol_resolve(7,8,4,M68K_SIM_ACCESS_MEMORY_WRITE,0,0,0,&b[0]));
 assert(b[0].profile==1 && b[0].value==8 && strstr(b[0].name,"PLAT_CPU_")==b[0].name);
 assert(!m68k_platform_symbol_resolve(1,0x118,4,M68K_SIM_ACCESS_MEMORY_WRITE,0,0,1,&b[1]));
 assert(!m68k_platform_symbol_resolve(7,4,4,M68K_SIM_ACCESS_MEMORY_READ,0,0,0,&b[1]));
 assert(m68k_platform_symbol_resolve(2,0xDFF002,1,M68K_SIM_ACCESS_MEMORY_READ,1,0xDFF000,0,&b[1]));
 assert(b[1].profile==2 && b[1].value==2 && strstr(b[1].name,"DMACONR_OFFSET"));
 assert(!m68k_platform_symbol_resolve(4,0xDFF002,1,M68K_SIM_ACCESS_MEMORY_READ,1,0xDFF000,0,&b[2]));
 assert(!m68k_platform_symbol_resolve(2,0xDFF002,2,M68K_SIM_ACCESS_MEMORY_WRITE,0,0,0,&b[2]));
 assert(!m68k_platform_symbol_resolve(2,0xDFF002,1,M68K_SIM_ACCESS_MEMORY_READ,1,0xDFF002,0,&b[2]));
 assert(m68k_platform_symbol_resolve(2,0xDFF040,2,M68K_SIM_ACCESS_MEMORY_WRITE,1,0xDFF000,0,&b[2]));
 assert(b[2].value==0x40 && strstr(b[2].name,"BLTCON0_OFFSET"));
 assert(!m68k_platform_symbol_resolve(2,0xDFF040,2,M68K_SIM_ACCESS_MEMORY_READ,0,0,0,&b[3]));
 assert(!m68k_platform_symbol_resolve(2,0xDFF040,4,M68K_SIM_ACCESS_MEMORY_WRITE,0,0,0,&b[3]));
 assert(m68k_platform_symbol_resolve(4,0xFFFFFA13,1,M68K_SIM_ACCESS_MEMORY_WRITE,0,0,0,&b[3]));
 assert(b[3].value==0xFFFFFA13 && strstr(b[3].name,"PLAT_ST_MFP_IMRA_ADDR"));
 assert(m68k_platform_symbol_resolve(4,0x00FFFA13,1,M68K_SIM_ACCESS_MEMORY_READ,0,0,0,&b[4]));
 assert(b[4].value==0x00FFFA13 && strstr(b[4].name,"BUS24"));
 assert(m68k_platform_symbol_definitions_alloc(b,5,2,&first)==0);
 assert(strstr(first,"DMACONR_OFFSET EQU $00000002") && strstr(first,"BLTCON0_OFFSET EQU $00000040"));
 assert(!strstr(first,"PLAT_CPU_") && !strstr(first,"PLAT_ST_"));
 assert(m68k_platform_symbol_definitions_alloc(b,5,2,&again)==0 && !strcmp(first,again));
 free(first);free(again);
 M68kRenderPlan plan={0};M68kRenderPlannedDeclaration existing={0};
 strcpy(existing.name,"plat_amiga_custom_dmaconr_offset");plan.declarations=&existing;plan.declaration_count=1;
 assert(m68k_platform_symbol_name_collides(&plan,b[1].name));
 assert(!m68k_platform_symbol_name_collides(&plan,b[2].name));
 M68kPlatformSymbolBinding duplicate[2]={b[1],b[1]};duplicate[1].value++;
 assert(m68k_platform_symbol_definitions_alloc(duplicate,2,2,&first)!=0);
 assert(!m68k_platform_symbol_resolve(4,0x118,4,M68K_SIM_ACCESS_MEMORY_WRITE,0,0,0,&b[0]));
 assert(m68k_platform_symbol_resolve(4,0x118,4,M68K_SIM_ACCESS_MEMORY_WRITE,0,0,1,&b[0]));
 assert(b[0].conditional && b[0].profile==4 && strstr(b[0].name,"KEYBOARD_MIDI"));
 assert(!m68k_platform_symbol_resolve(4,0x119,4,M68K_SIM_ACCESS_MEMORY_WRITE,0,0,1,&b[0]));
 assert(!m68k_platform_symbol_resolve(4,0x158,4,M68K_SIM_ACCESS_MEMORY_WRITE,0,0,1,&b[0]));
 assert(!m68k_platform_symbol_resolve(2,0xFFFFFA13,1,M68K_SIM_ACCESS_MEMORY_WRITE,0,0,0,&b[0]));
 assert(!m68k_platform_symbol_resolve(4,0xFFFFFA13,2,M68K_SIM_ACCESS_MEMORY_WRITE,0,0,0,&b[0]));
 assert(m68k_platform_symbol_resolve(7,8,4,M68K_SIM_ACCESS_MEMORY_WRITE,0,0,0,&b[0]));
 for(unsigned profile=1;profile<=4;profile*=2) {
  assert(m68k_platform_symbol_definitions_alloc(b,5,profile,&first)==0);
  fputs(first,stdout);free(first);
 }
 return 0;
}''')
    lib=ROOT/'src/build'
    out=tmp_path/'contracts'
    subprocess.run(['cc','-Isrc',str(code),'-L'+str(lib),'-lamiga_backend','-Wl,-rpath,'+str(lib),'-o',str(out)],cwd=ROOT,check=True,capture_output=True)
    result=subprocess.run([str(out)],capture_output=True,text=True)
    assert result.returncode==0,result.stdout+result.stderr
    body='''SECTION code,code
ORG $1000
lea.l $DFF000.l,a5
btst.b #6,PLAT_AMIGA_CUSTOM_DMACONR_OFFSET(a5)
move.w #$1F0,PLAT_AMIGA_CUSTOM_BLTCON0_OFFSET(a5)
move.b d0,PLAT_ST_MFP_IMRA_ADDR.w
move.b d0,PLAT_ST_MFP_BUS24_IMRA_ADDR.l
move.l #$1040,PLAT_CPU_VECTOR_BUS_ERROR_ADDR.w
rts
'''
    body=''.join(' '+line+'\n' for line in body.splitlines())
    numeric=body.replace('PLAT_AMIGA_CUSTOM_DMACONR_OFFSET','$2').replace('PLAT_AMIGA_CUSTOM_BLTCON0_OFFSET','$40').replace('PLAT_ST_MFP_IMRA_ADDR','$FFFFFA13').replace('PLAT_ST_MFP_BUS24_IMRA_ADDR','$00FFFA13').replace('PLAT_CPU_VECTOR_BUS_ERROR_ADDR','$8')
    expected=c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',numeric)[0]
    text=result.stdout+body
    assert c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',text)[0]==expected
    asm=tmp_path/'symbols.s';asm.write_text(text);binary=tmp_path/'symbols.bin'
    subprocess.run([str(ROOT/'tools/vasmm68k_mot.exe'),'-m68000','-no-opt','-Fbin','-quiet','-o',str(binary),str(asm)],check=True,capture_output=True)
    assert binary.read_bytes()==expected


def test_conflicting_controller_alias_metadata_refuses_generation(tmp_path):
    import json,pytest
    from src.scripts.generate_platform_symbol_contracts import generate
    knowledge=tmp_path/'knowledge';knowledge.mkdir()
    for name in ['amiga_hw_registers.json','atari_st_vector_controller.json']:
        (knowledge/name).write_bytes((ROOT/'knowledge'/name).read_bytes())
    path=knowledge/'atari_st_vector_controller.json';metadata=json.loads(path.read_text())
    metadata['symbol_base_aliases'].append(dict(metadata['symbol_base_aliases'][0],suffix='_CONFLICT'))
    path.write_text(json.dumps(metadata))
    with pytest.raises(ValueError,match='Ambiguous MFP encoded base alias'):generate(tmp_path)

"""Project only missing hardware access/name contracts from existing sourced KBs.

CPU vector definitions and Amiga hardware names remain in their existing runtime
metadata. This table adds access masks keyed by offset, not a second name table.
ST additions cover the small explicitly cited register/vector subset only.
"""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def generate(root=ROOT):
    amiga=json.loads((root/'knowledge/amiga_hw_registers.json').read_text())
    st=json.loads((root/'knowledge/atari_st_vector_controller.json').read_text())
    vr=next(row for row in st['symbol_registers'] if row['name']=='VR')
    if st['vector_register_address']-vr['offset'] not in {row['address'] for row in st['symbol_base_aliases']}:
        raise ValueError('MFP VR symbol contract disagrees with the existing controller address')
    if len({row['offset']for row in st['symbol_registers']})!=len(st['symbol_registers']):
        raise ValueError('Ambiguous MFP register offset')
    if len({row['address']for row in st['symbol_base_aliases']})!=len(st['symbol_base_aliases']):
        raise ValueError('Ambiguous MFP encoded base alias')
    rows={}
    for row in amiga['registers']:
        access=row.get('access','')
        mask=(1 if 'R'in access else 0)|(2 if 'W'in access else 0)
        if row.get('dma_only'):mask=0
        offset=int(row['address'],16)
        if offset in rows and rows[offset]!=mask:
            raise ValueError('Ambiguous Amiga hardware access contract')
        rows[offset]=mask
    lines=['/* Generated from knowledge/amiga_hw_registers.json and',
        ' * knowledge/atari_st_vector_controller.json. Do not edit. */',
        '#ifndef PLATFORM_SYMBOL_CONTRACTS_H','#define PLATFORM_SYMBOL_CONTRACTS_H',
        '#include <stdint.h>',
        'typedef struct { uint32_t offset; uint8_t access; } PlatformAmigaAccessContract;',
        'static const PlatformAmigaAccessContract g_platform_amiga_access_contracts[] = {']
    lines += [f'  {{ {offset}U, {mask}U }},'for offset,mask in sorted(rows.items())]
    lines += ['};','typedef struct { const char *name; uint32_t offset; uint8_t width,access; } PlatformMfpRegisterContract;',
        'static const PlatformMfpRegisterContract g_platform_mfp_register_contracts[] = {']
    for row in st['symbol_registers']:
        mask=(1 if 'R'in row['access']else 0)|(2 if 'W'in row['access']else 0)
        lines.append(f'  {{ "{row["name"]}", {row["offset"]}U, {row["width_bytes"]}U, {mask}U }},')
    lines += ['};','typedef struct { uint32_t address; const char *suffix; } PlatformMfpBaseAlias;',
        'static const PlatformMfpBaseAlias g_platform_mfp_base_aliases[] = {']
    lines += [f'  {{ {row["address"]}U, "{row["suffix"]}" }},'for row in st['symbol_base_aliases']]
    lines += ['};','typedef struct { uint32_t address; const char *name; } PlatformMfpVectorContract;',
        'static const PlatformMfpVectorContract g_platform_mfp_vector_contracts[] = {']
    lines += [f'  {{ {st["cpu_vector_base"]+(st["default_vector_base"]+row["channel"])*st["vector_slot_size"]}U, "{row["name"]}" }},'for row in st['symbol_vectors']]
    lines += ['};','#endif','']
    return '\n'.join(lines)

if __name__=='__main__':
    (ROOT/'src/generated/platform_symbol_contracts.h').write_text(generate())

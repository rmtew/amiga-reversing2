"""Generate the ST MFP slot contract; channel/base facts live in the cited KB."""
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]

def generate(root=ROOT):
    model=json.loads((root/'knowledge/atari_st_vector_controller.json').read_text())
    count=model['channel_count']; mask=model['vector_register_base_mask']; stride=model['vector_slot_size']
    assert count>0 and stride>0 and model['default_vector_base']&mask==model['default_vector_base']
    return f'''/* Generated from knowledge/atari_st_vector_controller.json. Do not edit. */
#ifndef ATARI_ST_VECTOR_RUNTIME_H
#define ATARI_ST_VECTOR_RUNTIME_H
#include <stdint.h>
#define ATARI_ST_MFP_VECTOR_REGISTER_ADDRESS {model['vector_register_address']}U
#define ATARI_ST_MFP_DEFAULT_VECTOR_BASE {model['default_vector_base']}U
/* VR selection is an explicit condition; the helper makes no active-state claim. */
static inline int atari_st_mfp_vector_slot(uint32_t address, uint8_t vector_register) {{
  uint32_t first = {model['cpu_vector_base']}U + (vector_register & {mask}U) * {stride}U;
  return (vector_register & {mask}U) >= {model["minimum_vector_base"]}U &&
    address >= first && address - first < {count*stride}U &&
    (address - first) % {stride}U == 0U;
}}
#endif
'''
if __name__=='__main__':
    (ROOT/'src/generated/atari_st_vector_runtime.h').write_text(generate())

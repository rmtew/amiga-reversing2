/* Generated from knowledge/atari_st_vector_controller.json. Do not edit. */
#ifndef ATARI_ST_VECTOR_RUNTIME_H
#define ATARI_ST_VECTOR_RUNTIME_H
#include <stdint.h>
#define ATARI_ST_MFP_VECTOR_REGISTER_ADDRESS 4294965783U
#define ATARI_ST_MFP_DEFAULT_VECTOR_BASE 64U
/* VR selection is an explicit condition; the helper makes no active-state claim. */
static inline int atari_st_mfp_vector_slot(uint32_t address, uint8_t vector_register) {
  uint32_t first = 0U + (vector_register & 240U) * 4U;
  return (vector_register & 240U) >= 64U &&
    address >= first && address - first < 64U &&
    (address - first) % 4U == 0U;
}
#endif

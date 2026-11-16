#ifndef M68K_PLATFORM_SYMBOLS_H
#define M68K_PLATFORM_SYMBOLS_H
#include "m68k_render_plan.h"
#define M68K_SYMBOL_PROFILE_CPU 1U
#define M68K_SYMBOL_PROFILE_AMIGA_CUSTOM 2U
#define M68K_SYMBOL_PROFILE_ST_MFP 4U
#define M68K_SYMBOL_PROFILE_ALL 7U
/* A spelling projection of a separately proved numeric binding. No discovery. */
typedef struct M68kPlatformSymbolBinding {
  char name[96];
  uint32_t value, address;
  uint8_t profile, relative, conditional;
  const char *provenance;
  const char *reason;
} M68kPlatformSymbolBinding;
int m68k_platform_symbol_resolve(uint32_t profiles,uint32_t address,uint8_t width,uint8_t access,
  uint8_t relative,uint32_t base,uint8_t native_vector_installation,M68kPlatformSymbolBinding *out);
int m68k_platform_symbol_name_collides(const M68kRenderPlan *plan,const char *name);
/* Deterministic EQU-only text, shared by include and inline projections.
 * Definitions with divergent values, malformed names or namespace confusion refuse. */
int m68k_platform_symbol_definitions_alloc(const M68kPlatformSymbolBinding *bindings,size_t count,
  uint8_t profile,char **out_text);
#endif

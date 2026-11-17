#ifndef M68K_PLATFORM_PROJECTION_H
#define M68K_PLATFORM_PROJECTION_H
#include "m68k_platform_symbols.h"
typedef struct M68kPlatformProjectedUse {
  uint32_t section_index,offset,operand_index,base_origin;
  uint32_t base;
  uint8_t admitted,source_overlap_disambiguated;
  M68kPlatformSymbolBinding binding;
} M68kPlatformProjectedUse;
typedef struct M68kPlatformProjection {
  M68kRenderPlan plan;
  M68kRenderPlanRow *rows;
  M68kRenderPlannedInstruction *instructions;
  M68kRenderPlannedDeclaration *declarations;
  M68kPlatformProjectedUse *uses;
  size_t use_count,use_capacity;
  char **texts;
  char *headers[3];
  uint32_t profiles;
  uint8_t inline_definitions;
  const char *reason;
} M68kPlatformProjection;
int m68k_platform_projection_build(M68kPlatformProjection *out,const M68kRenderPlan *base,
  const M68kSourceAnalysisIR *analysis,uint32_t profiles,uint8_t inline_definitions);
void m68k_platform_projection_destroy(M68kPlatformProjection *projection);
int m68k_platform_projection_json_alloc(const M68kPlatformProjection *projection,
  const M68kObject *object,uint32_t minimum_asset_size,char **out_text);
#endif

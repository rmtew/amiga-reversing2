/* Static native analysis of vasm-built synthetic register dispatchers. */
#include "m68k_analysis_facts_v2.h"
#include "platform_file_lib.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int code_at(const M68kSourceAnalysisIR *a, uint32_t offset) {
  for (size_t i = 0; i < a->sections[0].range_ownership_count; ++i) {
    const M68kRangeOwnershipIR *r = &a->sections[0].range_ownerships[i];
    if (r->kind == M68K_RANGE_OWNERSHIP_CODE && r->start_offset <= offset && offset < r->end_offset) return 1;
  }
  return 0;
}
int main(int argc, char **argv) {
  unsigned char bytes[512]; size_t size;
  M68kObject object; M68kSection section = {0}; M68kAnalysisPolicy policy;
  M68kFactsV2Profile profile; M68kSourceAnalysisIR analysis = {0}; char *source = NULL;
  assert(argc == 4);
  FILE *f = fopen(argv[1], "rb"); assert(f); size = fread(bytes, 1, sizeof(bytes), f); fclose(f);
  assert(size > 132 && size < sizeof(bytes));
  assert(m68k_object_create(&object) == 0); section.kind = M68K_SECTION_CODE;
  section.data = bytes; section.size = section.data_size = (uint32_t)size;
  assert(m68k_object_add_section(&object, &section).ok); m68k_analysis_policy_init_default(&policy);
  /* Accept the helper without an incoming A6 before analyzing the caller. */
  policy.entry_point_count = 2;
  policy.entry_points[0].has_section_index = policy.entry_points[1].has_section_index = 1;
  policy.entry_points[0].offset = 32; policy.entry_points[1].offset = 0;
  assert(m68k_facts_v2_render_asm_source_analysis_profile_alloc(&object, &policy,
    &source, &profile, &analysis, 1U, m68k_diag_sink(NULL)) == 0);
  assert(source && !profile.asm_source_refused && !profile.required_instruction_failures);
  assert(!profile.asm_source_instruction_byte_mismatches);
  fprintf(stderr, "target128=%d expected=%d\n", code_at(&analysis, 128), atoi(argv[2]));
  assert(code_at(&analysis, 128) == atoi(argv[2]));
  unsigned char *rebuilt = NULL; size_t rebuilt_size = 0U;
  char *assembly_profile = NULL, *error = NULL;
  assert(platform_file_assemble_source_text_bytes_profile_alloc("amiga-raw", "", source,
    "68000", &rebuilt, &rebuilt_size, &assembly_profile, &error) == 0);
  assert(rebuilt_size == size && !memcmp(bytes, rebuilt, size));
  platform_file_free_bytes(rebuilt); platform_file_free_text(assembly_profile); platform_file_free_text(error);
  f = fopen(argv[3], "wb"); assert(f); fwrite(source, 1, strlen(source), f); fclose(f);
  m68k_facts_v2_free_text(source); m68k_ir_source_analysis_destroy(&analysis);
  m68k_analysis_policy_destroy(&policy); m68k_object_destroy(&object);
  puts("register dispatch fixture passed"); return 0;
}

#include "m68k_platform_symbols.h"
#include "m68k_simulator.h"
#include "generated/m68k_cpu_runtime.h"
#include "generated/amiga_os_runtime.h"
#include "generated/platform_symbol_contracts.h"
#include "json_builder.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#define ARRAY_COUNT(a) (sizeof(a)/sizeof((a)[0]))
static int binding_name(M68kPlatformSymbolBinding *out,const char *prefix,const char *name,const char *suffix) {
  int n=snprintf(out->name,sizeof(out->name),"%s%s%s",prefix,name,suffix);
  if(n<0 || (size_t)n>=sizeof(out->name)) {out->reason="symbol_name_overflow";return 0;}
  for(size_t i=0;out->name[i];++i) {
    unsigned char c=(unsigned char)out->name[i];
    if(!isalnum(c) && c!='_') {out->reason="nonidentifier_metadata_name";return 0;}
    out->name[i]=(char)toupper(c);
  }
  out->reason="bound";return 1;
}
int m68k_platform_symbol_resolve(uint32_t profiles,uint32_t address,uint8_t width,uint8_t access,
    uint8_t relative,uint32_t base,uint8_t native_vector_installation,M68kPlatformSymbolBinding *out) {
  uint8_t required=access==M68K_SIM_ACCESS_MEMORY_READ ? 1U : access==M68K_SIM_ACCESS_MEMORY_WRITE ? 2U : 0U;
  if(!out)return 0;
  memset(out,0,sizeof(*out));out->reason="no_supported_platform_address_contract";
  out->address=address;out->value=relative ? address-base : address;out->relative=relative;
  if(!profiles || (profiles&~M68K_SYMBOL_PROFILE_ALL)) {out->reason="invalid_platform_profiles";return 0;}
  if(!required && access!=M68K_SIM_ACCESS_COMPUTE_ADDRESS) {out->reason="not_a_memory_or_address_access";return 0;}
  if(!relative && (profiles&M68K_SYMBOL_PROFILE_CPU)) {
    const M68kCpuExceptionVectorInfo *v=m68k_cpu_find_exception_vector_by_address(address);
    if(v && v->kind!=M68K_CPU_VECTOR_KIND_RESET && (width==4U || access==M68K_SIM_ACCESS_COMPUTE_ADDRESS)) {
      out->profile=M68K_SYMBOL_PROFILE_CPU;out->provenance="knowledge/m68k_instructions.json:_meta.exception_vectors";
      const char *name=v->symbol_name;
      if(!strncmp(name,"m68k_",5))name+=5;
      return binding_name(out,"PLAT_CPU_",name,"_ADDR");
    }
  }
  if(profiles&M68K_SYMBOL_PROFILE_AMIGA_CUSTOM) {
    uint32_t custom_base=0;
    if(amiga_os_find_hardware_base_address(amiga_os_hardware_base_symbol(AMIGA_OS_HARDWARE_BASE_ID_CUSTOM),&custom_base)) {
      if(!relative && address==custom_base && access==M68K_SIM_ACCESS_COMPUTE_ADDRESS) {
        out->profile=M68K_SYMBOL_PROFILE_AMIGA_CUSTOM;out->provenance="generated Amiga Custom base metadata";
        return binding_name(out,"PLAT_AMIGA_CUSTOM_","BASE","");
      }
      const AmigaOsHardwareRegisterInfo *reg=amiga_os_find_hardware_register_by_cpu_address(address);
      if(reg && reg->base_id==AMIGA_OS_HARDWARE_BASE_ID_CUSTOM) {
        if(relative && base!=custom_base) {out->reason="noncanonical_hardware_base";return 0;}
        if(!required || width==0 || width>2U) {out->reason="unsupported_custom_access_width_or_kind";return 0;}
        for(size_t i=0;i<ARRAY_COUNT(g_platform_amiga_access_contracts);++i) {
          const PlatformAmigaAccessContract *contract=&g_platform_amiga_access_contracts[i];
          if(contract->offset!=reg->offset) continue;
          if(!(contract->access&required)) {out->reason="hardware_access_not_supported";return 0;}
          out->profile=M68K_SYMBOL_PROFILE_AMIGA_CUSTOM;
          out->provenance="knowledge/amiga_hw_registers.json + sourced Amiga runtime symbol metadata";
          return binding_name(out,"PLAT_AMIGA_CUSTOM_",reg->symbol_name,relative ? "_OFFSET" : "_ADDR");
        }
      }
    }
  }
  if(profiles&M68K_SYMBOL_PROFILE_ST_MFP) {
    for(size_t i=0;i<ARRAY_COUNT(g_platform_mfp_base_aliases);++i) {
      const PlatformMfpBaseAlias *alias=&g_platform_mfp_base_aliases[i];
      char prefix[64];snprintf(prefix,sizeof(prefix),"PLAT_ST_MFP%s_",alias->suffix);
      if(!relative && address==alias->address && access==M68K_SIM_ACCESS_COMPUTE_ADDRESS) {
        out->profile=M68K_SYMBOL_PROFILE_ST_MFP;out->provenance="knowledge/atari_st_vector_controller.json:symbol_base_aliases";
        return binding_name(out,prefix,"BASE","");
      }
      for(size_t j=0;j<ARRAY_COUNT(g_platform_mfp_register_contracts);++j) {
        const PlatformMfpRegisterContract *reg=&g_platform_mfp_register_contracts[j];
        if(address!=alias->address+reg->offset)continue;
        if(relative && base!=alias->address) {out->reason="noncanonical_hardware_base";return 0;}
        if(width!=reg->width || !(reg->access&required)) {out->reason="unsupported_mfp_access_width_or_kind";return 0;}
        out->profile=M68K_SYMBOL_PROFILE_ST_MFP;out->provenance="knowledge/atari_st_vector_controller.json:symbol_registers";
        return binding_name(out,relative ? "PLAT_ST_MFP_" : prefix,reg->name,relative ? "_OFFSET" : "_ADDR");
      }
    }
    if(!relative)for(size_t i=0;i<ARRAY_COUNT(g_platform_mfp_vector_contracts);++i) {
      const PlatformMfpVectorContract *v=&g_platform_mfp_vector_contracts[i];
      if(v->address!=address)continue;
      if(!native_vector_installation || access!=M68K_SIM_ACCESS_MEMORY_WRITE || width!=4U) {
        out->reason="mfp_vector_requires_native_installation_evidence";return 0;
      }
      out->profile=M68K_SYMBOL_PROFILE_ST_MFP;out->conditional=1U;
      out->provenance="ST system vector metadata, conditional on selected MFP base and native installation evidence";
      return binding_name(out,"PLAT_ST_MFP_VECTOR_",v->name,"_ADDR");
    }
  }
  return 0;
}
static int equal_name(const char *a,const char *b) {
  while(*a && *b)if(toupper((unsigned char)*a++)!=toupper((unsigned char)*b++))return 0;
  return *a==*b;
}
int m68k_platform_symbol_name_collides(const M68kRenderPlan *plan,const char *name) {
  if(!plan || !name || !*name)return 1;
  for(size_t i=0;i<plan->label_count;++i)if(equal_name(plan->labels[i].name,name) || equal_name(plan->labels[i].storage_name,name))return 1;
  for(size_t i=0;i<plan->declaration_count;++i)if(equal_name(plan->declarations[i].name,name))return 1;
  for(size_t i=0;i<plan->runtime_alias_count;++i)if(equal_name(plan->runtime_aliases[i].name,name))return 1;
  return 0;
}
static int compare_binding(const void *a,const void *b) {
  const M68kPlatformSymbolBinding *x=a,*y=b;return strcmp(x->name,y->name);
}
int m68k_platform_symbol_definitions_alloc(const M68kPlatformSymbolBinding *bindings,size_t count,
    uint8_t profile,char **out_text) {
  M68kPlatformSymbolBinding *sorted=NULL;JsonBuilder text={0};size_t used=0;int status=-1;
  if(!out_text || (count && !bindings) || (profile!=1U && profile!=2U && profile!=4U))return -1;
  *out_text=NULL;
  if(count>SIZE_MAX/sizeof(*sorted))return -1;
  sorted=malloc((count ? count : 1U)*sizeof(*sorted));if(!sorted)return -1;
  for(size_t i=0;i<count;++i)if(bindings[i].profile==profile)sorted[used++]=bindings[i];
  qsort(sorted,used,sizeof(*sorted),compare_binding);
  if(json_builder_create(&text))goto done;
  for(size_t i=0;i<used;++i) {
    const M68kPlatformSymbolBinding *b=&sorted[i];
    const char *prefix=profile==1U ? "PLAT_CPU_" : profile==2U ? "PLAT_AMIGA_CUSTOM_" : "PLAT_ST_MFP_";
    if(strncmp(b->name,prefix,strlen(prefix)) || b->name[0]=='\0')goto done;
    for(size_t j=0;b->name[j];++j)if(!isupper((unsigned char)b->name[j]) && !isdigit((unsigned char)b->name[j]) && b->name[j]!='_')goto done;
    if(i && equal_name(sorted[i-1].name,b->name)) {
      if(sorted[i-1].value!=b->value)goto done;
      continue;
    }
    if(json_builder_appendf(&text,"%s EQU $%08X\n",b->name,(unsigned)b->value))goto done;
  }
  *out_text=json_builder_build(&text);status=*out_text ? 0 : -1;
done:
  json_builder_destroy(&text);free(sorted);return status;
}

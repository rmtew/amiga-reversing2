/* Opt-in typed decode of caller-admitted 68000 code. Does not classify bytes. */
#include "m68k_backend.h"
#include "m68k_disassembler.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_number(const char *text, uint32_t *value) {
  char *end;
  uintmax_t n;
  if (*text < '0' || *text > '9') return -1;
  errno = 0;
  n = strtoumax(text, &end, 0);
  if (errno != 0 || *end != '\0' || n > UINT32_MAX) return -1;
  *value = (uint32_t)n;
  return 0;
}

static uint8_t *read_raw(const char *path, uint32_t offset, uint32_t length) {
  FILE *file = fopen(path, "rb");
  uint8_t *data = NULL;
  long file_size;
  if (file == NULL) return NULL;
  if (fseek(file, 0L, SEEK_END) == 0 && (file_size = ftell(file)) >= 0L &&
      (uintmax_t)offset + length <= (uintmax_t)file_size &&
      fseek(file, (long)offset, SEEK_SET) == 0) {
    data = malloc(length);
    if (data != NULL && fread(data, 1U, length, file) != length) {
      free(data);
      data = NULL;
    }
  }
  fclose(file);
  return data;
}

static const char *operand_kind_name(uint8_t kind) {
  switch (kind) {
    case M68K_ASM_OPERAND_AN: return "an";
    case M68K_ASM_OPERAND_ABSL: return "absl";
    case M68K_ASM_OPERAND_BF_EA: return "bf_ea";
    case M68K_ASM_OPERAND_CACHE_SEL: return "cache_sel";
    case M68K_ASM_OPERAND_CCR: return "ccr";
    case M68K_ASM_OPERAND_CTRL_REG: return "ctrl_reg";
    case M68K_ASM_OPERAND_DN: return "dn";
    case M68K_ASM_OPERAND_DN_PAIR: return "dn_pair";
    case M68K_ASM_OPERAND_EA: return "ea";
    case M68K_ASM_OPERAND_IMM: return "imm";
    case M68K_ASM_OPERAND_IND: return "ind";
    case M68K_ASM_OPERAND_LABEL: return "label";
    case M68K_ASM_OPERAND_POSTINC: return "postinc";
    case M68K_ASM_OPERAND_PREDEC: return "predec";
    case M68K_ASM_OPERAND_REGLIST: return "reglist";
    case M68K_ASM_OPERAND_RN: return "rn";
    case M68K_ASM_OPERAND_RN_PAIR: return "rn_pair";
    case M68K_ASM_OPERAND_SR: return "sr";
    case M68K_ASM_OPERAND_USP: return "usp";
    default: return "none";
  }
}

static void write_operand(FILE *output, const M68kAsmOperandValue *op) {
  /* Keep the decoder's numeric values, including raw addressing-mode fields. */
  fprintf(output,
    "{\"kind\":\"%s\",\"kind_id\":%u,\"value\":%" PRIu32
    ",\"register\":%u,\"register_is_address\":%u,"
    "\"ea_mode\":%u,\"ea_reg\":%u,\"index_register\":%u,"
    "\"index_is_address\":%u,\"index_long\":%u,\"scale\":%u}",
    operand_kind_name(op->kind), (unsigned)op->kind, op->value,
    (unsigned)op->reg, (unsigned)op->reg_is_address,
    (unsigned)op->ea_mode, (unsigned)op->ea_reg, (unsigned)op->index_reg,
    (unsigned)op->index_is_address, (unsigned)op->index_long, (unsigned)op->scale);
}

static void write_instruction(FILE *output, const M68kDisasmResult *insn,
    const uint8_t *raw, uint32_t section, uint32_t offset) {
  size_t i;
  fprintf(output,
    "{\"section\":%" PRIu32 ",\"offset\":%" PRIu32 ",\"byte_count\":%zu,\"bytes\":\"",
    section, offset, insn->byte_count);
  for (i = 0; i < insn->byte_count; ++i) fprintf(output, "%02x", (unsigned)raw[i]);
  fputs("\",\"mnemonic\":\"", output);
  for (i = 0; insn->mnemonic[i] != '\0'; ++i) fputc(tolower((unsigned char)insn->mnemonic[i]), output);
  fputs("\",\"size\":", output);
  if (insn->size_suffix != '\0') fprintf(output, "\"%c\"", tolower((unsigned char)insn->size_suffix));
  else fputs("null", output);
  fprintf(output, ",\"form\":%u,\"operands\":[", (unsigned)insn->canonical_form_id);
  for (i = 0; i < insn->operand_count; ++i) {
    if (i != 0U) fputc(',', output);
    write_operand(output, &insn->operands[i]);
  }
  fputs("]}\n", output);
}

int main(int argc, char **argv) {
  uint32_t section, start, length, cursor;
  uint8_t *raw = NULL;
  const uint8_t *code = NULL;
  M68kObject object = {0};
  M68kDiagList diagnostics = {0};
  FILE *staging = NULL;
  unsigned char buffer[4096];
  size_t count;
  int result = EXIT_FAILURE;

  if (argc != 6 || (strcmp(argv[1], "raw") != 0 && strcmp(argv[1], "hunk") != 0) ||
      parse_number(argv[3], &section) != 0 || parse_number(argv[4], &start) != 0 ||
      parse_number(argv[5], &length) != 0 || (start & 1U) != 0U || (length & 1U) != 0U ||
      length == 0U || start > UINT32_MAX - length) {
    fprintf(stderr, "Usage: m68k_timing_decode raw|hunk FILE SECTION START LENGTH\n"
                    "Supply a nonempty, word-aligned range of established 68000 code.\n");
    return EXIT_FAILURE;
  }

  if (strcmp(argv[1], "raw") == 0) {
    raw = read_raw(argv[2], start, length);
    if (raw == NULL) {
      fprintf(stderr, "Cannot read raw range from %s\n", argv[2]);
      goto done;
    }
    code = raw;
  } else {
    const M68kSection *hunk;
    if (m68k_object_create(&object) != 0 ||
        M68K_BACKEND_AMIGA_HUNK.read_file(argv[2], &object, m68k_diag_sink(&diagnostics)) != 0) {
      const char *detail = m68k_diag_first_message(&diagnostics);
      fprintf(stderr, "Cannot read Hunk file %s%s%s\n", argv[2], detail ? ": " : "", detail ? detail : "");
      goto done;
    }
    if (section >= object.section_count || (hunk = &object.sections[section])->kind != M68K_SECTION_CODE ||
        hunk->data == NULL || start + length > hunk->data_size) {
      fprintf(stderr, "Range is not contained in stored bytes of a CODE section\n");
      goto done;
    }
    code = hunk->data + start;
  }

  /* Failed admission never leaves valid-looking partial JSONL on stdout. */
  staging = tmpfile();
  if (staging == NULL) {
    perror("Cannot stage decoded instructions");
    goto done;
  }
  for (cursor = 0; cursor < length;) {
    M68kDisasmResult insn = m68k_disassemble_one_for_cpu(code + cursor, length - cursor,
      M68K_ASM_CPU_68000, (M68kDiagSink){0});
    if (insn.byte_count == 0U || insn.byte_count > length - cursor ||
        insn.canonical_form_id == M68K_FORM_ID_NONE) {
      fprintf(stderr, "No canonical 68000 instruction at section %" PRIu32 " offset 0x%" PRIx32 "\n",
              section, start + cursor);
      goto done;
    }
    write_instruction(staging, &insn, code + cursor, section, start + cursor);
    cursor += (uint32_t)insn.byte_count;
  }
  if (!ferror(staging) && fseek(staging, 0L, SEEK_SET) == 0) {
    while ((count = fread(buffer, 1U, sizeof(buffer), staging)) != 0U) {
      if (fwrite(buffer, 1U, count, stdout) != count) goto done;
    }
    if (!ferror(staging) && fflush(stdout) == 0) result = EXIT_SUCCESS;
  }

done:
  if (staging != NULL) fclose(staging);
  m68k_object_destroy(&object);
  free(raw);
  return result;
}

/* Internal scheduling-budget regression; no new public analysis/seed API. */
#include "m68k_analysis_facts_v2.c"
#include <assert.h>
#include <stdio.h>

static void check_budget(int difference) {
  M68kDecodeIR decode = {0}; M68kDecodeSectionIR section = {0};
  M68kFactsV2WorkQueue queue; M68kFactsV2TraceState states[9];
  section.size = 256U; decode.section_count = 1U; decode.sections = &section;
  assert(work_queue_init_for_decode(&queue, &decode) == 0);
  for (unsigned i = 0; i < 9; ++i) {
    trace_state_init_unknown(&states[i]);
    trace_value_set_source_offset(&states[i].a[6], 0U, 128U);
    switch (difference) {
    case 0: trace_state_set_data_register_constant(&states[i], 7U, i); break;
    case 1: trace_value_set_source_offset(&states[i].a[0], 0U, i * 2U); break;
    case 2: states[i].absolute_slots[0].used = 1U;
      states[i].absolute_slots[0].address = 192U;
      trace_value_set_constant(&states[i].absolute_slots[0].value, i); break;
    case 3: states[i].stack_slots[0].used = 1U;
      trace_value_set_constant(&states[i].stack_slots[0].value, i); break;
    case 4: trace_state_set_data_register_constant_with_origin(&states[i], 7U, 7U, 0U, i * 2U, 0U); break;
    case 5: trace_value_set_source_offset(&states[i].a[6], 0U, 128U + 2U * i); break;
    }
    /* Low-confidence fallthrough, then its exact high-confidence loop input. */
    assert(work_queue_push(&queue, 0U, 64U, 1U, M68K_FACT_CODE_START_REASON_FALLTHROUGH,
      0U, 62U, 1U, 0x1040U, &states[i], M68K_FACTS_V2_TRACE_CONTROL_INPUT_VARIANT) == 0);
    size_t after_low = queue.count;
    if (i < 8U) assert(after_low == 2U * i + 1U);
    else assert(after_low == 16U); /* Ninth distinct full context is still refused. */
    assert(work_queue_push(&queue, 0U, 64U, 2U, M68K_FACT_CODE_START_REASON_CONTROL_TARGET,
      0U, 70U, 1U, 0x1040U, &states[i], M68K_FACTS_V2_TRACE_CONTROL_INPUT_VARIANT) == 0);
    /* Stronger confidence is independently queued, not promoted in place. */
    assert(queue.count == (i < 8U ? 2U * i + 2U : 16U));
  }
  M68kFactsV2WorkItem item; size_t popped = 0U;
  while (work_queue_pop(&queue, &item)) {
    assert(item.confidence == (popped % 2U ? 2U : 1U)); ++popped;
  }
  assert(popped == 16U); work_queue_destroy(&queue);
}
static void check_replay_modes_and_runtime_domains(void) {
  M68kDecodeIR decode = {0}; M68kDecodeSectionIR section = {0};
  M68kFactsV2WorkQueue queue; M68kFactsV2TraceState state;
  section.size = 256U; decode.section_count = 1U; decode.sections = &section;
  assert(work_queue_init_for_decode(&queue, &decode) == 0);
  trace_state_init_unknown(&state); trace_value_set_source_offset(&state.a[6], 0U, 128U);
  for (unsigned i = 0; i < 4U; ++i) {
    trace_state_set_data_register_constant(&state, 7U, i);
    for (unsigned mode = 1U; mode <= 3U; mode += 2U) {
      assert(work_queue_push(&queue, 0U, 64U, 1U, M68K_FACT_CODE_START_REASON_CONTROL_TARGET,
        0U, 0U, 1U, 0x1040U, &state, mode) == 0);
      assert(queue.count == i * 2U + (mode == 1U ? 1U : 2U));
    }
  }
  trace_state_set_data_register_constant(&state, 7U, 4U);
  assert(work_queue_push(&queue, 0U, 64U, 1U, M68K_FACT_CODE_START_REASON_CONTROL_TARGET,
    0U, 0U, 1U, 0x1040U, &state, 3U) == 0);
  assert(queue.count == 8U); /* Modes are distinct; no ninth state sneaks in. */
  assert(work_queue_push(&queue, 0U, 64U, 1U, M68K_FACT_CODE_START_REASON_CONTROL_TARGET,
    0U, 0U, 1U, 0x2040U, &state, 3U) == 0);
  assert(queue.count == 9U); /* Separate runtime address view, separate budget. */
  work_queue_destroy(&queue);
}
int main(void) {
  for (int difference = 0; difference < 6; ++difference) check_budget(difference);
  check_replay_modes_and_runtime_domains();
  puts("exact context budget fixtures passed"); return 0;
}

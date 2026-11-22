"""ABI-only compatibility helpers retained after quarantining mixed corpus tests.

These ctypes layouts and the backend-availability guard contain no target media,
assembly fixtures or corpus-reading tests. The original module remains private.
"""
from __future__ import annotations
import ctypes
import pytest
from src.tests._platform_backend_test_utils import M68kDiagList
from amiga_reversing.disasm.project_paths import PROJECT_ROOT

def _requires_c_backend_dlls() -> None:
    build_dir = PROJECT_ROOT / "src" / "build"
    if not (build_dir / "platform_file_lib.dll").exists() or not (build_dir / "platform_disk_lib.dll").exists():
        pytest.skip("C backend DLLs are missing; run cmd /c src\\build.bat")

class _M68kDiagSink(ctypes.Structure):
    _fields_ = [("list", ctypes.POINTER(M68kDiagList))]

class _M68kAnalysisRegisterSeed(ctypes.Structure):
    _fields_ = [
        ("platform_kind", ctypes.c_uint8),
        ("kind", ctypes.c_uint8),
        ("reg_kind", ctypes.c_uint8),
        ("reg_index", ctypes.c_uint8),
        ("has_entry_offset", ctypes.c_uint8),
        ("has_section_index", ctypes.c_uint8),
        ("array_element_count", ctypes.c_uint16),
        ("entry_offset", ctypes.c_uint32),
        ("section_index", ctypes.c_uint32),
        ("name", ctypes.c_char * 64),
        ("type_name", ctypes.c_char * 64),
        ("context_name", ctypes.c_char * 64),
        ("hardware_stride", ctypes.c_uint16),
        ("hardware_index_values", ctypes.c_uint16 * 8),
        ("hardware_index_count", ctypes.c_uint8),
        ("hardware_index_register", ctypes.c_uint8),
    ]

class _M68kFunctionSummaryAbiRegisterMember(ctypes.Structure):
    _fields_ = [
        ("register_kind", ctypes.c_uint8),
        ("register_index", ctypes.c_uint8),
    ]

class _M68kFunctionSummaryAbiLocation(ctypes.Structure):
    _fields_ = [
        ("kind", ctypes.c_uint8),
        ("width", ctypes.c_uint8),
        ("stack_convention", ctypes.c_uint8),
        ("register_count", ctypes.c_uint8),
        ("stack_offset", ctypes.c_int32),
        ("registers", _M68kFunctionSummaryAbiRegisterMember * 4),
    ]

class _M68kAnalysisFunctionSummaryInput(ctypes.Structure):
    _fields_ = [
        ("seed_kind", ctypes.c_uint8),
        ("has_platform_identity", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 2),
        ("location", _M68kFunctionSummaryAbiLocation),
        ("struct_name", ctypes.c_char * 64),
        ("platform_library_id", ctypes.c_uint16),
        ("platform_function_id", ctypes.c_uint16),
        ("platform_input_id", ctypes.c_uint16),
    ]

class _M68kAnalysisFunctionSummaryResult(ctypes.Structure):
    _fields_ = [
        ("location", _M68kFunctionSummaryAbiLocation),
        ("kind", ctypes.c_uint8),
        ("input_index", ctypes.c_uint8),
        ("platform_library_id", ctypes.c_uint16),
        ("platform_function_id", ctypes.c_uint16),
        ("platform_output_id", ctypes.c_uint16),
    ]

class _M68kFunctionSummaryLocationEffectIR(ctypes.Structure):
    _fields_ = [
        ("location", _M68kFunctionSummaryAbiLocation),
        ("effect", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 3),
    ]

class _M68kFunctionSummaryEffectSubjectIR(ctypes.Structure):
    _fields_ = [
        ("kind", ctypes.c_uint8),
        ("input_index", ctypes.c_uint8),
        ("stack_convention", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8),
        ("section_index", ctypes.c_uint32),
        ("offset", ctypes.c_uint32),
        ("abstract_region_id", ctypes.c_char * 96),
    ]

class _M68kFunctionSummaryMemoryEffectIR(ctypes.Structure):
    _fields_ = [
        ("kind", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 3),
        ("subject", _M68kFunctionSummaryEffectSubjectIR),
    ]

class _M68kFunctionSummaryEscapeIR(ctypes.Structure):
    _fields_ = [
        ("source_kind", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 3),
        ("source_location", _M68kFunctionSummaryAbiLocation),
        ("sink_subject", _M68kFunctionSummaryEffectSubjectIR),
    ]

class _M68kAnalysisFunctionSummary(ctypes.Structure):
    _fields_ = [
        ("callable_kind", ctypes.c_uint8),
        ("has_section_index", ctypes.c_uint8),
        ("input_count", ctypes.c_uint8),
        ("register_effect_state", ctypes.c_uint8),
        ("memory_effect_state", ctypes.c_uint8),
        ("escape_effect_state", ctypes.c_uint8),
        ("memory_effect_count", ctypes.c_uint8),
        ("escape_count", ctypes.c_uint8),
        ("effects_invalid", ctypes.c_uint8),
        ("location_effect_count", ctypes.c_uint8),
        ("result_count", ctypes.c_uint8),
        ("result_contract_invalid", ctypes.c_uint8),
        ("reserved1", ctypes.c_uint8),
        ("section_index", ctypes.c_uint32),
        ("entry_offset", ctypes.c_uint32),
        ("table_offset", ctypes.c_uint32),
        ("entry_count", ctypes.c_uint32),
        ("function_summary_id", ctypes.c_char * 96),
        ("context_name", ctypes.c_char * 64),
        ("inputs", _M68kAnalysisFunctionSummaryInput * 8),
        ("results", _M68kAnalysisFunctionSummaryResult * 16),
        ("location_effects", _M68kFunctionSummaryLocationEffectIR * 32),
        ("memory_effects", _M68kFunctionSummaryMemoryEffectIR * 8),
        ("escapes", _M68kFunctionSummaryEscapeIR * 8),
    ]

class _M68kAnalysisEntryPoint(ctypes.Structure):
    _fields_ = [
        ("has_section_index", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 3),
        ("section_index", ctypes.c_uint32),
        ("offset", ctypes.c_uint32),
    ]

class _M68kAnalysisStructuredDataItem(ctypes.Structure):
    _fields_ = [
        ("has_section_index", ctypes.c_uint8),
        ("kind", ctypes.c_uint8),
        ("is_pointer", ctypes.c_uint8),
        ("has_target", ctypes.c_uint8),
        ("section_index", ctypes.c_uint32),
        ("offset", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("target_section", ctypes.c_uint32),
        ("target_offset", ctypes.c_uint32),
        ("has_constant_value", ctypes.c_uint8),
        ("metadata_precedence", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 2),
        ("constant_value", ctypes.c_int32),
        ("has_consumer", ctypes.c_uint8),
        ("source_pattern_id", ctypes.c_uint8),
        ("table_kind_id", ctypes.c_uint8),
        ("table_base_expression_id", ctypes.c_uint8),
        ("table_conflicted", ctypes.c_uint8),
        ("table_conflict_state", ctypes.c_uint8),
        ("platform_kind_id", ctypes.c_uint16),
        ("platform_field_id", ctypes.c_uint16),
        ("struct_id", ctypes.c_uint16),
        ("field_id", ctypes.c_uint16),
        ("pointer_struct_id", ctypes.c_uint16),
        ("consumer_section", ctypes.c_uint32),
        ("consumer_offset", ctypes.c_uint32),
        ("has_index_register", ctypes.c_uint8),
        ("index_register_kind", ctypes.c_uint8),
        ("index_register", ctypes.c_uint8),
        ("has_target_register", ctypes.c_uint8),
        ("target_register_kind", ctypes.c_uint8),
        ("target_register", ctypes.c_uint8),
        ("entry_count_proof_id", ctypes.c_uint8),
        ("table_stop_reason_id", ctypes.c_uint8),
        ("has_index_mask_domain", ctypes.c_uint8),
        ("has_index_compare_domain", ctypes.c_uint8),
        ("index_domain_branch_mnemonic_id", ctypes.c_uint8),
        ("index_domain_reserved", ctypes.c_uint8 * 1),
        ("index_mask_min", ctypes.c_uint32),
        ("index_mask_max", ctypes.c_uint32),
        ("index_compare_min", ctypes.c_uint32),
        ("index_compare_max", ctypes.c_uint32),
        ("has_index_loop_domain", ctypes.c_uint8),
        ("index_loop_mnemonic_id", ctypes.c_uint8),
        ("index_loop_reserved", ctypes.c_uint8 * 2),
        ("index_loop_min", ctypes.c_uint32),
        ("index_loop_max", ctypes.c_uint32),
        ("semantic_role_flags", ctypes.c_uint32),
        ("label_len", ctypes.c_uint16),
        ("struct_name_len", ctypes.c_uint16),
        ("field_name_len", ctypes.c_uint16),
        ("field_type_len", ctypes.c_uint16),
        ("c_type_len", ctypes.c_uint16),
        ("pointer_struct_len", ctypes.c_uint16),
        ("value_domain_len", ctypes.c_uint16),
        ("constant_name_len", ctypes.c_uint16),
        ("semantic_role_len", ctypes.c_uint16),
        ("source_pattern_len", ctypes.c_uint16),
        ("comment_len", ctypes.c_uint16),
        ("reserved_text_len", ctypes.c_uint16),
        ("label", ctypes.c_char * 65),
        ("struct_name", ctypes.c_char * 65),
        ("field_name", ctypes.c_char * 65),
        ("field_type", ctypes.c_char * 65),
        ("c_type", ctypes.c_char * 65),
        ("pointer_struct", ctypes.c_char * 65),
        ("value_domain", ctypes.c_char * 65),
        ("constant_name", ctypes.c_char * 65),
        ("semantic_role", ctypes.c_char * 65),
        ("source_pattern", ctypes.c_char * 65),
        ("comment", ctypes.c_char * 97),
        ("pointer_address_domain", ctypes.c_uint8),
        ("pointer_symbol_group", ctypes.c_char * 64),
        ("has_source_owner_span", ctypes.c_uint8),
        ("source_owner_start", ctypes.c_uint32),
        ("source_owner_size", ctypes.c_uint32),
    ]

class _M68kAnalysisNamedLabel(ctypes.Structure):
    _fields_ = [
        ("has_section_index", ctypes.c_uint8),
        ("domain", ctypes.c_uint8),
        ("is_source_declaration", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 1),
        ("section_index", ctypes.c_uint32),
        ("offset", ctypes.c_uint32),
        ("name", ctypes.c_char * 64),
    ]

class _M68kAnalysisEntryComment(ctypes.Structure):
    _fields_ = [
        ("has_section_index", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 3),
        ("section_index", ctypes.c_uint32),
        ("offset", ctypes.c_uint32),
        ("comment", ctypes.c_char * 192),
    ]

class _M68kAnalysisRuntimeRange(ctypes.Structure):
    _fields_ = [
        ("has_section_index", ctypes.c_uint8),
        ("provenance", ctypes.c_uint8),
        ("use_mask", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8),
        ("section_index", ctypes.c_uint32),
        ("offset", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("runtime_address", ctypes.c_uint32),
        ("name", ctypes.c_char * 64),
    ]

class _M68kAnalysisRuntimeEntryPoint(ctypes.Structure):
    _fields_ = [
        ("has_section_index", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 3),
        ("section_index", ctypes.c_uint32),
        ("runtime_address", ctypes.c_uint32),
    ]

class _M68kAnalysisRssetLayoutRegion(ctypes.Structure):
    _fields_ = [
        ("offset", ctypes.c_uint32),
        ("size", ctypes.c_uint16),
        ("flags", ctypes.c_uint8),
        ("storage_kind_id", ctypes.c_uint8),
        ("layout_name", ctypes.c_char * 32),
        ("base_symbol", ctypes.c_char * 64),
        ("sizeof_symbol", ctypes.c_char * 64),
        ("symbol", ctypes.c_char * 64),
        ("struct_name", ctypes.c_char * 64),
        ("pointer_struct", ctypes.c_char * 64),
        ("storage_kind", ctypes.c_char * 32),
        ("semantic_type", ctypes.c_char * 64),
    ]

class _M68kAnalysisAbsoluteStorageSlot(ctypes.Structure):
    _fields_ = [
        ("address", ctypes.c_uint32),
        ("size", ctypes.c_uint8),
        ("storage_kind_id", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 2),
        ("symbol", ctypes.c_char * 64),
        ("pointer_struct", ctypes.c_char * 64),
        ("storage_kind", ctypes.c_char * 32),
        ("semantic_type", ctypes.c_char * 64),
    ]

class _M68kAnalysisRssetUseSiteBinding(ctypes.Structure):
    _fields_ = [
        ("section_index", ctypes.c_uint32),
        ("offset", ctypes.c_uint32),
        ("displacement", ctypes.c_uint32),
        ("operand_index", ctypes.c_uint8),
        ("base_reg", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 2),
        ("layout_name", ctypes.c_char * 32),
        ("base_symbol", ctypes.c_char * 64),
        ("base_evidence_id", ctypes.c_char * 96),
        ("binding_id", ctypes.c_char * 256),
        ("owner_action_id", ctypes.c_char * 96),
    ]

class _M68kAnalysisManualRepresentation(ctypes.Structure):
    _fields_ = [
        ("has_section_index", ctypes.c_uint8),
        ("style_id", ctypes.c_uint8),
        ("has_operand_index", ctypes.c_uint8),
        ("operand_index", ctypes.c_uint8),
        ("symbol_id", ctypes.c_uint16),
        ("target_equate_index", ctypes.c_uint16),
        ("layout_struct_index", ctypes.c_uint16),
        ("layout_field_index", ctypes.c_uint16),
        ("has_source_symbol", ctypes.c_uint8),
        ("source_symbol_runtime_view", ctypes.c_uint8),
        ("source_symbol_section", ctypes.c_uint32),
        ("source_symbol_offset", ctypes.c_uint32),
        ("source_symbol_value", ctypes.c_uint32),
        ("section_index", ctypes.c_uint32),
        ("offset", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
    ]

class _M68kAnalysisTargetEquate(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * 64),
        ("value", ctypes.c_int32),
        ("value_style_id", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 3),
        ("value_expr", ctypes.c_char * 64),
        ("group", ctypes.c_char * 64),
        ("extent_bytes", ctypes.c_uint32),
        ("address_domain", ctypes.c_uint8),
    ]

class _M68kAnalysisManualRuntimeAddressRef(ctypes.Structure):
    _fields_ = [
        ("has_section_index", ctypes.c_uint8),
        ("has_target", ctypes.c_uint8),
        ("has_runtime_address", ctypes.c_uint8),
        ("confidence", ctypes.c_uint8),
        ("section_index", ctypes.c_uint32),
        ("offset", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("target_section_index", ctypes.c_uint32),
        ("target_offset", ctypes.c_uint32),
        ("runtime_address", ctypes.c_uint32),
        ("owner_element_offset", ctypes.c_uint32),
        ("owner_kind", ctypes.c_char * 32),
        ("owner_id", ctypes.c_char * 96),
        ("owner_layout_id", ctypes.c_char * 64),
        ("xref_generation_mode", ctypes.c_char * 32),
    ]

class _M68kAnalysisCustomStructField(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * 64),
        ("type_name", ctypes.c_char * 64),
        ("offset", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("struct_name", ctypes.c_char * 64),
        ("pointer_struct", ctypes.c_char * 64),
        ("named_base", ctypes.c_char * 64),
        ("value_kind", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 3),
        ("pointer_address_domain", ctypes.c_uint8),
        ("pointer_symbol_group", ctypes.c_char * 64),
    ]

class _M68kAnalysisCustomStruct(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * 64),
        ("size", ctypes.c_uint32),
        ("field_count", ctypes.c_uint16),
        ("reserved", ctypes.c_uint16),
        ("fields", _M68kAnalysisCustomStructField * 32),
        ("base_struct", ctypes.c_char * 64),
        ("base_offset", ctypes.c_uint32),
        ("has_tag_guard", ctypes.c_uint8),
        ("tag_value", ctypes.c_uint16),
        ("tag_offset", ctypes.c_uint32),
        ("tag_root_struct", ctypes.c_char * 64),
    ]

class _M68kAnalysisManualDataReference(ctypes.Structure):
    _fields_ = [
        ("section_index", ctypes.c_uint32),
        ("offset", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("raw_value", ctypes.c_uint32),
        ("value_scale", ctypes.c_uint32),
        ("is_range", ctypes.c_uint8),
        ("raw_value_signed", ctypes.c_uint8),
        ("base_section_index", ctypes.c_uint32),
        ("base_offset", ctypes.c_uint32),
        ("target_section_index", ctypes.c_uint32),
        ("target_offset", ctypes.c_uint32),
        ("owner_element_offset", ctypes.c_uint32),
        ("owner_kind", ctypes.c_char * 32),
        ("owner_id", ctypes.c_char * 96),
        ("owner_layout_id", ctypes.c_char * 64),
        ("xref_generation_mode", ctypes.c_char * 32),
    ]

class _M68kAnalysisAbstractRegion(ctypes.Structure):
    _fields_ = [
        ("section_index", ctypes.c_uint32),
        ("start_offset", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("region_id", ctypes.c_char * 96),
    ]

class _M68kAddressFrameSiteIR(ctypes.Structure):
    _fields_ = [("section_index", ctypes.c_uint32), ("source_offset", ctypes.c_uint32),
        ("operand_index", ctypes.c_uint8), ("expected_bytes", ctypes.c_uint8 * 8)]

class _M68kMemoryRegionIR(ctypes.Structure):
    _fields_ = [
        ("region_id", ctypes.c_char * 96),
        ("name", ctypes.c_char * 64),
        ("runtime_address", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("alignment", ctypes.c_uint32),
        ("dma_access", ctypes.c_uint8),
        ("persistent", ctypes.c_uint8),
        ("source_mapped", ctypes.c_uint8),
        ("region_kind", ctypes.c_uint8),
        ("parent_region_id", ctypes.c_char * 96),
        ("has_loader_seed", ctypes.c_uint8),
        ("loader_seed_source_offset", ctypes.c_uint32),
        ("loader_seed_region_offset", ctypes.c_uint32),
        ("loader_seed_size", ctypes.c_uint32),
        ("address_frame_register", ctypes.c_uint8), ("address_frame_site_count", ctypes.c_uint8),
        ("address_frame_contract_sha256", ctypes.c_char * 65),
        ("address_frame_input_sha256", ctypes.c_char * 65),
        ("address_frame_sites", _M68kAddressFrameSiteIR * 8),
    ]

class _M68kMemoryPlacementIR(ctypes.Structure):
    _fields_ = [("region_id", ctypes.c_char * 96), ("runtime_address", ctypes.c_uint32)]

class _M68kMemoryLayoutIR(ctypes.Structure):
    _fields_ = [("layout_id", ctypes.c_char * 96), ("chip_bytes", ctypes.c_uint32),
        ("placement_count", ctypes.c_uint16), ("placements", _M68kMemoryPlacementIR * 32),
        ("bootstrap_contract_id", ctypes.c_char * 96), ("bootstrap_forward_disjoint", ctypes.c_uint8), ("bootstrap_source_helper", ctypes.c_uint8)]

class _M68kBootstrapContractIR(ctypes.Structure):
    _fields_ = [("contract_id", ctypes.c_char * 96), ("image_region_id", ctypes.c_char * 96),
        ("input_sha256", ctypes.c_char * 65), *[(name, ctypes.c_uint32) for name in (
            "load_address", "file_size", "copied_source_end", "helper_source_start", "helper_source_end",
            "helper_runtime_address", "continuation_source_offset", "comparison_source_offset",
            "helper_destination_source_offset", "helper_jump_source_offset")], ("has_source_helper_sites", ctypes.c_uint8),
        ("exit_dispatch_call_source_offset",ctypes.c_uint32), ("exit_dispatch_target_source_offset",ctypes.c_uint32),
        ("has_exit_dispatch",ctypes.c_uint8)]

class _M68kAnalysisPolicy(ctypes.Structure):
    _fields_ = [
        ("max_cpu", ctypes.c_uint8),
        ("has_entry_offset", ctypes.c_uint8),
        ("disable_implicit_entry_points", ctypes.c_uint8),
        ("storage_capacity_status", ctypes.c_uint8),
        ("register_seed_count", ctypes.c_uint16),
        ("function_summary_count", ctypes.c_uint16),
        ("entry_point_count", ctypes.c_uint16),
        ("structured_data_item_count", ctypes.c_uint16),
        ("named_label_count", ctypes.c_uint16),
        ("entry_comment_count", ctypes.c_uint16),
        ("runtime_range_count", ctypes.c_uint16),
        ("runtime_entry_point_count", ctypes.c_uint16),
        ("rsset_layout_region_count", ctypes.c_uint16),
        ("absolute_storage_slot_count", ctypes.c_uint16),
        ("rsset_use_site_binding_count", ctypes.c_uint16),
        ("manual_representation_count", ctypes.c_uint16),
        ("target_equate_count", ctypes.c_uint16),
        ("manual_runtime_address_ref_count", ctypes.c_size_t),
        ("manual_runtime_address_ref_capacity", ctypes.c_size_t),
        ("manual_data_reference_count", ctypes.c_uint16),
        ("abstract_region_count", ctypes.c_uint16),
        ("memory_region_count", ctypes.c_uint16),
        ("custom_struct_count", ctypes.c_uint16),
        ("custom_struct_capacity", ctypes.c_uint16),
        ("structured_data_item_capacity", ctypes.c_uint16),
        ("named_label_capacity", ctypes.c_uint16),
        ("entry_comment_capacity", ctypes.c_uint16),
        ("manual_representation_capacity", ctypes.c_uint16),
        ("rsset_layout_region_capacity", ctypes.c_uint16),
        ("register_seed_capacity", ctypes.c_uint16),
        ("custom_struct_owner", ctypes.c_uint8),
        ("structured_data_items_owner", ctypes.c_uint8),
        ("named_labels_owner", ctypes.c_uint8),
        ("entry_comments_owner", ctypes.c_uint8),
        ("manual_representations_owner", ctypes.c_uint8),
        ("rsset_layout_regions_owner", ctypes.c_uint8),
        ("register_seeds_owner", ctypes.c_uint8),
        ("manual_runtime_address_refs_owner", ctypes.c_uint8),
        ("entry_offset", ctypes.c_uint32),
        ("source_context_kind", ctypes.c_char * 512),
        ("source_context_disk_id", ctypes.c_char * 512),
        ("source_context_disk_path", ctypes.c_char * 512),
        ("source_context_entry_path", ctypes.c_char * 512),
        ("source_context_parent_disk_id", ctypes.c_char * 512),
        ("register_seeds_inline", _M68kAnalysisRegisterSeed * 256),
        ("register_seeds", ctypes.POINTER(_M68kAnalysisRegisterSeed)),
        ("function_summaries", _M68kAnalysisFunctionSummary * 192),
        ("entry_points", _M68kAnalysisEntryPoint * 256),
        ("structured_data_items_inline", _M68kAnalysisStructuredDataItem * 4),
        ("structured_data_items", ctypes.POINTER(_M68kAnalysisStructuredDataItem)),
        ("named_labels_inline", _M68kAnalysisNamedLabel * 4),
        ("named_labels", ctypes.POINTER(_M68kAnalysisNamedLabel)),
        ("entry_comments_inline", _M68kAnalysisEntryComment * 4),
        ("entry_comments", ctypes.POINTER(_M68kAnalysisEntryComment)),
        ("runtime_ranges", _M68kAnalysisRuntimeRange * 64),
        ("runtime_entry_points", _M68kAnalysisRuntimeEntryPoint * 64),
        ("rsset_layout_regions_inline", _M68kAnalysisRssetLayoutRegion * 4),
        ("rsset_layout_regions", ctypes.POINTER(_M68kAnalysisRssetLayoutRegion)),
        ("absolute_storage_slots", _M68kAnalysisAbsoluteStorageSlot * 128),
        ("rsset_use_site_bindings", _M68kAnalysisRssetUseSiteBinding * 128),
        ("manual_representations_inline", _M68kAnalysisManualRepresentation * 4),
        ("manual_representations", ctypes.POINTER(_M68kAnalysisManualRepresentation)),
        ("target_equates", _M68kAnalysisTargetEquate * 1024),
        ("manual_runtime_address_refs_inline", _M68kAnalysisManualRuntimeAddressRef * 4),
        ("manual_runtime_address_refs", ctypes.POINTER(_M68kAnalysisManualRuntimeAddressRef)),
        ("manual_data_references", _M68kAnalysisManualDataReference * 512),
        ("abstract_regions", _M68kAnalysisAbstractRegion * 128),
        ("memory_regions", _M68kMemoryRegionIR * 32),
        ("memory_layout_count", ctypes.c_uint16),
        ("memory_layouts", _M68kMemoryLayoutIR * 8),
        ("bootstrap_contract_count", ctypes.c_uint16),
        ("bootstrap_contracts", _M68kBootstrapContractIR * 8),
        ("selected_memory_layout_id", ctypes.c_char * 96),
        ("custom_structs", ctypes.POINTER(_M68kAnalysisCustomStruct)),
    ]

from copy import deepcopy

from amiga_reversing.disasm.operand_bindings import memory_operand_binding_audit


def test_memory_binding_audit_separates_observations_bindings_and_symbolic_output():
    observation = {
        "offset": 0,
        "operand_index": 0,
        "source_name": "absolute_operand",
        "access_kind_name": "memory_read",
        "owner_kind_name": "runtime_range",
        "owner_offset": 8,
        "address": 0x808,
        "conflicted": False,
    }
    section = {
        "section_index": 0,
        "accepted_code_runs": [{"start_offset": 0, "end_offset": 6}],
        "address_observations": [observation],
        "runtime_address_refs": [],
        "rendered_symbol_accesses": [],
    }
    analysis = {"sections": [section]}
    original = deepcopy(analysis)
    assert memory_operand_binding_audit(analysis)["counts"] == {
        "missing_native_operand_binding": 1
    }
    assert analysis == original
    section["runtime_address_refs"] = [
        {
            "offset": 0,
            "operand_index": 0,
            "has_target": True,
            "target_section_index": 0,
            "target_offset": 8,
        }
    ]
    assert memory_operand_binding_audit(analysis)["counts"] == {
        "bound_without_symbolic_operand": 1
    }
    section["rendered_symbol_accesses"] = [
        {
            "offset": 0,
            "operand_index": 0,
            "access_kind": "operand",
            "target_section_index": 0,
            "target_offset": 8,
        }
    ]
    assert memory_operand_binding_audit(analysis)["counts"] == {"symbolic_operand": 1}
    section["rendered_symbol_accesses"][0]["target_offset"] = 10
    assert memory_operand_binding_audit(analysis)["counts"] == {
        "conflicting_rendered_binding": 1
    }
    section["rendered_symbol_accesses"][0]["target_offset"] = 8
    saved = section["runtime_address_refs"]
    section["runtime_address_refs"] = []
    assert memory_operand_binding_audit(analysis)["counts"] == {"symbolic_operand": 1}
    section["runtime_address_refs"] = saved
    section["runtime_address_refs"][0]["target_offset"] = 10
    assert memory_operand_binding_audit(analysis)["counts"] == {
        "conflicting_native_bindings": 1
    }
    # Width alone cannot identify an immediate: unknown-width memory stays audited.
    observation["access_width"] = 0
    assert memory_operand_binding_audit(analysis)["counts"] == {
        "conflicting_native_bindings": 1
    }
    observation["conflicted"] = True
    assert memory_operand_binding_audit(analysis)["counts"] == {
        "conflicting_native_observation": 1
    }


def test_memory_binding_audit_excludes_numeric_immediates_external_and_unaccepted_sites():
    section = {
        "section_index": 0,
        "accepted_code_runs": [{"start_offset": 0, "end_offset": 6}],
        "runtime_address_refs": [],
        "rendered_symbol_accesses": [],
        "address_observations": [
            {
                "offset": 0,
                "operand_index": 0,
                "source_name": "absolute_operand",
                "access_kind_name": "memory_read",
                "access_width": 0,
                "operand_is_immediate": True,
                "owner_kind_name": "runtime_range",
            },
            {
                "offset": 0,
                "operand_index": 0,
                "source_name": "absolute_operand",
                "access_kind_name": "immediate",
                "owner_kind_name": "runtime_range",
            },
            {
                "offset": 0,
                "operand_index": 0,
                "source_name": "absolute_operand",
                "access_kind_name": "memory_read",
                "owner_kind_name": "amiga_custom",
            },
            {
                "offset": 8,
                "operand_index": 0,
                "source_name": "absolute_operand",
                "access_kind_name": "memory_read",
                "owner_kind_name": "runtime_range",
            },
        ],
    }
    assert memory_operand_binding_audit({"sections": [section]})["references"] == []


def test_inventory_check_bindings_fails_missing_and_conflicting_memory_refs(
    tmp_path, monkeypatch
):
    import json
    import sys

    import pytest

    from amiga_reversing.tools import source_inventory as cli

    section = {
        "section_index": 0,
        "accepted_code_runs": [{"start_offset": 0, "end_offset": 6}],
        "range_ownerships": [],
        "blocks": [],
        "edges": [],
        "code_start_refs": [],
        "orphan_code_signals": [],
        "rendered_symbol_accesses": [],
        "symbol_origins": [],
        "runtime_address_refs": [],
        "address_observations": [
            {
                "offset": 0,
                "operand_index": 0,
                "source_name": "absolute_operand",
                "access_kind_name": "memory_read",
                "access_width": 4,
                "owner_kind_name": "runtime_range",
                "owner_offset": 8,
                "address": 0x808,
                "conflicted": False,
            }
        ],
    }
    path = tmp_path / "analysis.json"
    output = tmp_path / "audit.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "source_inventory",
            "--target",
            "amiga_raw_foft",
            "--analysis-json",
            str(path),
            "--output",
            str(output),
            "--check-bindings",
        ],
    )
    for conflict in (False, True):
        section["rendered_symbol_accesses"] = (
            []
            if not conflict
            else [
                {
                    "access_kind": "operand",
                    "offset": 0,
                    "operand_index": 0,
                    "target_section_index": 0,
                    "target_offset": 10,
                    "symbol_name": "wrong",
                }
            ]
        )
        path.write_text(json.dumps({"sections": [section]}))
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 1
        expected = (
            "conflicting_rendered_binding"
            if conflict
            else "missing_native_operand_binding"
        )
        assert json.loads(output.read_text())["memory_operand_bindings"]["counts"] == {
            expected: 1
        }
    section["rendered_symbol_accesses"][0]["target_offset"] = 8
    path.write_text(json.dumps({"sections": [section]}))
    cli.main()

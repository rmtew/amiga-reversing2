"""Saved annotations may retain their append-only history; unsaved facts refuse."""
import json
from pathlib import Path
import pytest
from amiga_reversing.disasm.binary_source import resolve_target_binary_source
from amiga_reversing.disasm.target_metadata import TargetMetadata,write_target_metadata
from amiga_reversing.disasm.effective_metadata import effective_target_metadata
from amiga_reversing.disasm.manual_actions import ManualActionKind,append_manual_action
from amiga_reversing.disasm.manual_action_catalog import target_catalog_manual_payload
from tools.regenerate_starglider2_retail_source import require_saved_annotations


def test_snapshot_gate_retains_history_and_refuses_new_unsaved_facts(tmp_path):
    (tmp_path/'input.bin').write_bytes(bytes.fromhex('4e75'))
    (tmp_path/'source_binary.json').write_text(json.dumps(dict(kind='raw_binary',address_model='local_offset',
        path=str(tmp_path/'input.bin'),load_address=0,entrypoint=0,code_start_offset=0)))
    write_target_metadata(tmp_path,TargetMetadata(target_type='program',entry_register_seeds=()))
    source=resolve_target_binary_source(tmp_path)
    def add(name):
        kind,payload=target_catalog_manual_payload('target.custom_struct.add',dict(name=name,size=8,fields=[]))
        append_manual_action(tmp_path,kind=ManualActionKind(kind),payload=payload,binary_source=source)
    require_saved_annotations(tmp_path)
    add('First')
    with pytest.raises(ValueError,match='save checked annotations'):require_saved_annotations(tmp_path)
    history=(tmp_path/'manual_actions.jsonl').read_bytes()
    write_target_metadata(tmp_path,effective_target_metadata(tmp_path))
    require_saved_annotations(tmp_path)
    assert (tmp_path/'manual_actions.jsonl').read_bytes()==history
    add('Unsaved')
    with pytest.raises(ValueError,match='save checked annotations'):require_saved_annotations(tmp_path)

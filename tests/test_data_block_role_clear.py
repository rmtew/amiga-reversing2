import json

import pytest

from amiga_reversing.disasm import c_backend
from amiga_reversing.disasm.effective_metadata import (
    effective_metadata_file,
    effective_metadata_text,
)
from amiga_reversing.disasm.manual_action_catalog import target_catalog_manual_payload
from amiga_reversing.disasm.manual_actions import (
    ManualActionKind,
    append_manual_actions,
)
from tests.test_base_displacement_integration import _round_trip
from tests.test_base_displacement_ranges import _fixture


@pytest.mark.c_backend
@pytest.mark.parametrize("text", ["", "  "])
def test_clear_optional_layout_role_preserves_elements_references_and_bytes(tmp_path, text):
    source, original, ref, _ = _fixture(tmp_path, [0, 1, 2])
    def action(command, parameters):
        kind, payload = target_catalog_manual_payload(command, parameters=parameters)
        return ManualActionKind(kind), payload
    describe = "target.data_block.layout.describe"
    append_manual_actions(tmp_path, actions=[action(describe, {"layout_id": "offsets", "role": "provisional_caption"}), ref], binary_source=source)
    before = json.loads(effective_metadata_text(tmp_path))
    clear = action(describe, {"layout_id": "offsets", "role": text})
    assert clear[1]["data_block_layout"]["role"] is None
    append_manual_actions(tmp_path, actions=[clear], binary_source=source)
    after = json.loads(effective_metadata_text(tmp_path))
    expected = json.loads(json.dumps(before))
    expected["data_block_layouts"][0]["role"] = None
    for entity in expected["seeded_entities"]:
        if entity["comment"] == "provisional_caption":
            entity["comment"] = None
    assert after == expected
    # Replay keeps the original placeholder and the explicit clearing action.
    assert b'provisional_caption' in (tmp_path / "manual_actions.jsonl").read_bytes()
    with effective_metadata_file(tmp_path) as path:
        rendered = c_backend.render_project_source_with_c_backend(source, metadata_path=path)
    assert "provisional_caption" not in rendered
    _round_trip(tmp_path, rendered, original)


@pytest.mark.parametrize(("command", "parameters"), [
    ("target.data_block.layout.rename", {"layout_id": "x", "name": ""}),
    ("target.data_block.layout.describe", {"layout_id": "x", "role": None}),
])
def test_only_optional_text_role_can_be_cleared(command, parameters):
    with pytest.raises(ValueError, match="edit data-block layout"):
        target_catalog_manual_payload(command, parameters=parameters)

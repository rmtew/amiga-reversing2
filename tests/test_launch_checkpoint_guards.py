import json
from pathlib import Path
import pytest
from amiga_reversing.disasm import launch_fact_checkpoints as checkpoints
from amiga_reversing.disasm.media_fact_templates import digest

def setup(root):
    bundle=root/"bundle";bundle.mkdir()
    facts=root/"facts";owner=facts/"targets/amiga_raw_foft";(owner/"analysis").mkdir(parents=True)
    member=root/"member.bin";member.write_bytes(bytes(range(8)))
    expected=digest(b"{}")
    state={key:{"path":"analysis/"+key,"sha256":None} for key in ["target_metadata.json","manual_actions.jsonl","decision_journal.jsonl","target_seeded_metadata.json","target_corrections.json"]}
    contract={"id":"amiga_raw_foft","members":[{"id":"main","context":{"address_model":"runtime_absolute","load_address":4096,"entrypoint":4096,"code_start_offset":0},"analysis":{"metadata":{"path":"analysis/main.metadata.json","sha256":expected},"state":state}}]}
    raw=json.dumps(contract).encode();(owner/"manifest.json").write_bytes(raw)
    manifest={"files":[{"path":"targets/amiga_raw_foft/manifest.json","restored_sha256":digest(raw)}],"members":{"fixture":{"size":8,"sha256":digest(member.read_bytes())}},"derived_files":[{"member":"main","path":"targets/amiga_raw_foft/analysis/main.metadata.json","sha256":expected,"source_member":"fixture"}]}
    def save():
        (bundle/"bundle-manifest.json").write_text(json.dumps(manifest))
        return digest((bundle/"bundle-manifest.json").read_bytes())
    return bundle,facts,member,manifest,contract,save

def test_synthetic_checkpoint_roundtrip(tmp_path,monkeypatch):
    bundle,facts,member,manifest,contract,save=setup(tmp_path)
    monkeypatch.setattr(checkpoints,"effective_metadata_text",lambda *a,**k:"{}")
    result=checkpoints.derive(bundle,facts,{"fixture":member},save())
    assert result[0]["derived_from_base_and_ordered_journal"]
    assert (facts/manifest["derived_files"][0]["path"]).read_bytes()==b"{}"

@pytest.mark.parametrize("mutation",["manifest","contract","path","member","digest","duplicate"])
def test_checkpoint_guards_never_write_output(tmp_path,monkeypatch,mutation):
    bundle,facts,member,manifest,contract,save=setup(tmp_path)
    expected=save()
    monkeypatch.setattr(checkpoints,"effective_metadata_text",lambda *a,**k:"{}")
    if mutation=="manifest":(bundle/"bundle-manifest.json").write_text("{}")
    elif mutation=="contract":(facts/"targets/amiga_raw_foft/manifest.json").write_text("{}")
    elif mutation=="path":manifest["derived_files"][0]["path"]="../escape";expected=save()
    elif mutation=="member":member.write_bytes(b"wrong")
    elif mutation=="duplicate":manifest["derived_files"]*=2;expected=save()
    elif mutation=="digest":
        contract["members"][0]["analysis"]["metadata"]["sha256"]="0"*64
        raw=json.dumps(contract).encode()
        (facts/"targets/amiga_raw_foft/manifest.json").write_bytes(raw)
        manifest["files"][0]["restored_sha256"]=digest(raw)
        manifest["derived_files"][0]["sha256"]="0"*64
        expected=save()
    with pytest.raises(ValueError):
        checkpoints.derive(bundle,facts,{"fixture":member},expected)
    assert not (facts/"targets/amiga_raw_foft/analysis/main.metadata.json").exists()

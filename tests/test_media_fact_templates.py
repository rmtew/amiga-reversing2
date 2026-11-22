from pathlib import Path
import json
import pytest
from amiga_reversing.disasm.media_fact_templates import digest, materialize

def fixture(root):
    bundle=root/"bundle";bundle.mkdir()
    member=root/"member.bin";member.write_bytes(bytes(range(8)))
    ref={"member":"fixture","offset":1,"length":2,"signed":False,"slice_sha256":digest(member.read_bytes()[1:3])}
    original=b'{"value":258,"label":"authored"}\n'
    token=b'{"$media_integer":'+json.dumps(ref,sort_keys=True,separators=(",",":")).encode()+b'}'
    data=original.replace(b"258",token)
    (bundle/"fact.json").write_bytes(data)
    manifest={"schema":"private-proposed-fact-template-v1","members":{"fixture":{"size":8,"sha256":digest(member.read_bytes())}},"files":[{"path":"fact.json","template_sha256":digest(data),"restored_sha256":digest(original),"references":1}]}
    (bundle/"bundle-manifest.json").write_text(json.dumps(manifest))
    return bundle,member,manifest,original

def test_exact_fact_roundtrip(tmp_path):
    bundle,member,manifest,original=fixture(tmp_path)
    materialize(bundle,tmp_path/"out",{"fixture":member},digest((bundle/"bundle-manifest.json").read_bytes()))
    assert (tmp_path/"out/fact.json").read_bytes()==original

@pytest.mark.parametrize("mutation",["member","missing_member","template","manifest","bounds","slice","output","path"])
def test_invalid_input_never_installs_partial_facts(tmp_path,mutation):
    bundle,member,manifest,original=fixture(tmp_path)
    expected=digest((bundle/"bundle-manifest.json").read_bytes())
    if mutation=="member":member.write_bytes(b"wrong")
    elif mutation=="missing_member":member.unlink()
    elif mutation=="template":(bundle/"fact.json").write_text("changed")
    elif mutation=="manifest":(bundle/"bundle-manifest.json").write_text("{}")
    else:
        if mutation in {"bounds","slice"}:
            data=(bundle/"fact.json").read_bytes()
            marker=json.loads(data.decode().split('"$media_integer":',1)[1].split('},"label"',1)[0])
            if mutation=="bounds":marker["offset"]=999
            else:marker["slice_sha256"]="0"*64
            token=b'{"$media_integer":'+json.dumps(marker,sort_keys=True,separators=(",",":")).encode()+b'}'
            data=original.replace(b"258",token)
            (bundle/"fact.json").write_bytes(data)
            manifest["files"][0]["template_sha256"]=digest(data)
        elif mutation=="output":manifest["files"][0]["restored_sha256"]="0"*64
        elif mutation=="path":manifest["files"][0]["path"]="../escape"
        (bundle/"bundle-manifest.json").write_text(json.dumps(manifest))
        expected=digest((bundle/"bundle-manifest.json").read_bytes())
    with pytest.raises((ValueError,FileNotFoundError)):
        materialize(bundle,tmp_path/"out",{"fixture":member},expected)
    assert not (tmp_path/"out").exists()

@pytest.mark.parametrize('reference,expected',[
    ({'reference_kind':'base_displacement_range','width':32,'entry_width':4},4),
    ({'reference_kind':'base_displacement_range','width':8,'entry_width':2},2),
    ({'reference_kind':'base_displacement_range','width':8},2),
    ({'reference_kind':'base_displacement','width':2},2),
    ({'reference_kind':'absolute','width':4},4),
    ({'size':4},4),
])
def test_encoded_cell_width_uses_the_recorded_schema(reference,expected):
    from amiga_reversing.disasm.media_fact_templates import encoded_cell_width
    assert encoded_cell_width(reference)==expected

@pytest.mark.parametrize('reference',[{'width':3},{'size':True},{'reference_kind':'base_displacement_range','entry_width':0}])
def test_invalid_encoded_width_is_refused(reference):
    from amiga_reversing.disasm.media_fact_templates import encoded_cell_width
    with pytest.raises(ValueError):encoded_cell_width(reference)

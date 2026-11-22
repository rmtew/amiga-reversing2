"""Recreate FOFT checkpoints from base metadata and ordered journals."""
from pathlib import Path
import hashlib
import json
from amiga_reversing.disasm.media_fact_templates import digest, safe_path
from amiga_reversing.disasm.analysis_state_paths import bind_state_paths
from amiga_reversing.disasm.binary_source import BinarySourceKind, RawAddressModel, RawBinarySource
from amiga_reversing.disasm.effective_metadata import effective_metadata_text

def derive(bundle: Path, facts: Path, members: dict[str, Path], expected_manifest: str) -> list[dict]:
    raw = (bundle / "bundle-manifest.json").read_bytes()
    if digest(raw) != expected_manifest:
        raise ValueError("bundle manifest identity mismatch")
    manifest = json.loads(raw)
    owner = facts / 'targets/amiga_raw_foft'
    contract_data = (owner / "manifest.json").read_bytes()
    contract_record = next(r for r in manifest["files"] if r["path"] == "targets/amiga_raw_foft/manifest.json")
    if digest(contract_data) != contract_record["restored_sha256"]:
        raise ValueError("fact contract identity mismatch")
    contract = json.loads(contract_data)
    reports, pending, seen = [], [], set()
    for recipe in manifest['derived_files']:
        name = recipe['member']
        member = next(x for x in contract['members'] if x['id'] == name)
        context = member['context']
        relative = str(safe_path(recipe["path"]))
        if relative in seen:
            raise ValueError("duplicate derived checkpoint")
        seen.add(relative)
        if facts / relative != owner / str(safe_path(member["analysis"]["metadata"]["path"])) or recipe["sha256"] != member["analysis"]["metadata"]["sha256"]:
            raise ValueError("derived checkpoint binding mismatch")
        data = members[recipe["source_member"]].read_bytes()
        expected = manifest["members"][recipe["source_member"]]
        if len(data) != expected["size"] or digest(data) != expected["sha256"]:
            raise ValueError("checkpoint member identity mismatch")
        for reference in member["analysis"]["state"].values():
            path = owner / str(safe_path(reference["path"]))
            if reference["sha256"] is not None and digest(path.read_bytes()) != reference["sha256"]:
                raise ValueError("checkpoint input fact identity mismatch")
        source = RawBinarySource(kind=BinarySourceKind.RAW_BINARY, path=members[recipe['source_member']],
            address_model=RawAddressModel(context['address_model']), load_address=context['load_address'],
            entrypoint=context['entrypoint'], code_start_offset=context['code_start_offset'],
            display_path=contract['id'] + ':' + name, analysis_cache_path=facts / '.private-analysis-cache' / name)
        paths = {key: owner / value['path'] for key, value in member['analysis']['state'].items()}
        with bind_state_paths(owner, paths):
            text = effective_metadata_text(owner, binary_source=source)
        canonical = json.dumps(json.loads(text), sort_keys=True, indent=2)
        variants = [text.encode(), (text.rstrip('\n') + '\n').encode(), canonical.encode(), (canonical + '\n').encode()]
        data = next((v for v in variants if hashlib.sha256(v).hexdigest() == recipe['sha256']), None)
        if data is None:
            raise ValueError('derived checkpoint identity mismatch: ' + name)
        pending.append((facts / relative, data))
        reports.append({'member': name, 'size': len(data), 'sha256': recipe['sha256'], 'derived_from_base_and_ordered_journal': True})
    if any(path.exists() for path, _ in pending):
        raise FileExistsError('derived checkpoint already exists')
    for path, data in pending:
        path.write_bytes(data)
    return reports

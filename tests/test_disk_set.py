"""One owner, two independently classified media, colliding addresses and a view."""

import copy
import json
from pathlib import Path

import pytest

from amiga_reversing.disasm.disk_codecs import digest
from amiga_reversing.disasm.disk_set import (
    DiskSet,
    compose_source_package,
    create_disk_set,
    execute_owner,
)
from amiga_reversing.disasm.projects import initialize_project_metadata, list_projects
from amiga_reversing.disasm.source_package import build_source_package
from amiga_reversing.disasm.source_package_publish import publish_source_package
from amiga_reversing.disasm.target_metadata import (
    TargetMetadata,
    target_metadata_json_payload,
)
from tests.test_import_adf import _ffs_adf_with_single_file

ROOT = Path(__file__).resolve().parents[1]


def fixture(tmp_path):
    project = tmp_path / "project"
    target = project / "targets/amiga_disk_fixture"
    target.mkdir(parents=True)
    initialize_project_metadata(target, origin={"kind": "synthetic_disk_set"})
    texts = {
        "main": " SECTION code,code\n ORG $1000\n moveq #7,d0\n rts\n",
        "overlay": " SECTION code,code\n ORG $1000\n moveq #9,d0\n rts\n",
        "palette": " SECTION data,data\n ORG $2000\n dc.b $01,$02,$03,$04\n",
    }
    payloads = {
        "main": bytes.fromhex("70074e75"),
        "overlay": bytes.fromhex("70094e75"),
        "return_view": bytes.fromhex("4e75"),
        "palette": bytes.fromhex("01020304"),
    }
    (target / "analysis").mkdir()
    members = []
    for name, data in payloads.items():
        analysis = None
        if name not in {"return_view", "palette"}:
            metadata = json.dumps(
                target_metadata_json_payload(
                    TargetMetadata(target_type="raw_binary", entry_register_seeds=())
                )
            ).encode()
            (target / f"analysis/{name}.json").write_bytes(metadata)
            analysis = {
                "metadata": {
                    "path": f"analysis/{name}.json",
                    "sha256": digest(metadata),
                },
                "state_files": [],
            }
        start = (
            0x1002 if name == "return_view" else 0x2000 if name == "palette" else 0x1000
        )
        members.append(
            {
                "id": name,
                "kind": "data" if name == "palette" else "code",
                "size": len(data),
                "sha256": digest(data),
                "context": {
                    "address_model": "runtime_absolute",
                    "load_address": start,
                    "entrypoint": None if name == "palette" else start,
                    "code_start_offset": None if name == "palette" else 0,
                    "phase": "decoded_resource",
                },
                "source": None if name == "return_view" else name + ".s",
                "analysis": analysis,
            }
        )
    dos = _ffs_adf_with_single_file(payloads["main"])
    ndos = bytearray(len(dos))
    ndos[:4] = b"NDOS"
    ndos[256:260] = payloads["overlay"]
    ndos[512:516] = payloads["palette"]
    ndos[-7:] = b"UNKNOWN"
    images = {"dos": dos, "custom": bytes(ndos)}
    media, paths = [], {}
    for name, bindings in [
        ("dos", [("main", 910 * 512)]),
        ("custom", [("overlay", 256), ("palette", 512)]),
    ]:
        image = images[name]
        path = tmp_path / (name + ".adf")
        path.write_bytes(image)
        paths[name] = str(path)
        actions = [
            {
                "file": "RUN" if name == "dos" else member + ".bin",
                "size": len(payloads[member]),
                "sha256": digest(payloads[member]),
                "spans": [{"offset": at, "length": len(payloads[member])}],
            }
            for member, at in bindings
        ]
        recipe = json.dumps(
            {"kind": "byte_ranges", "image_sha256": digest(image), "actions": actions}
        ).encode()
        (target / (name + "-recipe.json")).write_bytes(recipe)
        media.append(
            {
                "id": name,
                "size": len(image),
                "sha256": digest(image),
                "codec": "byte_ranges",
                "recipe": {"path": name + "-recipe.json", "sha256": digest(recipe)},
                "outputs": {
                    "RUN" if name == "dos" else member + ".bin": member
                    for member, _ in bindings
                },
            }
        )
    manifest = {
        "schema_version": 1,
        "kind": "disk_set",
        "id": target.name,
        "name": "Synthetic DOS/NDOS set",
        "project_id": "synthetic",
        "build_id": "amiga_fixture",
        "platform": "amiga",
        "package_sha256": "0" * 64,
        "media": media,
        "members": members,
        "relationships": [
            {
                "kind": "embedded",
                "member": "return_view",
                "owner": "main",
                "offset": 2,
                "size": 2,
                "evidence": "Exact file tail and independently verified source assembly",
            }
        ],
    }
    packages = {
        name: build_source_package(
            {
                "filename": "source.s",
                "source_text": text,
                "target": name,
                "assembler_profile": "vasm",
                "metadata_hash": "0" * 64,
                "target_identity_sha256": digest(payloads[name]),
            },
            [],
            256,
        )
        for name, text in texts.items()
    }
    package = compose_source_package(manifest, packages)
    manifest["package_sha256"] = package["sha256"]
    publish_source_package(package, target)
    (target / "manifest.json").write_text(json.dumps(manifest))
    return project, target, paths, manifest


def test_dos_ndos_set_uses_one_project_and_rebuilds_all_images_from_sources(tmp_path):
    from amiga_reversing.amiga_disk.adf import analyze_adf

    project, target, paths, _ = fixture(tmp_path)
    # This checks actual filesystem classification rather than naming a flat
    # arbitrary byte array "DOS". Neither fixture is a boot qualification.
    dos = analyze_adf(paths["dos"], kb_root=ROOT)
    assert dos.filesystem is not None
    assert any(f.full_path == "RUN" and f.size == 4 for f in dos.files)
    assert analyze_adf(paths["custom"], kb_root=ROOT).filesystem is None
    records = list_projects(project)
    assert (
        len(records) == 1
        and records[0].id == target.name
        and records[0].target_count == 4
    )
    owner = DiskSet.load(target, project_root=project)
    result = owner.build(
        tmp_path / "rebuilt", paths, vasm=ROOT / "tools/vasmm68k_mot.exe"
    )
    assert set(result["members"]) == {"main", "overlay", "palette", "return_view"}
    assert (
        result["members"]["main"]["native_exact"]
        and result["members"]["overlay"]["vasm_exact"]
    )
    assert result["members"]["return_view"]["kind"] == "assembled_owner_slice"
    assert not result["members"]["return_view"]["separate_analysis_owner"]
    for name, path in paths.items():
        assert (tmp_path / "rebuilt" / (name + ".img")).read_bytes() == Path(
            path
        ).read_bytes()
    assert (tmp_path / "rebuilt/custom.img").read_bytes().endswith(b"UNKNOWN")
    assert result["runtime"] == "not tested"
    assert len(result["coverage"]["direct_placements"]) == 3
    view = result["coverage"]["embedded_placements"][0]
    assert view["member"] == "return_view" and view["within_file"] == "RUN"
    assert view["spans"] == [
        {"source_offset": 0, "length": 2, "storage": {"offset": 910 * 512 + 2}}
    ]


def test_native_queries_keep_colliding_members_and_shared_views_scoped(tmp_path):
    project, target, paths, _ = fixture(tmp_path)
    state = execute_owner(target, {"operation": "state"}, project_root=project)
    assert state["analysis_owner_count"] == 2 and not state["member_mutation_supported"]
    pages = {}
    for member in ("main", "overlay", "return_view"):
        pages[member] = execute_owner(
            target,
            {
                "operation": "query",
                "kind": "instructions",
                "member_id": member,
                "media_paths": paths,
                "limit": 1,
            },
            project_root=project,
        )
    assert "#7" in pages["main"]["items"][0]["text"]
    assert "#9" in pages["overlay"]["items"][0]["text"]
    assert pages["return_view"]["scope"]["analysis_member_id"] == "main"
    assert pages["return_view"]["scope"]["source_offset_bias"] == 2
    assert pages["return_view"]["items"][0]["source_offset"] == 2
    with pytest.raises(ValueError, match="cursor"):
        execute_owner(
            target,
            {
                "operation": "query",
                "kind": "instructions",
                "member_id": "overlay",
                "media_paths": paths,
                "limit": 1,
                "cursor": pages["main"]["next_cursor"],
            },
            project_root=project,
        )
    with pytest.raises(ValueError, match="explicit member"):
        execute_owner(
            target, {"operation": "query", "kind": "instructions"}, project_root=project
        )
    with pytest.raises(ValueError, match="sealed-import"):
        execute_owner(
            target,
            {"operation": "interpret", "member_id": "main", "expected_revision": state["revision"]},
            project_root=project,
        )
    with pytest.raises(ValueError, match="data-only"):
        execute_owner(
            target,
            {"operation": "query", "kind": "instructions", "member_id": "palette"},
            project_root=project,
        )


def packages_for(target, manifest):
    return {
        m["id"]: build_source_package(
            {
                "filename": "source.s",
                "source_text": (target / m["source"]).read_text(),
                "target": m["id"],
                "assembler_profile": "vasm",
                "metadata_hash": "0" * 64,
                "target_identity_sha256": m["sha256"],
            },
            [],
            256,
        )
        for m in manifest["members"]
        if m["source"] is not None
    }


def test_zero_bias_shared_view_does_not_leak_unscoped_owner_queries(tmp_path):
    project, target, paths, manifest = fixture(tmp_path)
    member = manifest["members"][2]
    member["context"].update(load_address=0x1000, entrypoint=0x1000)
    member["sha256"] = digest(bytes.fromhex("7007"))
    manifest["relationships"][0]["offset"] = 0
    package = compose_source_package(manifest, packages_for(target, manifest))
    publish_source_package(package, target)
    manifest["package_sha256"] = package["sha256"]
    (target / "manifest.json").write_text(json.dumps(manifest))
    owner = DiskSet.load(target, project_root=project)
    with pytest.raises(ValueError, match="canonical analysis owner"):
        owner.query("return_view", {"kind": "symbols"}, paths)
    page, scope = owner.query(
        "return_view", {"kind": "instructions", "limit": 2}, paths
    )
    assert scope["analysis_member_id"] == "main" and scope["source_offset_bias"] == 0
    assert len(page["items"]) == 1 and "#7" in page["items"][0]["text"]


def test_generic_import_and_canonical_service_do_not_register_child_targets(
    tmp_path, monkeypatch
):
    from amiga_reversing.disasm import projects, restoration, server

    _, source, paths, manifest = fixture(tmp_path)
    project = tmp_path / "new-project"
    root = project / "targets" / manifest["id"]
    refs = [m["recipe"] for m in manifest["media"]]
    refs += [m["analysis"]["metadata"] for m in manifest["members"] if m["analysis"]]
    files = {r["path"]: (source / r["path"]).read_bytes() for r in refs}
    owner = create_disk_set(
        root,
        manifest,
        packages_for(source, manifest),
        files,
        paths,
        project_root=project,
    )
    assert not (root / "targets").exists()
    monkeypatch.setattr(server, "PROJECT_ROOT", project)
    monkeypatch.setattr(
        server,
        "get_project",
        lambda name: projects.get_project(name, project_root=project),
    )
    state = restoration.execute(root.name, {"operation": "state"})
    assert state["revision"] == owner.revision and len(state["members"]) == 4
    assert len(list_projects(project)) == 1
    assert server._project_payload(root.name)["disk_manifest"]["kind"] == "disk_set"
    browser = server._project_disk_browser_payload(root.name)
    assert len(browser["entries"]) == 4 and not any(
        "target_id" in r or r.get("importable") for r in browser["entries"]
    )
    selected = server._project_disk_browser_payload(root.name, "return_view")
    detail = json.loads(selected["selected_entry"]["content"]["text"])
    discovered = next(m for m in state["members"] if m["id"] == "return_view")
    assert detail["member_id"] == "return_view"
    assert detail["analysis_owner"] == discovered["analysis_owner"] == "main"
    assert detail["source_offset_bias"] == discovered["source_offset_bias"] == 2
    assert detail["restoration_operations"] == discovered["restoration_operations"] == []
    exported = server._source_export_payload(root.name, {})
    assert (
        exported["scope"] == "whole_disk_set_source_package"
        and exported["archive_base64"]
    )
    import base64
    import io
    import zipfile

    with zipfile.ZipFile(
        io.BytesIO(base64.b64decode(exported["archive_base64"]))
    ) as archive:
        assert {"main.s", "overlay.s", "palette.s"} <= set(archive.namelist())
        assert not any(p.endswith((".adf", ".img", ".bin")) for p in archive.namelist())
    with pytest.raises(ValueError, match="persisted vasm"):
        server._source_export_payload(root.name, {"layout_id": ["unreviewed"]})
    # Removing an owner must never remove either private original image.
    projects.delete_project(root.name, project_root=project)
    assert not root.exists() and all(Path(p).is_file() for p in paths.values())


def test_failed_import_leaves_no_owner_or_registered_children(tmp_path):
    _, source, paths, manifest = fixture(tmp_path)
    project = tmp_path / "new-project"
    root = project / "targets" / manifest["id"]
    refs = [m["recipe"] for m in manifest["media"]]
    refs += [m["analysis"]["metadata"] for m in manifest["members"] if m["analysis"]]
    files = {r["path"]: (source / r["path"]).read_bytes() for r in refs}
    wrong = {**paths, "custom": paths["dos"]}
    with pytest.raises(ValueError, match="media identity"):
        create_disk_set(
            root,
            manifest,
            packages_for(source, manifest),
            files,
            wrong,
            project_root=project,
        )
    assert not root.exists() and not list(root.parent.iterdir())
    assert list_projects(project) == []


def test_member_package_collision_requires_declared_sharing(tmp_path):
    _, target, _, manifest = fixture(tmp_path)
    packages = packages_for(target, manifest)
    manifest["members"][1]["source"] = manifest["members"][0]["source"]
    with pytest.raises(ValueError, match="ownership collision"):
        compose_source_package(manifest, packages)


def test_equal_file_path_and_payload_on_two_disks_keep_distinct_member_ids(tmp_path):
    project, target, paths, manifest = fixture(tmp_path)
    packages = packages_for(target, manifest)
    clone = copy.deepcopy(manifest["members"][0])
    clone.update(id="disk-two-run", source="disk-two-run.s")
    manifest["members"].append(clone)
    packages[clone["id"]] = copy.deepcopy(packages["main"])
    disk = bytearray(Path(paths["dos"]).read_bytes())
    disk[-8:] = b"DISK-TWO"
    path = tmp_path / "disk-two.adf"
    path.write_bytes(disk)
    paths["dos-two"] = str(path)
    media = copy.deepcopy(manifest["media"][0])
    media.update(id="dos-two", sha256=digest(disk), outputs={"RUN": "disk-two-run"})
    recipe = json.loads((target / media["recipe"]["path"]).read_bytes())
    recipe["image_sha256"] = digest(disk)
    data = json.dumps(recipe).encode()
    (target / "dos-two-recipe.json").write_bytes(data)
    media["recipe"] = {"path": "dos-two-recipe.json", "sha256": digest(data)}
    manifest["media"].append(media)
    package = compose_source_package(manifest, packages)
    publish_source_package(package, target)
    manifest["package_sha256"] = package["sha256"]
    (target / "manifest.json").write_text(json.dumps(manifest))
    owner = DiskSet.load(target, project_root=project)
    values, _, _ = owner.recover(paths)
    assert values["main"] == values["disk-two-run"]
    assert (
        manifest["media"][0]["outputs"]["RUN"] == "main"
        and media["outputs"]["RUN"] == "disk-two-run"
    )
    assert owner.owner("main") == ("main", 0) and owner.owner("disk-two-run") == (
        "disk-two-run",
        0,
    )
    assert owner.members["main"]["sha256"] == owner.members["disk-two-run"]["sha256"]
    from amiga_reversing.amiga_disk.adf import analyze_adf

    assert any(
        f.full_path == "RUN" and f.size == 4
        for f in analyze_adf(path, kb_root=ROOT).files
    )


def test_missing_assembled_placement_fails_even_when_template_hash_matches(
    tmp_path, monkeypatch
):
    from amiga_reversing.disasm.disk_codecs import ByteRanges

    project, target, paths, _ = fixture(tmp_path)
    owner = DiskSet.load(target, project_root=project)
    rebuild = ByteRanges.rebuild
    observed = []

    def skip(cls, image, recipe, outputs, *, project_root):
        reduced = copy.deepcopy(recipe)
        reduced["actions"] = [
            a for a in reduced["actions"] if a["file"] != "palette.bin"
        ]
        result, receipt = rebuild(
            image,
            reduced,
            {f: b for f, b in outputs.items() if f != "palette.bin"},
            project_root=project_root,
        )
        observed.append(result == image)
        return result, receipt

    monkeypatch.setattr(ByteRanges, "rebuild", classmethod(skip))
    with pytest.raises(ValueError, match="placement write coverage"):
        owner.build(
            tmp_path / "missing-placement", paths, vasm=ROOT / "tools/vasmm68k_mot.exe"
        )
    assert all(observed) and len(observed) == 2


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (lambda m: m["members"].append(copy.deepcopy(m["members"][0])), "duplicate"),
        (lambda m: m["members"][2].update(analysis={}), "double-own"),
        (lambda m: m["relationships"][0].update(offset=3), "scope or ownership"),
        (lambda m: m["relationships"].clear(), "no assembly/analysis owner"),
        (
            lambda m: m["media"][0].update(codec="arbitrary_python_module"),
            "media binding",
        ),
        (
            lambda m: m["media"][0]["recipe"].update(path="../escape.json"),
            "relative path",
        ),
        (
            lambda m: m["members"][0]["context"].update(load_address=True),
            "address context",
        ),
    ],
)
def test_manifest_refuses_ambiguous_or_unowned_state(tmp_path, change, reason):
    project, target, _, manifest = fixture(tmp_path)
    change(manifest)
    (target / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match=reason):
        DiskSet.load(target, project_root=project)


def test_build_refuses_stale_state_wrong_media_or_unreviewed_output(tmp_path):
    project, target, paths, _ = fixture(tmp_path)
    owner = DiskSet.load(target, project_root=project)
    with pytest.raises(ValueError, match="stale_revision"):
        execute_owner(
            target,
            {"operation": "build", "expected_revision": "stale"},
            project_root=project,
        )
    wrong = dict(paths)
    wrong["custom"] = paths["dos"]
    with pytest.raises(ValueError, match="media identity"):
        owner.recover(wrong)
    (target / "analysis/main.json").write_text("{}")
    with pytest.raises(ValueError, match="stale disk-set file"):
        DiskSet.load(target, project_root=project)

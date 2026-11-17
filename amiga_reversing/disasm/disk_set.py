"""One target owns a disk set, scoped analysis members and exact image builds.

This first common slice supports sealed imports, read-only native member
queries and independent source builds. Interactive member-state mutation is
deliberately refused until the journal/command layer is member-aware.
"""

from __future__ import annotations

import base64
import copy
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from amiga_reversing.disasm.disk_codecs import CODECS, digest, verify_write_coverage
from amiga_reversing.disasm.source_package import (
    _json as package_manifest_bytes,
)
from amiga_reversing.disasm.source_package import (
    materialize_source_package,
    validate_source_package,
)
from amiga_reversing.disasm.source_package_publish import load_published_source_package

MAX_BYTES = 32 * 1024 * 1024


def subject_identity(manifest):
    """The set's identity includes member scopes/links, not a runtime address."""
    return digest(
        json.dumps(
            {
                k: manifest[k]
                for k in (
                    "id",
                    "project_id",
                    "build_id",
                    "platform",
                    "media",
                    "members",
                    "relationships",
                )
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )


def compose_source_package(manifest, member_packages):
    """Collect native-produced member sources without editing their text.

    Only identical include files may merge automatically. Sharing executable
    or asset ownership requires a declared relation, not a filename collision.
    """
    owned = {m["id"]: m for m in manifest["members"] if m["source"] is not None}
    if set(member_packages) != set(owned):
        raise ValueError("source packages must match the independent assembly owners")
    records, values = {}, {}
    for member in owned:
        package = member_packages[member]
        files = validate_source_package(package)
        for original in package["manifest"]["files"]:
            record = copy.deepcopy(original)
            old = record["path"]
            name = (
                owned[member]["source"] if old == package["manifest"]["source"] else old
            )
            data = files[old]
            if name in values:
                if (
                    data != values[name]
                    or record["kind"] != "include"
                    or records[name]["kind"] != "include"
                ):
                    raise ValueError("member source-package ownership collision")
                records[name]["members"].append(member)
                continue
            record.update(path=name, members=[member])
            records[name], values[name] = record, data
    base = copy.deepcopy(member_packages[next(iter(owned))]["manifest"])
    base.update(
        source=next(iter(owned.values()))["source"],
        target=manifest["id"],
        target_identity_sha256=subject_identity(manifest),
        metadata_hash=digest(
            json.dumps([m["analysis"] for m in owned.values()], sort_keys=True).encode()
        ),
        application={"kind": "disk_set", "assembly_owners": list(owned)},
        files=[records[p] for p in sorted(records)],
    )
    result = {
        "manifest": base,
        "sha256": digest(package_manifest_bytes(base)),
        "files": [
            {"path": p, "data_base64": base64.b64encode(values[p]).decode("ascii")}
            for p in sorted(values)
        ],
    }
    validate_source_package(result)
    return result


def identity(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value
    ):
        raise ValueError("invalid disk-set identity")
    return value


def sha(value):
    if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value):
        raise ValueError("invalid disk-set hash")
    return value


def extent(value, maximum=MAX_BYTES):
    if type(value) is not int or not 0 < value <= maximum:
        raise ValueError("invalid disk-set extent")
    return value


def file_at(root, name):
    if (
        not isinstance(name, str)
        or not name
        or "\\" in name
        or Path(name).is_absolute()
        or any(p in {"", ".", ".."} for p in name.split("/"))
    ):
        raise ValueError("invalid disk-set relative path")
    path = root
    for part in name.split("/"):
        path = path / part
        if path.is_symlink():
            raise ValueError("disk-set paths cannot traverse symlinks")
    return path


def checked_file(root, reference):
    if set(reference) != {"path", "sha256"}:
        raise ValueError("invalid disk-set file reference")
    path = file_at(root, reference["path"])
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("disk-set file budget exceeded")
    data = path.read_bytes()
    if digest(data) != sha(reference["sha256"]):
        raise ValueError("stale disk-set file identity")
    return data


def is_disk_set(root):
    path = root / "manifest.json"
    return path.is_file() and json.loads(path.read_bytes()).get("kind") == "disk_set"


def create_disk_set(
    root, manifest, member_packages, owned_files, media_paths, *, project_root
):
    """Publish a verified fresh owner through the normal target directory.

    Title adapters supply facts and codec data. They do not become runtime
    dependencies and cannot create independently registered member projects.
    """
    from amiga_reversing.disasm.projects import initialize_project_metadata
    from amiga_reversing.disasm.source_package_publish import publish_source_package

    root = Path(root)
    if root.parent.resolve() != (Path(project_root) / "targets").resolve():
        raise ValueError("disk-set owners belong in the canonical targets directory")
    if any(p.is_symlink() for p in (root, *root.parents)):
        raise ValueError("disk-set import cannot traverse symlinks")
    if root.exists() or root.is_symlink():
        raise FileExistsError("disk-set import requires a fresh owner")
    m = copy.deepcopy(manifest)
    if identity(m["id"]) != root.name:
        raise ValueError("disk-set owner id/path differs")
    package = compose_source_package(m, member_packages)
    m["package_sha256"] = package["sha256"]
    refs = [v["recipe"] for v in m["media"]]
    for member in m["members"]:
        if member["analysis"] is not None:
            refs += [member["analysis"]["metadata"], *member["analysis"]["state_files"]]
            refs += [
                r
                for r in member["analysis"].get("state", {}).values()
                if r["sha256"] is not None
            ]
    if set(owned_files) != {r["path"] for r in refs}:
        raise ValueError("disk-set import file inventory differs")
    package_files = validate_source_package(package)
    if set(owned_files) & (
        set(package_files)
        | {"manifest.json", "source-package-manifest.json", ".project.json"}
    ):
        raise ValueError("disk-set import ownership collision")
    all_paths = [*owned_files, *package_files]
    if len({p.casefold() for p in all_paths}) != len(all_paths):
        raise ValueError("disk-set import case collision")
    root.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".disk-set-import-", dir=root.parent
    ) as tmp:
        stage = Path(tmp) / root.name
        stage.mkdir()
        for name, data in owned_files.items():
            if not isinstance(data, bytes) or len(data) > MAX_BYTES:
                raise ValueError("invalid imported state/recipe bytes")
            p = file_at(stage, name)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        publish_source_package(package, stage)
        (stage / "manifest.json").write_text(json.dumps(m, indent=2) + "\n")
        initialize_project_metadata(
            stage,
            origin={
                "kind": "disk_set_import",
                "platform": m["platform"],
                "subject": subject_identity(m),
            },
        )
        owner = DiskSet.load(stage, project_root=project_root)
        owner.recover(media_paths)
        if any((m["analysis"] or {}).get("state") for m in owner.members.values()):
            from amiga_reversing.disasm.disk_set_state import verify_journal_snapshots

            verify_journal_snapshots(owner, media_paths)
        if root.exists():
            raise FileExistsError("disk-set owner appeared during import")
        stage.rename(root)
    return DiskSet.load(root, project_root=project_root)


@dataclass
class DiskSet:
    root: Path
    project_root: Path
    manifest: dict
    package: dict

    @classmethod
    def load(cls, root, *, project_root):
        root = Path(root)
        if root.is_symlink():
            raise ValueError("disk-set target cannot be a symlink")
        m = json.loads((root / "manifest.json").read_bytes())
        if (
            set(m)
            != {
                "schema_version",
                "kind",
                "id",
                "name",
                "project_id",
                "build_id",
                "platform",
                "package_sha256",
                "media",
                "members",
                "relationships",
            }
            or type(m["schema_version"]) is not int
            or m["schema_version"] != 1
            or m["kind"] != "disk_set"
            or identity(m["id"]) != root.name
            or not isinstance(m["name"], str)
            or not m["name"]
            or m["platform"] not in {"amiga", "atari-st"}
        ):
            raise ValueError("invalid disk-set manifest")
        identity(m["project_id"])
        identity(m["build_id"])
        package = load_published_source_package(root)
        if package["sha256"] != sha(m["package_sha256"]):
            raise ValueError("stale disk-set source package")
        files = validate_source_package(package)
        for key in ("media", "members"):
            if not isinstance(m[key], list) or not 1 <= len(m[key]) <= 256:
                raise ValueError("invalid disk-set collection")
            ids = [identity(v["id"]) for v in m[key]]
            if len({v.casefold() for v in ids}) != len(ids):
                raise ValueError("duplicate disk-set identity")
        if (
            sum(extent(v["size"]) for v in m["media"]) > MAX_BYTES
            or sum(extent(v["size"]) for v in m["members"]) > MAX_BYTES
        ):
            raise ValueError("disk-set aggregate byte budget exceeded")
        members = {v["id"]: v for v in m["members"]}
        for member in members.values():
            if set(member) != {
                "id",
                "kind",
                "sha256",
                "size",
                "context",
                "source",
                "analysis",
            }:
                raise ValueError("invalid disk-set member")
            if member["kind"] not in {"code", "mixed", "data"}:
                raise ValueError("invalid member content kind")
            data_only = member["kind"] == "data"
            sha(member["sha256"])
            extent(member["size"])
            c = member["context"]
            if (
                set(c)
                != {
                    "address_model",
                    "load_address",
                    "entrypoint",
                    "code_start_offset",
                    "phase",
                }
                or c["address_model"] not in {"runtime_absolute", "local_offset"}
                or c["phase"]
                not in {
                    "pre_handoff",
                    "handoff",
                    "decoded_resource",
                    "decoded_snapshot",
                }
                or type(c["load_address"]) is not int
                or not 0 <= c["load_address"] < 0x1000000
                or c["load_address"] + member["size"] > 0x1000000
                or (
                    data_only
                    and (
                        c["entrypoint"] is not None
                        or c["code_start_offset"] is not None
                    )
                )
                or (
                    not data_only
                    and (
                        any(
                            type(c[k]) is not int or not 0 <= c[k] < 0x1000000
                            for k in ("entrypoint", "code_start_offset")
                        )
                        or not c["load_address"] + c["code_start_offset"]
                        <= c["entrypoint"]
                        < c["load_address"] + member["size"]
                    )
                )
            ):
                raise ValueError("invalid member address context")
            if member["source"] is not None:
                if (
                    member["source"] not in files
                    or not member["source"].endswith(".s")
                    or "/" in member["source"]
                ):
                    raise ValueError("member assembly source missing")
                a = member["analysis"]
                if data_only:
                    if a is not None:
                        raise ValueError(
                            "data-only member cannot declare instruction analysis"
                        )
                else:
                    if (
                        not isinstance(a, dict)
                        or set(a)
                        not in (
                            {"metadata", "state_files"},
                            {"metadata", "state_files", "state"},
                        )
                        or not isinstance(a["state_files"], list)
                    ):
                        raise ValueError("member analysis import missing")
                    json.loads(checked_file(root, a["metadata"]))
                    for r in a["state_files"]:
                        checked_file(root, r)
            elif member["analysis"] is not None:
                raise ValueError("shared member cannot double-own analysis")
        from amiga_reversing.disasm.disk_set_state import validate_states

        validate_states(root, m, source_files=files)
        links = {}
        if not isinstance(m["relationships"], list):
            raise ValueError("invalid member relationships")
        for link in m["relationships"]:
            if isinstance(link, dict) and link.get("kind") == "load":
                if (
                    set(link)
                    != {
                        "kind",
                        "source",
                        "member",
                        "source_offset",
                        "source_size",
                        "member_offset",
                        "size",
                        "destination",
                        "trigger",
                        "evidence",
                    }
                    or link["source"] not in members
                    or link["member"] not in members
                    or type(link["source_offset"]) is not int
                    or link["source_offset"] < 0
                    or link["source_offset"] + extent(link["source_size"])
                    > members[link["source"]]["size"]
                    or type(link["member_offset"]) is not int
                    or link["member_offset"] < 0
                    or link["member_offset"] + extent(link["size"])
                    > members[link["member"]]["size"]
                    or type(link["destination"]) is not int
                    or link["destination"]
                    != members[link["member"]]["context"]["load_address"]
                    + link["member_offset"]
                    or any(
                        not isinstance(link[k], str) or not link[k]
                        for k in ("trigger", "evidence")
                    )
                ):
                    raise ValueError("invalid static load relationship")
                continue
            if (
                set(link) != {"kind", "member", "owner", "offset", "size", "evidence"}
                or link["kind"] != "embedded"
                or link["member"] in links
                or link["member"] not in members
                or link["owner"] not in members
                or type(link["offset"]) is not int
                or link["offset"] < 0
                or not isinstance(link["evidence"], str)
                or not link["evidence"]
            ):
                raise ValueError("invalid embedded-member relationship")
            child, parent = members[link["member"]], members[link["owner"]]
            if (
                child["source"] is not None
                or child["analysis"] is not None
                or extent(link["size"]) != child["size"]
                or link["offset"] + link["size"] > parent["size"]
                or child["context"]["address_model"]
                != parent["context"]["address_model"]
                or child["context"]["load_address"]
                != parent["context"]["load_address"] + link["offset"]
            ):
                raise ValueError("embedded member scope or ownership differs")
            links[link["member"]] = link
        for name in members:
            seen = set()
            while name in links:
                if name in seen:
                    raise ValueError("member relationship cycle")
                seen.add(name)
                name = links[name]["owner"]
            if members[name]["source"] is None:
                raise ValueError("member has no assembly/analysis owner")
        bound = set()
        for media in m["media"]:
            if (
                set(media) != {"id", "sha256", "size", "codec", "recipe", "outputs"}
                or media["codec"] not in CODECS
                or m["platform"] not in CODECS[media["codec"]].platforms
                or not isinstance(media["outputs"], dict)
                or not media["outputs"]
                or not set(media["outputs"].values()) <= set(members)
            ):
                raise ValueError("invalid disk-set media binding")
            sha(media["sha256"])
            extent(media["size"])
            recipe = json.loads(checked_file(root, media["recipe"]))
            if recipe.get("image_sha256") != media["sha256"]:
                raise ValueError("recipe media identity differs")
            bound.update(media["outputs"].values())
        owners = {
            name for name, member in members.items() if member["source"] is not None
        }
        if not owners <= bound:
            raise ValueError("unbound disk-set assembly owner")
        if len({members[name]["source"] for name in owners}) != len(owners):
            raise ValueError("independent members cannot double-own an assembly source")
        for record in package["manifest"]["files"]:
            refs = record.get("members")
            if (
                not isinstance(refs, list)
                or not refs
                or len(set(refs)) != len(refs)
                or not set(refs) <= owners
            ):
                raise ValueError("source file lacks scoped member ownership")
        for name in owners:
            record = next(
                r
                for r in package["manifest"]["files"]
                if r["path"] == members[name]["source"]
            )
            if record["kind"] != "source" or record["members"] != [name]:
                raise ValueError("member assembly entry ownership differs")
        if package["manifest"]["target"] != m["id"] or package["manifest"][
            "target_identity_sha256"
        ] != subject_identity(m):
            raise ValueError("source package is not bound to this disk-set subject")
        return cls(root, Path(project_root), m, package)

    @property
    def revision(self):
        return digest(
            json.dumps(self.manifest, sort_keys=True, separators=(",", ":")).encode()
        )

    @property
    def members(self):
        return {m["id"]: m for m in self.manifest["members"]}

    def owner(self, member_id):
        if member_id not in self.members:
            raise ValueError("unknown disk-set member")
        links = {
            v["member"]: v
            for v in self.manifest["relationships"]
            if v["kind"] == "embedded"
        }
        bias = 0
        while member_id in links:
            bias += links[member_id]["offset"]
            member_id = links[member_id]["owner"]
        return member_id, bias

    def recover(self, media_paths):
        if not isinstance(media_paths, dict) or set(media_paths) != {
            m["id"] for m in self.manifest["media"]
        }:
            raise ValueError("supply exactly the declared private media bindings")
        values, images, receipts = {}, {}, {}
        for m in self.manifest["media"]:
            input_path = Path(media_paths[m["id"]]).resolve()
            if input_path.is_relative_to(self.root.resolve()):
                raise ValueError(
                    "private original media must remain outside the owned source directory"
                )
            image = input_path.read_bytes()
            if len(image) != m["size"] or digest(image) != m["sha256"]:
                raise ValueError("private disk-set media identity differs")
            recipe = json.loads(checked_file(self.root, m["recipe"]))
            receipt, outputs = CODECS[m["codec"]].extract(
                image, recipe, project_root=self.project_root
            )
            if set(outputs) != set(m["outputs"]):
                raise ValueError("codec output/member inventory differs")
            for filename, data in outputs.items():
                name = m["outputs"][filename]
                member = self.members[name]
                if len(data) != member["size"] or digest(data) != member["sha256"]:
                    raise ValueError("extracted member identity differs")
                if name in values and values[name] != data:
                    raise ValueError("replicated member content differs")
                values[name] = data
            images[m["id"]], receipts[m["id"]] = image, receipt
        for name, member in self.members.items():
            if name not in values:
                owner, offset = self.owner(name)
                values[name] = values[owner][offset : offset + member["size"]]
                if (
                    len(values[name]) != member["size"]
                    or digest(values[name]) != member["sha256"]
                ):
                    raise ValueError("derived member identity differs")
        for link in self.manifest["relationships"]:
            if link["kind"] != "embedded":
                continue
            if (
                values[link["member"]]
                != values[link["owner"]][link["offset"] : link["offset"] + link["size"]]
            ):
                raise ValueError("embedded member byte identity differs")
        return values, images, receipts

    def _analysis_input(self, member_id, values):
        from amiga_reversing.disasm.binary_source import (
            BinarySourceKind,
            RawAddressModel,
            RawBinarySource,
        )

        owner, _ = self.owner(member_id)
        cache = self.project_root / ".amiga_reversing/disk-set-artifacts"
        if any(p.is_symlink() for p in (cache, *cache.parents)):
            raise ValueError("private member cache cannot traverse symlinks")
        cache.mkdir(parents=True, exist_ok=True)
        path = cache / (self.members[owner]["sha256"] + ".bin")
        if path.is_symlink():
            raise ValueError("private member cache cannot be a symlink")
        if path.exists() and path.read_bytes() != values[owner]:
            raise ValueError("private member cache identity differs")
        if not path.exists():
            with tempfile.NamedTemporaryFile(dir=cache, delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(values[owner])
            try:
                if path.exists() and path.read_bytes() != values[owner]:
                    raise ValueError("private member cache identity differs")
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)

        @dataclass(frozen=True, slots=True)
        class MemberSource(RawBinarySource):
            platform: str = "amiga"

            @property
            def backend_name(self):
                return self.platform + "-raw"

        c = self.members[owner]["context"]
        source = MemberSource(
            kind=BinarySourceKind.RAW_BINARY,
            path=path,
            address_model=RawAddressModel(c["address_model"]),
            load_address=c["load_address"],
            entrypoint=c["entrypoint"],
            code_start_offset=c["code_start_offset"],
            display_path=self.manifest["id"] + ":" + owner,
            analysis_cache_path=cache / (self.revision + "-" + owner),
            platform=self.manifest["platform"],
        )
        metadata = file_at(
            self.root, self.members[owner]["analysis"]["metadata"]["path"]
        )
        return source, metadata

    def query(self, member_id, body, media_paths):
        """Read-only native analysis, scoped before local C coordinates are used."""
        from amiga_reversing.disasm.c_backend import (
            build_listing_artifact_profile_from_binary_source,
        )
        from amiga_reversing.disasm.restoration import _pagination

        owner, bias = self.owner(member_id)
        if (
            self.members[member_id]["kind"] == "data"
            or self.members[owner]["analysis"] is None
        ):
            raise ValueError("data-only member has no instruction analysis owner")
        kind = body.get("kind")
        if kind not in {
            "instructions",
            "symbols",
            "fields",
            "references",
            "edges",
            "summary",
        }:
            raise ValueError("unsupported disk-set member query")
        if owner != member_id and kind != "instructions":
            raise ValueError(
                "shared views currently query instructions; use canonical analysis owner for other facts"
            )
        filters = {
            k: body[k]
            for k in (
                "kind",
                "query",
                "section_index",
                "source_offset",
                "end_offset",
                "symbol",
                "struct_name",
                "field_offset",
                "direction",
            )
            if k in body
        }
        offset, limit = _pagination(
            body, self.revision, {**filters, "member_id": member_id}
        )
        if kind == "instructions":
            lo, hi = (
                filters.get("source_offset", 0),
                filters.get("end_offset", self.members[member_id]["size"]),
            )
            if (
                type(lo) is not int
                or type(hi) is not int
                or not 0 <= lo < hi <= self.members[member_id]["size"]
            ):
                raise ValueError("instruction query outside member view")
            filters.update(source_offset=lo + bias, end_offset=hi + bias)
        values, _, _ = self.recover(media_paths)
        source, metadata = self._analysis_input(member_id, values)
        _, _, artifact = build_listing_artifact_profile_from_binary_source(
            source, metadata_path=metadata, project_root=self.project_root
        )
        try:
            if kind == "summary":
                analysis = artifact.analysis_payload()[0]
                items = [
                    {
                        "section_index": s["section_index"],
                        "accepted_code_bytes": sum(
                            r["end_offset"] - r["start_offset"]
                            for r in s["accepted_code_runs"]
                        ),
                        "accepted_code_runs": s["accepted_code_run_count"],
                        "cfg_blocks": s["block_count"],
                        "typed_accesses": s["recovered_platform_typed_access_count"],
                        "unresolved_typed_accesses": s[
                            "recovered_platform_unresolved_typed_access_count"
                        ],
                        "orphan_signals": s["orphan_code_signal_count"],
                    }
                    for s in analysis["sections"]
                ]
                from amiga_reversing.disasm.restoration import _page

                page = _page(items, offset, limit)
            else:
                page = artifact.query_payload(**filters, offset=offset, limit=limit)
        finally:
            artifact.close()
        # A shared view returns its owner's stable coordinates, never a second
        # independently editable set of facts at the same runtime address.
        return page, {
            "target_id": self.manifest["id"],
            "member_id": member_id,
            "analysis_member_id": owner,
            "artifact_sha256": self.members[owner]["sha256"],
            "source_offset_bias": bias,
            "coordinate_scope": "analysis_owner",
        }

    def regenerate(self, media_paths):
        """Compare native member projections with the one owned source bundle."""
        from amiga_reversing.disasm.c_backend import (
            listing_artifact_source_projection_with_c_backend_profile,
        )
        from amiga_reversing.disasm.source_package import collect_package_includes

        values, _, _ = self.recover(media_paths)
        expected = validate_source_package(self.package)
        results = {}
        for member, m in self.members.items():
            if m["source"] is None:
                continue
            if m["analysis"] is None:
                results[member] = {
                    "status": "data_source_build_only",
                    "native_projection_supported": False,
                }
                continue
            source, metadata = self._analysis_input(member, values)
            text, profile, native = (
                listing_artifact_source_projection_with_c_backend_profile(
                    source,
                    metadata_path=metadata,
                    project_root=self.project_root,
                    use_persisted_policy=True,
                )
            )
            from amiga_reversing.disasm.facts_v2_source_refusal import (
                facts_v2_source_refused,
            )

            if facts_v2_source_refused(profile):
                raise ValueError("native disk-set member source projection refused")
            files = {m["source"]: text.encode()}
            for record in [
                *(native["assets"] if native else []),
                *collect_package_includes(text, self.root),
            ]:
                path, data = record["path"], bytes.fromhex(record["data_hex"])
                if path in files and files[path] != data:
                    raise ValueError("member native source-file collision")
                files[path] = data
            owned = {
                r["path"]: expected[r["path"]]
                for r in self.package["manifest"]["files"]
                if member in r["members"]
            }
            if files != owned:
                changed = sorted(
                    p
                    for p in files.keys() | owned.keys()
                    if files.get(p) != owned.get(p)
                )
                raise ValueError(
                    "member source regeneration differs: "
                    + member
                    + ": "
                    + ", ".join(changed)
                )
            results[member] = {"files": len(files), "whole_source_package_exact": True}
        return results

    def build(self, output, media_paths, *, vasm):
        from amiga_reversing.disasm.c_backend import (
            assemble_platform_source_path_with_c_backend,
        )

        values, images, _ = self.recover(media_paths)
        output = Path(output).absolute()
        allowed = [
            Path("/tmp"),
            self.project_root / "bin/rebuilt",
            self.project_root / ".amiga_reversing",
        ]
        for parent in (output, *output.parents):
            if parent.is_symlink():
                raise ValueError("disk-set output cannot traverse symlinks")
        output = output.resolve()
        if output.is_relative_to(self.root.resolve()):
            raise ValueError(
                "private build output cannot be inside the owned source directory"
            )
        if not any(
            output.is_relative_to(p.resolve()) and output != p.resolve()
            for p in allowed
        ):
            raise ValueError("disk-set output must be fresh private storage")
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        built, builds = {}, {}
        with tempfile.TemporaryDirectory(prefix="disk-set-source-only-") as tmp:
            stage = Path(tmp)
            materialize_source_package(self.package, stage)
            for name, member in self.members.items():
                if member["source"] is None:
                    continue
                source = stage / member["source"]
                native, _ = assemble_platform_source_path_with_c_backend(
                    self.manifest["platform"] + "-raw",
                    source,
                    include_dir=stage,
                    target_cpu="68000",
                    project_root=self.project_root,
                )
                oracle = output / (name + "-vasm.bin")
                p = subprocess.run(
                    [
                        str(Path(vasm).resolve()),
                        "-m68000",
                        "-Fbin",
                        "-quiet",
                        "-no-opt",
                        "-nosym",
                        "-o",
                        str(oracle),
                        str(source),
                    ],
                    cwd=stage,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if p.returncode or not oracle.is_file():
                    raise ValueError(
                        "independent member assembly failed: " + p.stdout + p.stderr
                    )
                other = oracle.read_bytes()
                if native != other or native != values[name]:
                    raise ValueError("member assembly differs from oracle or original")
                built[name] = native
                (output / (name + "-native.bin")).write_bytes(native)
                builds[name] = {
                    "kind": "independent_assembly",
                    "bytes": len(native),
                    "sha256": digest(native),
                    "native_exact": True,
                    "vasm_exact": True,
                    "source": member["source"],
                }
        for name in self.members:
            if name not in built:
                owner, offset = self.owner(name)
                size = self.members[name]["size"]
                built[name] = built[owner][offset : offset + size]
                if built[name] != values[name]:
                    raise ValueError("assembled embedded member differs")
                builds[name] = {
                    "kind": "assembled_owner_slice",
                    "owner": owner,
                    "offset": offset,
                    "bytes": size,
                    "sha256": digest(built[name]),
                    "separate_analysis_owner": False,
                }
        media_receipts, direct_placements, embedded_placements = {}, [], []
        for m in self.manifest["media"]:
            recipe = json.loads(checked_file(self.root, m["recipe"]))
            codec = CODECS[m["codec"]]
            image, receipt = codec.rebuild(
                images[m["id"]],
                recipe,
                {f: built[n] for f, n in m["outputs"].items()},
                project_root=self.project_root,
            )
            completed = receipt.get("write_coverage")
            verify_write_coverage(codec.required_coverage(recipe), completed)
            _, decoded = codec.extract(image, recipe, project_root=self.project_root)
            if decoded != {f: built[n] for f, n in m["outputs"].items()}:
                raise ValueError("independent disk-set member re-decode differs")
            for placement in completed:
                member = m["outputs"][placement["file"]]
                assembly_owner, parent_bias = self.owner(member)
                direct_placements.append(
                    {
                        "media": m["id"],
                        "member": member,
                        "assembly_owner": assembly_owner,
                        "source_offset_bias": parent_bias,
                        **placement,
                    }
                )
                for child in self.members:
                    child_owner, child_bias = self.owner(child)
                    child_size = self.members[child]["size"]
                    if (
                        child == member
                        or child_owner != assembly_owner
                        or self.members[child]["source"] is not None
                        or not parent_bias
                        <= child_bias
                        < child_bias + child_size
                        <= parent_bias + placement["size"]
                    ):
                        continue
                    spans = []
                    for span in placement["spans"]:
                        start = parent_bias + span["source_offset"]
                        lo, hi = (
                            max(start, child_bias),
                            min(start + span["length"], child_bias + child_size),
                        )
                        if lo < hi:
                            spans.append(
                                {
                                    "source_offset": lo - child_bias,
                                    **codec.clip_coverage(span, lo - start, hi - lo),
                                }
                            )
                    if sum(s["length"] for s in spans) != child_size:
                        raise ValueError(
                            "embedded member placement write coverage is incomplete"
                        )
                    embedded_placements.append(
                        {
                            "media": m["id"],
                            "member": child,
                            "within_file": placement["file"],
                            "assembly_owner": assembly_owner,
                            "owner_source_offset": child_bias,
                            "size": child_size,
                            "sha256": digest(built[child]),
                            "spans": spans,
                        }
                    )
            if image != images[m["id"]]:
                raise ValueError("exact disk-set restoration changed media identity")
            if Path(media_paths[m["id"]]).read_bytes() != images[m["id"]]:
                raise ValueError("original media changed during build")
            (output / (m["id"] + codec.suffix)).write_bytes(image)
            media_receipts[m["id"]] = {
                "sha256": digest(image),
                "whole_file_exact": True,
                "codec_receipt": receipt,
            }
        if (
            DiskSet.load(self.root, project_root=self.project_root).revision
            != self.revision
        ):
            raise ValueError("disk-set state changed during build")
        receipt = {
            "kind": "disk_set_build",
            "target": self.manifest["id"],
            "revision": self.revision,
            "members": builds,
            "media": media_receipts,
            "coverage": {
                "complete": True,
                "direct_placements": direct_placements,
                "embedded_placements": embedded_placements,
                "independent_redecode": True,
            },
            "runtime": "not tested",
        }
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        return receipt


def execute_owner(root, body, *, project_root):
    """Canonical restoration operations for a disk-set owner (not child targets)."""
    from amiga_reversing.disasm.disk_set_state import MEMBER_OPERATIONS
    from amiga_reversing.disasm.restoration import _envelope, _page, _pagination
    from amiga_reversing.disasm.target_history import target_lock

    with target_lock(root):
        owner = DiskSet.load(root, project_root=project_root)
        current = {"revision": owner.revision, "subject_revision": owner.revision}
        operation = body.get("operation")
        if (
            operation in {"build", "verify", "interpret", "rollback", "review"}
            or body.get("expected_revision") is not None
        ) and body.get("expected_revision") != owner.revision:
            raise ValueError(
                "stale_revision: reload the disk-set owner before deciding"
            )
        members = [
            {
                **m,
                "analysis_owner": owner.owner(m["id"])[0]
                if owner.members[owner.owner(m["id"])[0]]["analysis"] is not None
                else None,
                "source_offset_bias": owner.owner(m["id"])[1],
                "editable": bool(
                    (owner.members[owner.owner(m["id"])[0]]["analysis"] or {}).get(
                        "state"
                    )
                ),
            }
            for m in owner.manifest["members"]
        ]
        for member in members:
            member["restoration_operations"] = (
                list(MEMBER_OPERATIONS) if member["editable"] else []
            )
        if operation == "state":
            return {
                **current,
                "ready": True,
                "kind": "disk_set",
                "members": members,
                "analysis_owner_count": len(
                    {
                        owner.owner(m["id"])[0]
                        for m in members
                        if owner.members[owner.owner(m["id"])[0]]["analysis"]
                        is not None
                    }
                ),
                "member_mutation_supported": any(
                    (m["analysis"] or {}).get("state") for m in owner.members.values()
                ),
                "unknowns": [
                    "Only declared editable members expose scoped label/comment interpretation; other members remain sealed.",
                    "Exact source/media builds do not prove natural boot or playback.",
                ],
            }
        if operation in MEMBER_OPERATIONS:
            from amiga_reversing.disasm.disk_set_state import (
                edit_member,
                history_member,
                inspect_member,
                review_member,
                rollback_member,
            )

            member = body.get("member_id")
            if not isinstance(member, str):
                raise ValueError("disk-set analysis requires an explicit member_id")
            return {
                "interpret": edit_member,
                "inspect": inspect_member,
                "history": history_member,
                "rollback": rollback_member,
                "review": review_member,
            }[operation](owner, member, body)
        if operation == "query":
            if body.get("kind") == "members":
                filters = {"kind": "members"}
                offset, limit = _pagination(body, owner.revision, filters)
                return _envelope(_page(members, offset, limit), current, filters)
            member = body.get("member_id")
            if not isinstance(member, str):
                raise ValueError("disk-set analysis requires an explicit member_id")
            page, scope = owner.query(member, body, body.get("media_paths", {}))
            filters = {
                k: body[k]
                for k in (
                    "kind",
                    "query",
                    "section_index",
                    "source_offset",
                    "end_offset",
                    "symbol",
                    "struct_name",
                    "field_offset",
                    "direction",
                )
                if k in body
            }
            filters["member_id"] = member
            if DiskSet.load(root, project_root=project_root).revision != owner.revision:
                raise ValueError("disk-set state changed during analysis")
            return {**_envelope(page, current, filters), "scope": scope}
        if operation in {"build", "verify"}:
            regeneration = (
                owner.regenerate(body.get("media_paths", {}))
                if operation == "verify"
                else None
            )
            result = owner.build(
                body["output"],
                body.get("media_paths", {}),
                vasm=Path(project_root) / "tools/vasmm68k_mot.exe",
            )
            if regeneration is not None:
                result["regeneration"] = regeneration
                (Path(body["output"]) / "receipt.json").write_text(
                    json.dumps(result, indent=2) + "\n"
                )
            return result
        raise ValueError(
            "disk-set member operation is not supported by this sealed-import slice"
        )

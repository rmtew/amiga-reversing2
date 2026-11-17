"""Closed disk-set codec registry. Recipes describe content, not target layout."""

from __future__ import annotations

import hashlib


def digest(data):
    return hashlib.sha256(data).hexdigest()


def required_coverage(recipe):
    """Required placements are independent of the writer's completion report."""
    result = []
    for action in recipe["actions"]:
        cursor, spans = 0, []
        for span in action["spans"]:
            spans.append(
                {
                    "source_offset": cursor,
                    "length": span["length"],
                    "storage": {k: v for k, v in span.items() if k != "length"},
                }
            )
            cursor += span["length"]
        result.append(
            {
                "file": action["file"],
                "sha256": action["sha256"],
                "size": action["size"],
                "spans": spans,
            }
        )
    return result


def clip_coverage(span, offset, length):
    """The registered codecs expose byte-affine decoded storage spans."""
    if not 0 <= offset < offset + length <= span["length"]:
        raise ValueError("invalid clipped placement span")
    return {
        "length": length,
        "storage": {**span["storage"], "offset": span["storage"]["offset"] + offset},
    }


def verify_write_coverage(required, actual):
    if (
        not isinstance(actual, list)
        or any(not isinstance(v, dict) or "file" not in v for v in actual)
        or sorted(required, key=lambda v: v["file"])
        != sorted(actual, key=lambda v: v["file"])
    ):
        raise ValueError("required disk-set placement write coverage is incomplete")


class ByteRanges:
    """Exact flat-media spans, e.g. independently established DOS file blocks.

    This is not a filesystem writer or a custom-track encoder. Unknown bytes
    stay template-owned, and changed assembled content is refused.
    """

    suffix = ".img"
    platforms = frozenset({"amiga", "atari-st"})
    required_coverage = staticmethod(required_coverage)
    clip_coverage = staticmethod(clip_coverage)

    @staticmethod
    def extract(image, recipe, *, project_root):
        if (
            set(recipe) != {"kind", "image_sha256", "actions"}
            or recipe["kind"] != "byte_ranges"
            or digest(image) != recipe["image_sha256"]
            or not isinstance(recipe["actions"], list)
            or not 1 <= len(recipe["actions"]) <= 256
        ):
            raise ValueError("invalid byte-range recipe or media identity")
        outputs = {}
        for a in recipe["actions"]:
            if (
                set(a) != {"file", "size", "sha256", "spans"}
                or not isinstance(a["file"], str)
                or a["file"] in outputs
                or type(a["size"]) is not int
                or a["size"] <= 0
                or not isinstance(a["spans"], list)
                or not 1 <= len(a["spans"]) <= 256
            ):
                raise ValueError("invalid byte-range resource")
            chunks, used = [], []
            for span in a["spans"]:
                if set(span) != {"offset", "length"}:
                    raise ValueError("invalid byte-range span")
                at, size = span["offset"], span["length"]
                if (
                    type(at) is not int
                    or type(size) is not int
                    or not 0 <= at < at + size <= len(image)
                    or any(max(at, x) < min(at + size, y) for x, y in used)
                ):
                    raise ValueError("overlapping or out-of-bounds byte range")
                chunks.append(image[at : at + size])
                used.append((at, at + size))
            data = b"".join(chunks)
            if len(data) != a["size"] or digest(data) != a["sha256"]:
                raise ValueError("byte-range resource identity differs")
            outputs[a["file"]] = data
        return {"kind": "byte_range_extraction", "image_sha256": digest(image)}, outputs

    @classmethod
    def rebuild(cls, image, recipe, outputs, *, project_root):
        _, original = cls.extract(image, recipe, project_root=project_root)
        if outputs != original:
            raise ValueError("assembled resources differ from bound byte ranges")
        result = bytearray(image)
        owners, coverage = {}, []
        for a in recipe["actions"]:
            cursor = 0
            completed = {
                "file": a["file"],
                "sha256": digest(outputs[a["file"]]),
                "size": len(outputs[a["file"]]),
                "spans": [],
            }
            for span in a["spans"]:
                at, size = span["offset"], span["length"]
                data = outputs[a["file"]][cursor : cursor + size]
                cursor += size
                for i, value in enumerate(data, at):
                    if i in owners and owners[i] != value:
                        raise ValueError("conflicting byte-range ownership")
                    owners[i] = value
                result[at : at + size] = data
                completed["spans"].append(
                    {
                        "source_offset": cursor - len(data),
                        "length": len(data),
                        "storage": {"offset": at},
                    }
                )
            coverage.append(completed)
        _, decoded = cls.extract(bytes(result), recipe, project_root=project_root)
        if decoded != outputs:
            raise ValueError("rebuilt byte-range re-decode differs")
        return bytes(result), {
            "kind": "exact_byte_range_rebuild",
            "redecoded": True,
            "replaced_bytes": len(owners),
            "untouched_bytes_preserved": True,
            "write_coverage": coverage,
        }


class IpfResources:
    suffix = ".ipf"
    platforms = frozenset({"amiga"})
    required_coverage = staticmethod(required_coverage)
    clip_coverage = staticmethod(clip_coverage)

    @staticmethod
    def extract(image, recipe, *, project_root):
        from amiga_reversing.disasm.ipf_resources import recover_resources

        return recover_resources(image, recipe, project_root=project_root)

    @staticmethod
    def rebuild(image, recipe, outputs, *, project_root):
        from amiga_reversing.disasm.ipf_resources import rebuild_resources

        return rebuild_resources(image, recipe, outputs, project_root=project_root)


# Manifest data cannot import arbitrary Python or execute a command/plugin path.
CODECS = {"byte_ranges": ByteRanges, "ipf_resource_recovery": IpfResources}

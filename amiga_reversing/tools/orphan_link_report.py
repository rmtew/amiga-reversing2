"""Compare orphan positions with proposed entry families using native facts.

No target project is loaded or adopted; only the explicit report output is
written. An analysis snapshot may be a private experiment, distinct from adoption.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from amiga_reversing.disasm.orphan_links import orphan_link_hypotheses


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analysis-json", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    snapshot, manifest = args.analysis_json.read_bytes(), args.manifest.read_bytes()
    report = orphan_link_hypotheses(json.loads(snapshot), json.loads(manifest))
    report["provenance"] = {
        "native_snapshot_sha256": hashlib.sha256(snapshot).hexdigest(),
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "snapshot_semantics": "caller-supplied; verify experiment and input identities separately",
    }
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        if args.output.resolve() in (
            args.analysis_json.resolve(),
            args.manifest.resolve(),
        ):
            parser.error("output must not overwrite either input")
        args.output.write_text(text)
        print(json.dumps(report["case_status_counts"], sort_keys=True))
    else:
        print(text, end="")


if __name__ == "__main__":
    main()

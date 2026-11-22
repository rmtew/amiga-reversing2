"""Read-only 68000 timing, trace attribution, and bounded rewrite reports."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from timing import TIMING_KB, m68k_timing


def code_range(value):
    try:
        section, start, length, *label = value.split(":", 3)
        section, start, length = (int(n, 0) for n in (section, start, length))
        if section < 0 or start < 0 or start % 2 or length < 2 or length % 2:
            raise ValueError
    except ValueError as exc:
        raise argparse.ArgumentTypeError("use SECTION:START:LENGTH[:LABEL], with an even byte range") from exc
    return section, start, length, label[0] if label else None


def routine_names(value):
    names = value.split(":")
    if len(names) != 2 or not all(names) or names[0] == names[1]:
        raise argparse.ArgumentTypeError("routine must be START_SYMBOL:END_SYMBOL")
    return tuple(names)


def resolve_routines(exporter, artifact, names):
    result = []
    for first, limit in names:
        raw = subprocess.run([str(exporter), "bounds", str(artifact), first, limit],
                             check=True, capture_output=True, text=True)
        values = json.loads(raw.stdout)
        section, start, length = (values[k] for k in ("section", "start", "length"))
        if (not all(type(n) is int for n in (section, start, length))
                or section < 0 or start < 0 or start % 2 or length < 2 or length % 2):
            raise ValueError("decoder returned invalid named bounds")
        result.append(dict(section=section, start=start, length=length, name=first, end_symbol=limit))
    return result


def code_entry(value):
    try:
        sec, offset = (int(n, 0) for n in value.split(":"))
        if sec < 0 or offset < 0 or offset % 2:
            raise ValueError
    except ValueError as exc:
        raise argparse.ArgumentTypeError("entry must be an aligned SECTION:OFFSET") from exc
    return sec, offset


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decode(exporter, file_format, artifact, ranges):
    instructions = {}
    for section, start, length, label in ranges:
        command = [str(exporter), file_format, str(artifact), str(section), str(start), str(length)]
        out = subprocess.run(command, check=True, capture_output=True, text=True)
        expected = start
        for line in out.stdout.splitlines():
            row = json.loads(line)
            raw = bytes.fromhex(row["bytes"])
            if (row["section"] != section or row["offset"] != expected or
                    len(raw) != row["byte_count"] or len(raw) < 2 or len(raw) % 2 or
                    (section, expected) in instructions):
                raise ValueError("decoder returned an inconsistent or overlapping instruction range")
            row["nominal"] = m68k_timing(row["mnemonic"], raw)
            row["range_label"] = label or f"{section}:{start:#x}+{length:#x}"
            instructions[section, expected] = row
            expected += len(raw)
        if expected != start + length:
            raise ValueError("decoder did not cover the complete requested range")
    return instructions


def join_hunk_profile(rows, profile, artifact_hash):
    # The legacy producer's pc keys are offsets from Hunk 0.
    # Do not guess other layouts or use listing mnemonics to model costs.
    if profile["binary_sha256"] != artifact_hash:
        raise ValueError("profile binary hash differs from the decoded artifact")
    args = profile["machine_args"]
    if "--cpu" not in args or args[args.index("--cpu") + 1:args.index("--cpu") + 2] != ["68000"]:
        raise ValueError("profile is not a 68000 capture")
    sites = {}
    for sample in profile["sites"]:
        key = (0, int(sample["pc"], 16))
        if key in sites:
            raise ValueError("duplicate profile site")
        cost = [sample[k] for k in ("hits", "total", "core", "wait")]
        if any(type(n) is not int or n < 0 for n in cost) or not cost[0] or cost[1] != sum(cost[2:]):
            raise ValueError("invalid profile totals")
        sites[key] = sample

    totals = Counter()
    for key, row in rows.items():
        sample = sites.get(key)
        if sample is None:
            continue
        row["source"] = {k: sample.get(k) for k in ("source", "line", "asm")}
        row["measured"] = {
            "retirements": sample["hits"],
            "core_cck": sample["core"],
            "wait_cck": sample["wait"],
            "elapsed_cck": sample["total"],
        }
        totals.update(sites=1, elapsed_cck=sample["total"])
    return {
        "format": "tank-ranking-v1",
        "config_sha256": profile["config_sha256"],
        "machine_args": args,
        "windows": [w["frame"] for w in profile["windows"]],
        "joined_sites": totals["sites"],
        "profile_sites": len(sites),
        "joined_elapsed_cck": totals["elapsed_cck"],
        "profile_elapsed_cck": sum(s["total"] for s in sites.values()),
    }


def build_report(args):
    digest = sha256(args.artifact)
    named = resolve_routines(args.decoder, args.artifact, args.routine or [])
    ranges = list(args.code or []) + [(item["section"], item["start"], item["length"], item["name"])
                                     for item in named]
    rows = decode(args.decoder, args.input_format, args.artifact, ranges)
    if sha256(args.artifact) != digest:
        raise ValueError("artifact changed while decoding")
    trace = None
    if args.profile:
        if args.input_format != "hunk":
            raise ValueError("Profile join requires the original Hunk executable, not a raw slice")
        trace = join_hunk_profile(rows, json.loads(args.profile.read_text()), digest)
    summaries = {}
    for key, row in rows.items():
        row["site_id"] = f"{digest}:{key[0]}:{key[1]:x}"
        row.setdefault("measured", None)
        name = row["range_label"]
        summary = summaries.setdefault(name, dict(label=name, instructions=0, unknown_timing=0,
                                                observed_sites=0, retirements=0, core_cck=0,
                                                wait_cck=0, elapsed_cck=0))
        summary["instructions"] += 1
        summary["unknown_timing"] += row["nominal"]["kind"] == "unknown"
        if row["measured"]:
            summary["observed_sites"] += 1
            for field in ("retirements", "core_cck", "wait_cck", "elapsed_cck"):
                summary[field] += row["measured"][field]
    order = lambda row: -row["elapsed_cck"]
    sites = list(rows.values())
    if args.action in ("hot", "rank"):
        sites.sort(key=lambda row: order(row["measured"]) if row["measured"] else 0)
    return dict(schema_version=1, cpu="68000", artifact_sha256=digest,
                admission="caller-selected contiguous code ranges; not whole-program code discovery",
                timing_source=TIMING_KB["source"], trace=trace, routines=named, ranges=sorted(summaries.values(), key=order), sites=sites)


def explain(report, contract_path, vasm=None, *, infer=False, normal_flow=False, entries=()):
    from rewrite import _assemble, prove_cmp_minus_one, prove_mulu40
    from liveness import infer_cmp_contract
    from signed_compare import infer_narrow_compare
    if infer:
        from range_inference import infer_mulu40
    explicit = {}
    if contract_path:
        contract = json.loads(contract_path.read_text())
        if contract["artifact_sha256"] != report["artifact_sha256"]:
            raise ValueError("proof contract refers to a different artifact")
        for site in contract["sites"]:
            key = (site["section"], site["offset"])
            if key in explicit:
                raise ValueError("duplicate proof contract")
            if not isinstance(site.get("evidence"), str) or not site["evidence"].strip():
                raise ValueError("site proof contract needs an evidence note")
            explicit[key] = site

    rows = {(row["section"], row["offset"]): row for row in report["sites"]}
    candidates = []
    supported = set()
    named = [(band, {p: insn for p, insn in rows.items()
                    if p[0] == band["section"] and band["start"] <= p[1] <
                    band["start"] + band["length"]})
             for band in report.get("routines", ())]
    for key, row in rows.items():
        raw = row["bytes"].lower()
        if raw not in ("c2fc0028", "0c42ffff") and not (
                infer and row["mnemonic"] == "cmpi" and row.get("size") == "l"):
            continue
        proof = explicit.get(key)
        inference = None
        routine, local = next(((band, subset) for band, subset in named if key in subset),
                              (None, rows))
        local_entries = [p for p in entries if p in local]
        if routine:
            local_entries.insert(0, (routine["section"], routine["start"]))
        if raw == "c2fc0028" and row["mnemonic"] == "mulu":
            rule = "mulu40_bounded"
            if infer and proof is None:
                inference = infer_mulu40(local, key, local_entries, assume_normal_flow=normal_flow)
                if inference["status"] == "verified":
                    proof = inference["contract"]
            item = (dict(status=inference["status"], reason=inference["reason"])
                    if inference and inference["status"] != "verified" else prove_mulu40(proof))
            expected = "3001d241d241d240e749"
            if proof and proof.get("result") == "d1_full":
                expected += "48c1"
        elif raw == "0c42ffff" and row["mnemonic"] == "cmpi":
            successor = rows.get((key[0], key[1] + row["byte_count"]))
            branch = successor["mnemonic"] if successor else None
            if proof and proof.get("following_branch") != branch:
                raise ValueError("proof branch is not the decoded immediate successor")
            rule = "cmp_minus_one_z_only"
            if infer and proof is None:
                inference = infer_cmp_contract(local, key, assume_normal_flow=normal_flow)
                if inference["status"] == "verified":
                    proof = inference["contract"]
            item = (dict(status=inference["status"], reason=inference["reason"])
                    if inference and inference["status"] != "verified"
                    else prove_cmp_minus_one(proof))
            expected = "5242"
        elif infer and row["mnemonic"] == "cmpi" and row.get("size") == "l":
            rule = "signed_compare_after_extend"
            item, expected = infer_narrow_compare(local, key, local_entries, routine=routine,
                                                 assume_normal_flow=normal_flow)
        else:
            continue
        supported.add(key)
        item.update(rule=rule, site_id=row["site_id"],
                    evidence=proof.get("evidence") if proof else item.get("evidence"),
                    measured_ab=None, assembly_check="not_requested")
        if inference is not None:
            item["inference"] = inference
        trace = row["measured"] if "measured" in row else None
        if item["status"] == "verified" and trace:
            delta = item["baseline_cost"]["cpu_clocks"] - item["candidate_cost"]["cpu_clocks"]
            item["ranking"] = {
                "sample_retirements": trace["retirements"],
                "nominal_cpu_clocks_saved_in_sample": delta * trace["retirements"],
                "baseline_wait_cck": trace["wait_cck"],
                "note": "Not predicted Chip wait or measured end-to-end savings.",
            }
        if vasm and item["status"] == "verified":
            before = _assemble(str(vasm.resolve()), item["baseline_assembly"], no_opt=False).hex()
            after = _assemble(str(vasm.resolve()), item["candidate_assembly"], no_opt=False).hex()
            item["assembly_check"] = ("matches_verified_form" if before == raw and after == expected else
                                      "already_emitted" if before == after else "different_encoding")
            item["assembled_baseline"] = before
            item["assembled_candidate"] = after
        candidates.append(item)
    if explicit.keys() - supported:
        raise ValueError("proof contract names a site outside the selected supported forms")
    return sorted(candidates, key=lambda item: (
        item["status"] != "verified",
        -item.get("ranking", {}).get("nominal_cpu_clocks_saved_in_sample", 0),
        item["site_id"],
    ))


def compare(data, *, frames):
    """Present a route verifier's measured receipt without inferring equivalence."""
    n = data["same_full_pages"]
    if type(n) is not int or n != frames or frames < 1:
        raise ValueError("route receipt did not verify the requested number of full pages")
    hashes = [data["baseline_sha"], data["candidate_sha"]]
    if not all(isinstance(x, str) and len(bytes.fromhex(x)) == 32 for x in hashes):
        raise ValueError("invalid route build identities")
    return dict(schema_version=1, kind="verified_route_receipt", baseline_sha256=hashes[0],
                candidate_sha256=hashes[1], same_full_pages=n, machine=data["machine"],
                emulator=data["emulator"], active_mean_ms_saved=data["saved_mean_active_ms"],
                active_median_ms_saved=data["saved_median_active_ms"],
                software_flips_per_second=data["software_flips_per_second"],
                loaded_bytes=data["loaded_bytes"], semantic_equivalence=None)


def nominal_str(rule):
    low, high = rule["min_cpu_clocks"], rule["max_cpu_clocks"]
    if high is None:
        return "unknown"
    if low is None:
        return f"≤{high}"
    return str(low) if low == high else f"{low}–{high}"


def operand_text(operand):
    kind = operand["kind"]
    value = operand["value"]
    if kind in ("dn", "an"):
        return kind[0] + str(operand["register"])
    if kind == "imm":
        return f"#{value:#x}"
    if kind == "label":
        delta = value if value < 2**31 else value - 2**32
        return f"disp {delta:+d}"
    if kind == "ea":
        mode, reg = operand["ea_mode"], operand["ea_reg"]
        if mode < 2:
            return "da"[mode] + str(reg)
        if mode == 7 and reg == 4:
            return f"#{value:#x}"
        return f"ea({mode},{reg})"
    return kind


def human(report, limit):
    result = [f"68000 {report['artifact_sha256'][:12]}  (nominal: CPU clocks; trace: CCK)"]
    trace = report["trace"]
    if trace:
        result.append(f"Joined {trace['joined_sites']}/{trace['profile_sites']} sites from trace windows {trace['windows']}.")
        for item in report["ranges"]:
            result.append(f"{item['label']}: {item['elapsed_cck']} CCK, {item['retirements']} retirements.")
    else:
        result.append("No trace: instruction costs only, no hotspot claim.")
    result.append("Location       Bytes                 Decoded        Nominal   Trace hits / core / wait")
    for row in report["sites"][:limit]:
        m = row["measured"]
        observed = "-" if not m else f"{m['retirements']} / {m['core_cck']} / {m['wait_cck']}"
        mnemonic = row["mnemonic"] + ("." + row["size"] if row.get("size") else "")
        text = mnemonic + " " + ",".join(operand_text(op) for op in row["operands"])
        result.append(f"{row['section']}:{row['offset']:08x}     {row['bytes']:20s}  "
                      f"{text:26s}  {nominal_str(row['nominal']):7s}   {observed}")
    return "\n".join(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("annotate", "hot", "calibrate", "explain", "rank", "compare"))
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--decoder", type=Path)
    parser.add_argument("--code", type=code_range, action="append")
    parser.add_argument("--routine", type=routine_names, action="append",
                        help="admit a contiguous CODE routine by Hunk START:END symbols")
    parser.add_argument("--input-format", default="hunk", choices=("hunk", "raw"))
    parser.add_argument("--profile", type=Path, help="caller-supplied Hunk offset ranking JSON")
    parser.add_argument("--vasm", type=Path)
    parser.add_argument("--contract", type=Path, help="explicit per-site proof contract (explain)")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--limit", default=20, type=int, help="terminal site limit")
    parser.add_argument("--receipt", type=Path, help="caller-supplied route verification JSON (compare)")
    parser.add_argument("--infer", action="store_true", help="infer a supported liveness contract")
    parser.add_argument("--normal-flow", action="store_true",
                        help="scope inference to normal, nonexceptional execution")
    parser.add_argument("--entry", type=code_entry, action="append", default=[],
                        help="admit a single-entry prefix as SECTION:OFFSET (may repeat)")
    parser.add_argument("--frames", type=int, default=256, help="expected verified pages (compare)")
    args = parser.parse_args()
    try:
        if args.action == "calibrate":
            from rewrite import calibrate
            print(json.dumps(calibrate(), indent=2))
            return
        if args.action == "compare":
            if not args.receipt:
                parser.error("compare requires --receipt")
            result = compare(json.loads(args.receipt.read_text()), frames=args.frames)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                before, after = result["software_flips_per_second"]
                size_before, size_after = result["loaded_bytes"]
                print(f"{result['same_full_pages']} matching pages; "
                      f"{result['active_mean_ms_saved']:+.4f} ms/frame mean active saving")
                print(f"Software flips/s {before:.6f} → {after:.6f}; loaded bytes {size_before} → {size_after}")
                print("Measured A/B is not a proof of general semantic equivalence.")
            return
        if args.limit < 1:
            parser.error("--limit must be positive")
        if not args.artifact or not args.decoder or not (args.code or args.routine):
            parser.error("this action requires --artifact, --decoder and --code or --routine")
        if args.routine and args.input_format != "hunk":
            parser.error("--routine requires a native Hunk with symbols")
        args.decoder = args.decoder.resolve()
        args.artifact = args.artifact.resolve()
        result = build_report(args)
        if args.action == "rank" and not args.profile:
            parser.error("rank requires --profile")
        if args.action in ("explain", "rank"):
            auto = args.infer or args.action == "rank"
            result["candidates"] = explain(result, args.contract, args.vasm,
                                           infer=auto, normal_flow=args.normal_flow,
                                           entries=args.entry)
            if auto:
                result["inference_scope"] = {
                    "normal_flow_only": args.normal_flow,
                    "admitted_prefix_entries": args.entry,
                }
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(human(result, args.limit))
            for item in result.get("candidates", [])[:args.limit]:
                if args.action == "rank":
                    rank = item.get("ranking", {})
                    estimate = rank.get("nominal_cpu_clocks_saved_in_sample")
                    extra = "" if estimate is None else f": nominal {estimate:+d} CPU clocks across the sample"
                    location = ":".join(item["site_id"].rsplit(":", 2)[-2:])
                    print(f"{item['status']:10s} {location}  {item['rule']}{extra}")
                    if "reason" in item:
                        print("  " + item["reason"])
                else:
                    print("\n" + json.dumps(item, indent=2))
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as exc:
        detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else exc
        parser.exit(2, f"m68k-cycle: {detail}\n")


if __name__ == "__main__":
    main()

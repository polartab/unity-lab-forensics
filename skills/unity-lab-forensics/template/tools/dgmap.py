#!/usr/bin/env python3
"""Generic, profile-driven IL2CPP -> wasm mapping and literal-tracing driver.

This is the build-agnostic counterpart of the proven DG10 investigation
tool.  All per-experiment facts (input paths, registration addresses,
expected counts, target literal slots, method expectations, field offsets,
rule record) live in a *profile* JSON; this driver only implements the
procedure:

1. parse metadata + wasm, verify the structure counts from the profile;
2. discover ``(base, mask)`` dispatch bases per wasm signature type from the
   disassembly's ``call_indirect`` sites;
3. resolve the profile's methods via
   ``func_index = table[base + (methodPointer & mask)]``;
4. trace the profile's target literals: literal text -> string-literal
   index -> metadata usage destinations -> consuming functions;
5. enumerate field access (both instruction forms, see reference.md) for the
   profile's field offsets;
6. validate the rule record against the experiment's answer config;
7. classify every problem into structure / disassembly / reference errors or
   incomplete inferences, and never print a blanket success conclusion.

Usage:
    python3 dgmap.py --profile profiles/dg10.json [--check] [--json PATH]

Paths in the profile are relative to the profile file's directory unless
absolute.  All reads are read-only; no network access.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import struct
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import il2cpp_metadata as im  # noqa: E402
import wasm_sections as ws  # noqa: E402
from wasm_map_core import (  # noqa: E402
    Memory,
    all_usage_pairs,
    containing_function,
    is_abort_like,
    parse_code_bodies,
    imported_func_count,
    parse_table,
    parse_types,
    parse_disassembly,
    read_pairs,
    resolve_method_mapping,
    slot_consumers,
)

CR_ARRAY_COUNT = 7  # corrected v24.1 Il2CppCodeRegistration field order
MR_ARRAY_COUNT = 8


def load_profile(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        profile = json.load(f)
    base = os.path.dirname(os.path.abspath(path))
    inputs = profile.get("inputs", {})
    resolved: dict[str, str | None] = {}
    for key, value in inputs.items():
        if value is None:
            resolved[key] = None
        elif os.path.isabs(value):
            resolved[key] = value
        else:
            resolved[key] = os.path.normpath(os.path.join(base, value))
    profile["resolved_inputs"] = resolved
    profile["_path"] = path
    return profile


def build_report(profile: dict[str, Any]) -> dict[str, Any]:
    inp = profile["resolved_inputs"]
    wasm_path = inp["wasm"]
    metadata_path = inp["metadata"]
    dis_path = inp.get("disassembly")
    if not wasm_path or not os.path.exists(wasm_path):
        raise FileNotFoundError(f"wasm input missing: {wasm_path}")
    if not metadata_path or not os.path.exists(metadata_path):
        raise FileNotFoundError(f"metadata input missing: {metadata_path}")

    data = open(wasm_path, "rb").read()
    mem = Memory(data)
    meta_bytes = open(metadata_path, "rb").read()
    meta = im.parse_metadata(meta_bytes)
    all_pairs = all_usage_pairs(meta_bytes, meta)
    types = parse_types(data)
    table = parse_table(data)
    bodies = parse_code_bodies(data)
    first_defined_func = imported_func_count(data)
    dis = parse_disassembly(dis_path) if dis_path else {
        "available": False, "functions": [], "dispatch": {}
    }

    reg = profile["registration"]
    if reg.get("code") is None or reg.get("metadata") is None:
        # Registration addresses not located yet (allowed for structural-only
        # profiles): structure facts are still checked, mapping is unavailable.
        cr = mr = None
        cr_fields: dict[str, Any] | None = None
        mr_fields: dict[str, Any] | None = None
        mp_addr: int | None = None
        mu_addr: int | None = None
        types_addr: int | None = None
        types_count: int | None = None
    else:
        cr = read_pairs(mem, reg["code"], CR_ARRAY_COUNT)
        mr = read_pairs(mem, reg["metadata"], MR_ARRAY_COUNT)
        cr_fields = {
            "method_pointers": {"count": cr[0][0], "address": cr[0][1]},
            "reverse_pinvoke_wrappers": {"count": cr[1][0], "address": cr[1][1]},
            "generic_method_pointers": {"count": cr[2][0], "address": cr[2][1]},
            "invoker_pointers": {"count": cr[3][0], "address": cr[3][1]},
            "custom_attribute_generators": {"count": cr[4][0], "address": cr[4][1]},
            "unresolved_virtual_call_pointers": {"count": cr[5][0], "address": cr[5][1]},
            "unresolved_instance_call_pointers": {"count": cr[6][0], "address": cr[6][1]},
        }
        mr_fields = {
            "generic_classes": {"count": mr[0][0], "address": mr[0][1]},
            "generic_insts": {"count": mr[1][0], "address": mr[1][1]},
            "generic_method_table": {"count": mr[2][0], "address": mr[2][1]},
            "types": {"count": mr[3][0], "address": mr[3][1]},
            "method_specs": {"count": mr[4][0], "address": mr[4][1]},
            "field_offsets": {"count": mr[5][0], "address": mr[5][1]},
            "type_definition_sizes": {"count": mr[6][0], "address": mr[6][1]},
            "metadata_usages": {"count": mr[7][0], "address": mr[7][1]},
        }
        mp_addr = cr_fields["method_pointers"]["address"]
        mu_addr = mr_fields["metadata_usages"]["address"]
        types_count = mr_fields["types"]["count"]
        types_addr = mr_fields["types"]["address"]

    type_names = {t["index"]: t["name"] for t in meta["types"]}
    type_full_names = {
        t["index"]: ((t["namespace"] + ".") if t.get("namespace") else "") + t["name"]
        for t in meta["types"]
    }

    # Group the discovered (base, mask) dispatch pairs by wasm signature so
    # resolve_method_mapping can select the right table window per method.
    shape_bases: dict[tuple[tuple[str, ...], tuple[str, ...]], list[tuple[int, int, int]]] = {}
    for typ, pairs in dis.get("dispatch", {}).items():
        params, results = types[int(typ)]
        for base, mask in sorted(pairs):
            shape_bases.setdefault((tuple(params), tuple(results)), []).append(
                (int(typ), int(base), int(mask))
            )

    # --- method resolution -------------------------------------------------
    by_full_name: dict[str, list[dict[str, Any]]] = {}
    by_short_name: dict[str, list[dict[str, Any]]] = {}
    for m in meta["methods"]:
        short = f"{type_names.get(m['declaring_type'], '?')}::{m['name']}"
        full = f"{type_full_names.get(m['declaring_type'], '?')}::{m['name']}"
        by_full_name.setdefault(full, []).append(m)
        by_short_name.setdefault(short, []).append(m)

    def body_for(func_index: int | None) -> bytes | None:
        if func_index is None:
            return None
        idx = func_index - first_defined_func
        if 0 <= idx < len(bodies):
            return bodies[idx]
        return None

    def resolve_one(type_name: str, method_name: str) -> dict[str, Any]:
        full = f"{type_name}::{method_name}"
        entries = (
            by_full_name.get(full)
            or by_short_name.get(full)
            or by_short_name.get(method_name)
            or []
        )
        entry: dict[str, Any] = {
            "type": type_name,
            "method": method_name,
            "found": bool(entries),
        }
        if not entries:
            entry["error"] = f"method {full} not in metadata"
            return entry
        m = entries[0]
        r = resolve_method_mapping(
            mem, table, mp_addr, m, types, shape_bases, type_names, types_addr, types_count
        )
        entry["method_index"] = r["method_index"]
        entry["method_pointer"] = r["method_pointer"]
        entry["return_type"] = r["return_type"]
        candidates = r["candidates"]
        # Prefer a real body over an abort stub; among real bodies prefer the
        # longest (thunks are tiny).  The profile's expected_func, when given,
        # is authoritative for the check.
        scored = []
        for c in candidates:
            body = body_for(c["target"])
            if body is None:
                continue
            scored.append(
                (0 if not is_abort_like(body) else 1, -len(body), c["target"], c)
            )
        scored.sort()
        entry["candidates"] = [c for _, _, _, c in scored]
        entry["resolved_target"] = scored[0][2] if scored else None
        entry["resolved"] = bool(scored)
        return entry

    methods = []
    for spec in profile.get("methods", []):
        if mp_addr is None:
            e = {
                "type": spec["type"],
                "method": spec["method"],
                "found": False,
                "error": "registration addresses not set; method mapping unavailable",
            }
        else:
            e = resolve_one(spec["type"], spec["method"])
        e["expected_func"] = spec.get("expected_func")
        methods.append(e)

    # --- literal tracing ---------------------------------------------------
    lit_by_text: dict[str, list[int]] = {}
    for lit in meta["literals"]:
        lit_by_text.setdefault(lit["text"], []).append(lit["index"])
    pairs_by_destination: dict[int, list[dict[str, int]]] = {}
    if mu_addr is not None:
        for p in all_pairs:
            dest = mem.u32(mu_addr + 4 * p["destination"])
            pairs_by_destination.setdefault(dest, []).append(p)

    literal_report: dict[str, Any] = {}
    for name, expected_slot in (profile.get("target_literals") or {}).items():
        indexes = lit_by_text.get(name, [])
        slots = []
        if mu_addr is not None:
            for p in all_pairs:
                lit = next((x for x in meta["literals"] if x["index"] == p["source_index"]), None)
                if lit and lit["text"] == name:
                    slots.append(mem.u32(mu_addr + 4 * p["destination"]))
        slots = sorted(set(slots))
        consumers = slot_consumers(dis, {name: expected_slot}, dis_path) if dis.get("available") else {}
        literal_report[name] = {
            "expected_slot": expected_slot,
            "literal_indexes": indexes,
            "slots": slots,
            "slot_match": expected_slot in slots,
            "consumers": consumers.get(name, []),
        }

    # --- field access enumeration (both instruction forms) -----------------
    # NOTE: writes through a pointer *parameter* (base held in a local) are
    # invisible to this scan; see reference.md "pointer-parameter writes".
    field_report: dict[str, Any] = {}
    if dis.get("available"):
        lines = open(dis_path, encoding="utf-8", errors="replace").read().splitlines()
        wanted_offsets = {int(v): k for k, v in (profile.get("fields") or {}).items()}
        access_rx = re.compile(
            r"i32\.(load 2|store 2|const|load8_[su] 0|store8 0) (\d+)"
        )

        # single pass: bucket every offset occurrence by field and kind
        buckets: dict[int, dict[str, set[int]]] = {
            off: {k: set() for k in ("load", "store", "addr_take", "load8", "store8")}
            for off in wanted_offsets
        }
        for i, line in enumerate(lines):
            for kind, off in access_rx.findall(line):
                off = int(off)
                if off in buckets:
                    kind_key = {
                        "load 2": "load",
                        "store 2": "store",
                        "const": "addr_take",
                        "load8_s 0": "load8",
                        "load8_u 0": "load8",
                        "store8 0": "store8",
                    }.get(kind, kind)
                    fn = containing_function(dis["functions"], i + 1)
                    if fn:
                        buckets[off][kind_key].add(fn["index"])
        for fname, offset in (profile.get("fields") or {}).items():
            field_report[fname] = {
                "offset": offset,
                **{k: sorted(v) for k, v in buckets[int(offset)].items()},
            }

    return {
        "profile": profile.get("name"),
        "inputs": {k: v for k, v in inp.items()},
        "metadata": {
            "literal_count": meta["literal_count"],
            "type_count": meta["type_count"],
            "method_count": meta["method_count"],
            "pair_count": meta["pair_count"],
            "max_destination": max((p["destination"] for p in all_pairs), default=0),
        },
        "code_registration": cr_fields,
        "metadata_registration": mr_fields,
        "table_size": len(table),
        "type_count_wasm": len(types),
        "dispatch": {
            typ: sorted(pairs)
            for typ, pairs in sorted(dis.get("dispatch", {}).items(), key=lambda kv: int(kv[0]))
        },
        "methods": methods,
        "target_literals": literal_report,
        "field_access": field_report,
    }


def validate_rule_record(
    profile: dict[str, Any],
    base_dir: str,
    errors: list[str],
    profile_errors: list[str],
) -> None:
    """Cross-check the profile's rule record against the answer config.

    A wrong endpoint, index or derived key appends to ``errors`` so the check
    fails instead of passing silently (DG10 acceptance: config-driven rule
    validation).  The per-experiment key format (e.g. DG10's ``a{index}b:``)
    lives in the profile -- the driver never hardcodes one.
    """
    spec = profile.get("rule_record")
    if not spec:
        return
    if spec.get("expected_key") is not None and not spec.get("key_format"):
        profile_errors.append(
            "rule_record.expected_key given without rule_record.key_format; "
            "the key format is per-experiment and must be declared in the profile"
        )
    config_path = spec["config"]
    if not os.path.isabs(config_path):
        config_path = os.path.normpath(os.path.join(base_dir, config_path))
    if not os.path.exists(config_path):
        errors.append(f"rule config missing: {config_path}")
        # the key-format derivation is profile-internal and independent of
        # the config file, so it is still validated below
    else:
        with open(config_path, encoding="utf-8") as f:
            config = json.load(f)
        list_name = spec["list"]
        index = spec["index"]
        records = config.get(list_name)
        if not isinstance(records, list):
            errors.append(f"config list {list_name} missing")
            return
        if index >= len(records):
            errors.append(
                f"rule record index {index} out of range for {list_name} "
                f"(len {len(records)})"
            )
            return
        record = records[index]
        for field, expected in spec.get("record_fields", {}).items():
            if record.get(field) != expected:
                errors.append(
                    f"rule record {list_name}[{index}].{field} "
                    f"{record.get(field)!r} != profile {expected!r}"
                )
    key_format = spec.get("key_format")
    if key_format is not None:
        derived = key_format.format(index=spec["index"])
        if spec.get("expected_key") != derived:
            errors.append(
                f"rule record expected key {spec.get('expected_key')!r} != "
                f"{derived!r} derived from index {spec['index']} via key_format"
            )


KNOWN_EXPECTED_KEYS = {
    "method_count",
    "type_count",
    "literal_count",
    "pair_count",
    "max_destination",
    "table_size",
}


def check(report: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    """Classify every problem; never collapse classes into one verdict.

    Classes:
    * ``structure_errors``   -- build facts contradict the profile;
    * ``disassembly_errors`` -- the disassembly cannot support mapping;
    * ``reference_errors``   -- expectations not confirmed by evidence;
    * ``profile_errors``     -- the profile itself is malformed (unknown
      expected keys, empty check targets, missing key format);
    * ``intermediate_evidence`` -- name/counts/disassembly successes without
      independent disambiguation.  These are recorded, never counted as
      verification.
    """
    structure_errors: list[str] = []
    disassembly_errors: list[str] = []
    reference_errors: list[str] = []
    profile_errors: list[str] = []
    intermediate: list[str] = []

    exp = profile.get("expected") or {}
    md = report["metadata"]
    for key, expected in exp.items():
        if key not in KNOWN_EXPECTED_KEYS:
            profile_errors.append(
                f"unknown expected key {key!r}; known keys: {sorted(KNOWN_EXPECTED_KEYS)}"
            )
            continue
        actual = report["table_size"] if key == "table_size" else md.get(key)
        if actual is None:
            structure_errors.append(f"expected key {key!r} missing from report")
        elif actual != expected:
            structure_errors.append(f"{key} {actual} != {expected}")

    has_targets = bool(
        profile.get("methods")
        or profile.get("target_literals")
        or profile.get("fields")
        or profile.get("rule_record")
    )
    if not has_targets:
        profile_errors.append(
            "profile declares no check targets (methods/target_literals/fields/"
            "rule_record); nothing is verified by this run"
        )

    if not report["dispatch"]:
        disassembly_errors.append("no call_indirect dispatch bases discovered")

    for name, lit in report["target_literals"].items():
        if not lit["literal_indexes"]:
            reference_errors.append(f"literal {name!r} not found in metadata")
        elif not lit["slot_match"]:
            reference_errors.append(
                f"literal {name!r} slots {lit['slots']} do not include "
                f"expected {lit['expected_slot']}"
            )

    for m in report["methods"]:
        label = f"{m['type']}::{m['method']}"
        if not m.get("found"):
            reference_errors.append(f"{label} not found in metadata")
            continue
        if not m.get("resolved"):
            reference_errors.append(
                f"{label}: no candidate maps to a defined body "
                f"({m.get('error') or 'no scored candidate'})"
            )
            continue
        n_candidates = len(m.get("candidates") or [])
        if m.get("expected_func") is None:
            # Name match + heuristic body pick is intermediate evidence only.
            intermediate.append(
                f"{label}: name match, {n_candidates} candidate(s), heuristic "
                f"pick func[{m['resolved_target']}]; no expected_func to "
                "disambiguate -> intermediate evidence, not verified"
            )
        elif m["resolved_target"] != m["expected_func"]:
            reference_errors.append(
                f"{label} resolved to func[{m['resolved_target']}] != "
                f"expected func[{m['expected_func']}]"
            )

    for fname, info in report["field_access"].items():
        if not any(info[k] for k in ("load", "store", "addr_take", "load8", "store8")):
            reference_errors.append(
                f"field {fname} (+{info['offset']}) has no enumerated access sites"
            )
    validate_rule_record(
        profile,
        os.path.dirname(os.path.abspath(profile["_path"])),
        reference_errors,
        profile_errors,
    )

    return {
        "structure_errors": structure_errors,
        "disassembly_errors": disassembly_errors,
        "reference_errors": reference_errors,
        "profile_errors": profile_errors,
        "intermediate_evidence": intermediate,
        "incomplete_inferences": list(profile.get("incomplete_inferences") or []),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--json", metavar="PATH")
    a = ap.parse_args(argv)
    try:
        profile = load_profile(a.profile)
        report = build_report(profile)
    except (FileNotFoundError, ws.WasmFormatError, im.MetadataError, OSError) as e:
        print(f"ERROR: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    check_result = None
    check_failed = False
    if a.check:
        check_result = check(report, profile)
        for label in ("structure_errors", "disassembly_errors", "reference_errors"):
            for e in check_result[label]:
                print(f"{label[:-7].upper()} CHECK FAILED: {e}", file=sys.stderr)
                check_failed = True
        for e in check_result["profile_errors"]:
            print(f"PROFILE CHECK FAILED: {e}", file=sys.stderr)
            check_failed = True
        for e in check_result["intermediate_evidence"]:
            print(f"INTERMEDIATE EVIDENCE (not verified): {e}", file=sys.stderr)
        report["check"] = check_result

    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(f"wrote {a.json}")

    if a.check:
        if check_result["intermediate_evidence"]:
            print(
                f"INTERMEDIATE EVIDENCE: {len(check_result['intermediate_evidence'])} "
                "method(s) matched by name only"
            )
        if check_result["incomplete_inferences"]:
            print("INCOMPLETE INFERENCES:")
            for e in check_result["incomplete_inferences"]:
                print(f"  - {e}")
        if check_failed:
            print(
                "CHECK FAILED: evidence incomplete; no success conclusion.",
                file=sys.stderr,
            )
            return 1
        # A blanket "CHECKS OK" still never claims the scoring logic is
        # proven: it only means no profile expectation was contradicted.
        parts = []
        if check_result["intermediate_evidence"]:
            parts.append(
                f"INTERMEDIATE EVIDENCE PRESENT ({len(check_result['intermediate_evidence'])} method(s) matched by name only)"
            )
        if check_result["incomplete_inferences"]:
            parts.append(
                f"INFERENCES INCOMPLETE ({len(check_result['incomplete_inferences'])} declared)"
            )
        if parts:
            print("CHECKS OK; " + "; ".join(parts))
        else:
            print("CHECKS OK (no open inference declared; verify this is intended)")
    else:
        print(f"profile: {profile.get('name')}")
        print(f"methods resolved: {sum(1 for m in report['methods'] if m.get('resolved'))}"
              f"/{len(report['methods'])}")
        for name, lit in report["target_literals"].items():
            print(
                f"  literal {name!r}: slot={lit['expected_slot']} "
                f"consumers={len(lit['consumers'])}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

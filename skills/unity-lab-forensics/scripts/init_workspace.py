#!/usr/bin/env python3
"""Scaffold a new experiment workspace from the skill template.

Usage:
    python3 init_workspace.py --name dg04 --dir /path/to/unity_analysis/DG04

Creates:
    <dir>/tools/          generic parsers + dgmap driver (copied from template)
    <dir>/tests/          generic parser smoke tests
    <dir>/profiles/<name>.json   profile skeleton to fill in
    <dir>/evidence/       empty evidence directory

The profile skeleton marks every per-experiment fact as TODO: input paths,
registration addresses, expected counts, target literal slots, method
expectations, field offsets, rule record.  Do not guess values -- derive them
following SKILL.md phase 1-2 and record the derivation in evidence notes.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys

TEMPLATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "template")

PROFILE_SKELETON = {
    "name": None,  # TODO: experiment name (e.g. "dg04")
    "inputs": {
        "wasm": None,  # TODO: absolute path to <Build>.wasm.code.unityweb
        "metadata": None,  # TODO: absolute path to global-metadata.dat
        "disassembly": None,  # TODO: absolute path to wasm code disassembly
    },
    "registration": {
        "code": None,  # TODO: Il2CppCodeRegistration address
        "metadata": None,  # TODO: Il2CppMetadataRegistration address
    },
    "expected": {},  # TODO: counts verified in phase 1 (methods/types/literals/pairs/table)
    "target_literals": {},  # TODO: literal text -> expected usage slot
    "methods": [],  # TODO: {"type": ..., "method": ..., "expected_func": ...}
    "fields": {},  # TODO: field name -> byte offset in its class
    "rule_record": None,  # TODO: {"config": ..., "list": ..., "index": ..., ...}
    "incomplete_inferences": [],  # every open inference, kept explicit
}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--name", required=True, help="experiment name, e.g. dg04")
    ap.add_argument("--dir", required=True, help="target workspace directory")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args(argv)

    target = os.path.abspath(a.dir)
    if os.path.exists(target) and os.listdir(target) and not a.force:
        print(f"ERROR: {target} exists and is not empty (use --force)", file=sys.stderr)
        return 2

    os.makedirs(target, exist_ok=True)
    shutil.copytree(
        os.path.join(TEMPLATE, "tools"),
        os.path.join(target, "tools"),
        dirs_exist_ok=True,
    )
    shutil.copytree(
        os.path.join(TEMPLATE, "tests"),
        os.path.join(target, "tests"),
        dirs_exist_ok=True,
    )
    os.makedirs(os.path.join(target, "evidence"), exist_ok=True)
    profiles = os.path.join(target, "profiles")
    os.makedirs(profiles, exist_ok=True)

    skeleton = json.loads(json.dumps(PROFILE_SKELETON))
    skeleton["name"] = a.name
    profile_path = os.path.join(profiles, f"{a.name}.json")
    with open(profile_path, "w", encoding="utf-8") as f:
        json.dump(skeleton, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"workspace ready: {target}")
    print(f"profile skeleton: {profile_path}")
    print("next steps (see SKILL.md):")
    print("  1. extract raw materials -> tools/extract_cache.py, artifact_manifest.py")
    print("  2. fill profile['inputs'] + registration addresses")
    print("  3. produce code disassembly, fill profile['expected']")
    print("  4. resolve methods / literals / fields, fill profile invariants")
    print("  5. python3 tools/dgmap.py --profile profiles/%s.json --check" % a.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

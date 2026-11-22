#!/usr/bin/env python3
"""Intake: classify captured materials, hash them, report what is missing.

Run after the user finishes one manual experiment session and points the
agent at the captured materials:

    python3 intake.py --dir <material-dir> [--hashes-out PATH] [--json PATH]

Behaviour (read-only; original materials are never modified):
* walks the directory (depth-limited) and classifies every file:
  metadata / wasm / HAR / pcap / http-jsonl / cache dirs / screenshots / html;
* computes SHA256 for each found file and writes a hashes file compatible
  with ``sha256sum -c`` (paths relative to --dir, one line per file);
* prints which critical pieces are present/missing and the matching next
  step (extract cache / parse HAR / structural read).

Exit codes: 0 = intake recorded (missing pieces are reported, not fatal);
2 = directory missing.  Without global-metadata.dat, a cache dir, or a HAR
with bodies, analysis cannot start -- the report says so explicitly.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

CHUNK = 1 << 20
MAX_FILE = 4 << 30  # refuse to hash beyond 4 GiB; report instead

CRITICAL = {
    "metadata": "global-metadata.dat (IL2CPP metadata; structural read)",
    "wasm": "*.wasm / *.unityweb (build code; table/type parsing, mapping)",
    "capture_record": "HAR / pcap / http.jsonl (request evidence, wrong payload)",
}


def classify(rel: str, is_dir: bool) -> str:
    name = os.path.basename(rel).lower()
    if is_dir:
        if any(k in name for k in ("cache_data", "cache", "extracted")):
            return "cache_dir"
        return "dir"
    if name == "global-metadata.dat":
        return "metadata"
    if name.endswith((".wasm", ".unityweb")) or ".wasm.code.unityweb" in name:
        return "wasm"
    if name.endswith(".har"):
        return "har"
    if name.endswith((".pcap", ".pcapng")):
        return "pcap"
    if name.endswith(".jsonl") and "http" in name:
        return "http_jsonl"
    if name.endswith((".png", ".jpg", ".jpeg")):
        return "screenshot"
    if name.endswith(".html"):
        return "html"
    if name.endswith((".data", ".unityweb.data", ".assets")):
        return "data_archive"
    return "other"


def sha256_of(path: str) -> str | None:
    size = os.path.getsize(path)
    if size > MAX_FILE:
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(CHUNK)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--hashes-out", default=None)
    ap.add_argument("--json", dest="json_out", default=None)
    a = ap.parse_args(argv)

    root = os.path.abspath(a.dir)
    if not os.path.isdir(root):
        print(f"ERROR: directory missing: {root}", file=sys.stderr)
        return 2

    files: list[dict[str, object]] = []
    hashes_lines: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        rel_dir = os.path.relpath(dirpath, root)
        for fn in sorted(filenames):
            rel = fn if rel_dir == "." else os.path.join(rel_dir, fn)
            full = os.path.join(dirpath, fn)
            kind = classify(rel, False)
            digest = sha256_of(full)
            entry: dict[str, object] = {
                "path": rel,
                "kind": kind,
                "size": os.path.getsize(full),
                "sha256": digest,
            }
            if digest is None:
                entry["note"] = "too large to hash (>4GiB); not hashed"
            files.append(entry)
            if digest is not None:
                hashes_lines.append(f"{digest}  {rel}")
        for dn in list(dirnames):
            rel = dn if rel_dir == "." else os.path.join(rel_dir, dn)
            kind = classify(rel, True)
            if kind == "cache_dir":
                files.append({"path": rel + "/", "kind": kind, "size": None, "sha256": None})

    kinds = {f["kind"] for f in files}
    present = {
        "metadata": "metadata" in kinds,
        "wasm": bool(kinds & {"wasm", "data_archive"}),
        "capture_record": bool(kinds & {"har", "pcap", "http_jsonl"}),
        "cache_dir": "cache_dir" in kinds,
    }
    missing = [name for name, ok in present.items() if not ok and name in CRITICAL]
    warnings: list[str] = []
    if not present["metadata"] and not present["cache_dir"] and not present["capture_record"]:
        warnings.append(
            "none of metadata / cache_dir / capture_record found: analysis cannot start"
        )
    if not present["wasm"]:
        warnings.append(
            "no wasm/unityweb found: table/type parsing and method mapping unavailable"
        )
    if not present["capture_record"]:
        warnings.append(
            "no HAR/pcap/http.jsonl: runtime wrong payload and submit POST cannot be corroborated"
        )

    if a.hashes_out:
        with open(a.hashes_out, "w", encoding="utf-8") as f:
            f.write("\n".join(hashes_lines) + ("\n" if hashes_lines else ""))
        print(f"wrote {a.hashes_out} ({len(hashes_lines)} entries)")

    report = {
        "directory": root,
        "file_count": len(files),
        "kinds_present": sorted(kinds),
        "critical_present": present,
        "missing": missing,
        "warnings": warnings,
        "files": files,
    }
    if a.json_out:
        with open(a.json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(f"wrote {a.json_out}")

    print(f"intake: {len(files)} entries under {root}")
    print(f"critical present: {present}")
    if missing:
        print("missing: " + ", ".join(missing))
    for w in warnings:
        print(f"NOTE: {w}")
    print("next steps:")
    if present["cache_dir"]:
        print("  - extract cache entries: tools/extract_cache.py + tools/artifact_manifest.py")
    if "har" in kinds:
        print("  - HAR provided: parse request/response records, redact tokens before storing")
    if "pcap" in kinds or "http_jsonl" in kinds:
        print("  - capture records: parse HTTP sessions; redact tokens before storing")
    if present["metadata"]:
        print("  - structural read: parse metadata counts, fill profile['expected']")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

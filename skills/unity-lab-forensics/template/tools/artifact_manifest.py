#!/usr/bin/env python3
"""Build a reproducible, evidence-backed artifact manifest for a Unity WebGL lab.

The manifest records every layer rather than only the final file:

1. Chrome Simple Cache container: header, key length, stream-1 body range,
   first/second EOF, stream-0 range, key SHA-256 trailer.
2. HTTP response: status, selected headers, body length/CRC/SHA-256.
3. Decoded payload: gzip/identity, decoded length/SHA-256.
4. Unity container: UnityWebData header/entries, UnityFS blocks/nodes,
   IL2CPP metadata summary and target literals/fields/methods.
5. Duplicate candidates: all candidates are kept; selection is explicit.

No cache entry is modified.  No token/cookie/query value is emitted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from typing import Any

import cache_entry as ce
import il2cpp_metadata as im
import unityfs as ufs
import unitywebdata as uwd
import wasm_sections as ws

SCHEMA = "unity-lab-agent/artifact-manifest/v1"
REDACT_HEADERS = {"set-cookie", "cookie", "authorization", "proxy-authorization"}
KEEP_HEADERS = {
    "content-type",
    "content-encoding",
    "content-length",
    "etag",
    "last-modified",
    "cache-control",
    "accept-ranges",
}
TARGET_NAMES = [
    "pointLineOne",
    "pointLineTwo",
    "pointLineThree",
    "pointLineFour",
    "pointLineFive",
    "pointLineSix",
    "pointLineSeven",
    "pointLineEight",
    "pointLineNine",
    "pointLineTen",
    "pointLineEleven",
    "startName",
    "endName",
    "errorName",
    "JsonDataSHow",
    "wrong",
    "Manager",
    "UIHandler",
    "pointConnectOne",
    "NewConnectJudage",
    "NewConnectJudageTwo",
    "CheckPointAndChangeMehod",
    "NEWConnectThreeLineCheck",
    "ReSubmitMethod",
    "JudgementMethod",
    "JudgementMethodTwo",
    "JudgeMentPost",
    "GiveResultToServer",
]


class ManifestError(Exception):
    pass


def _artifact_kind(url_path: str) -> str:
    base = os.path.basename(url_path)
    if base.endswith(".json"):
        return "json"
    if base == "UnityLoader.js":
        return "loader"
    if base.endswith(".wasm.code.unityweb"):
        return "wasm_code"
    if base.endswith(".wasm.framework.unityweb"):
        return "wasm_framework"
    if base.endswith(".data.unityweb"):
        return "data"
    return "unknown"


def _cache_layer(e: dict[str, Any]) -> dict[str, Any]:
    return {
        "cache_file": e["file_name"],
        "file_size": e["file_size"],
        "mtime_ns": e["mtime_ns"],
        "header": e["header"],
        "key_len": e["header"]["key_len"],
        "key_sha256": e["key_sha256"],
        "key_sha256_trailer_present": e["key_sha256_trailer_present"],
        "body_start": e["body_start"],
        "body_end": e["body_end"],
        "body_len": e["body_len"],
        "body_crc32": e["body_crc32"],
        "body_sha256": e["body_sha256"],
        "first_eof": e["first_eof"],
        "stream0_start": e["stream0_start"],
        "stream0_end": e["stream0_end"],
        "stream0_len": e["stream0_len"],
        "stream0_crc32": e["stream0_crc32"],
        "last_eof": e["last_eof"],
        "warnings": e["warnings"],
    }


def _response_layer(e: dict[str, Any]) -> dict[str, Any]:
    headers = {}
    for k, v in e["headers"].items():
        if k in REDACT_HEADERS:
            headers[k] = "<redacted>"
        elif k in KEEP_HEADERS:
            headers[k] = ce.redact_url(v) if "?" in v else v
    return {
        "status": e["status"],
        "headers": headers,
        "content_length": e["content_length"],
        "content_encoding": e["content_encoding"],
        "decoded_len": e["decoded_len"],
        "decoded_sha256": e["decoded_sha256"],
    }


def _build_json_artifact(decoded: bytes) -> dict[str, Any]:
    try:
        obj = json.loads(decoded)
    except Exception as e:
        raise ManifestError(f"invalid JSON: {e}") from e
    return {
        "valid": True,
        "json_type": type(obj).__name__,
        "top_level_keys": sorted(obj) if isinstance(obj, dict) else None,
        "sha256": hashlib.sha256(decoded).hexdigest(),
        "size": len(decoded),
    }


def _build_wasm_artifact(decoded: bytes) -> dict[str, Any]:
    try:
        info = ws.parse_wasm(decoded)
    except ws.WasmFormatError as e:
        raise ManifestError(f"invalid wasm: {e}") from e
    return {"valid": True, "wasm": info, "sha256": hashlib.sha256(decoded).hexdigest()}


def _build_data_artifact(
    decoded: bytes, *, hash_unityfs_nodes: bool
) -> dict[str, Any]:
    try:
        info = uwd.parse_webdata(decoded, hash_entries=True)
    except uwd.UnityWebDataError as e:
        raise ManifestError(f"invalid UnityWebData: {e}") from e

    result: dict[str, Any] = {
        "valid": True,
        "unitywebdata": info,
        "sha256": hashlib.sha256(decoded).hexdigest(),
        "errors": [],
    }

    by_path = {e["path"]: e for e in info["entries"]}
    meta_entry = by_path.get("Il2CppData/Metadata/global-metadata.dat")
    if not meta_entry:
        result["valid"] = False
        result["errors"].append("missing Il2CppData/Metadata/global-metadata.dat")
    else:
        meta_bytes = decoded[meta_entry["offset"]:meta_entry["end"]]
        try:
            meta = im.parse_metadata(meta_bytes)
            targets = im.find_targets(meta, TARGET_NAMES)
            result["il2cpp_metadata"] = {
                "summary": {
                    k: meta[k]
                    for k in (
                        "sanity",
                        "version",
                        "file_size",
                        "literal_count",
                        "type_count",
                        "field_count",
                        "method_count",
                        "pair_count",
                        "pair_type_counts",
                    )
                },
                "targets": targets,
            }
        except im.MetadataError as e:
            result["valid"] = False
            result["il2cpp_metadata"] = {"error": f"{type(e).__name__}: {e}"}
            result["errors"].append(f"global-metadata.dat: {type(e).__name__}: {e}")

    unity_entry = by_path.get("data.unity3d")
    if not unity_entry:
        result["valid"] = False
        result["errors"].append("missing data.unity3d")
    else:
        bundle_bytes = decoded[unity_entry["offset"]:unity_entry["end"]]
        try:
            bundle = ufs.parse_bundle(
                bundle_bytes,
                keep_data=True,
                hash_nodes=hash_unityfs_nodes,
                strict=True,
            )
            # Keep the structural data but drop the large payload immediately.
            bundle.pop("data", None)
            result["unityfs"] = bundle
        except ufs.UnityFSError as e:
            result["valid"] = False
            result["unityfs"] = {"error": f"{type(e).__name__}: {e}"}
            result["errors"].append(f"data.unity3d: {type(e).__name__}: {e}")
        finally:
            del bundle_bytes

    return result


def _build_artifact(
    kind: str, decoded: bytes, *, hash_unityfs_nodes: bool
) -> dict[str, Any]:
    if kind == "json":
        return _build_json_artifact(decoded)
    if kind == "wasm_code":
        return _build_wasm_artifact(decoded)
    if kind == "data":
        return _build_data_artifact(
            decoded, hash_unityfs_nodes=hash_unityfs_nodes
        )
    if kind in ("loader", "wasm_framework"):
        return {
            "valid": True,
            "kind": kind,
            "size": len(decoded),
            "sha256": hashlib.sha256(decoded).hexdigest(),
            "prefix": decoded[:240].decode("utf-8", "replace"),
        }
    return {
        "valid": True,
        "kind": kind,
        "size": len(decoded),
        "sha256": hashlib.sha256(decoded).hexdigest(),
    }


def _candidate_summary(e: dict[str, Any]) -> dict[str, Any]:
    return {
        "cache_file": e["file_name"],
        "file_size": e["file_size"],
        "mtime_ns": e["mtime_ns"],
        "body_len": e["body_len"],
        "body_sha256": e["body_sha256"],
        "decoded_len": e["decoded_len"],
        "decoded_sha256": e["decoded_sha256"],
        "content_encoding": e["content_encoding"],
        "warnings": e["warnings"],
    }


def build_manifest(
    *,
    cache_dir: str,
    match: str,
    hash_unityfs_nodes: bool = True,
    required_paths: list[str] | None = None,
) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    entries = ce.scan_cache(
        cache_dir,
        match=match,
        errors=errors,
        continue_on_error=True,
    )
    groups: dict[str, list[dict[str, Any]]] = {}
    for e in entries:
        groups.setdefault(e["url_path"], []).append(e)

    artifacts: dict[str, Any] = {}
    duplicate_groups: dict[str, Any] = {}
    missing: list[str] = []
    content_conflicts = 0
    for path in sorted(groups):
        candidates = groups[path]
        sha_values = sorted({e["decoded_sha256"] for e in candidates})
        conflict = len(sha_values) > 1
        if len(candidates) > 1:
            duplicate_groups[path] = {
                "count": len(candidates),
                "candidates": [_candidate_summary(e) for e in candidates],
                "decoded_sha256_values": sha_values,
                "content_conflict": conflict,
            }
        kind = _artifact_kind(path)
        if conflict:
            content_conflicts += 1
            artifact = {
                "url_path": path,
                "url_redacted": candidates[0]["url_redacted"],
                "kind": kind,
                "selection": {
                    "reason": "content_conflict",
                    "selected_cache_file": None,
                    "candidate_count": len(candidates),
                    "decoded_sha256_values": sha_values,
                },
                "cache": None,
                "response": None,
                "artifact": {
                    "valid": False,
                    "error": "duplicate candidates have conflicting decoded content",
                },
            }
            errors.append(
                {
                    "url_path": path,
                    "cache_file": None,
                    "error": "content_conflict: duplicate candidates differ; not auto-selected",
                }
            )
            artifacts[path] = artifact
            continue
        # Deterministic selection by file name; never use mtime to resolve
        # content differences.  Identical duplicates are interchangeable.
        selected = sorted(candidates, key=lambda e: e["file_name"])[0]
        reason = "only_candidate" if len(candidates) == 1 else "identical_content"
        artifact: dict[str, Any] = {
            "url_path": path,
            "url_redacted": selected["url_redacted"],
            "kind": kind,
            "selection": {
                "reason": reason,
                "selected_cache_file": selected["file_name"],
                "candidate_count": len(candidates),
            },
            "cache": _cache_layer(selected),
            "response": _response_layer(selected),
        }
        try:
            artifact["artifact"] = _build_artifact(
                kind,
                selected["decoded"],
                hash_unityfs_nodes=hash_unityfs_nodes,
            )
        except (ManifestError, OSError, ValueError) as e:
            artifact["artifact"] = {"valid": False, "error": f"{type(e).__name__}: {e}"}
            errors.append(
                {
                    "url_path": path,
                    "cache_file": selected["file_name"],
                    "error": f"{type(e).__name__}: {e}",
                }
            )
        artifacts[path] = artifact

    if not artifacts:
        missing.append(f"no entries matched {match!r}")

    for required in required_paths or []:
        found = any(os.path.basename(p) == required for p in groups)
        if not found:
            missing.append(f"required artifact missing: {required}")

    all_artifacts_valid = bool(artifacts) and all(
        isinstance(a.get("artifact"), dict)
        and a["artifact"].get("valid") is True
        for a in artifacts.values()
    )
    valid = not errors and not missing and all_artifacts_valid

    return {
        "schema": SCHEMA,
        "generated_at": None,
        "valid": valid,
        "source": {
            "method": "chrome-simple-cache-read-only",
            "cache_dir": os.path.abspath(cache_dir),
            "match": match,
            "required_paths": list(required_paths or []),
        },
        "summary": {
            "valid": valid,
            "matched_entries": len(entries),
            "artifact_paths": len(artifacts),
            "duplicate_groups": len(duplicate_groups),
            "content_conflicts": content_conflicts,
            "parse_errors": len(errors),
            "missing": missing,
        },
        "duplicates": duplicate_groups,
        "artifacts": artifacts,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--cache-dir",
        default=os.path.expanduser("~/.cache/google-chrome/Default/Cache/Cache_Data"),
    )
    ap.add_argument("--match", default="DG10/Build/")
    ap.add_argument("--out", default="evidence/artifact-manifest-dg10.json")
    ap.add_argument(
        "--no-unityfs-node-hashes",
        action="store_true",
        help="skip hashing the large UnityFS nodes (still validates them)",
    )
    ap.add_argument(
        "--require",
        action="append",
        default=[],
        help="required artifact basename; repeatable",
    )
    a = ap.parse_args(argv)
    required = list(a.require)
    if not required and a.match == "DG10/Build/":
        required = [
            "DG10.json",
            "UnityLoader.js",
            "DG10.wasm.code.unityweb",
            "DG10.wasm.framework.unityweb",
            "DG10.data.unityweb",
        ]
    try:
        manifest = build_manifest(
            cache_dir=a.cache_dir,
            match=a.match,
            hash_unityfs_nodes=not a.no_unityfs_node_hashes,
            required_paths=required,
        )
    except Exception as e:
        print(f"ERROR: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")
    print(f"wrote {a.out}")
    print(json.dumps(manifest["summary"], ensure_ascii=False))
    return 0 if manifest["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

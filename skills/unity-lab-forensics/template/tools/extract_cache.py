#!/usr/bin/env python3
"""Extract Chrome Simple-Cache response bodies by URL substring (read-only).

This is the strict replacement for the old ``body = d[24+klen:]`` extractor.
The response body ends at the first EOF record; the stream-0
``HttpResponseInfo`` pickle and optional key SHA-256 live after it.  Including
those bytes is why the old DG10.json extraction was 887 bytes instead of the
real 451-byte JSON document.

Duplicate cache candidates are never silently overwritten.  If two candidates
map to the same output name, each gets a deterministic ``.__candidate-<sha8>``
suffix.  Existing files are also preserved unless ``--allow-overwrite`` is
explicitly passed.

Usage:
  extract_cache.py --list
  extract_cache.py --match DG10/Build --out /tmp/unity-lab-example/raw/extracted-strict
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys

import cache_entry as ce


def safe_name(url: str) -> str:
    n = url.split("?", 1)[0].split("://", 1)[-1]
    n = re.sub(r"[^A-Za-z0-9._/-]+", "_", n)
    return n.strip("_")[-160:].replace("/", "__")


def _write_candidate(path: str, data: bytes, *, allow_overwrite: bool) -> tuple[str, str]:
    """Write without destroying an existing different file.

    Returns ``(actual_path, status)`` where status is ``written``, ``same`` or
    ``candidate``.
    """
    if os.path.exists(path):
        with open(path, "rb") as f:
            old = f.read()
        if old == data:
            return path, "same"
        if not allow_overwrite:
            digest = hashlib.sha256(data).hexdigest()[:8]
            alt = f"{path}.__candidate-{digest}"
            if os.path.exists(alt):
                with open(alt, "rb") as f:
                    if f.read() == data:
                        return alt, "candidate"
            with open(alt, "wb") as f:
                f.write(data)
            return alt, "candidate"
    with open(path, "wb") as f:
        f.write(data)
    return path, "written"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--cache-dir",
        default=os.path.expanduser("~/.cache/google-chrome/Default/Cache/Cache_Data"),
    )
    ap.add_argument("--match", default="")
    ap.add_argument("--out", default="/tmp/unity-lab-example/raw/extracted-strict")
    ap.add_argument("--list", action="store_true")
    ap.add_argument(
        "--allow-overwrite",
        action="store_true",
        help="replace an existing different output file (default: preserve it)",
    )
    ap.add_argument("--json", action="store_true", help="emit a JSON summary")
    a = ap.parse_args(argv)

    errors: list[dict] = []
    hits = ce.scan_cache(
        a.cache_dir,
        match=a.match or None,
        errors=errors,
        continue_on_error=True,
    )

    if a.list:
        # --list is strictly read-only: no output directory is created and no
        # file is written.
        rows = [
            {
                "cache_file": e["file_name"],
                "url": e["url_redacted"],
                "content_encoding": e["content_encoding"],
                "body_len": e["body_len"],
                "decoded_len": e["decoded_len"],
                "body_sha256": e["body_sha256"],
                "decoded_sha256": e["decoded_sha256"],
            }
            for e in hits
        ]
        if a.json:
            print(
                __import__("json").dumps(
                    {
                        "mode": "list",
                        "matched": len(hits),
                        "errors": errors,
                        "rows": rows,
                    },
                    indent=2,
                    ensure_ascii=False,
                )
            )
        else:
            for e in hits:
                print(
                    f"{e['file_size']:>10}  body={e['body_len']:>9}  "
                    f"dec={e['decoded_len']:>10}  {e['content_encoding']:<8} "
                    f"{e['url_redacted']}"
                )
            print(f"\nmatched={len(hits)} mode=list (no files written)")
            for err in errors:
                print(
                    f"ERROR {err['file_name']}: {err['error']} ({err.get('url_redacted')})",
                    file=sys.stderr,
                )
        return 1 if errors else 0

    os.makedirs(a.out, exist_ok=True)
    rows = []
    counts = {"written": 0, "same": 0, "candidate": 0}
    for e in hits:
        body = e["decoded"]
        name = safe_name(e["url"])
        target = os.path.join(a.out, name)
        actual, status = _write_candidate(
            target, body, allow_overwrite=a.allow_overwrite
        )
        counts[status] += 1
        row = {
            "cache_file": e["file_name"],
            "url": e["url_redacted"],
            "content_encoding": e["content_encoding"],
            "body_len": e["body_len"],
            "decoded_len": e["decoded_len"],
            "body_sha256": e["body_sha256"],
            "decoded_sha256": e["decoded_sha256"],
            "out": actual,
            "status": status,
        }
        rows.append(row)
        if not a.json:
            print(
                f"{e['file_size']:>10}  body={e['body_len']:>9}  "
                f"dec={e['decoded_len']:>10}  {e['content_encoding']:<8} "
                f"{e['url_redacted']}"
            )
            print(f"            -> {actual} ({len(body)} bytes, {status})")

    if a.json:
        print(
            __import__("json").dumps(
                {"matched": len(hits), "counts": counts, "errors": errors, "rows": rows},
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print(f"\nmatched={len(hits)} out={a.out}")
        print(
            "written={written} same={same} candidate={candidate} errors={errors}".format(
                **counts, errors=len(errors)
            )
        )
        for err in errors:
            print(
                f"ERROR {err['file_name']}: {err['error']} ({err.get('url_redacted')})",
                file=sys.stderr,
            )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

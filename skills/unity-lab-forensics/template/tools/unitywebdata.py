#!/usr/bin/env python3
"""Strict parser for Unity's ``UnityWebData1.0`` container.

Layout (all integers little-endian)::

    offset 0   16 bytes  b"UnityWebData1.0\\0"
    offset 16  uint32    header_size (also the first data offset)
    offset 20  entries...
        uint32 offset
        uint32 size
        uint32 path_length
        bytes  path (UTF-8, no NUL)
    offset header_size  first payload byte

The header-size field is the absolute offset of the first payload byte, not a
length relative to offset 20.  DG10's header_size is 270, entries end at 270,
and the first entry starts at 270.

The parser rejects overlapping/out-of-bounds entries and truncated headers.  It
never writes or modifies the source container.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from typing import Any, Iterator

MAGIC = b"UnityWebData1.0\x00"
U32 = struct.Struct("<I")
ENTRY = struct.Struct("<III")


class UnityWebDataError(Exception):
    pass


def parse_webdata(data: bytes, *, hash_entries: bool = True) -> dict[str, Any]:
    if len(data) < 20:
        raise UnityWebDataError(f"file too short for header: {len(data)}")
    if data[:16] != MAGIC:
        raise UnityWebDataError(f"bad magic: {data[:16]!r}")
    header_size = U32.unpack_from(data, 16)[0]
    if header_size < 20 or header_size > len(data):
        raise UnityWebDataError(
            f"header_size {header_size} outside [20, {len(data)}]"
        )

    entries: list[dict[str, Any]] = []
    pos = 20
    while pos < header_size:
        if pos + ENTRY.size > header_size:
            raise UnityWebDataError(
                f"truncated entry header at {pos}: need 12 bytes, have {header_size - pos}"
            )
        off, size, path_len = ENTRY.unpack_from(data, pos)
        pos += ENTRY.size
        if path_len <= 0:
            raise UnityWebDataError(f"entry at {pos - 12} has zero path length")
        if pos + path_len > header_size:
            raise UnityWebDataError(
                f"entry path at {pos} extends past header ({pos + path_len} > {header_size})"
            )
        raw_path = data[pos:pos + path_len]
        pos += path_len
        if b"\x00" in raw_path:
            raise UnityWebDataError(f"entry path contains NUL: {raw_path!r}")
        try:
            path = raw_path.decode("utf-8")
        except UnicodeDecodeError as e:
            raise UnityWebDataError(f"entry path is not UTF-8: {raw_path!r}") from e
        if off < header_size:
            raise UnityWebDataError(
                f"entry {path!r} starts inside header ({off} < {header_size})"
            )
        if size <= 0:
            raise UnityWebDataError(f"entry {path!r} has zero size")
        if off + size > len(data):
            raise UnityWebDataError(
                f"entry {path!r} extends past EOF ({off + size} > {len(data)})"
            )
        entries.append(
            {
                "index": len(entries),
                "path": path,
                "offset": off,
                "size": size,
                "end": off + size,
            }
        )

    if pos != header_size:
        raise UnityWebDataError(
            f"entries end at {pos}, header_size says {header_size}"
        )

    # Validate non-overlap and report ordering.  Unity normally writes entries
    # in increasing offset order, but the format itself does not require it.
    by_offset = sorted(entries, key=lambda e: (e["offset"], e["end"]))
    prev_end = header_size
    for e in by_offset:
        if e["offset"] < prev_end:
            raise UnityWebDataError(
                f"overlapping entry {e['path']!r}: starts {e['offset']}, previous ends {prev_end}"
            )
        prev_end = e["end"]
    warnings: list[str] = []
    if entries and [e["index"] for e in by_offset] != list(range(len(entries))):
        warnings.append("entry order is not increasing by offset")
    if entries and by_offset[0]["offset"] != header_size:
        warnings.append(
            f"first entry starts at {by_offset[0]['offset']}, not header_size {header_size}"
        )

    for e in entries:
        if hash_entries:
            chunk = data[e["offset"]:e["end"]]
            e["sha256"] = hashlib.sha256(chunk).hexdigest()
        # A path is a container-internal relative path; reject traversal.
        p = e["path"].replace("\\", "/")
        if p.startswith("/") or any(part == ".." for part in p.split("/")):
            raise UnityWebDataError(f"unsafe entry path: {e['path']!r}")

    return {
        "magic": MAGIC.decode("ascii").rstrip("\x00"),
        "header_size": header_size,
        "entry_count": len(entries),
        "entries": entries,
        "warnings": warnings,
        "total_size": len(data),
    }


def iter_entries(data: bytes, info: dict[str, Any]) -> Iterator[tuple[dict[str, Any], bytes]]:
    for e in info["entries"]:
        yield e, data[e["offset"]:e["end"]]


def safe_join(out_dir: str, rel: str) -> str:
    rel = rel.replace("\\", "/").lstrip("/")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise UnityWebDataError(f"unsafe path: {rel!r}")
    target = os.path.abspath(os.path.join(out_dir, *parts))
    root = os.path.abspath(out_dir)
    if target != root and not target.startswith(root + os.sep):
        raise UnityWebDataError(f"path escapes output directory: {rel!r}")
    return target


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("file")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--extract", metavar="OUTDIR")
    ap.add_argument("--no-hash", action="store_true")
    a = ap.parse_args(argv)
    with open(a.file, "rb") as f:
        data = f.read()
    try:
        info = parse_webdata(data, hash_entries=not a.no_hash)
    except UnityWebDataError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if a.extract:
        for e, chunk in iter_entries(data, info):
            target = safe_join(a.extract, e["path"])
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as f:
                f.write(chunk)
            print(f"{e['size']:>12}  {e['path']} -> {target}")
    if a.list or not a.extract:
        print(json.dumps(info, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

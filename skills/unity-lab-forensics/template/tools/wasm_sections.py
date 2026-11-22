#!/usr/bin/env python3
"""Strict WebAssembly section-boundary walker.

This is intentionally small: it validates the wasm header, every section length,
and rejects trailing bytes.  It proves only that section boundaries are
consistent; it is *not* full WebAssembly module validation and does not validate
function bodies, types, imports, or data segment semantics.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

MAGIC = b"\x00asm"
SECTION_NAMES = {
    0: "custom",
    1: "type",
    2: "import",
    3: "function",
    4: "table",
    5: "memory",
    6: "global",
    7: "export",
    8: "start",
    9: "element",
    10: "code",
    11: "data",
    12: "data_count",
}


class WasmFormatError(Exception):
    pass


def read_uleb(data: bytes, off: int) -> tuple[int, int]:
    value = 0
    shift = 0
    start = off
    while True:
        if off >= len(data):
            raise WasmFormatError(f"truncated LEB128 at {start}")
        b = data[off]
        off += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            if shift > 63:
                raise WasmFormatError(f"LEB128 too large at {start}")
            return value, off
        shift += 7
        if shift > 63:
            raise WasmFormatError(f"LEB128 too long at {start}")


def parse_wasm(data: bytes) -> dict[str, Any]:
    if len(data) < 8:
        raise WasmFormatError(f"file too short: {len(data)}")
    if data[:4] != MAGIC:
        raise WasmFormatError(f"bad wasm magic: {data[:4]!r}")
    version = int.from_bytes(data[4:8], "little")
    if version != 1:
        raise WasmFormatError(f"unsupported wasm version {version}")
    off = 8
    sections: list[dict[str, Any]] = []
    while off < len(data):
        sid = data[off]
        off += 1
        size, off = read_uleb(data, off)
        payload_off = off
        payload_end = off + size
        if payload_end > len(data):
            raise WasmFormatError(
                f"section {sid} at {payload_off} ends at {payload_end} > {len(data)}"
            )
        if sid not in SECTION_NAMES:
            raise WasmFormatError(f"unknown section id {sid} at {payload_off}")
        if sid == 0:
            # Custom section: name is a LEB128 length followed by UTF-8 bytes.
            if size < 1:
                raise WasmFormatError(f"empty custom section at {payload_off}")
            name_len, p = read_uleb(data, payload_off)
            if p + name_len > payload_end:
                raise WasmFormatError(f"custom section name overruns at {payload_off}")
            try:
                name = data[p:p + name_len].decode("utf-8")
            except UnicodeDecodeError as e:
                raise WasmFormatError(f"custom section name is not UTF-8 at {p}") from e
        else:
            name = SECTION_NAMES[sid]
        sections.append(
            {
                "id": sid,
                "name": name,
                "offset": payload_off,
                "size": size,
                "end": payload_end,
            }
        )
        off = payload_end
    if off != len(data):
        raise WasmFormatError(f"trailing bytes: off={off}, len={len(data)}")
    return {
        "magic": "\\0asm",
        "version": version,
        "size": len(data),
        "section_count": len(sections),
        "sections": sections,
        "validation_scope": "section_boundaries_only",
        "full_module_validation": False,
        "warnings": [],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    with open(a.file, "rb") as f:
        data = f.read()
    try:
        info = parse_wasm(data)
    except WasmFormatError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(info, indent=2))
    else:
        print(
            f"wasm version={info['version']} size={info['size']} "
            f"sections={info['section_count']}"
        )
        for s in info["sections"]:
            print(f"{s['id']:>2} {s['name']:<10} offset={s['offset']:>9} size={s['size']:>9}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

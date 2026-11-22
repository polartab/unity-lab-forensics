#!/usr/bin/env python3
"""Strict UnityFS bundle reader (LZ4/LZ4HC/LZMA/uncompressed).

Usage:
  unityfs.py list  <bundle> [--json]
  unityfs.py extract <bundle> <outdir>

The old prototype silently truncated or zero-padded LZ4 output.  This version
raises ``UnityFSError`` on any overrun, underrun, bad block size, bad node
range, or unknown compression type, so a corrupt bundle cannot be mistaken for
valid evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import os
import struct
import sys
from typing import Any

MAGIC = b"UnityFS\x00"


class UnityFSError(Exception):
    pass


def u32(b: bytes, o: int) -> int:
    if o + 4 > len(b):
        raise UnityFSError(f"u32 read past end at {o}")
    return struct.unpack_from(">I", b, o)[0]


def i64(b: bytes, o: int) -> int:
    if o + 8 > len(b):
        raise UnityFSError(f"i64 read past end at {o}")
    return struct.unpack_from(">q", b, o)[0]


def cstring(b: bytes, o: int, limit: int | None = None) -> tuple[str, int]:
    end = b.find(b"\x00", o, limit if limit is not None else len(b))
    if end < 0:
        raise UnityFSError(f"unterminated string at {o}")
    try:
        s = b[o:end].decode("utf-8")
    except UnicodeDecodeError as e:
        raise UnityFSError(f"invalid UTF-8 string at {o}") from e
    return s, end + 1


def lz4_block_strict(src: bytes, usize: int) -> bytes:
    """Decode one raw LZ4 block, requiring exactly ``usize`` output bytes."""
    out = bytearray()
    i = 0
    n = len(src)
    while i < n:
        token = src[i]
        i += 1
        ll = token >> 4
        if ll == 15:
            while True:
                if i >= n:
                    raise UnityFSError("truncated LZ4 literal length")
                x = src[i]
                i += 1
                ll += x
                if x != 255:
                    break
        if i + ll > n:
            raise UnityFSError(
                f"LZ4 literal overruns input: need {ll}, have {n - i}"
            )
        if len(out) + ll > usize:
            raise UnityFSError("LZ4 literal overruns output size")
        out += src[i:i + ll]
        i += ll
        if i == n:
            break
        if i + 2 > n:
            raise UnityFSError("truncated LZ4 match offset")
        off = src[i] | (src[i + 1] << 8)
        i += 2
        if off == 0 or off > len(out):
            raise UnityFSError(f"invalid LZ4 match offset {off} at output {len(out)}")
        ml = (token & 0x0F) + 4
        if (token & 0x0F) == 15:
            while True:
                if i >= n:
                    raise UnityFSError("truncated LZ4 match length")
                x = src[i]
                i += 1
                ml += x
                if x != 255:
                    break
        if len(out) + ml > usize:
            raise UnityFSError("LZ4 match overruns output size")
        start = len(out) - off
        for k in range(ml):
            out.append(out[start + k])
    if len(out) != usize:
        raise UnityFSError(f"LZ4 output size {len(out)} != expected {usize}")
    return bytes(out)


def decompress_block(data: bytes, usize: int, ctype: int) -> bytes:
    if ctype == 0:
        if len(data) != usize:
            raise UnityFSError(
                f"uncompressed block size {len(data)} != expected {usize}"
            )
        return data
    if ctype in (2, 3):
        return lz4_block_strict(data, usize)
    if ctype == 1:
        if len(data) < 5:
            raise UnityFSError("LZMA block shorter than 5-byte properties")
        props = data[:5]
        try:
            filt = lzma._decode_filter_properties(lzma.FILTER_LZMA1, props)
            dec = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[filt])
            out = dec.decompress(data[5:], max_length=usize)
        except (lzma.LZMAError, ValueError) as e:
            raise UnityFSError(f"LZMA decode failed: {e}") from e
        if len(out) != usize:
            raise UnityFSError(f"LZMA output size {len(out)} != expected {usize}")
        return out
    raise UnityFSError(f"unknown UnityFS compression type {ctype}")


def parse_bundle(
    data: bytes,
    *,
    keep_data: bool = True,
    hash_nodes: bool = False,
    strict: bool = False,
) -> dict[str, Any]:
    if len(data) < 8 or data[:8] != MAGIC:
        raise UnityFSError("not a UnityFS bundle (bad magic)")
    o = 8
    version = u32(data, o)
    o += 4
    unity_version, o = cstring(data, o)
    unity_revision, o = cstring(data, o)
    if o + 20 > len(data):
        raise UnityFSError("truncated UnityFS header")
    declared_size = i64(data, o)
    o += 8
    if declared_size < 0:
        raise UnityFSError(f"negative declared bundle size {declared_size}")
    if declared_size > len(data):
        raise UnityFSError(
            f"declared bundle size {declared_size} exceeds file size {len(data)}"
        )
    if version not in (6, 7, 8):
        raise UnityFSError(f"unsupported UnityFS version {version}")
    compressed_info_size = u32(data, o)
    o += 4
    uncompressed_info_size = u32(data, o)
    o += 4
    flags = u32(data, o)
    o += 4
    ctype = flags & 0x3F
    if ctype not in (0, 1, 2, 3):
        raise UnityFSError(f"unknown bundle compression type {ctype}")
    # Low six bits are compression; bit 0x40 means block/directory info is
    # combined.  Bit 0x80 (blocks info at end) is defined for v7+ but this
    # reader does not implement that layout, so it must reject it rather than
    # silently parse the header as if the blocks info were inline.
    allowed_flags = 0x3F | 0x40
    if flags & 0x80:
        raise UnityFSError(
            "blocks-info-at-end (bundle flag 0x80) is not supported"
        )
    if flags & ~allowed_flags:
        raise UnityFSError(
            f"unsupported bundle flags 0x{flags:08x} for version {version}"
        )
    if compressed_info_size == 0 or o + compressed_info_size > len(data):
        raise UnityFSError(
            f"compressed info size {compressed_info_size} outside file"
        )
    if declared_size and o + compressed_info_size > declared_size:
        raise UnityFSError(
            f"header/info end {o + compressed_info_size} exceeds declared size "
            f"{declared_size}"
        )
    info = decompress_block(
        data[o:o + compressed_info_size], uncompressed_info_size, ctype
    )
    o += compressed_info_size

    if len(info) < 16 + 4:
        raise UnityFSError("decompressed info too short")
    p = 16
    nblocks = u32(info, p)
    p += 4
    if nblocks <= 0 or nblocks > 1_000_000:
        raise UnityFSError(f"implausible block count {nblocks}")
    blocks: list[dict[str, int]] = []
    for i in range(nblocks):
        if p + 10 > len(info):
            raise UnityFSError(f"truncated block info {i}")
        usize = u32(info, p)
        csize = u32(info, p + 4)
        bflags = struct.unpack_from(">H", info, p + 8)[0]
        p += 10
        if usize <= 0 or csize <= 0:
            raise UnityFSError(f"block {i} has zero size")
        if bflags & ~0x3F:
            raise UnityFSError(
                f"block {i} has unsupported flag bits 0x{bflags:04x}"
            )
        btype = bflags & 0x3F
        if btype not in (0, 1, 2, 3):
            raise UnityFSError(f"block {i} has unknown compression {btype}")
        blocks.append(
            {"index": i, "uncompressed_size": usize, "compressed_size": csize,
             "flags": bflags, "compression": btype}
        )
    nnodes = u32(info, p)
    p += 4
    if nnodes <= 0 or nnodes > 1_000_000:
        raise UnityFSError(f"implausible node count {nnodes}")
    nodes: list[dict[str, Any]] = []
    for i in range(nnodes):
        if p + 20 > len(info):
            raise UnityFSError(f"truncated node info {i}")
        off = i64(info, p)
        size = i64(info, p + 8)
        nflags = u32(info, p + 16)
        p += 20
        name, p = cstring(info, p)
        if off < 0 or size < 0:
            raise UnityFSError(f"node {name!r} has negative range")
        nodes.append(
            {"index": i, "offset": off, "size": size, "flags": nflags, "name": name,
             "end": off + size}
        )
    if p != len(info):
        raise UnityFSError(f"{len(info) - p} trailing bytes in decompressed info")

    total_compressed = sum(b["compressed_size"] for b in blocks)
    if o + total_compressed > len(data):
        raise UnityFSError(
            f"block data overruns file: {o + total_compressed} > {len(data)}"
        )
    warnings: list[str] = []
    if declared_size != len(data):
        if strict:
            raise UnityFSError(
                f"declared bundle size {declared_size} != file size {len(data)}"
            )
        warnings.append(
            f"declared bundle size {declared_size} != file size {len(data)}"
        )
    if o + total_compressed < len(data):
        if strict:
            raise UnityFSError(
                f"{len(data) - o - total_compressed} trailing bytes after block data"
            )
        warnings.append(f"{len(data) - o - total_compressed} trailing bytes after block data")

    out = bytearray()
    for b in blocks:
        chunk = data[o:o + b["compressed_size"]]
        o += b["compressed_size"]
        dec = decompress_block(chunk, b["uncompressed_size"], b["compression"])
        out += dec
    max_end = max((n["end"] for n in nodes), default=0)
    if max_end > len(out):
        raise UnityFSError(
            f"node range ends at {max_end}, decompressed data is {len(out)}"
        )
    if keep_data and len(out) < max_end:
        raise UnityFSError("internal error: data shorter than node range")
    if hash_nodes:
        for n in nodes:
            n["sha256"] = hashlib.sha256(out[n["offset"]:n["end"]]).hexdigest()

    result: dict[str, Any] = {
        "magic": "UnityFS",
        "version": version,
        "unity_version": unity_version,
        "unity_revision": unity_revision,
        "declared_size": declared_size,
        "declared_size_matches_file": declared_size == len(data),
        "flags": flags,
        "compression": ctype,
        "compressed_info_size": compressed_info_size,
        "uncompressed_info_size": uncompressed_info_size,
        "block_count": len(blocks),
        "blocks": blocks,
        "node_count": len(nodes),
        "nodes": nodes,
        "decompressed_size": len(out),
        "warnings": warnings,
    }
    if keep_data:
        result["data"] = bytes(out)
    return result


def safe_join(out_dir: str, name: str) -> str:
    rel = name.replace("\\", "/").lstrip("/")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise UnityFSError(f"unsafe node name: {name!r}")
    target = os.path.abspath(os.path.join(out_dir, *parts))
    root = os.path.abspath(out_dir)
    if target != root and not target.startswith(root + os.sep):
        raise UnityFSError(f"node escapes output directory: {name!r}")
    return target


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("cmd", choices=["list", "extract"])
    ap.add_argument("bundle")
    ap.add_argument("outdir", nargs="?")
    ap.add_argument("--json", action="store_true")
    ap.add_argument(
        "--strict",
        action="store_true",
        help="reject declared-size mismatch and trailing bytes",
    )
    a = ap.parse_args(argv)
    with open(a.bundle, "rb") as f:
        data = f.read()
    try:
        b = parse_bundle(
            data,
            keep_data=(a.cmd == "extract"),
            hash_nodes=False,
            strict=a.strict,
        )
    except UnityFSError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if a.cmd == "list":
        if a.json:
            print(json.dumps(b, indent=2, ensure_ascii=False))
        else:
            print(
                f"Unity {b['unity_version']} rev {b['unity_revision']} "
                f"ver {b['version']} flags {b['flags']:#x} "
                f"blocks {b['block_count']} nodes {b['node_count']}"
            )
            for n in b["nodes"]:
                print(f"{n['size']:>12}  {n['offset']:>12}  {n['name']}")
        return 0
    if not a.outdir:
        ap.error("extract requires an output directory")
    os.makedirs(a.outdir, exist_ok=True)
    for n in b["nodes"]:
        target = safe_join(a.outdir, n["name"])
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as f:
            f.write(b["data"][n["offset"]:n["end"]])
        print(f"-> {target} ({n['size']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

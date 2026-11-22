#!/usr/bin/env python3
"""Strict, read-only parser for Chrome's Simple Cache entries.

Chrome's Simple Cache on-disk layout (version 5) is::

    +----------------------+ 0
    | 24-byte header       | magic, version, key_length, key_hash
    +----------------------+
    | key (key_length)     | e.g. "1/0/_dk_http://host http://host/path"
    +----------------------+
    | stream 1 body        | HTTP response body (possibly gzip)
    +----------------------+
    | EOF record (24 B)    | magic, flags=HAS_CRC32, crc32, size=0
    +----------------------+
    | stream 0 body        | HttpResponseInfo pickle (headers)
    +----------------------+
    | optional key SHA-256 | present when flags has HAS_KEY_SHA256
    +----------------------+
    | EOF record (24 B)    | magic, flags=HAS_CRC32|HAS_KEY_SHA256,
    |                      | crc32, stream0_size
    +----------------------+ EOF

The second u32 in an EOF record is a bitmask of flags, not a stream id.
Bit 0 means a CRC32 is present; bit 1 means the 32-byte key SHA-256 trailer
is present.  Treating the value as ``stream_id`` (1/3) is a parsing bug.

The body boundary must be derived from the first EOF record, *not* from
``Content-Length`` and *not* from ``file[24+key_len:]``.  Treating the whole
tail as the body is the bug that produced the old 887-byte DG10.json
extraction (451 bytes JSON + 436 bytes of cache metadata).

This module deliberately fails loudly on malformed/truncated entries.  It never
writes to the cache and never needs the original browser session.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
import zlib
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

CACHE_MAGIC = 0xFCFB6D1BA7725C30
EOF_MAGIC = 0xF4FA6F45970D41D8
# 8-byte magic + version + key length + key hash + 4 bytes of padding = 24.
HEADER = struct.Struct("<QIII4x")
# magic (u64), flags (u32), data_crc32 (u32), stream_size (u64).
EOF = struct.Struct("<QIIQ")
EOF_MAGIC_BYTES = struct.pack("<Q", EOF_MAGIC)
KEY_HASH_SIZE = 32
EOF_FLAG_HAS_CRC32 = 1 << 0
EOF_FLAG_HAS_KEY_SHA256 = 1 << 1
URL_RE = re.compile(rb"https?://\S+$")
HTTP_RE = re.compile(rb"HTTP/\d(?:\.\d)?")
SENSITIVE_HEADERS = {
    "set-cookie",
    "cookie",
    "authorization",
    "proxy-authorization",
    "location",
    "referer",
}


class CacheFormatError(Exception):
    """The entry is not a valid/complete Simple Cache entry."""


class UnsupportedEncoding(CacheFormatError):
    """The response uses an encoding this tool does not decode."""


def redact_url(url: str) -> str:
    """Remove the query component, which may carry tokens or user data."""
    try:
        split = urlsplit(url)
    except Exception:
        return "<unparseable-url>"
    if split.query:
        split = split._replace(query="<redacted>")
    return urlunsplit(split)


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADERS:
            out[key] = "<redacted>"
        else:
            out[key] = redact_url(value) if "://" in value else value
    return out


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def _parse_eof(data: bytes, offset: int) -> dict[str, int]:
    if offset < 0 or offset + EOF.size > len(data):
        raise CacheFormatError(f"EOF record outside file at {offset}")
    magic, flags, crc32, stream_size = EOF.unpack_from(data, offset)
    if magic != EOF_MAGIC:
        raise CacheFormatError(
            f"bad EOF magic at {offset}: 0x{magic:016x} (want 0x{EOF_MAGIC:016x})"
        )
    return {
        "offset": offset,
        "flags": flags,
        "has_crc32": bool(flags & EOF_FLAG_HAS_CRC32),
        "has_key_sha256": bool(flags & EOF_FLAG_HAS_KEY_SHA256),
        "crc32": crc32,
        "stream_size": stream_size,
    }


def _find_last_eof(data: bytes) -> int:
    """Return the offset of the final EOF record.

    Normally the final record ends exactly at EOF.  We allow up to 4 KiB of
    trailing bytes only if the last complete EOF record is still at the end of
    the meaningful region, and we record that fact as a warning by returning
    the offset.  A missing final EOF is a hard error.
    """
    if len(data) < EOF.size:
        raise CacheFormatError(f"file too short for EOF record: {len(data)}")
    off = len(data) - EOF.size
    if data[off:off + 8] == EOF_MAGIC_BYTES:
        return off
    # Be explicit rather than silently accepting a truncated tail.
    search_start = max(0, len(data) - 4096)
    idx = data.rfind(EOF_MAGIC_BYTES, search_start)
    if idx < 0:
        raise CacheFormatError("final EOF record not found in last 4096 bytes")
    if idx + EOF.size != len(data):
        raise CacheFormatError(
            f"final EOF record at {idx} does not end at file end {len(data)}"
        )
    return idx


def _parse_key(key: bytes) -> tuple[str, str]:
    m = URL_RE.search(key)
    if m:
        url = m.group(0).decode("utf-8", "replace")
    else:
        url = key.decode("utf-8", "replace")
    from urllib.parse import urlsplit

    try:
        split = urlsplit(url)
        path = split.path or url
    except Exception:
        path = url
    return url, path


def read_key_only(path: str) -> dict[str, Any]:
    """Read only the fixed header and key.  Used to scan large cache dirs."""
    with open(path, "rb") as f:
        hdr = f.read(HEADER.size)
        if len(hdr) != HEADER.size:
            raise CacheFormatError(f"short header ({len(hdr)} bytes)")
        magic, version, key_len, key_hash = HEADER.unpack(hdr)
        if magic != CACHE_MAGIC:
            raise CacheFormatError(f"bad cache magic 0x{magic:016x}")
        if version != 5:
            raise CacheFormatError(f"unsupported cache version {version}")
        if key_len <= 0 or key_len > 1 << 20:
            raise CacheFormatError(f"implausible key length {key_len}")
        key = f.read(key_len)
        if len(key) != key_len:
            raise CacheFormatError(f"short key: {len(key)}/{key_len}")
    url, url_path = _parse_key(key)
    return {
        "file": os.path.abspath(path),
        "file_name": os.path.basename(path),
        "file_size": os.path.getsize(path),
        "mtime_ns": os.stat(path).st_mtime_ns,
        "version": version,
        "key_len": key_len,
        "key_hash": key_hash,
        "key": key,
        "url": url,
        "url_redacted": redact_url(url),
        "url_path": url_path,
    }


def _parse_http_info(stream0: bytes) -> tuple[str | None, dict[str, str]]:
    """Extract the status line and headers from Chrome's HttpResponseInfo.

    The pickle is not a Python pickle.  The HTTP response info contains a
    NUL-separated block beginning with ``HTTP/1.1 ...``.  We locate that block
    and parse only printable ASCII header lines; binary pickle bytes are
    ignored.
    """
    m = HTTP_RE.search(stream0)
    if not m:
        return None, {}
    start = m.start()
    parts = stream0[start:].split(b"\0")
    status = parts[0].decode("latin-1", "replace").strip()
    headers: dict[str, str] = {}
    for part in parts[1:]:
        if not part:
            break
        if b":" not in part:
            continue
        k, v = part.split(b":", 1)
        key = k.decode("latin-1", "replace").strip().lower()
        val = v.decode("latin-1", "replace").strip()
        if not key or not all(32 <= ord(c) < 127 for c in key):
            continue
        headers[key] = val
    return status, headers


def decompress_gzip_strict(data: bytes) -> bytes:
    """Decode one or more complete gzip members and reject trailing garbage."""
    if not data.startswith(b"\x1f\x8b"):
        raise CacheFormatError("gzip body does not start with 1f 8b")
    out = bytearray()
    pos = 0
    members = 0
    while pos < len(data):
        if data[pos:pos + 2] != b"\x1f\x8b":
            raise CacheFormatError(f"trailing non-gzip bytes at {pos}")
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            chunk = d.decompress(data[pos:]) + d.flush()
        except zlib.error as e:
            raise CacheFormatError(f"gzip member at {pos} is invalid: {e}") from e
        if not d.eof:
            raise CacheFormatError(f"gzip member at {pos} is truncated")
        consumed = len(data) - pos - len(d.unused_data)
        if consumed <= 0:
            raise CacheFormatError(f"gzip member at {pos} consumed no bytes")
        out += chunk
        pos += consumed
        members += 1
    if members == 0:
        raise CacheFormatError("empty gzip body")
    return bytes(out)


def _decode_response(body: bytes, headers: dict[str, str]) -> tuple[str, bytes, list[str]]:
    warnings: list[str] = []
    enc = (headers.get("content-encoding") or "").strip().lower()
    if enc in ("gzip", "x-gzip"):
        return "gzip", decompress_gzip_strict(body), warnings
    if enc in ("", "identity"):
        if body.startswith(b"\x1f\x8b"):
            warnings.append("body has gzip magic but no Content-Encoding header; decoded as gzip")
            return "gzip", decompress_gzip_strict(body), warnings
        return "identity", body, warnings
    raise UnsupportedEncoding(f"unsupported Content-Encoding: {enc!r}")


def parse_entry(path: str, *, validate_crc: bool = True, decode: bool = True) -> dict[str, Any]:
    """Parse one cache entry.

    Returns a dictionary.  The response body is under ``body`` (exact stream 1
    bytes) and the decoded payload under ``decoded``.  Every structural check
    that can be performed offline is performed; failures raise
    ``CacheFormatError``.
    """
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < HEADER.size + 1:
        raise CacheFormatError(f"file too short: {len(data)}")
    magic, version, key_len, key_hash = HEADER.unpack_from(data, 0)
    if magic != CACHE_MAGIC:
        raise CacheFormatError(f"bad cache magic 0x{magic:016x}")
    if version != 5:
        raise CacheFormatError(f"unsupported cache version {version}")
    if key_len <= 0 or key_len > 1 << 20:
        raise CacheFormatError(f"implausible key length {key_len}")
    body_start = HEADER.size + key_len
    if body_start > len(data):
        raise CacheFormatError("key extends past end of file")
    key = data[HEADER.size:body_start]
    url, url_path = _parse_key(key)

    last_eof_off = _find_last_eof(data)
    last_eof = _parse_eof(data, last_eof_off)
    if last_eof["stream_size"] <= 0:
        raise CacheFormatError("final EOF has zero stream-0 size")

    key_sha = hashlib.sha256(key).digest()
    key_sha_present = bool(last_eof["flags"] & EOF_FLAG_HAS_KEY_SHA256)
    if key_sha_present:
        if last_eof_off < KEY_HASH_SIZE:
            raise CacheFormatError(
                "final EOF claims HAS_KEY_SHA256 but file is too short for trailer"
            )
        trailer = data[last_eof_off - KEY_HASH_SIZE:last_eof_off]
        if trailer != key_sha:
            raise CacheFormatError(
                "final EOF has HAS_KEY_SHA256 but trailer != sha256(key)"
            )
        stream0_end = last_eof_off - KEY_HASH_SIZE
    else:
        stream0_end = last_eof_off
    stream0_start = stream0_end - last_eof["stream_size"]
    if stream0_start < body_start:
        raise CacheFormatError(
            f"stream 0 starts before body start ({stream0_start} < {body_start})"
        )
    stream0 = data[stream0_start:stream0_end]
    if len(stream0) != last_eof["stream_size"]:
        raise CacheFormatError("short stream-0 body")
    if validate_crc:
        if not (last_eof["flags"] & EOF_FLAG_HAS_CRC32):
            raise CacheFormatError("final EOF has no HAS_CRC32 flag")
        got = zlib.crc32(stream0) & 0xFFFFFFFF
        if got != last_eof["crc32"]:
            raise CacheFormatError(
                f"stream-0 CRC mismatch: 0x{got:08x} != 0x{last_eof['crc32']:08x}"
            )

    first_eof_off = stream0_start - EOF.size
    if first_eof_off < body_start:
        raise CacheFormatError(
            f"first EOF starts before body start ({first_eof_off} < {body_start})"
        )
    first_eof = _parse_eof(data, first_eof_off)
    body_end = first_eof_off
    if body_end < body_start:
        raise CacheFormatError(f"body end before start ({body_end} < {body_start})")
    body = data[body_start:body_end]
    if validate_crc:
        if not (first_eof["flags"] & EOF_FLAG_HAS_CRC32):
            raise CacheFormatError("first EOF has no HAS_CRC32 flag")
        got = zlib.crc32(body) & 0xFFFFFFFF
        if got != first_eof["crc32"]:
            raise CacheFormatError(
                f"stream-1 CRC mismatch: 0x{got:08x} != 0x{first_eof['crc32']:08x}"
            )

    status, headers = _parse_http_info(stream0)
    warnings: list[str] = []
    if first_eof_off + EOF.size != stream0_start:
        warnings.append(
            f"gap between first EOF and stream 0: {stream0_start - first_eof_off - EOF.size} bytes"
        )
    if key_sha_present:
        pass
    elif stream0_end != last_eof_off:
        warnings.append("non-empty bytes before final EOF are not the key SHA-256")

    encoding = "identity"
    decoded = body
    if decode:
        encoding, decoded, dec_warnings = _decode_response(body, headers)
        warnings.extend(dec_warnings)

    cl = headers.get("content-length")
    content_length = None
    if cl and cl.isdigit():
        content_length = int(cl)
        if content_length != len(body):
            warnings.append(
                f"Content-Length {content_length} != stream-1 body length {len(body)}"
            )

    return {
        "file": os.path.abspath(path),
        "file_name": os.path.basename(path),
        "file_size": len(data),
        "mtime_ns": os.stat(path).st_mtime_ns,
        "header": {
            "magic": f"0x{magic:016x}",
            "version": version,
            "key_len": key_len,
            "key_hash": key_hash,
        },
        "key": key,
        "key_sha256": hashlib.sha256(key).hexdigest(),
        "key_sha256_trailer_present": key_sha_present,
        "url": url,
        "url_redacted": redact_url(url),
        "url_path": url_path,
        "body_start": body_start,
        "body_end": body_end,
        "body_len": len(body),
        "body_crc32": f"0x{zlib.crc32(body) & 0xFFFFFFFF:08x}",
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "first_eof": first_eof,
        "stream0_start": stream0_start,
        "stream0_end": stream0_end,
        "stream0_len": len(stream0),
        "stream0_crc32": f"0x{zlib.crc32(stream0) & 0xFFFFFFFF:08x}",
        "last_eof": last_eof,
        "status": status,
        "headers": headers,
        "content_length": content_length,
        "content_encoding": encoding,
        "decoded_len": len(decoded),
        "decoded_sha256": hashlib.sha256(decoded).hexdigest(),
        "warnings": warnings,
        "body": body,
        "decoded": decoded,
    }


def strip_payload(entry: dict[str, Any]) -> dict[str, Any]:
    """Return a JSON-serialisable, redacted copy without byte payloads."""
    out = dict(entry)
    out.pop("body", None)
    out.pop("decoded", None)
    out.pop("key", None)
    out["url"] = redact_url(str(out.get("url", "")))
    headers = out.get("headers")
    if isinstance(headers, dict):
        out["headers"] = redact_headers({str(k): str(v) for k, v in headers.items()})
    return out


def scan_cache(
    cache_dir: str,
    *,
    match: str | None = None,
    url_path: str | None = None,
    validate_crc: bool = True,
    decode: bool = True,
    errors: list[dict[str, Any]] | None = None,
    continue_on_error: bool = False,
) -> list[dict[str, Any]]:
    """Scan a Chrome cache directory and return parsed matching entries.

    Entries are sorted by URL then by cache file name so duplicate candidates
    are deterministic.  With ``continue_on_error`` a malformed matching entry
    is recorded in ``errors`` (if supplied) and skipped; otherwise the first
    malformed entry raises.
    """
    hits: list[dict[str, Any]] = []
    for name in sorted(os.listdir(cache_dir)):
        path = os.path.join(cache_dir, name)
        if not os.path.isfile(path):
            continue
        try:
            meta = read_key_only(path)
        except (CacheFormatError, OSError):
            continue
        if match and match not in meta["url"]:
            continue
        if url_path is not None and meta["url_path"] != url_path:
            continue
        try:
            entry = parse_entry(path, validate_crc=validate_crc, decode=decode)
        except (CacheFormatError, OSError) as e:
            if errors is not None:
                errors.append(
                    {
                        "file": os.path.abspath(path),
                        "file_name": os.path.basename(path),
                        "url_redacted": meta.get("url_redacted"),
                        "error": f"{type(e).__name__}: {e}",
                    }
                )
            if continue_on_error:
                continue
            raise
        hits.append(entry)
    hits.sort(key=lambda e: (e["url_path"], e["url"], e["file_name"]))
    return hits


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--cache-dir",
        default=os.path.expanduser("~/.cache/google-chrome/Default/Cache/Cache_Data"),
    )
    ap.add_argument("--match", default=None, help="substring of the URL")
    ap.add_argument("--url-path", default=None, help="exact URL path")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--json", action="store_true", help="print JSON manifest")
    ap.add_argument("--no-crc", action="store_true")
    a = ap.parse_args(argv)
    try:
        entries = scan_cache(
            a.cache_dir,
            match=a.match,
            url_path=a.url_path,
            validate_crc=not a.no_crc,
        )
    except CacheFormatError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps([strip_payload(e) for e in entries], indent=2, ensure_ascii=False))
        return 0
    for e in entries:
        print(
            f"{e['file_size']:>10}  body={e['body_len']:>9}  "
            f"{e['content_encoding']:<8} {e['url_redacted']}"
        )
    print(f"\nmatched={len(entries)} cache_dir={a.cache_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

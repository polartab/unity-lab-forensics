#!/usr/bin/env python3
"""Minimal, strict reader for Unity IL2CPP ``global-metadata.dat`` v24.1.

This is not a full Il2CppDumper replacement.  It extracts the sections needed to
link DG10's JSON keys, C# field names, and candidate judging methods to concrete
metadata offsets:

* string table and string literals (including literal index + data offset)
* type definitions (v24.1 100-byte records)
* field definitions (12-byte records)
* method definitions (v24.1 52-byte records)
* metadata-usage pairs for string literals

The struct layouts were verified empirically against DG10:
``typeDefinitionsSize=380600=3806*100``,
``fieldsSize=198888=16574*12``, and
``methodsSize=1215448=23374*52``.  All offsets are file offsets into
``global-metadata.dat``.
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from collections import Counter
from typing import Any

MAGIC = 0xFAB11BAF
TYPE_SIZE = 100
FIELD_SIZE = 12
METHOD_SIZE = 52
LITERAL_SIZE = 8
PAIR_SIZE = 8

# v24.1 header field offsets (byte offsets into the header).
H = {
    "string_literal": (8, 12),
    "string_literal_data": (16, 20),
    "string": (24, 28),
    "events": (32, 36),
    "properties": (40, 44),
    "methods": (48, 52),
    "parameter_default_values": (56, 60),
    "field_default_values": (64, 68),
    "field_and_parameter_default_value_data": (72, 76),
    "field_marshaled_sizes": (80, 84),
    "parameters": (88, 92),
    "fields": (96, 100),
    "generic_parameters": (104, 108),
    "generic_parameter_constraints": (112, 116),
    "generic_containers": (120, 124),
    "nested_types": (128, 132),
    "interfaces": (136, 140),
    "vtable_methods": (144, 148),
    "interface_offsets": (152, 156),
    "type_definitions": (160, 164),
    "rgctx_entries": (168, 172),
    "images": (176, 180),
    "assemblies": (184, 188),
    "metadata_usage_lists": (192, 196),
    "metadata_usage_pairs": (200, 204),
    "field_refs": (208, 212),
    "referenced_assemblies": (216, 220),
    "attributes_info": (224, 228),
    "attribute_types": (232, 236),
    "unresolved_virtual_call_parameter_types": (240, 244),
    "unresolved_virtual_call_parameter_ranges": (248, 252),
    "windows_runtime_type_names": (256, 260),
    "windows_runtime_strings": (264, 268),
}


class MetadataError(Exception):
    pass


def _u32(data: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(data):
        raise MetadataError(f"u32 out of range at {off}")
    return struct.unpack_from("<I", data, off)[0]


def _i32(data: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(data):
        raise MetadataError(f"i32 out of range at {off}")
    return struct.unpack_from("<i", data, off)[0]


def _check_section(data: bytes, off: int, size: int, name: str) -> None:
    if off < 0 or size < 0 or off + size > len(data):
        raise MetadataError(
            f"section {name} outside file: off={off} size={size} file={len(data)}"
        )


def parse_metadata(data: bytes) -> dict[str, Any]:
    if len(data) < 272:
        raise MetadataError(f"metadata too short: {len(data)}")
    sanity = _u32(data, 0)
    version = _i32(data, 4)
    if sanity != MAGIC:
        raise MetadataError(f"bad sanity 0x{sanity:08x}")
    if version != 24:
        raise MetadataError(f"unsupported metadata version {version} (expected 24)")

    sections: dict[str, dict[str, int]] = {}
    for name, (off_field, size_field) in H.items():
        off = _i32(data, off_field)
        size = _i32(data, size_field)
        _check_section(data, off, size, name)
        sections[name] = {"offset": off, "size": size}

    # String table.
    str_off = sections["string"]["offset"]
    str_size = sections["string"]["size"]
    strings = data[str_off:str_off + str_size]

    def get_string(idx: int) -> str | None:
        if idx < 0 or idx >= str_size:
            return None
        end = strings.find(b"\x00", idx)
        if end < 0:
            raise MetadataError(f"unterminated string at table index {idx}")
        try:
            return strings[idx:end].decode("utf-8")
        except UnicodeDecodeError:
            return strings[idx:end].decode("utf-8", "replace")

    # String literals.
    lit_off = sections["string_literal"]["offset"]
    lit_size = sections["string_literal"]["size"]
    lit_data_off = sections["string_literal_data"]["offset"]
    lit_data_size = sections["string_literal_data"]["size"]
    if lit_size % LITERAL_SIZE:
        raise MetadataError(f"string literal size {lit_size} not divisible by 8")
    literals: list[dict[str, Any]] = []
    for i in range(lit_size // LITERAL_SIZE):
        length, data_idx = struct.unpack_from("<II", data, lit_off + i * LITERAL_SIZE)
        if data_idx + length > lit_data_size:
            raise MetadataError(
                f"literal {i} data range {data_idx}+{length} > {lit_data_size}"
            )
        raw = data[lit_data_off + data_idx:lit_data_off + data_idx + length]
        literals.append(
            {
                "index": i,
                "length": length,
                "data_index": data_idx,
                "data_offset": lit_data_off + data_idx,
                "record_offset": lit_off + i * LITERAL_SIZE,
                "text": raw.decode("utf-8", "replace"),
            }
        )

    # Types.
    type_off = sections["type_definitions"]["offset"]
    type_size = sections["type_definitions"]["size"]
    if type_size % TYPE_SIZE:
        raise MetadataError(f"typeDefinitionsSize {type_size} not divisible by {TYPE_SIZE}")
    ntypes = type_size // TYPE_SIZE
    types: list[dict[str, Any]] = []
    for i in range(ntypes):
        rec = struct.unpack_from("<" + "i" * 25, data, type_off + i * TYPE_SIZE)
        name = get_string(rec[0])
        ns = get_string(rec[1])
        if name is None or ns is None:
            raise MetadataError(f"type {i} has invalid name/namespace index")
        method_count = rec[19] & 0xFFFF
        property_count = (rec[19] >> 16) & 0xFFFF
        field_count = rec[20] & 0xFFFF
        event_count = (rec[20] >> 16) & 0xFFFF
        types.append(
            {
                "index": i,
                "record_offset": type_off + i * TYPE_SIZE,
                "name": name,
                "namespace": ns,
                "field_start": rec[11],
                "method_start": rec[12],
                "method_count": method_count,
                "property_count": property_count,
                "field_count": field_count,
                "event_count": event_count,
                "flags": rec[10],
                "token": rec[24] if len(rec) > 24 else None,
            }
        )

    # Fields.
    field_off = sections["fields"]["offset"]
    field_size = sections["fields"]["size"]
    if field_size % FIELD_SIZE:
        raise MetadataError(f"fieldsSize {field_size} not divisible by {FIELD_SIZE}")
    nfields = field_size // FIELD_SIZE
    fields: list[dict[str, Any]] = []
    for i in range(nfields):
        name_idx, type_idx, token = struct.unpack_from(
            "<III", data, field_off + i * FIELD_SIZE
        )
        name = get_string(name_idx)
        if name is None:
            raise MetadataError(f"field {i} has invalid name index")
        fields.append(
            {
                "index": i,
                "record_offset": field_off + i * FIELD_SIZE,
                "name": name,
                "type_index": type_idx,
                "token": token,
            }
        )

    # Methods.
    method_off = sections["methods"]["offset"]
    method_size = sections["methods"]["size"]
    if method_size % METHOD_SIZE:
        raise MetadataError(f"methodsSize {method_size} not divisible by {METHOD_SIZE}")
    nmethods = method_size // METHOD_SIZE
    methods: list[dict[str, Any]] = []
    for i in range(nmethods):
        rec = struct.unpack_from("<" + "i" * 13, data, method_off + i * METHOD_SIZE)
        name = get_string(rec[0])
        if name is None:
            raise MetadataError(f"method {i} has invalid name index")
        token = _u32(data, method_off + i * METHOD_SIZE + 40)
        flags, iflags, slot, pcount = struct.unpack_from(
            "<HHHH", data, method_off + i * METHOD_SIZE + 44
        )
        methods.append(
            {
                "index": i,
                "method_definition_index": i,
                "record_offset": method_off + i * METHOD_SIZE,
                "file_offset": method_off + i * METHOD_SIZE,
                "name": name,
                "declaring_type": rec[1],
                "return_type": rec[2],
                "parameter_start": rec[3],
                "generic_container": rec[4],
                "method_index": rec[5],
                "invoker_index": rec[6],
                "reverse_pinvoke_wrapper_index": rec[7],
                "rgctx_start_index": rec[8],
                "rgctx_count": rec[9],
                "function_table_slot": None,
                "wasm_function_index": None,
                "runtime_memory_address": None,
                "token": token,
                "flags": flags,
                "iflags": iflags,
                "slot": slot,
                "parameter_count": pcount,
            }
        )

    # Metadata usage pairs: each record is
    #   destinationIndex (u32), encodedSourceIndex (u32)
    # where encodedSourceIndex = (usageType << 29) | sourceIndex.
    # There is no +4 alignment word and no stream-id-like second field.
    pairs_off = sections["metadata_usage_pairs"]["offset"]
    pairs_size = sections["metadata_usage_pairs"]["size"]
    if pairs_size % PAIR_SIZE:
        raise MetadataError(f"metadataUsagePairsSize {pairs_size} not divisible by 8")
    pair_count = pairs_size // PAIR_SIZE
    if pairs_off + pair_count * PAIR_SIZE > len(data):
        raise MetadataError("metadata usage pair table runs past end of file")
    pair_types: Counter = Counter()
    string_usage_pairs: list[dict[str, Any]] = []
    for i in range(pair_count):
        destination, encoded = struct.unpack_from(
            "<II", data, pairs_off + i * PAIR_SIZE
        )
        typ = encoded >> 29
        idx = encoded & 0x1FFFFFFF
        if typ > 6:
            raise MetadataError(
                f"metadata usage pair {i} has unknown type {typ} at "
                f"0x{pairs_off + i * PAIR_SIZE:x}"
            )
        pair_types[typ] += 1
        if typ == 5:
            string_usage_pairs.append(
                {
                    "index": i,
                    "pair_offset": pairs_off + i * PAIR_SIZE,
                    "literal_index": idx,
                    "destination": destination,
                }
            )

    return {
        "sanity": f"0x{sanity:08x}",
        "version": version,
        "file_size": len(data),
        "sections": sections,
        "string_count": str_size,
        "literal_count": len(literals),
        "type_count": ntypes,
        "field_count": nfields,
        "method_count": nmethods,
        "pair_count": pair_count,
        "pair_type_counts": dict(pair_types),
        "string_usage_pairs": string_usage_pairs,
        "types": types,
        "fields": fields,
        "methods": methods,
        "literals": literals,
    }


def find_targets(meta: dict[str, Any], names: list[str]) -> dict[str, Any]:
    literal_by_text: dict[str, list[dict[str, Any]]] = {}
    for lit in meta["literals"]:
        literal_by_text.setdefault(lit["text"], []).append(lit)
    usage_by_literal: dict[int, list[int]] = {}
    for p in meta["string_usage_pairs"]:
        usage_by_literal.setdefault(p["literal_index"], []).append(p["destination"])

    target_types = []
    for t in meta["types"]:
        if t["name"] in names or t["namespace"] in names:
            target_types.append(t)

    target_fields = []
    for f in meta["fields"]:
        if f["name"] in names:
            target_fields.append(f)

    target_methods = []
    for m in meta["methods"]:
        if m["name"] in names:
            target_methods.append(m)

    literals = []
    for name in names:
        for lit in literal_by_text.get(name, []):
            literals.append(
                {
                    "text": name,
                    "literal_index": lit["index"],
                    "record_offset": lit["record_offset"],
                    "data_index": lit["data_index"],
                    "data_offset": lit["data_offset"],
                    "usage_destinations": sorted(set(usage_by_literal.get(lit["index"], []))),
                }
            )

    # Attach declaring type names to fields/methods.
    def type_name(idx: int) -> str | None:
        if 0 <= idx < len(meta["types"]):
            t = meta["types"][idx]
            return (t["namespace"] + "." if t["namespace"] else "") + t["name"]
        return None

    for f in target_fields:
        owner = None
        for t in meta["types"]:
            if t["field_start"] <= f["index"] < t["field_start"] + t["field_count"]:
                owner = t
                break
        f["declaring_type"] = (
            (owner["namespace"] + "." if owner["namespace"] else "") + owner["name"]
            if owner
            else None
        )
    for m in target_methods:
        m["declaring_type_name"] = type_name(m["declaring_type"])

    return {
        "names": names,
        "literals": literals,
        "types": target_types,
        "fields": target_fields,
        "methods": target_methods,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true")
    ap.add_argument(
        "--names",
        default="pointLineOne,pointLineTwo,pointLineThree,startName,endName,errorName,JsonDataSHow,wrong",
    )
    a = ap.parse_args(argv)
    with open(a.file, "rb") as f:
        data = f.read()
    try:
        meta = parse_metadata(data)
    except MetadataError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    names = [x.strip() for x in a.names.split(",") if x.strip()]
    targets = find_targets(meta, names)
    if a.json:
        print(
            json.dumps(
                {
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
                },
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print(
            f"metadata v{meta['version']} size={meta['file_size']} "
            f"types={meta['type_count']} fields={meta['field_count']} "
            f"methods={meta['method_count']} literals={meta['literal_count']} "
            f"pairs={meta['pair_count']}"
        )
        print("literal targets:")
        for lit in targets["literals"]:
            print(
                f"  {lit['text']!r} index={lit['literal_index']} "
                f"data_offset=0x{lit['data_offset']:x} "
                f"usage_destinations={lit['usage_destinations']}"
            )
        print("type targets:")
        for t in targets["types"]:
            print(
                f"  {(t['namespace'] + '.') if t['namespace'] else ''}{t['name']} "
                f"index={t['index']} fields={t['field_start']}+{t['field_count']} "
                f"methods={t['method_start']}+{t['method_count']} "
                f"token=0x{t['token']:08x}"
            )
        print("field targets:")
        for f in targets["fields"]:
            print(
                f"  {f['declaring_type']}.{f['name']} index={f['index']} "
                f"token=0x{f['token']:08x}"
            )
        print("method targets:")
        for m in targets["methods"]:
            print(
                f"  {m['declaring_type_name']}.{m['name']} "
                f"method_def={m['method_definition_index']} "
                f"method_index={m['method_index']} token=0x{m['token']:08x} "
                f"file_offset=0x{m['file_offset']:x} "
                f"wasm_function={m['wasm_function_index']} "
                f"table_slot={m['function_table_slot']} "
                f"runtime_addr={m['runtime_memory_address']} "
                f"params={m['parameter_count']}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Generic IL2CPP->wasm mapping core (build-agnostic).

Extracted verbatim from the proven DG10 implementation
(unity_analysis/DG10/tools/wasm_method_map.py, generic block only -- no
per-experiment constants).  Provides:

* wasm Memory / section / LEB readers
* metadata usage pair reconstruction (corrected destination pairs)
* Il2CppType parsing and resolution
* the mapping rule  func_index = table[dispatch_base(signature) + (mp & mask)]
* element table / code body / abort-stub detection
* disassembly parsing (function ranges + call_indirect dispatch bases)
* slot consumers, function-body extraction, instruction hit scanning

Per-experiment profiles and checks live in the driver (dgmap.py).
"""
from __future__ import annotations

import json
import os
import re
import struct
from typing import Any

import wasm_sections as ws

# Metadata usage types identify the *kind of entity* referenced by
# ``source_index``.  The index spaces are not interchangeable:
#   1 TypeInfo       -> Il2CppType index space
#   2 Il2CppType     -> Il2CppType index space
#   3 MethodDef      -> method definition index space
#   4 FieldInfo      -> field definition index space
#   5 StringLiteral  -> string literal index space
#   6 MethodRef      -> method-specification index space
#
# A type-6 ``source_index`` is an ``Il2CppMethodSpec`` index, *not* a method
# definition index.  It must be resolved through ``method_specs`` to obtain the
# method definition.  Reading it directly as a definition index silently maps
# to an unrelated method.
USAGE_TYPE_NAMES = {
    1: "TypeInfo",
    2: "Il2CppType",
    3: "MethodDef",
    4: "FieldInfo",
    5: "StringLiteral",
    6: "MethodRef",
}
USAGE_TYPE_SOURCE_SPACE = {
    1: "il2cpp_type",
    2: "il2cpp_type",
    3: "method_definition",
    4: "field_definition",
    5: "string_literal",
    6: "method_spec",
}



class MapError(Exception):
    pass


def read_uleb(data: bytes, off: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if off >= len(data):
            raise MapError("truncated uleb")
        b = data[off]
        off += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            return value, off
        shift += 7
        if shift > 63:
            raise MapError("uleb too long")


def read_sleb(data: bytes, off: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if off >= len(data):
            raise MapError("truncated sleb")
        b = data[off]
        off += 1
        value |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if b & 0x40:
                value |= -(1 << shift)
            return value, off


def section(data: bytes, sid: int) -> dict[str, Any]:
    info = ws.parse_wasm(data)
    for s in info["sections"]:
        if s["id"] == sid:
            return s
    raise MapError(f"missing wasm section {sid}")


class Memory:
    """Address-to-file mapper for active wasm data segments."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.segments: list[tuple[int, int, int]] = []
        sec = section(data, 11)
        off = sec["offset"]
        count, off = read_uleb(data, off)
        for _ in range(count):
            flags, off = read_uleb(data, off)
            if flags == 0:
                if data[off] != 0x41:
                    raise MapError("unsupported data offset expression")
                off += 1
                addr, off = read_sleb(data, off)
                if data[off] != 0x0B:
                    raise MapError("unterminated data offset expression")
                off += 1
            elif flags == 2:
                _, off = read_uleb(data, off)  # memory index
                if data[off] != 0x41:
                    raise MapError("unsupported data offset expression")
                off += 1
                addr, off = read_sleb(data, off)
                if data[off] != 0x0B:
                    raise MapError("unterminated data offset expression")
                off += 1
            else:
                raise MapError(f"unsupported data segment flags {flags}")
            size, off = read_uleb(data, off)
            self.segments.append((addr, off, size))
            off += size
        if off != sec["end"]:
            raise MapError("data section length mismatch")
        self.segments.sort()

    def file_offset(self, addr: int) -> int:
        for base, off, size in self.segments:
            if base <= addr < base + size:
                return off + (addr - base)
        raise MapError(f"address 0x{addr:x} is not in a data segment")

    def u32(self, addr: int) -> int:
        return struct.unpack_from("<I", self.data, self.file_offset(addr))[0]

    def i32(self, addr: int) -> int:
        return struct.unpack_from("<i", self.data, self.file_offset(addr))[0]

    def bytes(self, addr: int, size: int) -> bytes:
        off = self.file_offset(addr)
        if off + size > len(self.data):
            raise MapError("read past end of file")
        return self.data[off:off + size]


def read_pairs(mem: Memory, addr: int, count: int) -> list[tuple[int, int]]:
    return [(mem.u32(addr + 8 * i), mem.u32(addr + 8 * i + 4)) for i in range(count)]


def all_usage_pairs(data: bytes, meta: dict[str, Any]) -> list[dict[str, int]]:
    """Read every metadata-usage pair, not only string literals (type 5).

    The encoded source index is ``(usageType << 29) | sourceIndex``.  The
    source index belongs to the index space named by ``usage_type``; in
    particular type 1/2 sources are ``Il2CppType`` indices and must not be
    compared with method-definition indices.
    """
    sec = meta["sections"]["metadata_usage_pairs"]
    off, size = sec["offset"], sec["size"]
    if size % 8:
        raise MapError("metadata usage pair table is not 8-byte aligned")
    out = []
    for i in range(size // 8):
        dest, encoded = struct.unpack_from("<II", data, off + i * 8)
        usage_type = encoded >> 29
        out.append(
            {
                "index": i,
                "pair_offset": off + i * 8,
                "usage_type": usage_type,
                "usage_type_name": USAGE_TYPE_NAMES.get(usage_type, "unknown"),
                "source_index_space": USAGE_TYPE_SOURCE_SPACE.get(usage_type, "unknown"),
                "source_index": encoded & 0x1FFFFFFF,
                "destination": dest,
            }
        )
    return out


def parse_types(data: bytes) -> list[tuple[list[str], list[str]]]:
    sec = section(data, 1)
    off = sec["offset"]
    count, off = read_uleb(data, off)
    names = {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64",
             0x7B: "v128", 0x70: "funcref", 0x6F: "externref"}
    out = []
    for _ in range(count):
        if data[off] != 0x60:
            raise MapError("bad functype")
        off += 1
        nparams, off = read_uleb(data, off)
        params = [names.get(data[off + i], hex(data[off + i])) for i in range(nparams)]
        off += nparams
        nresults, off = read_uleb(data, off)
        results = [names.get(data[off + i], hex(data[off + i])) for i in range(nresults)]
        off += nresults
        out.append((params, results))
    return out


TYPE_ENUM_NAMES = {
    0x01: "void", 0x02: "bool", 0x03: "char", 0x04: "sbyte", 0x05: "byte",
    0x06: "short", 0x07: "ushort", 0x08: "int", 0x09: "uint", 0x0A: "long",
    0x0B: "ulong", 0x0C: "float", 0x0D: "double", 0x0E: "string",
    0x0F: "ptr", 0x10: "byref", 0x11: "valuetype", 0x12: "class",
    0x13: "var", 0x14: "array", 0x15: "genericinst", 0x16: "typedbyref",
    0x17: "iptr", 0x18: "uptr", 0x19: "fnptr", 0x1A: "object",
    0x1B: "szarray", 0x1C: "methodvar",
}


def resolve_il2cpp_type(
    mem: Memory,
    types_addr: int,
    types_count: int,
    index: int,
    type_definition_names: dict[int, str],
) -> dict[str, Any] | None:
    """Resolve an ``Il2CppType`` index through ``MetadataRegistration.types``.

    ``Il2CppMethodDefinition.returnType`` and ``Il2CppFieldDefinition.typeIndex``
    are indices into the ``Il2CppType`` pointer array, *not* into the
    type-definition table.  Mixing those two index spaces is the parsing bug
    this helper removes.
    """
    if index < 0 or index >= types_count:
        return None
    try:
        type_ptr = mem.u32(types_addr + 4 * index)
        data = mem.u32(type_ptr)
        bits = mem.u32(type_ptr + 4)
    except MapError:
        return None
    type_enum = (bits >> 16) & 0xFF
    name = TYPE_ENUM_NAMES.get(type_enum, f"0x{type_enum:02x}")
    result: dict[str, Any] = {
        "index": index,
        "type_ptr": type_ptr,
        "type_enum": type_enum,
        "type_enum_name": name,
        "data": data,
    }
    if type_enum in (0x11, 0x12):
        result["type_definition_index"] = data
        result["type_definition_name"] = type_definition_names.get(data)
        if result["type_definition_name"]:
            result["name"] = result["type_definition_name"]
        else:
            result["name"] = f"{name}[{data}]"
    else:
        result["name"] = name
    return result


def resolve_method_mapping(
    mem: Memory,
    table: list[int],
    mp_addr: int,
    method: dict[str, Any],
    types: list[tuple[list[str], list[str]]],
    shape_bases: dict[tuple[tuple[str, ...], tuple[str, ...]], list[tuple[int, int, int]]],
    type_names: dict[int, str],
    types_addr: int,
    types_count: int,
) -> dict[str, Any]:
    """Resolve ``methodIndex`` to a wasm function using the signature vtable.

    ``methodPointers[methodIndex]`` is an offset inside the signature-specific
    ``call_indirect`` dispatch table, not a direct element-table index.  The
    correct body is ``table[base + (methodPointer & mask)]`` where
    ``(base, mask)`` belongs to the method's wasm signature type.  This is the
    same ``(slot & mask) + base`` pattern emitted by the IL2CPP dispatch
    wrappers; the earlier ``table[mp]`` attempts omitted the base.
    """
    mi = method["method_index"]
    mp = mem.u32(mp_addr + 4 * mi)
    ret = resolve_il2cpp_type(
        mem, types_addr, types_count, method["return_type"], type_names
    )
    # Instance methods pass ``this`` plus an implicit ``MethodInfo*``; static
    # methods pass only the parameters plus ``MethodInfo*``.
    is_static = bool(method["flags"] & 0x10)
    n_i32 = method["parameter_count"] + (1 if is_static else 2)
    params = tuple(["i32"] * n_i32)
    results = tuple([] if (ret and ret["name"] == "void") else ["i32"])
    candidates = []
    seen: set[tuple[int, int]] = set()
    for wasm_type, base, mask in shape_bases.get((params, results), []):
        idx = (mp & mask) + base
        if 0 <= idx < len(table):
            target = table[idx]
            if (idx, target) in seen:
                continue
            seen.add((idx, target))
            candidates.append(
                {
                    "wasm_type": wasm_type,
                    "base": base,
                    "mask": mask,
                    "table_index": idx,
                    "target": target,
                }
            )
    return {
        "method_index": mi,
        "method_pointer": mp,
        "return_type": ret["name"] if ret else None,
        "parameter_count": method["parameter_count"],
        "candidates": candidates,
    }


def _read_name(data: bytes, off: int) -> tuple[str, int]:
    size, off = read_uleb(data, off)
    if off + size > len(data):
        raise MapError("import name overruns file")
    return data[off:off + size].decode("utf-8"), off + size


def imported_table_min(data: bytes) -> int:
    """Return the imported table minimum when the module has no table section."""
    sec = section(data, 2)
    off = sec["offset"]
    count, off = read_uleb(data, off)
    for _ in range(count):
        _, off = _read_name(data, off)
        _, off = _read_name(data, off)
        kind = data[off]
        off += 1
        if kind == 0:
            _, off = read_uleb(data, off)
        elif kind == 1:
            reftype = data[off]
            off += 1
            if reftype != 0x70:
                raise MapError(f"unsupported imported table reftype 0x{reftype:02x}")
            flags, off = read_uleb(data, off)
            minimum, off = read_uleb(data, off)
            if flags & 1:
                _, off = read_uleb(data, off)
            if flags & 0xFC:
                raise MapError(f"unsupported table limits flags 0x{flags:x}")
            return minimum
        elif kind == 2:
            flags, off = read_uleb(data, off)
            _, off = read_uleb(data, off)
            if flags & 1:
                _, off = read_uleb(data, off)
        elif kind == 3:
            off += 2
        else:
            raise MapError(f"unknown import kind {kind}")
    raise MapError("no imported table and no table section")


def parse_table(data: bytes) -> list[int]:
    """Return the initialized element table, padded to the table minimum."""
    try:
        tsec = section(data, 4)
    except MapError:
        tsec = None
    if tsec is None:
        minimum = imported_table_min(data)
    else:
        off = tsec["offset"]
        tcount, off = read_uleb(data, off)
        if tcount != 1:
            raise MapError(f"expected one table, got {tcount}")
        reftype = data[off]
        off += 1
        if reftype != 0x70:
            raise MapError(f"unsupported table reftype 0x{reftype:02x}")
        flags, off = read_uleb(data, off)
        minimum, off = read_uleb(data, off)
        if flags & 1:
            _, off = read_uleb(data, off)
        if flags & 0xFC:
            raise MapError(f"unsupported table limits flags 0x{flags:x}")
    table = [0] * minimum

    esec = section(data, 9)
    off = esec["offset"]
    ecount, off = read_uleb(data, off)
    for _ in range(ecount):
        eflags, off = read_uleb(data, off)
        if eflags == 0:
            if data[off] == 0x41:
                off += 1
                base, off = read_sleb(data, off)
            elif data[off] == 0x23:
                off += 1
                global_index, off = read_uleb(data, off)
                # env.tableBase is imported i32 global 0 and is 0 in the
                # module's initial state.
                if global_index != 0:
                    raise MapError(
                        f"element offset uses non-tableBase global {global_index}"
                    )
                base = 0
            else:
                raise MapError(
                    f"unsupported element offset opcode 0x{data[off]:02x}"
                )
            if data[off] != 0x0B:
                raise MapError("unterminated element offset expression")
            off += 1
            n, off = read_uleb(data, off)
            for i in range(n):
                value, off = read_uleb(data, off)
                if base + i >= len(table):
                    table.extend([0] * (base + i + 1 - len(table)))
                table[base + i] = value
        elif eflags == 2:
            _, off = read_uleb(data, off)  # table index
            if data[off] == 0x41:
                off += 1
                base, off = read_sleb(data, off)
            elif data[off] == 0x23:
                off += 1
                global_index, off = read_uleb(data, off)
                if global_index != 0:
                    raise MapError(
                        f"element offset uses non-tableBase global {global_index}"
                    )
                base = 0
            else:
                raise MapError(
                    f"unsupported element offset opcode 0x{data[off]:02x}"
                )
            if data[off] != 0x0B:
                raise MapError("unterminated element offset expression")
            off += 1
            elemkind = data[off]
            off += 1
            if elemkind != 0:
                raise MapError(f"unsupported element kind {elemkind}")
            n, off = read_uleb(data, off)
            for i in range(n):
                value, off = read_uleb(data, off)
                if base + i >= len(table):
                    table.extend([0] * (base + i + 1 - len(table)))
                table[base + i] = value
        else:
            raise MapError(f"unsupported element segment flags {eflags}")
    if off != esec["end"]:
        raise MapError("element section length mismatch")
    return table


def parse_code_bodies(data: bytes) -> list[bytes]:
    sec = section(data, 10)
    off = sec["offset"]
    count, off = read_uleb(data, off)
    bodies = []
    for _ in range(count):
        size, off = read_uleb(data, off)
        bodies.append(data[off:off + size])
        off += size
    if off != sec["end"]:
        raise MapError("code section length mismatch")
    return bodies


def imported_func_count(data: bytes) -> int:
    """Number of imported functions; defined bodies start after them."""
    sec = section(data, 2)
    off = sec["offset"]
    count, off = read_uleb(data, off)
    n = 0
    for _ in range(count):
        _, off = _read_name(data, off)
        _, off = _read_name(data, off)
        kind = data[off]
        off += 1
        if kind == 0:
            n += 1
            _, off = read_uleb(data, off)
        elif kind == 1:
            off += 1
            flags, off = read_uleb(data, off)
            _, off = read_uleb(data, off)
            if flags & 1:
                _, off = read_uleb(data, off)
        elif kind == 2:
            flags, off = read_uleb(data, off)
            _, off = read_uleb(data, off)
            if flags & 1:
                _, off = read_uleb(data, off)
        elif kind == 3:
            off += 2
        else:
            raise MapError(f"unknown import kind {kind}")
    return n


def is_abort_like(body: bytes) -> bool:
    """Small abort thunk: ``i32.const N; call 1; i32.const 0; end``."""
    # call 1 is encoded as 0x10 0x01.  A thunk is tiny and has no locals.
    return len(body) <= 24 and b"\x10\x01" in body


def parse_disassembly(path: str) -> dict[str, Any]:
    """Extract function ranges and call_indirect dispatch bases from text."""
    if not os.path.exists(path):
        return {"available": False, "functions": [], "dispatch": {}}
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    starts = []
    for i, line in enumerate(lines):
        import re
        m = re.match(r"^([0-9a-f]+) func\[(\d+)\](?: <([^>]+)>)?:", line)
        if m:
            starts.append((i, int(m.group(2)), m.group(3)))
    functions = []
    for idx, (i, f, name) in enumerate(starts):
        end = starts[idx + 1][0] if idx + 1 < len(starts) else len(lines)
        functions.append({"index": f, "name": name, "start": i + 1, "end": end})
    dispatch: dict[str, set[tuple[int, int]]] = {}
    import re
    pat = re.compile(r"call_indirect \d+ <env\.table> \(type (\d+)\)")
    for i, line in enumerate(lines):
        m = pat.search(line)
        if not m:
            continue
        typ = m.group(1)
        window = lines[max(0, i - 14):i]
        base = None
        mask = None
        for j in range(len(window) - 1):
            if "i32.and" in window[j + 1] and "i32.const" in window[j]:
                mm = re.search(r"i32\.const (\d+)", window[j])
                if mm:
                    mask = int(mm.group(1))
            if "i32.add" in window[j + 1] and "i32.const" in window[j]:
                mm = re.search(r"i32\.const (\d+)", window[j])
                if mm:
                    base = int(mm.group(1))
        if base is not None and mask is not None:
            dispatch.setdefault(typ, set()).add((base, mask))
    return {"available": True, "functions": functions, "dispatch": dispatch}


def containing_function(functions: list[dict[str, Any]], line_no: int) -> dict[str, Any] | None:
    found = None
    for f in functions:
        if f["start"] <= line_no <= f["end"]:
            found = f
        elif f["start"] > line_no:
            break
    return found


def slot_consumers(
    dis: dict[str, Any], slots: dict[str, int], dis_path: str
) -> dict[str, list[dict[str, Any]]]:
    """Map literal -> list of (function, line) that load its usage slot."""
    if not dis["available"]:
        return {}
    lines = open(dis_path, encoding="utf-8", errors="replace").read().splitlines()
    out: dict[str, list[dict[str, Any]]] = {}
    for name, slot in slots.items():
        needle = f"i32.const {slot}"
        hits = []
        for i, line in enumerate(lines):
            if needle in line:
                fn = containing_function(dis["functions"], i + 1)
                if fn:
                    hits.append({"function": fn["index"], "line": i + 1})
        out[name] = hits
    return out


def extract_function_bodies(
    dis_path: str, wanted: set[int]
) -> dict[int, list[str]]:
    """Return the raw disassembly lines for the requested function indices.

    This is the evidence source for the wiring-chain checks: the checks assert
    that the *actual* instructions are present (split/sort/contains/... and the
    negative absence of a PC-field store), instead of comparing a prose claim
    against a second hard-coded prose claim.
    """
    if not os.path.exists(dis_path):
        return {}
    import re

    lines = open(dis_path, encoding="utf-8", errors="replace").read().splitlines()
    starts: list[tuple[int, int]] = []
    for i, line in enumerate(lines):
        m = re.match(r"^([0-9a-f]+) func\[(\d+)\](?: <([^>]+)>)?:", line)
        if m:
            starts.append((i, int(m.group(2))))
    out: dict[int, list[str]] = {}
    for idx, (i, f) in enumerate(starts):
        if f not in wanted:
            continue
        end = starts[idx + 1][0] if idx + 1 < len(starts) else len(lines)
        out[f] = lines[i:end]
    return out


def instruction_hits(
    body: list[str], patterns: dict[str, str]
) -> dict[str, list[str]]:
    """Return the matching instruction lines for each named pattern."""
    import re

    hits: dict[str, list[str]] = {}
    for name, pattern in patterns.items():
        rx = re.compile(pattern)
        hits[name] = [
            line.split("|", 1)[-1].strip()
            for line in body
            if rx.search(line)
        ]
    return hits


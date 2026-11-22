#!/usr/bin/env python3
"""Smoke tests for the generic (build-agnostic) parser core.

Run from the template root:
  python3 -m unittest discover -s tests -v

These tests use only synthetic data -- no experiment binaries required.
Per-experiment regression expectations live in that experiment's profile
and workspace tests, not here.
"""
from __future__ import annotations

import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import wasm_map_core as core


class LebReaderTests(unittest.TestCase):
    def test_uleb_single_byte(self):
        val, off = core.read_uleb(bytes([0x05]), 0)
        self.assertEqual((val, off), (5, 1))

    def test_uleb_multi_byte(self):
        # 624485 -> standard ULEB128 example
        val, off = core.read_uleb(bytes([0xE5, 0x8E, 0x26]), 0)
        self.assertEqual((val, off), (624485, 3))

    def test_sleb_negative(self):
        val, off = core.read_sleb(bytes([0x7B]), 0)
        self.assertEqual((val, off), (-5, 1))


class UsageTypeMapTests(unittest.TestCase):
    def test_index_spaces_are_documented(self):
        self.assertEqual(set(core.USAGE_TYPE_NAMES), {1, 2, 3, 4, 5, 6})
        # type 6 source is a method-spec index, NOT a method definition index
        self.assertEqual(core.USAGE_TYPE_SOURCE_SPACE[6], "method_spec")
        self.assertEqual(core.USAGE_TYPE_SOURCE_SPACE[5], "string_literal")


class ParseDisassemblyTests(unittest.TestCase):
    def test_function_ranges_and_dispatch(self):
        text = "\n".join(
            [
                "000100 func[10]:",
                " 000101: local.get 0",
                " 000102: i32.const 262143",
                " 000103: i32.and",
                " 000104: i32.const 214488",
                " 000105: i32.add",
                " 000106: call_indirect 0 <env.table> (type 3)",
                "000108 func[11]:",
                " 000109: i32.const 200",
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sample.dis")
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            dis = core.parse_disassembly(path)
        self.assertTrue(dis["available"])
        idx = {fn["index"] for fn in dis["functions"]}
        self.assertEqual(idx, {10, 11})
        self.assertEqual(dis["dispatch"].get("3"), {(214488, 262143)})

    def test_unavailable_for_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            dis = core.parse_disassembly(os.path.join(tmp, "nope.dis"))
        self.assertFalse(dis["available"])
        self.assertEqual(dis["functions"], [])


class MemoryBoundsTests(unittest.TestCase):
    @staticmethod
    def _minimal_wasm() -> bytes:
        # header + one active data segment at address 0 holding 0xDEADBEEF
        # payload = count + flags + (i32.const 0; end) + size + 4 data bytes
        return (
            b"\0asm\x01\x00\x00\x00"
            + b"\x0b\x0a"
            + bytes([0x01, 0x00, 0x41, 0x00, 0x0B, 0x04])
            + b"\xEF\xBE\xAD\xDE"
        )

    def test_read_segment(self):
        mem = core.Memory(self._minimal_wasm())
        self.assertEqual(mem.u32(0), 0xDEADBEEF)

    def test_out_of_bounds_read_raises(self):
        mem = core.Memory(self._minimal_wasm())
        with self.assertRaises(Exception):
            mem.u32(1 << 30)


if __name__ == "__main__":
    unittest.main()

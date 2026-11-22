#!/usr/bin/env python3
"""Locate MonoBehaviour objects in stripped, little-endian Unity v17 assets."""

import argparse
from pathlib import Path
import re
import struct
import sys


def read_string(data, offset):
    size, = struct.unpack_from("<I", data, offset)
    start = offset + 4
    end = start + size
    if end > len(data):
        raise ValueError("serialized string exceeds object bounds")
    return data[start:end].decode("utf-8"), (end + 3) & ~3


class SerializedFile:
    def __init__(self, path):
        self.path = Path(path)
        with self.path.open("rb") as stream:
            metadata_size, file_size, version, data_offset = struct.unpack(
                ">4I", stream.read(16)
            )
            endian = stream.read(4)
            if version != 17 or endian != bytes(4):
                raise ValueError(f"{path}: expected little-endian Unity serialized v17")
            if not 20 + metadata_size <= data_offset <= file_size == self.path.stat().st_size:
                raise ValueError(f"{path}: inconsistent serialized file bounds")
            metadata = stream.read(metadata_size)

        cursor = metadata.index(0) + 1  # Unity engine version string
        _platform, has_typetree, type_count = struct.unpack_from("<iBi", metadata, cursor)
        if has_typetree or not 0 < type_count <= len(metadata) // 23:
            raise ValueError(f"{path}: expected a stripped type tree and a valid type table")
        cursor += 9
        classes = []
        for _ in range(type_count):
            class_id, = struct.unpack_from("<i", metadata, cursor)
            classes.append(class_id)
            cursor += 23 + (16 if class_id == 114 else 0)

        object_count, = struct.unpack_from("<i", metadata, cursor)
        cursor += 4
        if not 0 <= object_count <= (len(metadata) - cursor) // 20:
            raise ValueError(f"{path}: inconsistent object table size")
        self.objects = {}
        for _ in range(object_count):
            cursor = (cursor + 3) & ~3
            path_id, offset, size, type_index = struct.unpack_from("<qIIi", metadata, cursor)
            cursor += 20
            offset += data_offset
            if not 0 <= type_index < len(classes) or offset + size > file_size:
                raise ValueError(f"{path}: invalid object record {path_id}")
            if path_id in self.objects:
                raise ValueError(f"{path}: duplicate object Path ID {path_id}")
            self.objects[path_id] = offset, size, classes[type_index]

    def object_bytes(self, path_id):
        offset, size, _class_id = self.objects[path_id]
        with self.path.open("rb") as stream:
            stream.seek(offset)
            data = stream.read(size)
        if len(data) != size:
            raise ValueError(f"{self.path}: truncated object {path_id}")
        return data

    def find_scripts(self, scripts, file_id, name):
        script_ids = {
            path_id
            for path_id, (_, _, class_id) in scripts.objects.items()
            if class_id == 115 and read_string(scripts.object_bytes(path_id), 0)[0] == name
        }
        matches = []
        with self.path.open("rb") as stream:
            for path_id, (offset, size, class_id) in self.objects.items():
                if class_id != 114 or size < 28:
                    continue
                stream.seek(offset + 16)
                script_file_id, script_path_id = struct.unpack("<iq", stream.read(12))
                if script_file_id == file_id and script_path_id in script_ids:
                    matches.append((path_id, offset, size))
        return matches


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("asset", type=Path)
    parser.add_argument("--scripts", type=Path, required=True, help="file containing MonoScript definitions")
    parser.add_argument("--file-id", type=int, required=True, help="index of that file in asset's PPtrs")
    parser.add_argument("--type", required=True, help="exact MonoScript type name")
    args = parser.parse_args()
    if not re.fullmatch(r"[\w.$`+]+", args.type) or args.file_id < 0:
        parser.error("expected a type name and a nonnegative file ID")
    try:
        asset = SerializedFile(args.asset)
        scripts = SerializedFile(args.scripts)
        matches = asset.find_scripts(scripts, args.file_id, args.type)
    except (OSError, ValueError, struct.error) as exc:
        print(f"读取失败：{exc}", file=sys.stderr)
        return 2
    if not matches:
        print("未找到匹配对象。请核对脚本文件索引、类型名和当前场景。", file=sys.stderr)
        return 1
    for path_id, offset, size in matches:
        print(f"Path ID={path_id}  offset={offset}  size={size}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

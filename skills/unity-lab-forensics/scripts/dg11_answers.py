#!/usr/bin/env python3
"""Reproduce the three static DG11 answer sections for the audited build."""

import argparse
import hashlib
from pathlib import Path
import struct
import sys

from unity_scene import SerializedFile, read_string


BUILD_HASHES = {
    "data_unity3d/level0": "020d985be21b15cddfa10d3d613f32afa76103f59eda59c723ba43a13661b9ce",
    "data_unity3d/sharedassets0.assets": "216394f277c6fabc10080fca2c04597ae40fcd6c58efc7947fa03c0e1fd51d2d",
    "DG11.wasm": "eaa08c0f713c9cca657a4f92f323f005363b768b5bd326187dca826d2d6acd25",
}

# 1-based UI slots from the construction order in wasm 51378/51380 and
# the label dispatch in 23989. The asset supplies the selection mask.
COMPONENTS = (
    "直流负载组件(一)", "直流负载组件(二)", "日光灯组件", "电力拖动组件",
    "交流负载组件", "元件箱组件", "智能交流数字电压表", "智能功率、功率因数表",
    "智能交流数字电流表", "智能直流仪表", "可调直流电源", "交流电源模块",
)

# HKW-03 internal suffix 01 through 22, translated using the socket positions
# from level0 and the reference front-panel photo. Use the left power N and
# voltage-meter N variants of duplicate internal IDs 02 and 04.
PANEL_NUMBERS = (1, 3, 5, 6, 7, 8, 9, 10, 11, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26)


class AnswerReader:
    def __init__(self, data, offset):
        self.data = data
        self.offset = offset

    def uint(self):
        value, = struct.unpack_from("<I", self.data, self.offset)
        self.offset += 4
        return value

    def string(self):
        value, self.offset = read_string(self.data, self.offset)
        return value

    def array(self, read_item):
        count = self.uint()
        if count > (len(self.data) - self.offset) // 4:
            raise ValueError("array count exceeds the remaining serialized object")
        return [read_item() for _ in range(count)]

    def port(self):
        value = self.string()
        if len(value) != 8 or not value.startswith("HKW-03") or not value[6:].isdigit():
            raise ValueError(f"unexpected HKW-03 internal port {value!r}")
        return int(value[6:])

    def paired_ports(self):
        # NewJudgement clears the serialized use flags and resolves one end
        # from each pair on each of its two nets.
        self.uint()
        first = self.port()
        self.uint()
        return first, self.port()

    def wiring_task(self):
        label = self.string()
        self.offset += 12  # task diagram Sprite PPtr
        groups = self.array(lambda: (self.array(self.port), self.array(self.paired_ports)))
        return label, groups


def load_answers(root):
    extracted = root / "extracted"
    for relative_path, expected in BUILD_HASHES.items():
        path = extracted / relative_path
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != expected:
            raise ValueError(f"{relative_path}: 构建哈希不符，请走通用答案工作流")

    scene = SerializedFile(extracted / "data_unity3d/level0")
    resources = SerializedFile(extracted / "data_unity3d/sharedassets0.assets")
    file_id, object_id = struct.unpack_from("<iq", scene.object_bytes(44718), 104)
    if (file_id, object_id) != (2, 2313):
        raise ValueError("Manager does not reference the audited answer asset")
    data = resources.object_bytes(object_id)
    name, offset = read_string(data, 28)
    if name != "11PowerFactorImprovement":
        raise ValueError(f"unexpected answer asset: {name}")

    reader = AnswerReader(data, offset + 8)  # two aligned boolean flags
    reader.string()  # aim answer
    reader.string()  # principle answer
    mask = reader.string()
    tasks = reader.array(reader.wiring_task)
    report = reader.array(lambda: (reader.uint(), reader.array(reader.string)))
    if len(mask) != len(COMPONENTS) or set(mask) - {"0", "1"}:
        raise ValueError("invalid component selection mask")
    if [label for label, _ in tasks] != [f"ts{index}" for index in range(1, 8)]:
        raise ValueError("unexpected task labels")
    if len(report) != 1 or report[0][0] != 0 or len(report[0][1]) != 42:
        raise ValueError("unexpected virtual-simulation report layout")
    return mask, tasks, report[0][1]


def panel_groups(label, groups):
    nets = []
    seen_ports = set()
    for fixed, paired in groups:
        fixed = set(fixed)
        # DG11's fixed anchors identify which group gets the second terminal.
        use_second_end = bool(fixed & {10, 11, 12})
        selected = [second if use_second_end else first for first, second in paired]
        ports = sorted(fixed) + sorted(selected)
        if len(set(ports)) != len(ports) or seen_ports.intersection(ports):
            raise ValueError(f"{label}: a port is repeated across wiring groups")
        for first, second in paired:
            if (first in ports) == (second in ports):
                raise ValueError(f"{label}: expected exactly one end of a paired component")
        if any(not 1 <= port <= len(PANEL_NUMBERS) for port in ports):
            raise ValueError(f"{label}: no panel mapping for an internal port")
        seen_ports.update(ports)
        net = [PANEL_NUMBERS[port - 1] for port in ports]
        if {12, 13}.intersection(net):
            raise ValueError(f"{label}: a fuse-holder label entered the wiring")
        nets.append("-".join(str(port) for port in net))
    return "  ".join(nets)


def render(mask, tasks, report, panel_matches):
    lines = ["## 1. 元器件", ""]
    for index, (selected, name) in enumerate(zip(mask, COMPONENTS), 1):
        if selected == "1":
            lines.append(f"- **第 {index} 项** {name}")

    lines += ["", "## 2. 电路搭建", ""]
    if panel_matches:
        lines += [
            "每行是该档的完整接线。`1-5-7` 表示接 `1-5` 和 `5-7`，空格隔开的组独立连接。",
            "",
            "```text",
        ]
        for capacitance, (label, groups) in enumerate(tasks):
            lines.append(f"{capacitance} μF   {panel_groups(label, groups)}")
        lines.append("```")
    else:
        lines.append("待核对。请提供电路搭建面板的清晰正视截图，显示插孔编号和器件名称。")

    lines += ["", "## 3. 实验报告", "", "虚拟仿真表的 U 已预填 220 V。", "", "```text"]
    rows = [("C (μF)", "P (W)", "U (V)", "I (mA)", "IL (mA)", "IC (mA)", "cos φ", "φ (°)")]
    for capacitance in range(7):
        power, current, load, capacitor, pf, phase = report[6 * capacitance:6 * (capacitance + 1)]
        rows.append((str(capacitance), power, "220", current, load, capacitor, pf, phase))
    widths = [max(map(len, column)) for column in zip(*rows)]
    lines += ["  ".join(word.ljust(width) for word, width in zip(row, widths)).rstrip() for row in rows]
    lines += ["```", "", "以上为本地构建的静态核对结果，尚未在线验分。"]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="DG11 project directory containing extracted/")
    parser.add_argument(
        "--panel-matches-reference",
        action="store_true",
        help="use the audited panel mapping after comparing it to the current panel",
    )
    args = parser.parse_args()
    try:
        mask, tasks, report = load_answers(args.root)
        print(render(mask, tasks, report, args.panel_matches_reference))
    except (OSError, ValueError, KeyError, struct.error) as exc:
        print(f"DG11 提取失败：{exc}", file=sys.stderr)
        return 2
    return 0 if args.panel_matches_reference else 1


if __name__ == "__main__":
    sys.exit(main())

# unity-lab-forensics

分析 Unity WebGL 电路虚拟实验，输出元器件勾选项、使用面板实际编号的接线方案和实验报告填表数值。
另外在此声明，此为AI产物，一些潜在的错误目前没有被发现，若要下载到本地使用，请自行审查。

## 内容

- `skills/unity-lab-forensics/` 包含技能说明、采集工具、静态解析器及实验适配样例。
- [DG11 实验答案](answers/DG11.md) 包含与面板印号核对后的三部分答案。
- [答案分析工作流](skills/unity-lab-forensics/answer-workflow.md) 说明从当前场景配置到界面答案的核对步骤。

## 安装

将仓库下载或克隆到本地，把 `skills/unity-lab-forensics` 整个目录复制到 agent 的技能目录。当前安装使用 `~/.agents/skills/`。已有同名技能时，先比较内容并备份。

在能读取技能的 agent 中输入：

```text
使用 $unity-lab-forensics 分析这个实验目录，给出元器件、
电路搭建和实验报告的答案。接线使用实际面板印号。
```

准备本地构建文件或已有采集材料。接线分析还需要能看清编号和器件名称的面板截图，或与当前场景匹配的可核对资源。

## 依赖与验证

静态 Python 工具使用 Python 3.10 及以上版本。执行 WASM 文本反汇编时需要 WABT 的 `wasm2wat`。用户主动采集模式另需 Node.js、系统 Chrome/Chromium 和 `capture/package.json` 中的依赖，具体步骤见技能里的采集工作流。

```bash
python3 -B -m unittest discover -s skills/unity-lab-forensics/template/tests
```

DG11 样例需要用户自己的匹配构建。核对面板符合样例后运行：

```bash
python3 -B skills/unity-lab-forensics/scripts/dg11_answers.py /path/to/DG11 --panel-matches-reference
```

`profiles/` 中的 DG04、DG10 配置保留研究样例参数，输入路径需按自己的文件位置调整。DG11 样例限定于脚本记录哈希的构建。其他实验按通用工作流分析。

## 验证范围

DG11 的答案经本地构建和面板静态核对，尚未在线提交验分。跨实验复用需要逐个实验验证。原始构建、HAR、缓存和用户账号数据由使用者保存在自己的本地目录。

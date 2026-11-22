# 采集引导（用户亲手做实验）

当用户要开始一个新实验会话时，**先引导采集，再谈分析**。用户若明确要求
"命令行自动采集"，优先走下面的自动 HAR 流程；否则使用手动 DevTools 流程。
两条路线都只记录用户亲手操作的会话，不做请求重放或动态判分验证。

如果本次还需给出接线答案，可请用户在手动操作时一并保存接线面板正视截图，需看清插孔印号和器件名称。

### 自动 HAR 采集（用户说"开始" / "做完了"）

适用边界：普通方式打开的既有浏览器**不能被直接接管**。本流程启动独立的
Chromium 采集窗口，使用临时浏览器配置；用户在该窗口中自行登录和操作，
不读取现有浏览器 profile，不需要 DevTools，也不会自动点击或提交。

首次为 skill 安装隔离的 Node 依赖（仅 `playwright-core`，复用系统 Chromium，
不执行 `playwright install`，不做全局安装）：

```bash
npm install --prefix "$SKILL_DIR/capture" --ignore-scripts
```

固定剧本：

1. **用户说"开始"**：确认工作区与实验 URL；URL 未知就只询问这一项。先问
   用户要哪种窗口：

   **A. 独立临时窗口（默认）**：

   ```bash
   python3 "$SKILL_DIR/scripts/har_capture.py" start \
     --workspace /path/to/DG06 --url http://lab.example.invalid/
   ```

   **B. 用户自己的 Chrome 窗口（CDP 附加，推荐日常使用）**：

   ```bash
   python3 "$SKILL_DIR/scripts/har_capture.py" start \
     --workspace /path/to/DG06 --url http://lab.example.invalid/ --cdp
   ```

   - `--cdp` 模式：脚本用系统 Chrome 二进制 + 独立 profile 目录
     （`<workspace>/profiles/chrome-cdp`，Chrome 136+ 要求非默认
     `--user-data-dir` 才能开 debug 端口）+ `--remote-debugging-port=9222`
     启动真实 Chrome 窗口，recorder 仅通过 CDP 被动记录网络事件。
   - 该窗口使用方式与普通 Chrome 相同（可登录、装扩展、同步）；首次为
     全新 profile，登录 Google 账号后即与用户日常环境一致。
   - **stop 不会关闭用户的浏览器**，只断开记录；会话结束后建议用户关闭
     该窗口（debug 端口开着期间本机其他进程理论上可附加）。
   - 若 Chrome 已由用户带 `--remote-debugging-port` 启动，可省略浏览器
     启动、仅附加：`--cdp` 且不传 `--browser`（默认 `chromium` 不在 PATH
     时会自动找 google-chrome 等常见二进制）。
   - 自定义浏览器/端口/目录：`--browser /path/to/chrome --cdp-port 9222
     --profile-dir /path/to/dir`。

   命令会等页面到达 `domcontentloaded`（A）/ CDP 端点就绪（B）后才返回
   `CAPTURE READY`。只有看到该标记才能告诉用户"捕获已就绪，可以开始做
   实验"。启动失败时报告错误，不得让用户在未被捕获的窗口中做实验。
   可用 `status` 查看状态，无需轮询。

2. **等待用户完成**：不要催促、不要代替用户操作、不要请求重放。采集期间
   保留窗口。若用户已手动关闭窗口，仍执行下一步以完成状态与内容检查。

3. **用户说"做完了"**：必须优雅停止并等待 HAR 落盘，禁止直接 SIGKILL：

   ```bash
   python3 "$SKILL_DIR/scripts/har_capture.py" stop --workspace /path/to/DG06
   python3 "$SKILL_DIR/scripts/intake.py" --dir /path/to/DG06 \
     --hashes-out /path/to/DG06/evidence/intake-hashes.txt \
     --json /path/to/DG06/evidence/intake.json
   ```

   `stop` 输出请求数、含嵌入响应体的响应数、POST/提交候选及构建产物候选数，
   并写 `capture/har-summary.json`（只含计数与哈希，不打印 URL/token/body）。
   **只有 `usable_capture=true` 才继续分析**；`entries=0`、无响应体或 HAR 未
   落盘时以非零退出，明确补采/改用缓存路线，不得把 `.har` 后缀当作有效证据。
   后续分析按阶段 0 继续，所有结论绑定 intake 哈希。

HAR 原始文件可能含 Cookie、token 与完整 POST body：保存在 `raw/` 中，派生
证据脱敏后再入库。A 模式停止流程关闭临时 context 以触发 Playwright 的
HAR flush；B 模式由 recorder 自行组装 HAR 并落盘，从不关闭用户浏览器。
这也是不能使用 `npx playwright open` 后强杀进程替代本脚本的原因。

### 手动 DevTools 采集

agent 的固定剧本：

1. **开场提醒**（在用户开始实验前发出）：
   - 提醒用户在浏览器中打开 DevTools → Network，勾选 **Preserve log**，
     然后从加载页面开始完整做一遍实验直到提交成功；
   - 需要捕获的关键流量：页面加载期的 `*.wasm.code.unityweb`/`.data`/
     `global-metadata.dat` 等构建产物、实验过程中的判分/配置请求、
     最终提交 POST（DG10 类实验是 `/api/user/sendjson`，含 `wrong` 字段）；
   - 提醒：实验期间不要清缓存、不要提前关页面；记录大致时间窗；
   - 可选增强：同时导出 HAR（Network 面板 → 右键 → Save all as HAR），
     或事后直接拷贝浏览器 HTTP 缓存目录；
   - 可选 pcap 路线（需要用户自己授权/执行）：若需要接口层原始抓包存档
     或怀疑有 DevTools 看不到的流量，由用户自行运行
     `sudo tcpdump -i any -w dgxx.pcap`（或加入 wireshark 组后用 dumpcap
     免 sudo）。这不是必需项：本分析所需的应用层记录 HAR 全部可提供。
2. **等待用户完成**。不要催促、不要代替用户操作浏览器、不要请求重放。
3. **接收材料**：用户提供文件路径后，运行 `scripts/intake.py --dir <材料目录>`：
   自动分类（HAR / 缓存条目 / wasm / metadata / pcap-http 记录）、逐文件
   SHA256、写出 intake 哈希清单、报告缺失的关键件。
4. **后续**：按阶段 0 提取 → manifest → 继续六阶段流程。所有后续结论绑定
   intake 哈希；原始材料保持只读。

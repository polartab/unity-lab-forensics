# 陷阱清单与发现程序（reference）

每条陷阱都来自 DG10（Unity WebGL，IL2CPP v24.1）的实证教训。换实验时按此清单排查，
可避免重踩已知的坑。"每实验一次"的数值其发现程序附后。

## T1. 方法映射规则（易错点最高）

**错误候选**：`func_index = table[methodPointer]`（省略 dispatch base）。
**已证规则**：`methodPointers[methodIndex]` 是签名专属 `call_indirect` 分发表内的
偏移，真实函数为：

```
func_index = table[dispatch_base(wasm签名类型) + (methodPointer & mask)]
```

`(base, mask)` 从反汇编 dispatch wrapper 的模式提取：
`local.get; i32.const <mask>; i32.and; i32.const <base>; i32.add; call_indirect (type N)`。
按签名类型分组（dgmap 自动完成）。
DG10 案例多处方法在旧规则下映射到无关函数，修正后 18/18 命中。

## T2. usage pair 索引空间不可混用

| type | 含义 | source_index 空间 |
|---|---|---|
| 1 | TypeInfo | Il2CppType |
| 2 | Il2CppType | Il2CppType |
| 3 | MethodDef | 方法定义 |
| 4 | FieldInfo | 字段定义 |
| 5 | StringLiteral | 字符串字面量 |
| 6 | MethodRef | **methodSpec（不是方法定义！）** |

type 6 的 source_index 必须经 `method_specs` 解析到方法定义，直接当定义索引用会
静默映射到无关方法。DG10 案例：slot 2761656（type 6，src 3219）是传给 thunk 的
隐藏 `MethodInfo*` 参数，不是字符串。

## T3. 指针参数写回对偏移扫描不可见（最重要的负证据陷阱）

**"某字段偏移没有直接 store 指令"不能推出"该字段从未被写"。** 函数可以把
`&this.field` 作为指针参数传给另一个函数，写入发生在被调函数里（基址在局部变量中，
偏移扫描看不到 `i32.store 2 <off>` 与该字段的关联）。

DG10 案例：`Manager.connectNew(+340)` 的追加写入者 28199/28201 通过
`&connectNew` 指针参数写回，纯偏移扫描只找到 resets（28217/28164/28165）和
28196，漏掉两个真正的追加者——直到逐函数读反汇编才发现。

**排查程序**：对目标字段，除偏移扫描外，追踪 (a) 该字段的 `i32.const <off>; i32.add`
取地址位点；(b) 取地址结果作为参数传入的调用链；(c) 被调函数体内的指针写入。

## T4. wasm 字段访问的两种指令形式

1. 立即偏移：`i32.load 2 <off>` / `i32.store 2 <off>`（2 = 对齐）；
2. 常量加法：`i32.const <off>; i32.add`（基址 + 常量）。

两种都要扫（dgmap 的 `field_access` 已实现：load/store/addr_take/load8/store8）。
另有 `i32.load8_s/u 0 <off>` 用于字节字段。

## T5. 隐藏尾参

实例方法传 `this` + 显式参数 + **隐式 `MethodInfo*`**；某些 thunk（如接口/虚分发
wrapper）额外接收 `MethodInfo*`。DG10 案例：3 参 thunk 25603 → 23699（`List.Contains`），
第 3 参是 slot 2761656 的 MethodRef，不是字符串。

## T6. icall 与内建函数的双参形式

`String.Contains` 等经 icall 时参数形式与托管签名不同，按实际反汇编确认，勿按
托管签名硬套。DG10 已确认的 func id（仅 DG10 build 有效，换实验必须重测）：
`33461=Int32.Parse, 32710=Contains, 32541=Concat2, 32544=Concat3, 32682=Split,
32479=Substring`。

## T7. .NET 语义照抄，不凭直觉

- `string.Split(char)` **保留空项**（`"a:b".Split(':')` 长度 2；`":b"` 长度 2 含空首项）。
- DG10 案例：`bsChange` 语义最终修正如：循环内**两个累加器分别追加**（左=归一化
  A 项，右=原始 B 项），结果为真当且仅当 ∀i<len(A)：`A[i].startswith(B[i])`；
  多余 B 项被丢弃。调用方 28127 以"两端 Split 长度相等"为门（指令级验证）。
- **辅助函数边界与调用方约束分开陈述**：`IndexError`（len(B)<len(A) 时）是 helper
  边界；等长约束是调用方 28127 的门。混写会得到错误结论。

## T8. 通用 thunk 与"表内多义"

小函数（≤24 字节且含 `call 1`）是 abort thunk（`is_abort_like`），不得当作真实实现。
方法解析时优先选非 abort、体最长的候选；profile 的 expected_func 是校验权威。

## T9. 证据分级与结论纪律

- 结论必须标 `structure / disassembly / reference / incomplete`；
- "结构上与已验证函数相同" ≠ 指令级验证（DG10 的 28201 尾部即此状态，列为
  incomplete）；
- `--check` 在证据缺失时**不得打印固定成功结论**；只允许
  `CHECKS OK; INFERENCES INCOMPLETE`；
- 撤销旧断言留痕（何时、为何、被什么取代）。DG10 案例：撤销
  "28167 写入 +328" 与 "比较结果 → PCOne..Five → strError" 两条旧断言。

## T10. 自举不可达性证明（终态规则类问题的通用武器）

当运行时输出与"某分支永不执行"的假设一致时，可做自举证明：若所有**无条件**写入者
只写入不满足分支守卫的初值（如纯数字、`error:`），则归纳可得任何执行历史都无法
使守卫为真 → 分支死。DG10 案例：`a{i}b:` 追加分支要求 connectNew 中已有 2/3 组键，
而 connectNew 从空/数字起步、无条件写入者只追加数字或 `error:` → 死分支 →
每个 PC 记录都报错，与运行时 `wrong` 完全吻合（20/11/18）。

## R1. 每实验一次：发现程序

| 数值 | 发现程序 |
|---|---|
| CodeRegistration / MetadataRegistration 地址 | 在 wasm data 段中按已知计数数组特征扫描（method pointers 数组的元素为表内偏移、递增聚集）；用 `read_pairs` 读出 7/8 组 (count,address) 对并交叉验证计数与 metadata 计数一致 |
| dispatch (base, mask) 集合 | 全量反汇编（wasm2gpu/wasm-decompile 文本），扫 `call_indirect` 位点，回看 14 行窗口取 `(const,and)` 与 `(const,add)` 对；按 wasm 签名类型分组 |
| target literal 槽位 | literal 文本 → index → type-5 usage pairs → 目的槽位 → 消费函数 |
| 字段偏移 | metadata `field_offsets`（type definition sizes + field offsets 表）或从已证函数的访问指令反推；**同名偏移跨类会撞**，按类限定函数范围 |
| helper func id（Contains/Split/…） | 从已证调用点（metadata usage + 指令序列）逐个确认；不可跨 build 复用 |
| 实验适用性 | 从提取的答案配置（errorName 等）与运行时 `wrong` 载荷逐项比对 |

## R2. 机器可读输出

`dgmap.py --json PATH` 产出完整报告（metadata 计数、registration、dispatch 表、
方法解析、字面量追踪、字段访问、check 结果）。报告仅供导航，结论以证据文档为准。

## R3. DG10 专用值只放 profile（适配层），不放驱动

- **键格式**：DG10 的 `a{index}b:` 键是实验专属格式，写在 profile 的
  `rule_record.key_format`（驱动用 `key_format.format(index=...)` 推导并
  与 `expected_key` 比对）。驱动不硬编码任何实验的键格式；profile 给了
  `expected_key` 却没给 `key_format` 会报 PROFILE CHECK FAILED。
- **默认路径**：DG10 的输入路径（/tmp 提取产物、disassembly、答案配置）
  全部在 `profiles/dg10.json` 的 `inputs`/`rule_record.config`；其他实验
  在自己的 profile 里填自己的路径。
- **检查目标为空的 profile 不允许静默通过**：`--check` 会以
  PROFILE CHECK FAILED 拒绝——这是防止"跑通了脚本"被误读为"验证了逻辑"。

## R4. 中间证据与停止点

- 方法按名字命中、计数吻合、反汇编解析成功都只是中间证据；多个候选函数
  无 `expected_func` 消歧时，驱动的启发式选择仅供导航，检查结果记为
  INTERMEDIATE EVIDENCE（not verified）。
- 材料不全时的最低交付与停止点：只有 metadata → 结构读取即交付；
  无反汇编 → 映射停止；语义结论需要逐函数阅读，读不完就显式列出未读函数。

## R5. 构建取证工具与流程

按需要选择以下阶段。只交付三部分答案时，先按 [答案工作流](answer-workflow.md) 定位有效配置和界面映射。

### 快速开始

```bash
# 新实验工作区（模板含通用解析器 + 驱动）
python3 $SKILL_DIR/scripts/init_workspace.py --name dg04 --dir <workspace>

# 分析主循环（profile 驱动，证据分级，绝不打印固定成功）
python3 <workspace>/tools/dgmap.py --profile <workspace>/profiles/dg04.json --check
```

`--check` 退出码：0 = 结构/反汇编/引用检查全过（但可能仍有 incomplete inferences）；
1 = 检查失败；2 = 输入缺失。**绝不因为脚本退出 0 就声称"判分逻辑已证明"**——
只有证据文档中逐条分类的条目才算数。

### 取证阶段

#### 阶段 0：获取与固化材料
1. 从 HTTP 缓存严格提取（以第一个 EOF 界定 body，禁止整文件读入）：
   `tools/extract_cache.py`、`tools/cache_entry.py`。
2. 逐层 manifest + SHA256：`tools/artifact_manifest.py`；生成 `evidence/hashes.txt`。
3. pcap 若有：`tools/pcap_http.py` 提取 HTTP 会话；**先脱敏（token 等）再入库**。

#### 阶段 1：metadata 解析与候选发现
1. `tools/il2cpp_metadata.py` 解析 global-metadata.dat（v24/24.1）。
2. 记录计数：methods/types/literals/pairs/table size —— 写入 profile `expected`。
3. 找 Il2CppCodeRegistration / Il2CppMetadataRegistration 地址（写入 profile
   `registration`；发现程序见 reference.md §R1）。
4. 候选类型发现：按命名模式（Manager/UIHandler/DataHandler/…Center/…Handle）+
   JSON 键形字面量（pointLineN、startName、endName、errorName…）的消费者定位。

#### 阶段 2：方法映射
- 规则（已证，勿用 `table[mp]`）：`func_index = table[dispatch_base(签名) + (methodPointer & mask)]`。
- dispatch base 从反汇编的 `call_indirect` 位点按签名分组自动发现（dgmap 已实现）。
- profile `methods` 每条记录 expected_func；`--check` 逐条比对，不符即 REFERENCE CHECK FAILED。

#### 阶段 3：字面量与字段追踪
1. 字面量：文本 → literal index → usage pairs（type 5）→ 目的槽位 → 消费函数
   （dgmap `target_literals`）。
2. 字段：profile `fields`（名称→偏移）→ 全量单遍扫描两种访问形式
   （`i32.load/store 2 <off>` 与 `i32.const <off>; i32.add`）。
3. **必读 reference.md 的陷阱清单**——尤其是"指针参数写回对偏移扫描不可见"。

#### 阶段 4：证据分级与交付
- 每条结论标注类别：`structure`（结构事实）/ `disassembly`（指令级验证）/
  `reference`（外部文档或运行时佐证）/ `intermediate`（名字/计数/解析成功，
  未经独立消歧）/ `incomplete`（未闭合推断）。
- 中间证据规则见上文 v0.1 小节；运行时历史输出（如 `wrong` 载荷）只佐证
  那一次会话的输出，不外推。
- 未闭合推断**显式列出**（profile `incomplete_inferences`），不隐藏、不默认成立。
- 交付物：evidence 文档 + 验证报告 + hashes.txt + 机器可读 report（`--json`）。
- 撤销旧断言时留痕（写明何时、为何撤销），禁止静默改写历史结论。

#### 阶段 5：回归
- 通用解析器冒烟测试：`python3 -m unittest discover -s tests`（模板自带）。
- 本实验回归：`dgmap.py --check` + 负向测试（篡改 profile 任一期望值必须 exit 1）。

### 低层取证约束

1. **没有指令级证据，不得写"已证明"**；结构相似 ≠ 指令相同（须注明）。
2. **偏移扫描无结果 ≠ 没有写入**（指针参数写回、icall 双参形式都会漏）。
3. **索引空间不可混用**：usage type 6 的 source 是 methodSpec 索引，不是方法定义索引。
4. **.NET 语义照抄**：`Split(char)` 保留空项；辅助函数边界与调用方约束分开陈述。
5. **动态验证 / 请求重放 / 浏览器操作**：一律需要用户单独批准。
6. 原始材料中的敏感 token：先脱敏再提交入库。

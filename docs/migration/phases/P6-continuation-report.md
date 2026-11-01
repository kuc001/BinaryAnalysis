# P6 持续修复与保真验收

2026-10-29。**QUALITY=PASS，P6 PHASE=PASS，state=complete。** 最终统一验收恢复 535 条 MAY 候选，逐条 missing=extra=0；完整逻辑调用图逐边一致，真实摘要失效/撤回/恢复通过，执行与图重分析 pending 均为空。全部 Python 源码在验收期间未变，受保护目录与 frozen Schema 检查通过。未进入 P7，未验收 Gate A，未开发 Rust。

## 输入、版本与可复现入口

三份 v5 文档已完整阅读。用户确认的 [目标运行版本](../TARGET_RUNTIME.md) 优先于规划文档的 10.0.5 假设；目标仍是原 `.venv` 的 Python 3.12.9、angr/Claripy/pyvex/cle/archinfo 9.3.4、z3-solver 4.13.0.0。旧解释器为 `../EmTaint/.venv/Scripts/python.exe`，Python 3.7.2 / angr 9.0.9792。没有安装或调整依赖。

固件 SHA256：`334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787`。

本轮证据根：[20261029T030059Z-continue-9a4cee7c](../../../.p6-work/20261029T030059Z-continue-9a4cee7c/)。最终验收：[validation-p6.json](../../../.p6-work/20261029T030059Z-continue-9a4cee7c/acceptance-20261029T071606Z-9fab46e0/validation-p6.json)。所有开发失败、被中断的诊断、早期不变代码校验失败及此前 partial 报告均保留。

| 本次要求 | 最终结果 | 验收证据（最终目录内） |
|---|---|---|
| 入口、3 unknown 最早分歧、14 未到达障碍 | 17/17 已分类且静态 CFG 可达；0 执行 frontier | `legacy/legacy-report.json`、`integration/site-coverage.json`、逐函数规则/预算 |
| 旧 load/store alias、反向需求、use/def | 旧真实方法样例、新 scope/MemoryQueryPort 测试通过；535 候选逐条一致 | `all-tests.stderr.txt`、`reference/reference-report.json`、`integration/differential.json` |
| 真实摘要、全依赖图、重分析 | cold 5397 / warm 5892 边均一致；祖先 2 次分析；61→0→61，缓存/port/边撤回与恢复通过 | `integration/native-revision-test.json`、`invalidation-events.json`、`revision-invalidation-events.json` |
| ARM lowering / Schema | 21 个 native tests 通过；Schema、codec、契约 hash 不变 | `scalar/tests.txt`、`frozen-schema.json`、P3 全回归 |
| 同 CIR/预算/输入，17 站点/CG/证据 | 535 条 MAY，missing=extra=0；旧 Collector 同需求同字节差分通过；unknown 保留 | `reference/reference-facts.json`、`integration/target-facts.json`、`cg-logical-edges.json` |

```powershell
Set-Location D:\works\dataflow\EmTaint\emtaint-migration\BinaryAnalysis
.\.venv\Scripts\python.exe -B scripts/p6_acceptance.py .p6-work/20261029T030059Z-continue-9a4cee7c
```

脚本每次创建新目录，显式使用两套解释器，清除混用的 PYTHONPATH/VIRTUAL_ENV；原生探测及旧 PLY cache 被限制在本次子目录，PLY write_tables=false，bytecode 禁用。没有直接执行旧仓库的 `main.py -i/-t`。完整新 CLI 是 P7 工作。

## 三个已到达 unknown 站点的最早定义分歧

此前新 FlowState 没有旧 FastSearch 的入口 SP 定义，导致第一个 push/store 已使用未知地址。真实旧初始化器已直接执行对照，SP 为 `0x7fffffff`；新模型以稳定 function/context/frame Root 表达这一约定，绝不以可改写的寄存器名充当对象身份。

| iCall 站点 | 最早受影响的指令 | 修复后相同入口约定 | 后续关键分歧及结果 |
|---|---|---|---|
| `0x10f1c` | `0x10ee4 str lr,[sp,#-4]!` | SP 变为 `0x7ffffffb` | ARM 条件 helper 获得标量 lowering；站点仍 unknown，与原无候选一致，保留 unknown edge |
| `0x23f50` | `0x23eb8 push {r4-r8,lr}` | SP 减 24 | `0x23ef8` 读取 GOT `0xa1024`，CLE 后为 `0xa15d4`，raw 文件初值不能代替；恢复 6 条候选 |
| `0x6eeb8` | `0x6ee80 push {r4,r5,lr}` | SP 减 12 | `0x6ee88` 读取 GOT `0xa1038`，CLE 后为 `0xa88a0`；结合 loop use/def 恢复 15 条候选 |

入口表是静态最早使用定位，结合实际旧 initializer characterization，不是运行可达性或约束可满足证明。独立证据在 `definition-and-barrier-audit/entry-definitions.json`。旧/新 loader 的两个 PT_LOAD segment 全字节及 443 个 relocation 计数对照；不只比较选取的几个地址。

`_initialize_callsite_arguments` 已用真实旧函数执行，按实际 ARM argument_registers 初始化原全局配置，得到 backward `r8`。新模型把旧 offset 名称归一为 ABI `r0-r3`，根据真实 caller 定义绑定；额外栈参数按实际 callsite SP 和 reaching store 取值。完整字覆盖入口参数、跨 scope 参数/返回 alias 与 callee 参数 store 均有独立测试。

## 14 个原未到达站点与最终 17 站点

下表为逐站点原 Golden 候选数与当前恢复数。所有站点在所用 CFG 中可达，函数内执行/预算 frontier 与图重分析 pending 为空；这不代表实际 guard 可满足。

| caller | site | 候选数 | 原障碍与对应修复 |
|---|---|---:|---|
| `0x10ee0` | `0x10f1c` | 0 / unknown | 已到达；入口 SP、条件 helper；保持未知 |
| `0x18590` | `0x188ac` | 14 | helper/shift、computed-PC CFG、反向 reaching definitions 与表循环 |
| `0x18590` | `0x189dc` | 27 | 同函数第二需求，独立表起点；不能与前站点混合 |
| `0x1c2d0` | `0x1c3ec` | 14 | helper/shift 与跨块寄存器定义；实际 DDG stride 摘要 |
| `0x1d330` | `0x1d688` | 194 | helper/shift、循环控制及表恢复；改用有界需求，不通过 wall 超时截断 CFG |
| `0x1f9a0` | `0x2115c` | 1 | 入口栈参数、调用处参数定义、真实 `1ea0c→1e9ac→1e8a8` 摘要链、store alias |
| `0x1f9a0` | `0x2120c` | 9 | 相同真实摘要链；保留原地址上界启发式 |
| `0x1f9a0` | `0x212d8` | 25 | 真实 callee 参数写定义、latest reaching store 与 use/def |
| `0x1f9a0` | `0x21404` | 25 | 同上，独立站点需求与 guard 的 unknown remainder |
| `0x23eb8` | `0x23f50` | 6 | 已到达；GOT 重定位、SP、循环与返回寄存器 clobber |
| `0x25bac` | `0x25c88` | 104 | 旧 nested Load 先枚举内部数据指针，再独立枚举外层函数表；不可使用两个相同 i 的对角线枚举 |
| `0x2d394` | `0x2d560` | 61 | 实际 callee `0x23dc4` 返回 alias；fresh scope 实例化 |
| `0x2d990` | `0x2e040` | 25 | 实际 callee `0x29590` 返回 alias 与寄存器 use/def |
| `0x6ee74` | `0x6eeb8` | 15 | 已到达；GOT 重定位与 stride=16 的真实 DDG |
| `0x6f740` | `0x6f804` | 15 | helper、CFG 控制与同类表循环需求 |
| `0x7d100` | `0x7d1a8` | 0 / return | 原 IDA iCall 注解；机器码 `08f09de4` 是 `LDR pc,[sp],#8`，VEX Ijk_Ret / CIR Return |
| `0x7d1c4` | `0x7d29c` | 0 / return | 同类真实返回；不制造间接调用候选 |

最终验收口径：17 个原注解 = 14 个有候选调用 + 1 个未知调用 + 2 个返回。14 个站点合计 **535 条数值 MAY 记录**。逐条 missing/extra、候选来源、规则、MemoryVersion、origin 与 CFG 证据保存在 integration 的 `differential.json`、`target-facts.json`、`site-coverage.json` 及逐函数文件；不是只比较数量。

## 旧规则移植与 MemoryQueryPort

当前模块映射与接口见 [P6_DATAFLOW_CONTINUATION.md](../P6_DATAFLOW_CONTINUATION.md)。反向 scalar use/def、load 定义替换、store alias、DDG 递增及循环摘要均对照实际旧方法。完整 MustAlias、同宽同端序且 guard=true 的定义才可直接替换值；MayAlias、部分覆盖、不确定路径/地址保留未知。P5 的 byte overlap/endianness/solver unknown 回归继续执行。

Root、APG、SSE 与 MemoryVersion 分离。新版查询实际经过 `MemoryRuntimePort→MemoryQueryPort→P5 engine`，没有把旧 Claripy Load/Store 放进求解器，也没有用 APG 路径相同冒称别名证明。

callee recipe 从真实 CIR 中提取返回与参数 store，只有 detached typed nodes/整数边，不持有任何 callee scoped ID；在 caller 当前 MemoryVersion 中重新查询。必须先证明 store 地址对应，再展开 stored value。开发中的 eager 展开曾触发 200000 节点预算及多报，修复选择顺序后回到 535；没有通过无限提高预算掩盖问题。

## 相同 CIR 与旧 Collector 的独立边界差分

原 `httpd_icall.json` 在运行前已含 535 条，是旧 IDAProcess 的 warm input；不能把导入它当作本轮新恢复。新流程从无候选的 cold graph 开始，不读取该文件作为分析种子。Golden 在目标分析完成后才打开。

同一份冻结 CIR 生成的需求根以 detached recipe 交给旧 Python 3.7 的实际 Collector；新旧使用同一重定位映像、最大索引 4096 及原 `0x2115c/0x2120c` 地址边界。15 个真实调用站点（含 1 个 unknown）的目标逐条一致。两个 return 由独立机器字节/VEX/CIR 分类证据覆盖。

首次边界回放仅得到 13 条，原因是 CIR 的 `ADD(pointer(0),BV)` 地址 cast 被旧自定义 Load 简化保留为外层 Add，Collector 只按顶层 Load 分派。适配仅去除已证明同宽等值的零加法，并以旧实际 Collector 验证这一 identity；没有替换 Collector 算法。修复后为 535 条、missing=extra=0。

这是旧 Collector/内存边界的独立执行，不是第二套完全独立 FastSearch；上游需求移植的共同偏差风险由实际旧方法样例、Golden 逐条结果、callee/stack/alias 测试和完整图差分约束。没有重新执行完整旧 `-i/-t`。

## 真实依赖图与 invalidation

冷图：881 个内部函数、337 个外部名称，共 1218 个逻辑节点；5397 条逻辑边与实际旧 IDAProcess cold graph 完全一致。保留 per-site/unknown 元数据时有 13023 条记录，不能与逻辑边混比。

从 IDA 的原 13 个 caller 扩展到 5 个实际 callee 摘要依赖及 caller 子图以外的真实祖先 `0x2e9b4`，总计 lifting 19 个函数 / 1983 个 CIR blocks。其余函数有真实依赖元数据，不声称已分析其全部函数体。候选提交后 5892 条逻辑边与旧 warm graph 逐边一致；535 个 site-target 记录对应 495 个新增 function-pair。

常规固定点为 2 轮、30 次函数分析，祖先 `0x2e9b4` 实际分析 2 次。30 个只有 metadata、无先前活跃分析结果的受影响函数记录 invalidation epoch；没有虚构其 reanalysis。

独立受控测试在内存中临时替换真实 `0x23dc4` recipe 的返回为 0，实际 caller `0x2d394` 由 61 候选变 0；相关 heap/alias/SSE/APG/summary/facts/result 缓存失效，旧 port/handle 拒绝使用，旧 derived edges 撤回而 unknown edge 保留。恢复真实 recipe 后重新分析，61 候选及完整 CG 恢复相同，所有 pending 为空。源代码、CIR、Golden 均未为此修改。

## ARM、Schema、预算与未知

ARM flags/condition helpers、Shl/Shr/Sar 各位宽、CLZ 及动态合法 CC_OP 使用已有 CIR 标量操作 lowering；测试 oracle 对照实际安装的 angr helper/irop。CLZ(0) 是 VEX 未定义输入，不把自选扩展值当作保真证明。纯值 unsupported 仅标记相关 tmp/寄存器，不全状态 havoc 冒充精确支持。CAS/LLSC/Dirty/barrier 仍显式保守未知；AAPCS 调用保留非易失寄存器，未知内存写仍显式记录。

固定预算：每函数 demand steps 250000、alternatives 256、depth 500，SSE nodes 200000、worklist/memory iterations 2000000，表索引 4096，CG reanalysis 最多 4 轮。没有执行 frontier 超限时才通过；未知运行时内存/guard 仍为 Incomplete，所有候选 exhaustive=false。

P3 CIR/Memory v1 的契约、tag、wire codec 与 schema 文件未改变；完整 memory arena 用原 P3 record JSONL 和 hash/count manifest 流式归档，不截断，也不宣称这是新的 Schema。原生回放留下 `CallMemoryEffects` 及祖先元数据边界的 `InputBoundary`，没有抹去不支持项。

## 测试、资源与保存

最终统一脚本包含：47 项纯 P6 `-S` 测试、231 项全回归、21 项 ARM/P4 原生测试、旧方法 characterization、旧新 loader、19 函数 CIR acquisition、真实图/摘要变更回放、旧 Collector 同 CIR 差分、git diff check、原生边界与全部受保护目录完整性检查。具体 exit code、采样 RSS、wall time 见最终 `commands.json`。

最终回放的最后 19 个 scope 合计：DAG unique nodes=30107、APG nodes/edges=337/233、APG summaries=0、Heap object observations=209、Heap cells=284、MemoryVersions=91、Alias queries=31524、Definition queries=128、solver queries=0，worklist/memory accounting iterations=627055。此处 objects 是各 scope 的观测数之和，不是全程序去重；facts=0 是 P5 taint arena，535 个 iCall 候选另计。30 次常规分析的完整 arena 均已归档并核对全部文件 hash；完整解码/损坏拒绝另有独立测试，不声称逐一重新解码了全部大型原生 arena。

本次 10 个验收命令全部 exit=0，无 timeout。CIR acquisition 98.875 秒；包含完整常规 arena 归档、真实摘要变更及恢复重分析的 integration 命令 726.344 秒，采样进程树 RSS 峰值 303017984 bytes（约 289 MiB）；同 CIR 的旧 Collector 回放 10.750 秒、10539 次字节读取请求。原生 CIR coverage 为 5366 条 metadata、35566 条 lowered statement；所有资源口径及命令绝对路径见 `commands.json`，不将这些端到端时间解释成纯数据流内核耗时。

本轮不据这些数值宣称整体性能提升：旧 Golden 是 warm input，而新流程独立冷恢复；诊断归档、19 函数范围、数据流实现、引擎和版本均不同。采样 RSS 也是 100ms 的进程树之和，不是精确的单进程峰值。

只读保护核对旧仓库（含 .venv/.git/未跟踪文件）、目标 .venv、全部 Golden、P1–P5 封存目录及首次 P6 封存目录的 size/mtime/SHA256，全部一致。文件数依次为旧仓库 13461、目标 .venv 13044、Golden 351、P1/P2/P3/P4/P5 封存 214/55/78/80/140、首次 P6 封存 126。原目标工程保留的 native wrappers 单独列出并验证未变；迁移后的 CIR 核心不依赖这些 wrappers。三份 v5 文档及 frozen Schema 不变。本轮所有目标代码变更有 before/after hash，未清理用户已有 dirty 文件。

## 回退与停止边界

`run_with_legacy_fallback` 调用实际提供的 legacy runner，保留失败 primary；无 runner 明确报错，不把 Golden 当作执行结果。既有默认选择器与原 reference 保留。完整新 CLI、Taint/BugFinder、source/sink/sanitizer、跨函数漏洞证据与 Gate A 属于 P7，本轮未开始；Rust 未开发。

自动审批曾拒绝删除旧 `p6_validate.py`，理由是可能丢失未提交验收逻辑；该脚本已保留，本轮新增 `p6_acceptance.py` 并复用其命令采样工具。没有绕过被拒绝的删除操作，也没有待审批的破坏性操作。

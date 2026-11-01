# P1：angr 10.0.5 / Claripy 兼容边界与原生求解故障

> 历史报告：以下是切换版本前的 10.0.5 结论和当时阶段状态。用户随后更新为 9.3.4；当前结果见 [P1-9.3.4-report.md](P1-9.3.4-report.md)，表达式补采见 [P0-B-v5-report.md](P0-B-v5-report.md)。原始失败证据保持不变。

日期：2026-10-28（Asia/Shanghai）。阶段：S1 / P1。**兼容边界、证据采集和回归已完成；P1 Gate：BLOCKED_NATIVE_SOLVER。** 目标 Claripy 的最小 SAT/UNSAT 查询仍原生退出 0xC0000005，不能宣称目标求解器已可用或进入 P2。P0-B v5 表达式规模补采仍未执行；既有通过的 P0-B 保持原样。

## 范围、Git 与完整性

工作区：`D:\works\dataflow\EmTaint\emtaint-migration\BinaryAnalysis`。旧仓库为同级 `EmTaint`，未使用外层同名目录。目标 base `6cb026767db005e48b36b994ee8542962b6df627`；旧 base `72a9e3081632b2f9d1881141bc7b0d43c7158033`。目标三份 v5 文档的用户修改及旧仓库已有 dirty 状态均保留，未切分支、提交或 push。

本轮只新增必要的 Python SolverPort/ClaripyAdapter/legacy marker 描述、隔离 probe 和测试。不修改现有 SSE、alias、dataflow、taint、IR/PAG、前端业务代码；不安装/更新依赖、不修改两个 .venv、不建立 Rust 项目、不运行固件分析 `-i/-t`。

从最初 P1 before 到最终 after 的完整记录相等，包括大小、SHA256 与 mtime_ns：

| 保护范围 | 文件数 | 结果 |
|---|---:|---|
| 全旧仓库（含 .git/.venv/未跟踪数据） | 13,461 | 不变 |
| 目标 .venv | 10,020 | 不变 |
| 全既有 baselines | 233 | 不变 |
| 用户三份 v5 文档 | 3 | 哈希不变 |

证据见最终 `phase-integrity.json`，各 probe 轮也各自保留 before/after。旧 Git 三项原有记录不变；没有修复/恢复旧文件或属性。

## 文件与公共边界

| 文件 | 作用 |
|---|---|
| `emtaint/solver/port.py` | 原生库无关的有限纯 BV 查询 DTO、类型/位宽/预算验证、明确状态与 SolverPort Protocol |
| `emtaint/solver/process_port.py` | 每次查询独立 target 子进程，记录完整命令/请求/退出码，隔离 crash，截止时终止 venv launcher 与实际 worker |
| `emtaint/solver/backends/ast_tools.py` | Python 3.7-compatible AST 遍历/替换/结构导出，由旧/新 probe 共用；native 对象只留在 backend 边界 |
| `emtaint/solver/backends/claripy_adapter.py` | 固定 `from angr import claripy`，仅接受目标 10.0.5；有限纯 BV 转换与显式求解结果 |
| `emtaint/compat/legacy_memory.py` | 旧 Load/Store marker 的地址/宽度及缺失语义描述，不能执行内存 effects |
| `scripts/p1_probe.py`、`p1_runtime.py` | 绝对解释器、私有 TEMP、PLY 禁写表、文件写入守卫、faulthandler 与 DLL 路径证据 |
| `scripts/p1_collect.py` | 新 UTC-ID、逐旧调用完整性校验、前后环境/Golden 清单；默认 dry-run |
| `scripts/p1_solver_worker.py` | SolverPort target worker；所有临时缓存仅写当前请求目录 |
| `scripts/p1_api_inventory.py` | native import/调用/属性候选清单，显式区分解析证据与候选 |
| `tests/test_solver_contracts.py` | 28 项新增契约/异常/进程边界测试；另保留原 25 项基线测试 |
| `.gitignore` | 仅新增忽略 `.p1-work/` 本地缓存/原始证据；不是基线目录 |

包初始化不隐式导入 native solver。公共 DTO 不保存 Claripy/VEX 原生对象。`Term` 是 P1 的 `p1-pure-bv-1` 求解消息协议，**不是 P3 CIR-Wire 或 Memory-Semantics Schema**。

## 真实环境与表达式契约

旧解释器：`D:\works\dataflow\EmTaint\emtaint-migration\EmTaint\.venv\Scripts\python.exe`，Python 3.7.2，angr 9.0.9792，Z3 4.13.3。

目标解释器：`D:\works\dataflow\EmTaint\emtaint-migration\BinaryAnalysis\.venv\Scripts\python.exe`，Python 3.12.9，angr 10.0.5，Z3 5.3.1。两套进程各用本地库，不把旧 DLL 或 site-packages 注入新环境。

两个 probe 的结果逐项比较相同：

- Extract `0x12345678[15:8] = 0x56`，Concat `0x12:0x34 = 0x1234`。
- ZeroExt `0x80:8 → 0x0080:16`，SignExt `0x80:8 → 0xff80:16`。
- 常真 ITE 选 7；`0xffffffff:32 + 2 = 1:32`。
- Concat(x,x) 导出两次 occurrence、一次结构 unique、一次 leaf；替换两处 x 为 y，两侧导出完全相同。
- 普通 BVS 归一化后相同 key：`bc3daa31373f3aa6d0540eb67eee4acfcce95d7bc46758e905e3d3eeb8970e49`。
- 两侧错误 Extract 均抛 ClaripyOperationError；adapter 明确拒绝不同 sort/width 替换。
- 两侧附加 SimplificationAvoidanceAnnotation 成功；旧 annotations 为 tuple，新为 list。

结构 key 不是一般 SMT 等价性。portable export 明确拒绝非空 annotation、旧 VSA bounds/flags、自定义内存操作和未知 operation；不会为让测试通过而删除它们。完整 SimAction/RecursiveExpr 位置关联、annotate/simplify 的全部行为与真实 SSE 状态仍待 P5。

## 求解故障与 UNKNOWN 丢失

| 检查 | 旧环境 | 目标环境 |
|---|---|---|
| Claripy `x:32 == 7` | SAT；eval tuple(7)，min=max=7 | satisfiable 原生退出 0xC0000005 |
| Claripy 同时 `x==7`、`x==8` | False（该 fixture 确为 UNSAT） | 同样原生退出 |
| 直接 z3-python，`x==7` | SAT，值 7 | SAT，值 7 |
| 先 import z3 再 import angr/Claripy | SAT，值 7 | 仍原生退出 |
| Claripy timeout=1ms，32 值放入 31 槽的 pigeonhole | 底层 unknown/reason=timeout；上层 False | 原生退出，目标真实 timeout 行为未验证 |
| 自定义 Load/Store，16-bit 结果/32-bit 地址 | 构造成功，求解报 ClaripyFrontendError | API 不存在，显式 Unsupported |

旧 `BackendZ3._satisfiable` 把任何非 z3.sat 当 False；更隐蔽的是 `backends/__init__.py:626` 的 `_check_satisfiability` 基类实现又将 False 包装为 `'UNSAT'`。所以 **不能因存在名为 check_satisfiability 的方法就信任三态结果**。真实 timeout probe 的原始 Z3 check 只执行一次，观测器保留原返回值，没有改变旧算法。

Adapter 对没有单独验证过的精确 status reader，仅接受 True 为 SAT，将 False 保守标为 UNKNOWN。额外 UNKNOWN/TIMEOUT/UNSUPPORTED/ERROR/CRASH 不能转为“无发现”；`SolverResult` 禁止 bool 转换。底层显式 timeout 中断与通用 canceled 中断分别分类；这些异常分类中的部分是 fault injection 验证，不冒充目标真实 timeout 求解通过。

`SubprocessSolverPort` 的真实 smoke 已返回 CRASH（0xC0000005），父进程正常退出，values 为空；原始证据位于 `.p1-work/solver-requests/534c74245e314a10bc94f82b780b3e86/`。没有自动回退旧 Python、SolverConcrete/VSA 或 z3-python。直接 Z3 仅用于诊断，不是替代求解路径。

## 原生链接线索：事实与假设分离

已确认：目标 crash 前加载的是目标 `.venv/Lib/site-packages/z3/lib/libz3.dll` 和目标 `angr/rustylib.pyd`，未见旧环境 Z3 DLL。Python 直接 Z3 使用同一目标 DLL 路径却能完成该最小查询；提前导入 Z3 仍不能修复 Claripy crash。

PE 静态检查发现 rustylib.pyd 对 libz3.dll 的 **153 项导入全部按 ordinal**，没有按名称导入。对比本机两份 DLL，138 个相同 ordinal 的导出函数名不同，例如 ordinal 73 在目标为 Z3_mk_not、旧版为 Z3_mk_add。详见第二轮 `native-linkage.json`，包含文件路径、哈希和完整映射。

这支持“原生构建的 import library 与运行 DLL ordinal/ABI 不匹配”的假设，**尚未证明 wheel 编译时实际预期的导出表**。没有 native symbol/debug build，不能将假设写成已证实根因。未复制/加载旧 DLL、修改 IAT 或替换任何包。P1 Gate 仍被 native 故障阻塞。

## 调用点与旧内存语义映射

最终 `legacy-api-callsites.json` 扫描旧源码 166 个 Python 文件：95 条 native import、373 条按 import alias 解析的调用，以及未解析调用/属性候选。4 个旧 IDA exporter 的 Python 2/缩进语法错误单列，另做文本线索检索；未执行 exporter。

目标扫描当前 `emtaint/` 下 98 个 Python 文件，均可解析。候选名称不等于已证实的 native 对象；文件级 alias 也有重绑定和动态分派限制。完整支持/不兼容矩阵见 [API_COMPAT_MATRIX.md](../API_COMPAT_MATRIX.md)，逐语义来源与 P3/P5 边界见 [P1_MEMORY_MAPPING.md](../P1_MEMORY_MAPPING.md)。

关键限制：旧 Store(addr,bits) 没有写入值/前后状态；Load 也没有 endian/version。P1 只描述它们并禁止直接求解。未来必须从 Action/CIR 补齐 Read/Store effects、稳定 Root、APG 路径、Heap 与 MemoryVersion，再做按需 lowering；不能把 marker 直接改名为 SMT Array store/select。

## 命令、退出码与证据

所有命令从 TARGET 执行；所有 Python 均绝对路径、`-B`、`PYTHONDONTWRITEBYTECODE=1`。旧进程在导入 angr 前启用 PLY 禁写表和写入 guard；私有 TEMP 已固定。Windows NUL 设备仅对明确打开操作作精确例外，不放行其他外部写入。

```powershell
# 默认只读计划，退出 0，不创建证据
& 'D:\works\dataflow\EmTaint\emtaint-migration\BinaryAnalysis\.venv\Scripts\python.exe' -B scripts/p1_collect.py
# 全套 API probes，采集器退出 0；子进程失败逐项保留
& 'D:\works\dataflow\EmTaint\emtaint-migration\BinaryAnalysis\.venv\Scripts\python.exe' -B scripts/p1_collect.py --execute
# 最终表达式契约与真实超时对照，采集器退出 0
& 'D:\works\dataflow\EmTaint\emtaint-migration\BinaryAnalysis\.venv\Scripts\python.exe' -B scripts/p1_collect.py --execute --cases expressions timeout
# 最终回归：53/53，无跳过，退出 0
& 'D:\works\dataflow\EmTaint\emtaint-migration\BinaryAnalysis\.venv\Scripts\python.exe' -B -m unittest discover -s tests -v
```

采集器退出 0 表示证据完成且保护范围不变，**不表示所有 native 契约通过**。原始目录：

| P1 ID | 内容 |
|---|---|
| `20261028T060718Z-84cb4608` | 初始诊断：旧 UninitializedAnnotation 不存在导致 fixture 失败；目标 NUL 设备被严格 guard 拒绝。保留原错误，旧/新环境与 Golden 不变 |
| `20261028T061905Z-221fb340` | 修正 fixture 和 NUL 精确例外后的 12 个 probes；目标 SAT/UNSAT/preload 三次 native crash；含 DLL/ordinal 证据 |
| `20261028T062916Z-123a2aa6` | 最终共享 AST helper 的双版本契约、旧 raw UNKNOWN/timeout、目标 timeout crash、API 清单、最终测试及完整性验收 |

每个 probe 子目录包含绝对命令/CWD/退出码、stdout checkpoint JSONL、stderr、report（原生退出时 report 缺失如实记录）和私有 cache。最终目录的 `tests-reviewed.*` 保存 53 项测试与退出码；`validation-summary.json` 明确 Gate=BLOCKED_NATIVE_SOLVER；`phase-integrity.json` 覆盖整个 P1 起止。三个初始约束文档未被本轮编辑。

53 项包含原 25 项基线回归与新增 28 项：协议/位宽/边界、不同符号宽度冲突、内存 marker 拒绝、annotation/VSA 不丢失、默认与 unique 遍历、leaf 次序、UNKNOWN/错误/超时分类、禁止结果转 bool、模型验证，以及进程故障和截止清理。测试中的 native 退出注入是 Windows ExitProcess 模拟，用于验证隔离；真实 native crash 另有上述 probe/port smoke 证据。

## Gate、未知覆盖、回退与后续

- 已通过：所列纯表达式/遍历/替换/结构键契约、错误显式化、进程隔离、单测、旧环境和 Golden 保护。
- **未通过：目标 Claripy 原生 SAT/UNSAT/EVAL/min/max/timeout 求解。** 包装层不能修复 native ABI；不能将这一失败改标成功。
- 未执行：固件 `-i/-t`、P0-B v5 指标补采、端到端新旧 finding 差分、P2–P5、Rust。APG/Heap/DAG/facts/worklist 指标和 opcode/unsupported 语义覆盖率为未实现/未采集，不填 0 或 100%。P1 probe 不是性能 benchmark，没有加速结论。
- unknown annotations、VSA、BoolS/FP/String 等超出当前纯 BV 消息子集的操作显式拒绝。完整内存 lowering、别名、重叠字节和 guard 传播仍待 P3/P5 Gate M。
- 回退：新边界尚未接入业务，停止使用 P1 helper/port 即不再新增进程；按本报告文件清单人工撤回目标新增文件及 .gitignore 条目，保留用户三份文档修改。所有既有 baseline 和新证据保留，不自动 reset/clean/删除。

下一步仍在 P1：取得当前 wheel 编译所需 Z3 import-library/ABI 的可验证信息，制定匹配 Windows native 构建或依赖修复方案；包更换/构建须单独批准。修复后先重跑最小 SAT/UNSAT/EVAL 与真实 UNKNOWN/timeout，再复查本边界；不得通过静默降级求解器或注入旧 DLL 继续迁移。本轮停在 P1，不自动进入 P2。

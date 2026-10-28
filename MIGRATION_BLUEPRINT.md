# EmTaint → BinaryAnalysis 迁移架构蓝图（Windows / angr 9→10）

> **版本**：v3.0，2026-10-28。**状态**：待按本机仓库与虚拟环境复核的执行蓝图。本文不代表已在用户 Windows 主机上运行任何测试；不授权修改旧项目。配套：`AGENTS.md`（强制约束），`CODE_TASK.md`（逐阶段执行指令）。

## 1. 目标、约束和成功标准

### 1.1 唯一任务

在不牺牲 EmTaint 原有间接调用、控制流/Switch、SSE/结构化符号表达式、别名、跨函数污点及安全漏洞分析能力的前提下，把它们**逐层迁入** `BinaryAnalysis`。最终核心分析算法不直接依赖任何特定 IR；支持（A）直接 angr/VEX，（B）IDA CFG/指令范围→angr/VEX，（C）IDA Microcode 三条前端。

**旧环境**：`emtaint-migration/EmTaint/.venv/`（`angr==9.0.9792`），随 `EmTaint` 旧仓库放置；**新环境**：`emtaint-migration/BinaryAnalysis/.venv/`（`angr==10.0.5`）。两个仓库并列放在 `emtaint-migration/` 下。Windows + PowerShell 原生执行，不使用 WSL/Docker。严禁修改旧仓库（包含运行结果）；如需重跑旧 CLI，先复制到隔离目录。

### 1.2 成功标准（必须是可测语义，而不是代码量）

- **F1**：固定旧仓库 rv130 `httpd` 样本及依赖，首先只读保存已有历史 JSON；在获准的隔离副本中复现 `-i` 并保存 `icall.json`，之后复现 `-t` 并保存 `taint.json`，记录输入/配置/时序/输出哈希，原旧仓库任何文件都不改变。
- **F2**：BinaryAnalysis 的新 CLI/SDK 至少复现原先两阶段的关键事实：间接调用候选与已确认目标、CG/CFG 变化、Source→Sink 传播、漏洞类别/位置/证据；每个差异有诊断说明。允许纠正原项目缺陷，但**不能无解释地减少已知真阳性**。
- **F3**：`emtaint/core`、`emtaint/ir`、`emtaint/graph`、`emtaint/analysis` 内零新引入的 `angr`、`pyvex`、`ida*` 依赖；最终零直接依赖。
- **F4**：可手工构造 Canonical IR，**不安装 angr/IDA** 就可以测数据流、SSE、别名、污点的纯核心逻辑（可替换求解器接口）。
- **F5**：来自 VEX / Microcode 的不支持操作、求解超时和分析不完整情况有显式可聚合的诊断，绝不以“不支持”冒充“未发现漏洞”。
- **F6**：从 VEX、Microcode 前端得到的相同分析事实可用统一语义验证，不要求基本块/临时变量逐项一致。

### 1.3 已确认的两个仓库和父目录（唯一布局）

```text
emtaint-migration/                     # MIGRATION_ROOT
├── EmTaint/                           # LEGACY_ROOT，只读
│   ├── .venv/                         # LEGACY_PYTHON：angr==9.0.9792
│   ├── main.py
│   ├── data/                          # IDA 导出 + 历史结果（只读）
│   ├── dataflow/
│   └── firmware-binaries/rv130_v44/httpd
├── BinaryAnalysis/                    # TARGET_ROOT，可修改代码
│   ├── .venv/                         # TARGET_PYTHON：angr==10.0.5
│   ├── emtaint/
│   ├── AGENTS.md
│   ├── MIGRATION_BLUEPRINT.md
│   └── CODE_TASK.md
├── baselines/                         # 旧版已有结果及隔离运行结果归档
└── baseline-work/                     # 批准后创建的旧版运行副本
```

从目标仓库出发的路径：`../EmTaint` 是**唯一旧源码仓库**，`../EmTaint/.venv/Scripts/python.exe` 是旧解释器，`.venv/Scripts/python.exe` 是新解释器，`../EmTaint/data/result_data/rv130_1_0_3_44.json` 是旧输出文件。**不存在需要选择的第二份旧源码或外层旧 `venv`。** P0 的职责是确认这些明确路径存在且环境版本正确，并检查运行所需元数据，不是推测哪个目录才是旧项目。

**不可变性约束**：历史 JSON、IDA 数据、固件样本、虚拟环境乃至 `.git/` 都不可在原旧仓库修改。旧解释器的只读探测采用 `-B` / `PYTHONDONTWRITEBYTECODE=1`，并避免让扫描工具在旧目录创建缓存。基线收集默认只读复制现有文件；需复现两阶段命令时从隔离物理副本运行，防止 `-i/-t` 回写旧仓库。若旧脚本硬编码旧仓库输出路径，则停止复现，先进行只读风险审计。

## 2. 公开源码中已确认的线索与必须重新核查的事实

> 下列是**公开代码观察**，不是对用户本地 checkout 的断言。Codex 须在 `docs/migration/INVENTORY.md` 中给出实际路径、类/函数、引用者、证据行或 Git commit，更新每项结论。

### 2.1 原始执行链

`main.py` 的命令行参数包括 `-f/--binary_file`、`-n/--firmware_name`、`-v/--firmware_version`、`-i/--icall_check`、`-t/--taint_check` 和 `--resolve_icall`。调用 `perform_analysis` 后，读取 IDA 导出的 CFG/Block/Switch/间接调用资料，通过 IDAProcess/FunctionCFG 建 CFG，利用 angr 提升为 VEX IRSB，再由 `vex_process.py`、数据流框架及 `FastSearch` 完成相关分析，最后由结果收集和 `security_check.py` 写入/判定输出。

**关键精度要求**：IDA 并非仅输出汇编文本供纯 Python 手写翻译；原始 `generate_cfg.py` 使用 `project.factory.block(...).vex` 对二进制字节 lifting，而且一个 IDA Block 可能跨越多个 VEX IRSB。必须正确维护指令与基本块来源映射。

### 2.2 目标仓库已有原型（作为迁移起点）

`emtaint/ir/vex_ir.py` 保留 `pyvex.IRSB`/`IRStmt`；`ir` 子类及 `frontend/angr` 当前仍与 VEX 耦合；`analysis/pag` 原型与 CFG 路径已存在。公开代码中还出现硬编码实验函数地址 `0x16FD8`、未实现接口、错误/丢弃式转换行为。不能把这些原型视为可直接承载原始算法的稳定框架；应先写可复现测试再逐项替换。

### 2.3 源码重要参考（Codex 应逐一阅读）

| 旧仓库入口/模块 | 审计重点 | 迁移策略 |
|---|---|---|
| `main.py` | 参数、路径、模式开关、结果写入、`-i/-t` 时序 | CLI 兼容层 + orchestration |
| `dataflow/ida_plugin/parse_arm_binary.py` | IDA 版本、CFG/块/间接目标导出格式 | IDA exporter / legacy metadata reader |
| `dataflow/ida_process.py` | IDA 元数据解析、CallGraph/CFG、地址映射 | `frontends/ida_vex/metadata.py` + graph |
| `dataflow/generate_cfg.py` | IDA blocks → 一个或多个 pyvex IRSB | `frontends/ida_vex/lifter.py` |
| `dataflow/vex_process.py`, `parse_binary.py` | VEX Statement/Expr 与 Action/DefUse | VEX lowering + Core Transfer（分清归属） |
| `dataflow/variable_expression.py`, `parse_ast.py` | `VarExpr`、`TraceExpr`、`SimAction`、Claripy AST | 保留行为，渐进提取 SSE、solver ports |
| `dataflow/fast_data_flow.py` | 快速 def-use、变换、数据传播 | `analysis/dataflow/fast.py` |
| `dataflow/accurate_data_flow.py` | 符号表达式传播/别名/精确分析 | `analysis/dataflow/accurate.py` |
| `dataflow/data_trace.py` | `FastSearch`、调度、跨函数依赖、污点路径 | scheduler + passes + session |
| `dataflow/data_process.py` | Seed 构造、指针/间接控制分析入口 | analysis seeds/strategies |
| `dataflow/data_collector.py` | iCall、表达式、漏洞结果汇集、全局共享状态 | results/session collector |
| `dataflow/security_check.py` | 敏感操作与漏洞判定 | taint policies + finding rules |
| `dataflow/call_graph.py`, `global_config.py`, `procedures/` | CG、架构配置、外部调用摘要 | graph / config / procedure registry |
| 目标 `emtaint/assembly`, `ir`, `analysis/pag`, `frontend` | 类签名/依赖、原型缺陷与已有测试 | 保留有用抽象，修正语义边界 |

**删除规则**：所有“废弃代码”须先通过引用扫描、测试覆盖、实验入口检查与 Git 历史判断，独立形成删除清单；P0～P8 不因名称/风格删除。

## 3. 新架构决策：模块化单体 + Ports/Adapters + Canonical IR

```text
CLI / Python API
        |
AnalysisOrchestrator -- Session/Config -- ResultStore -- Baseline Comparator
        |
PassScheduler / AnalysisContext (worklist, budget, graph revisions)
        |
  +-----+-----------+------------------+
  |                 |                  |
Graph & CFG       Analysis Core      External Models
CFG/CG/ICFG       SSE/Memory/Alias    ABI/Procedure Summaries
PAG/DDG derived   DefUse/Dataflow     Solver Port
  |               Indirect/Switch     Finding Policies
  |               Taint/BugFinder
  +-----------------+------------------+
                    |
      Canonical Semantic IR (typed, immutable, provenance)
                    ^
                IR Adapter boundary
          +---------+------------+
          |         |            |
      angr/VEX   IDA+VEX     IDA Microcode
       direct    legacy cfg   portable snapshot
                 + bytes      (IDA-side exporter)
```

### 3.1 建议目标包

```text
BinaryAnalysis/
├── emtaint/
│   ├── core/               # Program, Function, Block, Location, Arch, ABI, Session
│   ├── ir/                 # typed Expr/Stmt/Terminator, Width, Provenance, Serialization
│   ├── frontends/
│   │   ├── angr_vex/       # angr CFG + pyvex -> CIR
│   │   ├── ida_vex/        # legacy IDA metadata + binary bytes -> VEX -> CIR
│   │   └── ida_microcode/  # Hex-Rays snapshot -> CIR; exporter 与解析器分离
│   ├── graph/              # CFG, CG, ICFG, graph revisions; PAG/DDG derived views
│   ├── solver/             # SolverPort, ClaripyAdapter, timeout/unknown
│   ├── memory/             # stack/heap/global/unknown regions, strong/weak update
│   ├── analysis/
│   │   ├── framework/      # worklist/lattice/transfer/fixpoint/summary
│   │   ├── sse/            # VarExpr/TraceExpr semantics, symbolic memory addresses
│   │   ├── alias/          # alias facts + evidence
│   │   ├── dataflow/       # fast/accurate transfer
│   │   ├── controlflow/    # switch/ijmp/icall
│   │   ├── taint/          # source/sink/sanitizer/propagation
│   │   └── bugfinder/      # overflow/command injection findings and evidence
│   ├── procedures/         # external function semantics & ABI
│   ├── results/            # result schema/legacy JSON serializer/differential
│   ├── orchestration/      # CLI session and pass scheduling
│   └── cli.py
├── tests/{unit,conformance,differential,regression,integration}/
├── docs/migration/
├── AGENTS.md
├── MIGRATION_BLUEPRINT.md
└── CODE_TASK.md
```

路径是**目标设计**，不得因该树而批量创造空文件。保留仓库已有有效包、模块名/发布接口；如需重命名，提供兼容过渡层。

### 3.2 精确的依赖方向

- `core/ir/graph/analysis` → 仅依赖领域类型与协议，不向 `frontends` 反向导入。
- `frontends` → `core/ir`，可使用 `angr/pyvex/idaapi`。
- `solver/backends/claripy_adapter.py` → 通过 `SolverPort` 提供 SMT/AST 操作，隔离 native AST 类型。
- `application/orchestration` 负责组合各部分；不承载符号表达式传播算法。
- `PAG` 是从 IR 派生的 def-use/data dependency facts，不等于 CFG；ControlFlowPass 更新 CFG/CG 时递增图版本，触发增量失效。

### 3.3 Canonical IR 的设计范围

**首先做 VEX 语义的正确子集，不急于建立完整编译器 IR。** 建议直接采用 typed effects/assignments + basic-block terminator 的非 SSA 初版，避免在迁移时又引入 SSA 重命名造成难以比较；未来可添加 SSA view。

- Expr: Constant, Register/Temp, Unary/BinaryOp, Cast(Sign/Zero/Trunc), Extract/Concat, ITE, Load, UnknownExpr。
- Statement/effect: Assign, RegisterWrite, Store, GuardedLoad/Store 或规范化条件效果, Dirty/UnknownEffect, Fence/Atomic if necessary。
- Terminator: Jump, CondBranch, IndirectBranch, Call, Return, UnsupportedTerminator；条件及目标表达式必须保留。
- Width: 统一**bit 数**，显式整数溢出截断、signed/unsigned 比较、大小端；子寄存器读写别名有可测试的规则。
- Memory: 分离 IR 的 Load/Store 与 SSE 的抽象对象，未知外部调用不得默认无副作用。
- Provenance: binary_sha256, provider, provider_version, instruction address, function/block/stmt ID, IR maturity, source ranges；不能直接序列化 pyvex IRSB 或 IDA 原生指针。
- Lowering: Strict 模式抛 `UnsupportedIROp`，Conservative 模式生成 unknown effect 并置 `complete=false`；提供 opcode histogram 和 unsupported audit。
- Edge cases: VEX `IMark/Exit/next/jumpkind`，LoadG/StoreG，LLSC/CAS/Dirty；Microcode 的优化成熟度、lvar 和调用参数模型不可与 VEX 一对一比较。

### 3.4 SSE、Claripy 与数据流分层（最关键）

| 层 | 数据/职责 | 绝对不能做 |
|---|---|---|
| Canonical IR | 保真程序控制与数据操作语义 | 不以 Claripy AST 当作 IR 类型 |
| SSE / SymbolicDomain | 结构化符号表达式、AST 替换/传播、约束 | 不直接处理原生 `pyvex.stmt.*` |
| MemoryDomain | Location/MemoryObject、堆栈/全局/未知、强弱更新 | 不把普通 Load 等同于抽象位置 |
| SolverPort | 建构 BV/Bool、simplify、substitute、solver eval/sat | 不在公共接口暴露具体 Rust 类路径 |
| AliasAnalysis | must/may/no alias，证据与 unknown | 求解失败不得等于 no alias |
| DataflowEngine | block transfer, fact store, worklist, summary | 不在模块初始化时执行整个分析 |
| Taint/Finding | source/sink/sanitizer + 机制规则、证据 | 不能只因污点抵达任意函数即报告确定漏洞 |

**Claripy 兼容策略**：

1. 对旧环境与新环境分别探测：`import claripy`、`from angr import claripy`、BVS/BVV、BV 宽度、AST 访问器、AST 替换、简化、约束、求解、超时行为、类型/异常。
2. 形成逐调用点表：`legacy usage → old observed → new observed → adapter strategy → contract test`。不可只根据版本号批量 `sed` 替换。
3. 保留原 SSE 的 `VarExpr`/`TraceExpr`/`SimAction` 语义；先用 Adapter 替换其对 Claripy 的直接调用，然后迁到独立 domain。旧版与新版 AST 的 structural equality/hash/caching 方式不一定相同：使用明确的 canonical key 或求解等价性测试，而不假设 Python 对象相等。
4. **不要**把旧版 `claripy.ast.Base` 继承/`isinstance` 体系直接平移到 Rust 类型；按可探测的运算协议、封装的结果类型和契约测试实现。
5. `SolverPort` 应至少提供宽度/常量/符号变量、`add/sub/cmp`, Extract/Concat/ITE, simplify/replace/substitute, SAT/eval, timeout/unknown, serialization-for-testing；额外能力由代码实际需求决定。
6. 保持未知、solver timeout、资源耗尽为三种可区分结果，避免精度退化造成漏报。

## 4. Windows 运行基线（最重要的迁移资产）

### 4.1 用户确认的旧版调用

以下命令描述旧版运行契约。**只允许在独立复制出的 `RUN_ROOT` 中执行**（`RUN_ROOT` 保留 `main.py`、`data/`、`firmware-binaries/` 及所需元数据），解释器可指向旧 `.venv`，但不得写入旧根目录：

```powershell
& $LegacyPython main.py -f ./firmware-binaries/rv130_v44/httpd -n rv130 -v 1_0_3_44 -i
& $LegacyPython main.py -f ./firmware-binaries/rv130_v44/httpd -n rv130 -v 1_0_3_44 -t
```

运行副本中的结果路径 `data/result_data/rv130_1_0_3_44.json` 在两阶段相同，且旧仓库可能已经包含只读历史结果。因此先从旧根目录只读归档已有 JSON；若获批准运行，必须在 `RUN_ROOT` 中分别快照，不能将 `-t` 后的文件误认成 `-i` 的结果；至少保留：

```text
emtaint-migration/baselines/rv130_1_0_3_44/<run-id>/
├── manifest.json              # 两仓 Commit / dirty / interpreter / lib versions / input hashes / cmd
├── preexisting.json           # 若运行前已有结果，不得覆盖丢失
├── icall.json                 # -i 执行完成后立即备份
├── taint.json                 # -t 执行完成后立即备份
├── icall.log
├── taint.log
├── file-inventory-before.txt
├── file-inventory-after.txt
└── normalized/               # 后续规范化比对，不修改原始 JSON
```

`-t` 是否使用 `-i` 先前记录的 iCall 信息，要检查 `perform_analysis`、`get_idirect_call_info`、`IDAProcess`、`save_icall_*` 的真实调用和文件时序。按用户已验证的**先 -i，后 -t**顺序在同一隔离副本中执行，不在原始 `LEGACY_ROOT` 中执行。先确认无硬编码绝对写路径、联接点或符号链接会回写旧仓库。任何阶段失败、输出不存在或无法确认是本次运行生成的、样本 SHA 改变，均应保留日志并标记为阻塞，不得伪造 Golden。

### 4.2 Golden 结果差分层级

| 级别 | 项目 | 对比规则 |
|---|---|---|
| 0 原始 | 两阶段 JSON 原文与 stdout | 永久保留，不就地规范化 |
| 1 配置 | firmware sha, arch, loader, IDA 输入版本, CLI, angr versions | 必须可比、可记录 |
| 2 程序图 | 函数集合、block/CFG 边、CG 边、iCall/switch 候选和确定目标 | 地址归一化须记录 image base；集合比较需有来源 |
| 3 数据流 | SSE 等价类、结构偏移、def-use、alias facts | 必须关联测试点和证据，不仅比较数量 |
| 4 漏洞 | source/sink/guard/path、漏洞类型、函数/指令地址、约束和证据 | 必须逐例解释丢失/新增/变化 |
| 5 性能/完整性 | 分析耗时、内存、被分析函数、unknown 数、unsupported op | 仅同配置/样本/预算可比 |

JSON 结构未知时，先审计实际 schema，再设计差分规范。若 `-i`/`-t` 均更新同一 JSON 字段，需要根据语义归档而非简单将整个 JSON 当某个阶段的唯一产物。不要未经核实给旧版漏洞结果冠以 CVE/TP 标签。

## 5. 分阶段开发与验收（P0—P9）

> 每阶段只能在 **BinaryAnalysis** 中改代码；P0 允许经批准产生旧程序运行**输出**，不改旧源码。每阶段完成后做独立 Code Review / Git 提交，再进入下一阶段。

| 阶段 | 目标与关键迁移 | 强制 Gate | 回退 |
|---|---|---|---|
| **P0** Repository audit + Legacy Golden | 核实唯一旧仓库 `../EmTaint`、两套 `.venv`；先只读归档已有 JSON，获准后在隔离副本中建立 `icall/taint` 快照与版本/哈希清单 | 两阶段基线可验证（或有阻塞记录）；旧仓库全部文件哈希/状态未改变 | 丢弃隔离副本/辅助文件前须审批，旧仓库保持不变 |
| **P1** angr 10 API/Claripy Compatibility | 列出每一处 API 调用点；建立 target `angr_v10_probe` 和 `SolverPort` 的最小契约测试 | 新环境确认为 10.0.5，受用 API 能按测试调用；不改核心算法 | 保留兼容实验分支，撤回 shim |
| **P2** Program/Graph Domain | 独立 Program/Function/Block/CallSite/ABI/CFG/CG，session 生命周期；修正 target prototype 问题 | 无 angr/IDA 的模型单测通过，图边/ID/可变性正确 | 保留旧模型 Facade |
| **P3** Canonical IR Contract | 类型化 Expr/Stmt/Terminator/Origin，unknown/havoc，schema；先 handcrafted tests | IR 不导入原生后端；宽度/内存/控制流契约测试通过 | 旧 VexIR 过渡实现保留 |
| **P4** 两条 VEX 前端 | angr → VEX → CIR；IDA metadata + bytes → VEX → CIR；消除调试地址 | rv130 样本能生成有来源的 CFG/CIR，转换率/不支持比例有报告 | 保留原始 IDA+VEX 入口 |
| **P5** Solver/SSE/Memory/Alias | Claripy 适配、原 `VarExpr/TraceExpr/SimAction/parse_ast` 提取与对照 | 指针/结构体字段/LoadStore/SSE/alias fixture 经双版本对照，unknown 明确 | 旧 SSE Facade 并存 |
| **P6** Dataflow + iCall/Switch + CG | Fast/AccurateDataFlow 迁移，FastSearch 调度拆分，增量图更新/摘要失效 | rv130 `-i` 的间接目标和图证据可解释差异；可达性无无故回退 | feature flag 回到旧工作流 |
| **P7** Taint + BugFinder + CLI | Source/Sink/Sanitizer、Procedure models、命令注入与缓冲区溢出规则；实现 `-i/-t` CLI 兼容 | rv130 `-i`→`-t` 流程可端到端运行，对每个 finding 逐条解释差异 | 保留 legacy CLI/serializer，禁用新 pass |
| **P8** IDA Microcode Backend | IDA 插件导出 versioned snapshot，Microcode → CIR，不修改 Core | 样本上 microcode 与 VEX **可观察语义**比较通过；unsupported 完整记录 | 继续使用 VEX backend |
| **P9** Clean-up & Release | 代码死引用证明、保留历史行为、资源性能、API 文档、版本化发行 | 全部 gate、结果/完整性/性能报告；在分支中可回退 | 上一个通过 gate 的 Git tag/commit |

### 5.1 核心算法不可被重构丢失的细节

- **间接调用**：区分可能目标/已证实目标/未知目标；保存原地址、callsite ID、推导证据、函数摘要和新 CG 边；不能因 solver 未支持就认为不存在。
- **Switch/Indirect Jump**：保留 CFG edge kinds 和 branch guards；VEX 多 IRSB 与 IDA block 的对应信息。
- **SSE**：保留符号表达式中的结构偏移、load/store、约束、AST substitution、上下文信息；避免基于 Python 对象身份做跨版本比较。
- **污点类漏洞**：结果必须包括 Source、传播关系、Sink、Guard/Sanitizer、约束可满足性/未知、结果类别及置信解释；区分条件不满足与未分析。
- **过程间分析**：外部函数摘要及 ABI 仍是解析 iCall 和 taint 的关键，不可替换为无条件返回 Top 而宣称功能等价。

### 5.2 每阶段一致的输出格式

Codex 在 `docs/migration/phases/Px-report.md`（阶段审批后才写）记录：

1. 已审计旧类/函数及文件证据（路径和行号）、新模块及映射。
2. Git base + files changed、影响的公开接口、是否引入依赖。
3. 执行的完整命令、解释器路径、退出码、测试用例与通过/失败/跳过。
4. baseline 差分摘要（严格列出新增、丢失、仅排序差异及未知状态）。
5. IR 支持 opcode histogram、unsupported 总数、分析完整性百分比（有明确分母）。
6. 风险、未覆盖路径、回退命令与下阶段前置条件。

## 6. IR 语义一致性测试矩阵（P3/P4/P8 必须维护）

| 语义族 | 测试点 | 结果必须保留 |
|---|---|---|
| bitvector | 8/16/32/64 位溢出、signed/unsigned | 结果宽度、截断/扩展、比较语义 |
| register | x86 子寄存器 / ARM 寄存器别名（按样本） | write mask、aliases |
| memory | 不同 endianness、Load/Store、强弱更新 | 大小、地址、内存版本/region |
| control | guard、conditional、switch、indirect jmp | 目标集、分支可达条件 |
| call | direct/indirect、ABI 参数/返回、未知外部调用 | side effects 与 CG 更新 |
| SSE | pointer arithmetic、structure fields、alias | 表达式规范化和约束证据 |
| taint | source→sink、sanitize true/false、branch guards | 传播路径、证据和状态 |
| unsupported | Dirty、LLSC/CAS、未知 Microcode opcode | 明确 Unsupported/Conservative 而非静默略过 |

推荐 microprogram fixtures 同时有人工确认的预期语义；两个前端彼此一致不等于都正确。先增加 rv130 真实样本，再扩大架构覆盖。

## 7. 决策记录、性能与风险

- **ADR-001**：采用 typed semantic CIR，而不是 `IR` wrapper 返回原生 `pyvex` 或 Microcode `minsn_t`。
- **ADR-002**：SSE 领域层与 IR 分离；Claripy 版本差异统一在 SolverPort 后。
- **ADR-003**：不强制一开始使用 SSA，不强制先移除 Claripy，不强制更换所有分析算法。
- **ADR-004**：先两条 VEX 前端跑通完整 `-i`/`-t`，再加入 Microcode 做 IR 无关性证明。
- **ADR-005**：旧版 golden 不因发现缺陷而重写；已确认缺陷以已批准的变更记录解释。
- **ADR-006**：不把 10.0.5 叫作永久“最新”，而是**固定的目标验证版本**，后续升级使用独立兼容性矩阵。

性能指标：相同机器、同一二进制 SHA、相同选项/分析预算、记录 cold/warm 次数及函数覆盖；缓存命中导致的提速不得混入算法对比。若覆盖率/函数数变化，耗时不可直接当成效率改进。

## 8. 明确非目标与风险提示

- P0～P7 不构建 Web 后端/UI/Agent、不采用 Docker/WSL、不发布新增漏洞利用方法；不得通过直接修改旧 `data/` 来制造 Golden。
- 旧版能运行并不意味着新版 10.0.5 API 兼容；`import angr` 成功不等于 VEX/Claripy 和污点链正确。
- 固件/IDA 元数据很可能包含二进制许可及敏感信息，Golden 放在工作区外或 `.gitignore`，不自动上传。
- 现已明确只有 `emtaint-migration/EmTaint` 这一份旧仓库，不再寻找外层旧源码；仍不假定本地工作树与公开仓库相同，也不假定 BinaryAnalysis 已实现 `-i/-t`；须由 P0/P7 实测。

## 9. 参考链接

- https://github.com/kuc001/EmTaint
- https://github.com/kuc001/BinaryAnalysis
- https://docs.angr.io/en/v10.0.5/advanced-topics/claripy.html
- https://github.com/angr/angr/releases/tag/v10.0.5
- https://hex-rays.com/blog/hex-rays-microcode-api-vs-debugger-api (Microcode 相关内容以对应版本 SDK 文档为准)

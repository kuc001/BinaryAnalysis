# BinaryAnalysis — Codex 工作规则（Windows 双 Python 环境）

> 本文件位于 **`emtaint-migration/BinaryAnalysis/AGENTS.md`**。适用于从 BinaryAnalysis 根目录启动的 Codex 开发会话。本文是**项目约束**，不是对阶段性任务的授权；要执行哪一阶段，以 `CODE_TASK.md` 为准。

## 0. 唯一目标与真实目录

**唯一可信的目录结构**（`MIGRATION_ROOT = emtaint-migration/`，不要再推断外层 EmTaint 仓库）：

```text
emtaint-migration/                    # MIGRATION_ROOT，两个仓库共同的父目录
├── EmTaint/                          # LEGACY_ROOT，旧仓库，严格只读
│   ├── .venv/                        # 旧 Python 环境：angr==9.0.9792
│   ├── main.py                       # 旧版 CLI 入口
│   ├── data/                         # IDA 元数据、历史结果；不得修改
│   │   └── result_data/rv130_1_0_3_44.json
│   ├── dataflow/                     # 旧版分析核心，参考源，不允许编辑
│   └── firmware-binaries/           # 旧版样本目录，不允许修改
│       └── rv130_v44/httpd
├── BinaryAnalysis/                   # TARGET_ROOT，唯一允许改业务代码
│   ├── .venv/                        # 新 Python 环境：angr==10.0.5
│   ├── emtaint/                      # 新版分析核心
│   ├── AGENTS.md
│   ├── MIGRATION_BLUEPRINT.md
│   └── CODE_TASK.md
├── baselines/                        # 可选：只写入新建的独立基线目录
└── baseline-work/                    # 可选：经批准的隔离运行副本，不是旧仓库
```

从 `BinaryAnalysis/` 启动的 Codex **必须**使用如下相对路径：

| 变量 | 路径（相对于 `TARGET_ROOT`） | 访问权限 |
|---|---|---|
| `MIGRATION_ROOT` | `..` | 仅在批准后创建基线/隔离副本 |
| `LEGACY_ROOT` | `..\EmTaint` | **严格只读，包括 data/ 和 .venv/** |
| `TARGET_ROOT` | `.` | 当前阶段允许的业务代码修改 |
| `LEGACY_PYTHON` | `..\EmTaint\.venv\Scripts\python.exe` | 只能运行只读探测，或在隔离副本中运行旧分析 |
| `TARGET_PYTHON` | `.venv\Scripts\python.exe` | 新代码和新测试 |
| `LEGACY_RESULT` | `..\EmTaint\data\result_data\rv130_1_0_3_44.json` | 只读归档，不得覆盖 |

先以 `Resolve-Path` 和 `Test-Path` 验证绝对路径；不要构造 `..\..\venv` 或把 `emtaint-migration` 的父目录当作旧项目。

- **Legacy**：`emtaint-migration/EmTaint` 是原始仓库，**一切文件（含 JSON/IDA 数据、虚拟环境）均不允许修改**。只读扫描及复制到独立目录是允许的；不要在此目录下运行可能写文件的旧分析命令。
- **Target**：`emtaint-migration/BinaryAnalysis` 是唯一可修改业务代码的仓库；在专用 Git 分支进行阶段性重构。
- **Baselines/Run Copy**：需要运行旧版 `-i/-t` 时，先经人工批准，将必要文件复制到 `MIGRATION_ROOT/baseline-work/` 中的**独立物理副本**，从副本执行，归档到 `MIGRATION_ROOT/baselines/`；不能使用会回写旧仓库的硬链接、联接点或共享输出路径。
- **Python**：始终使用对应解释器的**绝对路径**，不依赖 `python`、`pip`、激活状态或全局 `PYTHONPATH`；严禁混用虚拟环境。对只读旧环境的探测和运行副本中的旧程序均使用 Python `-B` 并设置 `PYTHONDONTWRITEBYTECODE=1`，避免产生 `.pyc` 等副作用。
- **运行平台**：Windows + PowerShell；不使用 WSL、Docker 或 Linux shell。

## 1. 任务目标（禁止重新造一个简化版本替代 EmTaint）

将 EmTaint 实有的 `IDA metadata → CFG/blocks → angr/pyvex lifting → VEX 分析 → SSE/别名/间接控制流 → 污点/漏洞发现` 增量迁入 BinaryAnalysis，复用原有研究算法且保持已验证结果。构建无需依赖 VEX 类型的 **Canonical IR**，使下列前端都可向同一个核心分析引擎供给 IR：

1. `angr + VEX`（直接从二进制）。
2. `IDA CFG/Block/Bytes + angr VEX`（兼容原始 EmTaint 数据路径）。
3. `IDA Hex-Rays Microcode → portable snapshot → Canonical IR`（后期添加，独立于 VEX）。

不可仅按目录搬运旧 `dataflow/`，也不可为“消除耦合”把成熟 SSE/污点算法无测试地整体重写。

## 2. 架构硬约束

1. 新建/迁移后的 `core/`、`ir/`、`graph/`、`analysis/` 不得**直接**导入 `angr`、`pyvex`、`idaapi`、`ida_hexrays` 或原生 IR 类。现有违例应先清点，按阶段移除，不应新增。
2. 原生对象只可存在于 `frontends/`、`compat/` 或 `solver/backends/` 边界中；不要用 `class X(pyvex...)` 作为独立 IR。
3. `Canonical IR` 明确语义：bitwidth、signedness、extension/truncation、endianness、部分寄存器、内存 Load/Store、guard、branch、call/return、未知调用副作用、source/provenance。
4. 遇到不能安全转换的操作：严格模式返回有上下文的诊断；保守模式采用明确的 Top/Havoc/UnknownEffect（含完整性标识），**禁止静默 `continue`、吞异常、`exit()` 或假定无副作用**。
5. `SSE`、`MemoryObject`、`Alias`、`Taint` 是独立于 Canonical IR 的**分析抽象域**；Claripy/Rust AST 或求解器通过适配接口访问。
6. 每次分析拥有独立 `AnalysisSession`，不依赖可变模块全局集合、单例分析状态；CFG/CG/摘要更新与失效必须显式可测试。
7. 保留旧版 `-i`、`-t` 的可观察行为与结果字段（除非有经批准、可记录的变更）。不能仅以“JSON 文件存在”为成功。
8. 不先建设微服务、Web UI、LLM Agent，也不迁移到 Linux/Docker；先完成二进制分析引擎最小闭环。

## 3. angr 9 → 10 与 Claripy 专项约束

- 用户已知：旧虚拟环境 `angr==9.0.9792`；目标虚拟环境 `angr==10.0.5`。实际版本、Python ABI、`pyvex`、`cle`、`archinfo`、`z3` 与 Claripy 的导入及类型必须**在各自解释器中探测**并写入兼容矩阵。
- **不要假定** `import claripy` 一定成功/失败；angr 10.0.5 官方文档使用 `from angr import claripy`。实际环境可能包含兼容 shim，须以本机探测为准。
- 不可假定新版 Claripy AST 与旧版 `claripy.ast.Base/BV`、`op/args/variables/annotations`、`replace`、`recursive_*`、`cache_key`、`hash` 或 solver 结果签名一致。先创建 `solver/claripy_adapter.py` 边界和**契约测试**，逐项证明受支持操作，不要直接修改旧版 `site-packages`。
- Rust 底层实现不等于所有 Python API 消失；依据实际 API 行为设计接口，避免以类名代替语义判断。
- 禁止为了让测试通过而静默降级、禁用污点传播或删除 Claripy 表达式。
- 不自动更新任何 Python 包；升级需要明确计划与批准。对被移除的 API 采用 adapter/migration，不能把新版装回旧版。

## 4. 基线与结果保护

用户提供的旧版调用（**下面只是命令契约，不得在只读 `LEGACY_ROOT` 中直接执行**；应在独立运行副本的根目录中使用旧环境 Python）：

```powershell
& $LegacyPython main.py -f ./firmware-binaries/rv130_v44/httpd -n rv130 -v 1_0_3_44 -i
& $LegacyPython main.py -f ./firmware-binaries/rv130_v44/httpd -n rv130 -v 1_0_3_44 -t
```

共同输出路径（相对于运行副本根目录）为 `data/result_data/rv130_1_0_3_44.json`。**两个阶段可能更新同一路径**：先只读复制 `LEGACY_ROOT/data/result_data/...` 既存结果；获准在隔离副本重跑时，先备份副本中的已有结果，执行 `-i` 并立即保存 `icall.json`，再执行 `-t` 并保存 `taint.json`；同时归档日志、退出码、输入 SHA256、环境版本和副产物。`-t` 的依赖关系需先从旧源码核对。旧 `LEGACY_ROOT/data/` 绝不能被覆盖。

基线放在 **`MIGRATION_ROOT/baselines/`**，隔离运行副本放在 **`MIGRATION_ROOT/baseline-work/`**（都不在两个 Git 仓库中，且不作为 Git 提交物）。对比器须保留原始 JSON，另生成规范化表示；只有经过证据证明的无序集合才允许排序去重。不得随意删除时序、调用上下文、调用目标、污点路径和告警证据字段。

## 5. 允许与禁止的操作

允许：只读查看旧仓库及两个环境、在目标仓库当前阶段新增/修改文件、读取旧版已有结果并复制到独立 baselines 目录、运行已批准且不会回写旧仓库的测试。

禁止：编辑 **任何** `LEGACY_ROOT` 下的文件（源码、`data/` 结果、IDA 元数据、样本、`.venv/` 均包括）；在旧根目录执行会写输出的 `-i/-t`；删除/重建两个 `.venv`；在旧环境安装依赖；执行 `git clean -fdx`、`git reset --hard`、递归删除、自动 `git push`、无关格式化；输出密钥或未批准联网下载。

执行 `-i/-t` 前必须先检查输出路径不会指向旧仓库，再取得用户批准，只能在隔离副本中执行。不得写入旧仓库（即使获得一般性的“运行测试”批准）；如旧源码中存在硬编码绝对写路径指向旧仓库，则必须停止并报告，由用户另行决定如何处理。

## 6. 每阶段工作流和验收门槛

1. 读 `MIGRATION_BLUEPRINT.md`、`CODE_TASK.md`，确认当前阶段、Git 状态和必备阶段已通过。
2. 输出可验证的执行计划：涉及文件、接口与不变量、测试、差分标准、失败回退；保持任务边界小。
3. 尽量先写 characterization/conformance 回归测试，再修改实现；只操作目标仓库。
4. 新测试只用 `TARGET_ROOT/.venv/Scripts/python.exe`；旧分析只用 `LEGACY_ROOT/.venv/Scripts/python.exe` **在隔离的 RunRoot 中运行**；旧仓库保持只读。
5. 若验证失败，提供实际堆栈、分类（依赖/API/转换/分析算法/测试环境），不得强改 Golden Data 以掩盖回归。
6. 结束时必须汇报：修改文件、命令与退出码、通过/失败/未执行测试、差分详情、未知语义覆盖、潜在漏报风险、回退方式。
7. **每次只完成一个阶段**；通过 gate 后停止，等待审核，不自动执行下一阶段。

## 7. 代码可审计性要求

- 来源可追踪：每条 IR 可定位原始 provider、函数/块、指令地址、statement index、位宽和版本信息。
- CFG/PAG/CG 分离：PAG 是派生的 Def-Use/依赖事实，不是 CFG；新增间接目标必须更新图版本及受影响摘要。
- 未知 ≠ 安全：分析预算耗尽、IR 未支持或 solver 超时均要显式标记 `incomplete`/`unknown`。
- `-i` 和 `-t` 结果需分阶段 diff，不得仅比较最终 JSON 的漏洞数量。

## 8. 必读资料与事实范围

- 原项目：https://github.com/kuc001/EmTaint
- 目标：https://github.com/kuc001/BinaryAnalysis
- angr 10.0.5 Solver 文档：https://docs.angr.io/en/v10.0.5/advanced-topics/claripy.html

`MIGRATION_BLUEPRINT.md` 中的公开源码观察是迁移线索，不是对当前 Windows 工作树的已确认事实。以真实本地代码和已运行测试为准。

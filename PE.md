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

## 9. 当前 P7 阶段附加规则

- 当前只完成 Python P7 污点分析与漏洞检测，不开展 Rust、Microcode 或 P8 以后工作。
- P6 的 iCall/CG、函数可达性、图更新逻辑和寄存器 clobber/version 修复作为冻结基线；若 P7 证据证明 P6 是差异根因，必须先给出最小复现、首次分歧、影响范围和独立回归，再单独修复并重跑受影响的 P6 测试。
- 已有 378 项回归通过状态必须保留；不得删除用例、降低断言或修改 Golden 制造通过。目标是恢复旧 EmTaint `-t` 的语义，而不是只让告警数量相等。
- 每轮只处理一个明确 Difference ID：定位旧/新首次分歧、保存输入状态快照、建立最小回归、修复一个根因、运行专项及受影响回归、更新差异矩阵。连续两轮没有新诊断信息时必须改变诊断方法，不得盲目重复全量回放。
- CIR Load/Store 是程序内存 effect，不得直接作为自定义 Claripy AST 交给 SMT；APG 环不等于 Heap Alias；MemoryVersion 必须表达读写顺序、到达定义和 Join/Phi。
- 仅在 MustAlias、唯一目标且完整覆盖时允许 Strong Update；MayAlias/Unknown 使用 Weak Update 或保守建模。Solver UNKNOWN/TIMEOUT/UNSUPPORTED、预算耗尽、MayTaint 和 Incomplete 不得当作 UNSAT、安全或无漏洞；MayAlias/MayTaint 只能形成候选，不能直接升级为 Confirmed Finding。
- 每个 Finding 必须可追溯到 Source、传播事实、Sink、调用链、MemoryVersion、Guard/约束和原始地址。
- 阶段报告更新 `docs/migration/phases/P7-report.md`；未执行的测试必须明确写“未执行”。

# BinaryAnalysis 代码质量规范

本节适用于 `BinaryAnalysis/` 目录下的所有 Python 代码，并作为强制验收标准。与前述项目、迁移阶段或安全约束同时适用；发生冲突时采用更严格且不破坏既有行为、公共接口和二进制分析语义的要求。

## 总体原则

所有修改必须保持现有对外行为和公共接口兼容，除非现有行为明确是缺陷。修改前必须理解调用关系、数据流、状态约束和二进制分析语义。不得为了形式上的整洁而改变地址、位宽、符号扩展、截断、端序、控制流或污点传播语义。

## 1. Python 编码规范

- 遵循 PEP 8。
- 优先遵守仓库现有的 Ruff、Black、isort 或其他格式化及检查配置。
- 统一命名、空行、行宽、导入分组和导入顺序。
- 删除确认无用的导入、变量和不可达代码。
- 禁止仅为格式化而修改任务范围外的文件。
- 不得使用通配符导入。
- 避免循环导入；确实无法避免时必须说明原因。

## 2. 类型标注

- 新增或修改的函数必须标注参数和返回值类型。
- 公共函数、类属性、重要局部变量、复杂容器和回调必须具有准确类型。
- 类型必须符合项目支持的 Python 版本。
- 优先使用精确类型、Protocol、TypeAlias、TypedDict、dataclass 或 Enum 表达接口。
- 禁止用 Any 掩盖未知类型；只有外部库边界或确实无法表达时才可使用，并添加说明。
- Optional 值必须在使用前显式处理。
- 类型标注不得与实际运行时行为冲突。

## 3. 文档字符串

以下对象必须有清晰的文档字符串：

- 模块；
- 类；
- 公共函数和公共方法；
- 复杂算法；
- 存在重要副作用、状态变化或异常行为的接口。

文档字符串应说明职责、参数、返回值、异常、副作用、关键不变量，以及二进制分析中特有的地址、位宽、端序或状态语义。遵循项目已有风格；没有既有风格时使用简洁一致的 Google 风格。

## 4. 必要注释

注释用于解释：

- 算法原理；
- 设计选择及其原因；
- 边界条件；
- 二进制地址和位宽处理；
- 符号扩展、截断、端序转换；
- 状态机转换；
- 容易被误解但不能简化的逻辑。

禁止逐行复述代码。注释必须与实现同步，过时注释应更新或删除。

## 5. 输入和契约校验

在公共接口、外部数据边界和不可信输入处验证：

- 参数类型和值域；
- 必需字段和数据结构；
- 地址是否为非负数、是否位于允许范围；
- 位宽是否合法且与目标架构一致；
- 区间起止关系及溢出；
- 枚举值、状态转换和对象生命周期；
- 回调及接口契约；
- 文件、序列化数据和第三方库返回值。

校验失败必须尽早抛出明确异常。不要在可信的高频内部路径重复进行无意义校验；内部不变量可以使用断言，但不能使用断言验证外部输入。

## 6. 异常处理

- 捕获最具体的异常类型。
- 禁止裸 `except:`。
- 禁止 `except Exception: pass` 或其他静默忽略错误的行为。
- 重新抛出时补充文件、地址、函数、分析阶段或输入对象等上下文。
- 保留原异常链，必要时使用 `raise ... from exc`。
- 只在确实能够恢复、转换或补充上下文时捕获异常。
- 清理资源优先使用上下文管理器或 finally。
- 不得把程序错误伪装成正常分析结果。

## 7. 模块职责

- 每个模块、类和函数应具有清晰单一职责。
- 拆分超长函数、混合抽象层次的函数和同时承担解析、计算、状态修改、日志输出等多项职责的代码。
- 抽取重复逻辑，但避免为了复用而制造不自然的抽象。
- 降低跨模块耦合和全局状态依赖。
- 通过明确接口、参数和返回值传递依赖。
- 遇到循环依赖时分析共同职责，优先抽取稳定的底层接口或数据类型。

## 8. 可维护性

- 使用能表达领域含义的名称，避免无意义缩写。
- 公共接口必须明确输入、输出、异常、副作用和状态要求。
- 减少隐式状态、可变全局变量和依赖调用顺序的行为。
- 常量、状态值和操作类型优先使用常量或 Enum 表示。
- 复杂条件应拆成具有领域名称的变量或函数。
- 删除重复代码、过期兼容分支和确认不可达的代码时，必须有测试或调用关系证据。
- 新设计应便于增加新架构、位宽、分析规则和数据源。

## 重构约束

- 修改前先检查调用者、子类、注册表、插件、动态导入和测试。
- 不得凭文件名或单次文本搜索判断代码无用。
- 不得擅自修改公共 API、序列化格式、异常契约或分析结果结构。
- 必须保留用户已有的未提交修改。
- 不得进行与当前批次无关的大范围格式化。
- 不得擅自新增生产依赖。
- 不得自行提交、推送或改写 Git 历史。

## 测试与验收

每个重构批次必须：

1. 记录修改前的基线测试结果。
2. 为修改过的逻辑补充或更新测试。
3. 覆盖正常路径、边界条件、无效输入和异常路径。
4. 先运行针对性测试，再运行受影响模块的测试。
5. 在阶段性里程碑运行完整测试套件。
6. 运行仓库已有的格式检查、静态检查和类型检查。
7. 清楚区分修改前已存在的失败和本次引入的失败。
8. 未通过验证时不得宣称任务完成。

### 当前仓库的质量检查入口

- 当前仓库未发现 Ruff、Black、isort、mypy、Pyright、Flake8、pytest、tox、nox 或 pre-commit 的独立配置；不得据此擅自引入生产依赖或批量格式化。
- 现有测试以标准库 `unittest` 为主。针对性测试应使用 `BinaryAnalysis/.venv/Scripts/python.exe -B -m unittest ...`；完整测试入口为 `BinaryAnalysis/.venv/Scripts/python.exe -B -m unittest discover -s tests -v`，并从 `BinaryAnalysis/` 目录运行。
- 若当前阶段已有验证脚本（例如 `scripts/p3_validate.py`、`scripts/p4_validate.py`、`scripts/p5_validate.py`、`scripts/p6_validate.py`、`scripts/p6_acceptance.py`），优先运行与改动阶段匹配的脚本，并记录命令和退出码。
- 格式、静态和类型检查仅运行仓库已经配置且与当前环境兼容的工具；若尚未配置，在验收报告中明确标记“未配置”，不得伪称已通过。
- 本规范文件本身发生变化时，至少检查文件内容、作用域、Git diff 和工作树状态；纯规范变更不要求运行分析测试，但必须明确记录“未运行代码测试（仅文档变更）”。

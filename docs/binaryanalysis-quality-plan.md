# BinaryAnalysis 系统性代码质量计划

更新日期：2026-11-01（Asia/Shanghai）

本计划覆盖 `BinaryAnalysis/` 中的 Python 生产代码、测试、脚本和质量配置。执行顺序以静态导入拓扑为主，并同时尊重 `AGENTS.md` 中的 P6 冻结、P7 语义、旧仓库只读和公共接口兼容约束。不能由调用关系与测试证明安全的修改只记录，不为提高指标而机械改写。

## 1. 调查范围与模块清单

基线提交：`66e1d073cc2eec01da080296730ad5fe6b240437`。

调查开始时，`.venv/` 之外的 Git 工作树干净。仓库共有 322 个 Python 文件：185 个 `emtaint` 生产模块、68 个测试、67 个脚本，以及根目录 `main.py`、`setup.py`。生产模块按目录汇总如下；完整文件清单由 `rg --files emtaint -g '*.py'` 生成，并作为每次审查的输入，避免以单次文本搜索判断模块无用。

| 模块组 | 数量 | 主要职责 |
|---|---:|---|
| `emtaint.analysis.*` | 60 | CFG/PAG、数据流、SSE、污点与漏洞判定 |
| `emtaint.ir.*` | 48 | 旧 IR、Canonical IR、表达式和语句模型 |
| `emtaint.frontend.*` / `frontends.*` | 21 | angr、IDA、VEX 和已保存 CIR 输入边界 |
| `emtaint.memory.*` | 12 | AccessPath/APG、堆、版本化内存和查询端口 |
| `emtaint.core.*` | 5 | 身份、契约、程序模型和分析会话 |
| `emtaint.orchestration.*` | 6 | 固定点、iCall 和 taint 协调 |
| `emtaint.solver.*` | 7 | 求解器协议、进程边界和 lowering |
| `emtaint.assembly.*` | 4 | 旧程序集块、函数和代码位置模型 |
| `emtaint.compat.*` | 7 | 旧 API 兼容与桥接 |
| `emtaint.graph.*` | 2 | 新程序图模型 |
| `emtaint.procedures.*` | 3 | 旧过程规则与注册数据 |
| `emtaint.results.*` | 2 | 结果与内存归档 |
| 根包、配置、入口及 builder | 8 | CLI、入口和程序构建 |

未发现 `pyproject.toml`、`setup.cfg`、`tox.ini`、pytest 配置、CI 配置、Ruff、Black、isort、mypy、Pyright、Flake8、Pylint、coverage 或 pre-commit 配置。项目现有测试使用标准库 `unittest`。`pyvenv.cfg` 和 `docs/migration/TARGET_RUNTIME.md` 共同确认目标为 CPython 3.12.9；当前 angr/Claripy 系列为 9.3.4。

## 2. 修改前基线

| 检查 | 命令 | 修改前结果 |
|---|---|---|
| Python/平台 | `.venv/Scripts/python.exe -B -c ...` | Python 3.12.9，Windows 11，成功 |
| Python 语法 | 以 `ast.parse` 读取 `emtaint/`、`scripts/`、`tests/`、`main.py`、`setup.py` | 322/322 成功 |
| 完整测试 | `.venv/Scripts/python.exe -B -m unittest discover -s tests -v` | 450 项通过，0 失败，12.794 秒 |
| 格式/Lint/类型工具探测 | `importlib.util.find_spec` | Ruff/Black/isort/mypy/Pyright/Flake8/Pylint 均未安装、未配置 |
| 打包元数据 | `.venv/Scripts/python.exe -B setup.py --name` | 修改前失败：目标环境缺少 `setuptools` |

第一次 AST 基线命令因 PowerShell 引号错误退出 1；修正后的只读命令已成功。这属于命令构造错误，不是代码失败。不得将缺少 `setuptools` 或未配置质量工具归因于后续重构。

静态质量基线（AST）为：5 个裸 `except`，0 个通配符导入，89 个缺少模块文档字符串的模块，178 个缺少类文档字符串的顶层公共类，514 个缺少文档字符串的顶层公共可调用对象/方法，599 个缺少完整参数/返回类型的顶层公共可调用对象/方法。初版探测曾把嵌套局部函数误计为公共接口；Q0 的回归测试修正后采用上述数字。后四项包含历史兼容层和特殊方法，必须逐模块确认公共性及运行时兼容性，不能机械填充。

## 3. 依赖模型与分层

静态 AST 模型覆盖普通导入、相对导入和常量参数形式的 `__import__`/`importlib.import_module`；另以文本和调用者检索复核注册表、回调、继承、协议、入口及全局状态。基线包含 185 个生产模块和 428 条内部导入边，压缩强连通分量后共有 180 个节点，最长依赖深度为 15。Q9 增加了一个仅位于 `TYPE_CHECKING` 分支的 `FunctionStore` 类型边，当前为 429 条边；运行时 SCC 未改变。

为审查使用以下五个语义层；同层内仍按压缩图拓扑排序：

1. **基础类型、常量、异常和纯工具**：`core.identity`、`core.contracts`、`solver.port`、`memory.read_index`、无内部依赖的 IR/变量/图节点类型。
2. **数据模型、解析器和状态表示**：`core.program`、`core.session`、`ir.canonical`、`assembly`、`memory.access_path`、`abstract_heap/state`、输入模型。
3. **核心分析算法**：`memory.engine/memory_version`、`analysis.dataflow`、`analysis.sse`、`analysis.pag`、`analysis.taint`、`analysis.bugfinder`。
4. **跨模块服务和协调逻辑**：`memory.query_port`、`graph`、`orchestration`、`results`、程序 builder。
5. **适配器、入口和对外接口**：`solver.backends`、`compat`、`frontend/frontends`、`procedures`、`cli`、`main`、`__main__`。

### 强连通分量

| SCC | 模块 | 处理原则 | 风险 |
|---|---|---|---|
| C1 | `analysis.taint.demand`, `query_worklist`, `tables` | 作为同一审查单元；禁止拆开造成中间不可运行 | 极高 |
| C2 | `cli`, `orchestration.taint_program` | 入口/协调边界同批审查，保留 CLI JSON 和退出契约 | 高 |
| C3 | `memory.abstract_heap`, `memory.state` | 同批检查类型与状态不变量；不改变 alias/update 语义 | 高 |
| C4 | `memory.engine`, `memory.memory_version` | 同批检查版本图、读写与缓存；保持 P6 冻结行为 | 极高 |

已发现的动态机制包括 `ir.canonical.wire.REGISTRY`、legacy procedure/rule 注册数据、CLI 的 `importlib.metadata`、隔离探测脚本的文件级动态导入、分析回调和 summary/runtime 缓存。任何“未使用”判断都必须同时检查这些关系。

## 4. 风险分级

- **极高**：`analysis.taint.demand`（1731 行）、两个内存 SCC、跨函数摘要、缓存失效、求解器状态分类、CLI 最终结果结构。
- **高**：Canonical IR、VEX lowering、程序/会话身份、PAG visitor、输入/序列化边界、旧兼容层。
- **中**：纯模型验证、只读索引、规则表、结果归档、独立 lowering helper。
- **低**：包文档、无运行时副作用的类型/文档补全、测试和标准库质量工具。

## 5. 批次与状态

每批先复核调用者、继承/协议、注册表、动态导入和测试，再执行“专项测试 → 受影响测试 → AST/静态审计 → diff 复核”。完整 450 项回归在阶段里程碑和最终交付运行。

| 批次 | 范围 | 目标 | 状态 |
|---|---|---|---|
| Q0 | 本计划、标准库质量审计 | 固化基线、依赖图、循环与可重复检查，不触及生产语义 | 已完成 |
| Q1 | `core.identity`, `core.contracts`, `core.program` | 基础身份/契约的类型、文档和边界校验；保持 wire/hash 行为 | 已完成 |
| Q2 | `solver.port`, `solver.process_port`, `solver.backends.*` | 协议类型、异常上下文和外部后端边界 | 已完成 |
| Q3 | `memory.abstract_heap` + `memory.state`（C3）及相邻纯模型 | 文档、类型、不变量和无副作用校验 | 已完成 |
| Q4 | `memory.engine` + `memory.memory_version`（C4） | 只实施有完整内存回归证明的安全改动 | 已完成审查；无安全代码改动 |
| Q5 | Canonical IR、wire、输入解析边界 | 明确地址/位宽/端序/序列化契约 | 已完成 |
| Q6 | P7 无环叶模块（guard/policy/evidence/region 等） | 类型、职责、异常与测试 | 已完成安全子集；高耦合债务记录 |
| Q7 | taint SCC C1 | 高风险单批；只处理测试证明的缺陷与局部职责拆分 | 已完成审查；无 SCC 代码改动 |
| Q8 | PAG visitor 与旧兼容路径 | 处理裸异常；需先建立异常行为 characterization | 安全修复已完成；历史类型/文档债务保留 |
| Q9 | orchestration/CLI SCC C2、入口和适配器 | 保持 CLI、JSON、退出码和结果结构 | 已完成 |
| Q10 | 全目录复核 | 完整测试、静态复扫、循环/TODO/临时兼容复核 | 已完成 |
| Q11 | 旧 IR/PAG 基础层质量续改 | 清零模块文档；精确化表达式、语句和值包装器 | 已完成本批 |

## 6. 问题登记

| ID | 级别 | 位置 | 问题 | 当前决定 |
|---|---|---|---|---|
| BASE-001 | P1 | `analysis/pag/visitor.py` | 5 个裸 `except`，可能掩盖程序错误 | 已修复并由异常路径测试覆盖 |
| BASE-002 | P2 | 全目录 | 公共类型与文档债务数量大 | 按拓扑逐批处理；不机械添加 `Any`、空洞 docstring 或 `type: ignore` |
| BASE-003 | P2 | 四个 SCC | 循环导入提高初始化和耦合风险 | SCC 同批审查；只有稳定接口与测试足够时才解环 |
| BASE-004 | P2 | `setup.py` / 环境 | `setuptools` 未安装，打包元数据命令不可运行 | 不新增依赖；保留为基线环境限制 |
| BASE-005 | P3 | 多个历史模块 | 压缩式格式和超长函数降低可维护性 | 禁止全目录格式化；只在行为改动触及的局部整理 |

## 7. 批次执行记录

### Q0：计划与本地质量审计

- 新增 `scripts/quality_audit.py` 和 `tests/test_quality_audit.py`。工具只读 AST，不导入被审计模块，报告安全违规、公共文档/类型债务、静态/常量动态导入以及 SCC。
- 专项测试：3 项通过。工具自身 `--fail-on all` 为 0 finding。
- 初次测试因系统临时目录不可写出现 3 个 `PermissionError`；改为工作区临时目录后通过，归类为测试环境启动问题。

### Q1：基础身份和契约

- 修改 `core/identity.py`、`core/contracts.py`、`core/program.py`：补齐精确公共类型、领域文档和地址/位宽/作用域说明；没有改变 RVA、hash token、wire 字段或合法输入行为。
- 严格批次审计：0 finding。专项/受影响测试：`test_program_models` 25 项、`test_p3_contracts` 24 项、`test_p7_runtime` 3 项、P5 31 项，全部通过。
- 一次按包名直接加载测试导致 10 个历史顶层导入 `ModuleNotFoundError`；改用仓库规定的 discover 入口后全部通过，归类为命令入口错误。

### Q2：求解器与原生后端边界

- 修改 solver port/process/backend 共 5 个模块：为 portable DTO、进程边界和 Claripy 边界补齐类型/文档；对不可信 query/result payload 增加容器、字段和值类型校验；保留 UNKNOWN/TIMEOUT/UNSUPPORTED/ERROR 区分及原异常上下文。
- 新增 malformed payload 回归。严格批次审计 0 finding；`test_solver_contracts.py` 33 项通过；`ast_tools.py` 使用旧 Python 3.7 解释器 AST 解析通过。

### Q3：内存状态 SCC C3

- 同批修改 `memory.abstract_heap` 与 `memory.state`，补齐公开类型、文档和 strong-update/alias/version 语义说明；未拆 SCC，未改变 descriptor/wire 字段。
- 严格批次审计 0 finding。P3/P5/P7 region、resolution、alias、definition-cache 相关测试共 85 项通过。

### Q4：内存执行/版本 SCC C4

- 同批复核 `memory.engine` 和 `memory.memory_version` 的版本图、按需字节解析、强弱更新、alias/definition cache、预算异常及所有调用者。未发现裸异常、静默异常或可独立证明的 P0/P1。
- 两个模块仍有 2 个类、38 个公共可调用文档和 40 个公共可调用精确类型债务；这些接口共享动态 DAG/cache/query DTO。当前拆分或用宽泛类型消项会直接增加 P6/P7 语义风险，故不改代码。
- `test_p5*.py` 31 项和 `test_p7*.py` 219 项全部通过，覆盖大小端、部分覆盖、guard、havoc、版本缓存、固定点与查询预算。

### Q5：Canonical IR、wire 与输入边界

- 修改 `ir/canonical/model.py`、`wire.py`：为 22 个公开 CIR 语义类型、内存访问校验、operand 遍历和三个 wire 入口补齐精确契约；未改变 dataclass 字段、注册表、tag、schema 或合法序列化结果。
- 修改 `frontends/inputs.py`、`loader_image.py`、`saved_cir.py`、`vex_input.py`：明确无符号 64 位地址、ELF ET_EXEC 映射、端序、文件支持区间、保存 CIR 字节预算以及 native 第三方边界；新增非正/布尔/非整数保存预算拒绝测试。
- 严格批次审计 0 finding。输入测试 7 项、P3 wire/CIR 24 项、程序模型 25 项通过；受保护 `p4_probe.py` 原生用例 15 项通过且 0 写入违规。直接启动原生用例曾分别遇到系统临时目录权限和错误 unittest 入口，均在进入有效用例前失败，改用仓库规定 probe 后成功。

### Q6：P7 无环 guard/fact 叶模块

- `analysis.taint.guards` 新增结构化 recipe Protocol、精确决定类型和 guard 关系文档；`facts` 已满足严格审计，无需修改。没有改变 legacy kill/bound 真值表或 ARM flag-chain 识别。
- guard、ARM lowering 和 constraint frontier 共 15 项通过；整个 P7 套件 219 项通过。
- `evidence`、`regions`、`global_outputs` 虽不在静态 SCC 中，但其参数和返回值直接引用 demand 内部动态对象。精确类型化需要先稳定 C1 的 summary/query 协议，机械使用 `Any` 不符合规范，故本批只记录债务。

### Q7：taint 固定点 SCC C1

- 将 `demand`（1731 行）、`query_worklist`、`tables` 作为一个单元复核静态/延迟导入、summary/table 回调、共享状态、预算异常和测试入口；未发现宽泛捕获、静默错误或可在 SCC 外独立修复的 P0/P1。
- 大函数拆分会改变 query 公平性、frontier 保留和固定点顺序；现有 219 项 P7 回归全部通过，因此保持实现不动，并将协议抽取/精确类型化列为后续架构工作。

### Q8（提前执行安全子批）：旧 PAG 异常契约

- `analysis.pag.visitor` 的 5 个裸 `except` 已替换为具体表达式契约异常集合；错误重新抛出为带语句/参数上下文的 `ValueError` 并使用 `raise ... from error`。`KeyboardInterrupt` 等进程控制异常不再被吞掉。
- 同时清除 visitor、`BinopValue`、`UnopValue`、旧 unary expression 中所有 `raise logger.error/warning(...)`（原行为实际抛出 `TypeError: exceptions must derive from BaseException`）。
- 新增 5 个异常路径 characterization 测试，全部通过；全生产目录 safety 审计已无裸异常或静默异常。pyvex 首次导入的 FFI 缓存被显式定向到忽略的 `.p7-work`，避免写系统临时目录失败。

### Q9：CLI/orchestration SCC C2

- 同批修改 `cli.py` 和 `orchestration/taint_program.py`，为 append-only JSON 写入、source manifest、进程元数据、iCall/taint 入口和 summary receipt 路径补齐类型与职责/异常说明。
- `FunctionStore` 仅在 `TYPE_CHECKING` 分支导入，避免增加运行时循环；CLI 参数、JSON 字段、退出码、路径限制和 `BaseException` 记录后原样重新抛出的契约均保持不变。
- 严格批次审计 0 finding；legacy plan 3 项、runtime cache 3 项及 P7 全套 219 项通过。

### Q10：最终回归与复扫

- 完整测试命令 `.venv/Scripts/python.exe -B -m unittest discover -s tests -v`：460 项通过，0 失败，6.372 秒；修改前为 450 项通过。
- 全部生产、脚本、测试和根 Python 文件以 `ast.parse` 复核：325/325 成功。生产目录 safety 审计为 0；质量债务余量为 89 个模块文档、130 个公共类文档、484 个公共可调用文档和 569 个完整公共类型标注。
- 裸 `except`、`except Exception: pass`、通配符导入、`raise logger.error/warning`、大写 `TODO/FIXME/HACK/XXX` 均为 0。仅保留两处有意宽捕获：Claripy 外部后端边界把未知原生故障转换为显式 ERROR；CLI 捕获 `BaseException` 写失败收据后立即原样重新抛出。
- Ruff、Black、isort、mypy、Pyright、Flake8、Pylint 均未安装且仓库无配置，不能虚构其成功结果；使用逐批 AST 审计、专项测试、完整回归及 `git diff --check` 代替可用检查。`git diff --check` 成功，仅报告两个已有 CRLF 工作树文件未来会转换为 LF 的 Git 警告。

### Q11：旧 IR/PAG 基础层质量续改

- `ir.expressions` 与 `ir.statements` 共 41 个模块完成真实模块/类/方法文档、精确 pyvex 参数和返回类型、导入分组及局部 PEP 8 整理；两个子包严格审计均为 0 finding。
- `analysis.variables` 9 个模块完成值类别、可选位宽、代码位置、IR 来源和 opaque runtime payload 的准确契约；未用 `Any` 假定 Claripy 类型。修复 `Binder` 错误调用 `super.__init__` 的确定性缺陷。
- legacy graph node/edge 增加 graph navigation Protocol 和明确节点类型；补回 `stmt_node.py` 缺失的运行时导入，并用 `ValueError` 取代外部构造参数上的 `assert`。
- 新增表达式包装器和 graph node 契约测试各 2 项。完整回归为 464/464 通过；生产 safety 审计仍为 0。
- 所有 185 个生产模块现在都有模块文档。剩余质量债务为 112 个公共类文档、400 个公共可调用文档和 486 个完整公共类型标注。

## 8. 当前剩余批次和无法安全修改项

- Q4 内存 SCC 和 Q7 taint SCC 已完成系统审查，但仍有大量动态缓存、紧凑代码、公共文档和精确类型债务。后续需要先稳定 query/result/summary 协议；不能用 `Any`、`cast` 或错误注解机械消项。
- 旧 PAG visitor 仍有公共类型/文档债务，并直接依赖 pyvex，违反目标分层但属于已存在迁移债务。解除该依赖需要改变旧 IR 适配架构，不属于安全局部重构。
- 当前全生产目录的模块文档缺口已清零；仍有 112 个顶层公共类、400 个公共可调用对象缺少文档，以及 486 个公共可调用对象缺少完整类型。它们主要集中在旧 CFG/PAG builder、前端兼容层和高风险动态分析层；后续仍需按调用证据分批处理，不能用宽泛类型机械消项。

## 9. 完成与保留原则

“完成批次”表示该批范围内所有安全、可由代码和测试证明的修改已实施并验证，不表示强行消除所有历史指标。必须改变公共 API、持久化格式、合法输入行为或分析领域规则的问题保持代码不动并在本文件记录原因。每批记录实际命令、退出码、测试数量、修改文件和剩余风险；未配置的格式/Lint/类型检查明确标为“未配置”。

任务名称：
BinaryAnalysis Alias/taint P0–P2 基线建立与分阶段升级

工作目录：
D:\works\dataflow\EmTaint\emtaint-migration

目标：
先建立不可污染、可重复、可比较的评测基线，再依次完成：

P0：形式化分析完整性状态；
P0：审计 Strong Update 和 MustAlias；
P0：建立 Unknown 分类与性能指标；
P1：实现 Lazy Binary Value-Flow Graph；
P1：实现分级 Alias Refinement 和最终切片 SMT；
P2：实现地址、区间、长度、Guard 的跨域精化；
P2：实现符号化内存副作用和参数化过程摘要。

最终验收目标：

1. rv130_1_0_3_44/httpd 的旧版 EmTaint 兼容结果保持不变；
2. Test-Suite-master 以下四个目录的 172 个样本全部被处理：
   - basic_c_tests
   - basic_cpp_tests
   - cs_tests
   - fs_tests
3. 490 个普通 Alias 断言全部得到 complete 且标签完全一致的结果；
4. 9 个 EXPECTEDFAIL 断言必须被识别和单独报告，不允许静默丢失；
5. 6 个无活动 Alias 断言的样本必须成功加载和完成 smoke 分析；
6. P6 iCall/CG 冻结结果不得退化；
7. 不允许通过提高预算、降低断言、增加忽略列表或修改源码标记制造通过。

==================================================
一、开始前必须遵守的约束
==================================================

1. 完整阅读：
   - BinaryAnalysis/AGENTS.md
   - BinaryAnalysis/docs/migration/phases/P7-report.md
   - BinaryAnalysis/emtaint/analysis/aliasing/benchmark.py
   - BinaryAnalysis/scripts/alias_benchmark.py
   - BinaryAnalysis/tests/test_alias_benchmark.py
   - Test-Suite-master/aliascheck.h

2. 只允许修改 BinaryAnalysis/。

3. 以下目录和文件全部只读：
   - Test-Suite-master/
   - baselines/
   - 旧 EmTaint 仓库及其虚拟环境
   - P6 Golden 和历史结果
   - rv130_1_0_3_44 旧版基线

4. 不得重新运行旧 EmTaint 覆盖现有结果。
   旧版只使用已经保存的基线文件进行比较。

5. 不得安装或升级依赖，不得修改虚拟环境。

6. 不得修改 P6 iCall/CG、函数可达性或间接调用目标算法。
   如果四套件失败的首次分歧来自 P6，必须：
   - 保存最小复现；
   - 给出首次错误的 callsite→target；
   - 给出受影响样本和范围；
   - 暂停 P6 修改；
   - 单独请求授权。
   P0–P2 任务不得隐式修改 P6。

7. 每轮只处理一个 Difference ID。
   不得在同一轮同时修复别名、路径、摘要和格式问题。

8. 不得把下列结果解释成 NOALIAS、clean 或分析成功：
   - Unknown
   - Incomplete
   - Timeout
   - BudgetExceeded
   - Solver UNKNOWN
   - Solver UNSUPPORTED
   - 未解析地址
   - 未解析调用目标
   - 未匹配 marker call

9. 所有新增代码遵循：
   - PEP 8；
   - 准确类型标注；
   - 公共接口和复杂算法有 docstring；
   - 注释解释算法不变量；
   - 禁止裸 except 和静默忽略；
   - 缓存必须声明版本依赖；
   - 可变状态归属 AnalysisSession 或明确的 benchmark session。

10. 首先只建立清单和计划，不修改算法。
    获得基线输入、Oracle 和判定器的确定结果后，再进入算法升级。

==================================================
二、建立三层基线
==================================================

基线 A：旧版 httpd 兼容性基线
--------------------------------

只读引用：

baselines/rv130_1_0_3_44/p7-20261029T140752Z-d85ea47a/

至少固定以下文件及 SHA-256：

- taint.json
- taint.log
- taint.command.json
- taint.verified.json
- taint-targets.json
- icall.json
- icall-targets.json
- environment.json
- legacy-integrity-taint.json

其中 taint.json 的固定 SHA-256：

20662BDAC19C2C88BD5882312D8E4DF06E01B4CDF3E8759AF5CEB1322F384FA5

旧版关键统计：

- all_functions = 881
- analyzed_functions = 796
- all_blocks = 30919
- tainted_blocks = 4584
- tainted_sinks = 402
- buffer_overflow_num = 143
- command_exec_num = 7

建立两种检查：

A1. Golden 完整性检查
- 检查基线文件自身的 SHA-256；
- 任何现有基线文件变化立即失败；
- 不允许重新生成或覆盖。

A2. 新版兼容投影检查
- 将新版结果投影到旧版 taint.json 可比较字段；
- 比较全部 sink site、sink name、offset、function、info；
- 比较 buffer_overflow 和 command_exec 的完整键集合；
- 比较每个 Finding 的字段，而不只是比较总数；
- 新增性能和 Unknown 指标写入独立文件，禁止污染兼容 JSON；
- 差异输出按 added/removed/changed 分类；
- 默认要求差异为零。

如果未来确实需要改变 httpd 语义：
- 不得覆盖旧 Golden；
- 生成 candidate 结果和 Difference ID；
- 提供首次分歧证据；
- 等待用户批准后再决定是否建立新版本基线。

基线 B：Test-Suite 源码 Oracle
--------------------------------

测试集清单必须固定为：

- basic_c_tests：56 个样本
- basic_cpp_tests：56 个样本
- cs_tests：35 个样本
- fs_tests：25 个样本
- 合计：172 个样本

普通硬门禁断言：

- MUSTALIAS：202
- MAYALIAS：67
- NOALIAS：221
- 合计：490

单独追踪：

- EXPECTEDFAIL_MAYALIAS：5
- EXPECTEDFAIL_NOALIAS：4
- 合计：9

当前四套件没有活动 PARTIALALIAS，但 parser 必须能识别并报告它，
不得静默当成普通 MAYALIAS。

定义样本通过规则：

1. marker-bearing 样本：
   - 二进制成功加载；
   - 所有源码普通 marker 都有且只有一个对应二进制 query site；
   - 没有额外未匹配 marker call；
   - 每个 query 的 complete == true；
   - predicted 与源码标签完全相等；
   - 没有 timeout、budget exhaustion 或 unresolved 被伪装成 MAY；
   - 所有普通 marker 全部通过，样本才通过。

2. 无 marker 样本：
   - 成功加载；
   - 成功发现 main 和可达函数；
   - 不崩溃、不超时；
   - 输出 smoke_only=true；
   - 不计入 490 个 Alias 断言分母。

3. EXPECTEDFAIL：
   - 解析并记录；
   - 报告 XFAIL 或 XPASS；
   - 不计入 490 个硬门禁；
   - 不允许从报告中消失；
   - 不得用它们掩盖普通断言失败。

Alias 分类必须形式化为：

NOALIAS：
- 查询完整；
- 左右 points-to alternatives 完整；
- 所有可行位置组合均为 NoAlias。

MUSTALIAS：
- 查询完整；
- 所有可行求值都指向同一精确对象和相同字节区间；
- 允许多个表达式规范化到同一个位置；
- 不能简单依赖原始 alternatives 数量等于 1。

MAYALIAS：
- 查询完整；
- 既不能证明 NO，也不能证明 MUST；
- 至少存在一个可行的 alias-capable 组合。

INCOMPLETE：
- 任一地址、调用目标、路径、摘要、solver 或预算不完整；
- INCOMPLETE 是完整性状态，不是 MAYALIAS；
- INCOMPLETE 与源码 MAYALIAS 标签相同也不得判定通过。

源码中的变量表达式和期望标签只能用于最终比较和报告，
禁止将源码表达式、标签或注释输入地址求值、别名推理或路径求解器。

基线 C：性能和完整性观测基线
--------------------------------

为每个样本收集：

身份：
- suite
- source path、source SHA-256
- binary path、binary SHA-256
- compiler/ABI/architecture 信息
- image base
- CIR/schema 版本
- Git/工作区版本
- Python、angr、pyvex、claripy 版本
- 固定预算配置

规模：
- discovered functions
- lifted functions
- blocks
- effects
- direct calls
- indirect calls
- marker calls
- summary count

查询工作量：
- scalar steps
- memory work units
- CFG frontier visits
- scanned effects
- scanned StoreEffect 数
- scanned CallEffect 数
- definition frontier hits/misses
- alias query 数和 cache hit/miss
- Must/May/No/Unknown 数
- summary bind 次数
- query retry 次数
- 最大递归深度
- 最大 alternatives 数

Solver：
- solver calls
- SAT/UNSAT/UNKNOWN/TIMEOUT/UNSUPPORTED
- solver wall time
- 最大约束节点数

资源：
- lift time
- callgraph time
- summary time
- query time
- total wall time
- CPU time
- peak working set
- cold-cache/warm-cache 标志

完整性：
- complete query 数
- incomplete query 数
- Unknown reason code 分布
- 每个 reason 的首次位置和样本
- pending summary 数
- unresolved indirect call 数
- unsupported CIR effect 数

性能测量要求：
- 正确性运行固定 jobs=1；
- 性能运行和正确性运行分开；
- 完整 172 样本至少运行一次；
- 分层选择代表样本做至少 3 次 cold 和 3 次 warm 重复；
- 使用中位数和 p95，不使用单次最好结果；
- 正确性门禁以 deterministic work units 为主，wall time 只作性能指标。

==================================================
三、基准基础设施阶段
==================================================

阶段 B0：输入清单和只读预检
--------------------------------

不得修改算法。

生成 manifest，至少包含：

{
  "suite": "...",
  "sample": "...",
  "source": "...",
  "source_sha256": "...",
  "binary": "...",
  "binary_sha256": "...",
  "binary_origin": "Binaries|test_cases_bc|generated",
  "markers": {
    "MUSTALIAS": n,
    "MAYALIAS": n,
    "NOALIAS": n,
    "EXPECTEDFAIL_MAYALIAS": n,
    "EXPECTEDFAIL_NOALIAS": n,
    "PARTIALALIAS": n
  }
}

二进制选择必须固定，禁止运行时静默 fallback。

建议规则：

1. 优先使用 Test-Suite-master/Binaries/<suite>/<source>.elf；
2. fs_tests/array_alias_6.c.elf 若 Binaries 缺失，可使用
   Test-Suite-master/test_cases_bc/fs_tests/array_alias_6.c.elf；
3. 使用 fallback 前验证：
   - ELF 可加载；
   - marker symbols 存在；
   - marker call 数与源码一致；
   - architecture 与同套件一致；
4. 将选择结果和 SHA-256 写入 manifest；
5. 如果候选不兼容，不得临时编译覆盖原目录；
6. 如必须编译，只能输出到 BinaryAnalysis/.p7-work/alias-benchmark/build/，
   并记录完整编译器版本和命令。

阶段 B1：修正 Oracle 和 suite runner
--------------------------------

允许修改 benchmark 基础设施，但不改变 Alias 算法。

完成以下任务：

1. parser 支持：
   - MUSTALIAS
   - MAYALIAS
   - NOALIAS
   - PARTIALALIAS
   - EXPECTEDFAIL_MAYALIAS
   - EXPECTEDFAIL_NOALIAS
   - 单行和多行注释排除
   - 保留准确源文件、行号、左右表达式

2. 将预测标签与完整性分离：
   - prediction
   - completeness
   - reason_codes
   - matched
   - expected_status

3. matched 必须要求：
   complete and prediction == expected

4. 修复源码 marker 和二进制 callsite 映射：
   优先使用 DWARF/source line；
   无 DWARF 时使用：
   - source function identity
   - binary symbol/function identity
   - function 内 marker kind + ordinal
   - callsite RVA
   禁止只按全程序同类 marker 顺序匹配。

5. suite runner 支持：
   - manifest 输入；
   - 单样本执行；
   - 单套件执行；
   - 四套件执行；
   - resume；
   - 每样本独立超时；
   - JSON/JSONL 输出；
   - deterministic ordering；
   - 非零退出码；
   - 失败后继续收集其他样本。

6. 不得把源码 operand 字符串用于分析。

7. 对 C++ 和间接调用：
   - benchmark 必须消费冻结 P6 提供的调用目标；
   - 不得在 benchmark 内另写一套宽松虚调用猜测；
   - 如果 P6 没有目标，输出 INCOMPLETE_CALL_TARGET；
   - 不得把该结果判成 MAYALIAS 通过。

8. 新增基础设施测试：
   - 注释中的 marker 不被读取；
   - EXPECTEDFAIL 正确读取；
   - PARTIALALIAS 被显式识别；
   - unresolved + expected MAY 不通过；
   - marker 缺失不通过；
   - marker 多出不通过；
   - 跨函数顺序变化仍正确匹配；
   - 同一精确位置的多个规范化表达式可判 MUST；
   - smoke-only 样本不进入断言分母。

阶段 B2：执行升级前观测
--------------------------------

在不修改 Alias、taint、memory、summary 算法的前提下运行四套件。

输出目录：

BinaryAnalysis/.p7-work/alias-benchmark/<run-id>/

至少生成：

- manifest.json
- environment.json
- commands.json
- aggregate.json
- metrics.jsonl
- failures.json
- unknown-reasons.json
- samples/<suite>/<sample>.json
- httpd-compat-diff.json

建立 Difference Matrix：

- Difference ID
- suite/sample
- source line
- expected
- predicted
- complete
- first divergent fact
- root-cause category
- affected layer
- planned phase
- regression test
- current status

失败按根因聚类，不按样本逐个硬编码：

- STACK_FRAME
- GLOBAL_OBJECT
- HEAP_OBJECT
- FIELD_OFFSET
- ARRAY_INTERVAL
- POINTER_ARITHMETIC
- STRONG_UPDATE
- WEAK_UPDATE
- BRANCH_JOIN
- LOOP
- CONTEXT_SENSITIVITY
- RECURSIVE_SUMMARY
- FUNCTION_POINTER
- CPP_VIRTUAL_CALL
- CPP_LAYOUT
- SUMMARY_BINDING
- PATH_FEASIBILITY
- SOLVER_INCOMPLETE
- UNSUPPORTED_IR
- ORACLE_MAPPING
- BUDGET
- UNKNOWN_OTHER

此阶段当前程序的错误结果只是 observation，不得写成期望 Golden。
真正的期望始终来自源码 marker 和旧 httpd 基线。

==================================================
四、P0：完整性、Unknown 和 Strong Update
==================================================

阶段 P0.1：形式化完整性状态
--------------------------------

引入显式模型，概念上至少包含：

AnalysisCompleteness:
- COMPLETE
- INCOMPLETE

IncompleteReason:
- ADDRESS_UNRESOLVED
- OFFSET_UNRESOLVED
- CALL_TARGET_UNRESOLVED
- CFG_INCOMPLETE
- SUMMARY_INCOMPLETE
- RECURSION_WIDENED
- MODEL_MISSING
- UNSUPPORTED_EFFECT
- MAY_ALIAS_UNREFINED
- PATH_UNKNOWN
- SOLVER_UNKNOWN
- SOLVER_TIMEOUT
- SOLVER_UNSUPPORTED
- SCALAR_BUDGET
- MEMORY_BUDGET
- ALTERNATIVE_BUDGET
- DEPTH_BUDGET
- WALL_BUDGET
- ORACLE_MAPPING_FAILED

分析结果应建模为：

AnalysisResult[T] = {
    facts: T,
    completeness: AnalysisCompleteness,
    reasons: tuple[IncompleteReason, ...],
    evidence: tuple[...]
}

不要再把 Unknown 当作普通 TaintDependency 的伪 Source。
为保持兼容，可在旧 API 边界提供 adapter，但内部新逻辑必须区分：

- 已证明事实；
- 可能遗漏事实；
- 不完整原因；
- 是否允许得出 NO/clean 结论。

要求：

- join 单调；
- COMPLETE + INCOMPLETE = INCOMPLETE；
- reason 不丢失；
- 预算耗尽保留已证明 facts；
- INCOMPLETE 永远不能证明 NOALIAS；
- 顺序不影响结果；
- wall timeout 不得改变已经提交事实。

为 join、subsumption、序列化和旧 API adapter 建立性质测试。

阶段 P0.2：Strong Update/MustAlias 审计
--------------------------------

搜索所有：

- AliasKind.MUST
- strong update
- kill
- StoreEffect
- MemoryVersion.write
- definition frontier kill
- summary store replay

统一 Strong Update 判定，不允许各模块复制不同条件。

定义 StrongUpdateCertificate，至少包含：

- alias_kind == MUST
- same concrete object
- object cardinality == SINGLETON
- unique target
- write interval known
- demand interval known
- complete byte coverage
- guard concretely true
- path feasible
- memory version/cutoff identity
- proof evidence

只有完整 certificate 才允许 kill 前序定义。

以下情况只能 Weak Update：

- MAYALIAS
- Unknown alias
- 多对象目标
- unknown offset
- unknown width
- partial coverage
- non-singleton heap
- symbolic guard
- incomplete path
- incomplete summary

重点审计：

BinaryAnalysis/emtaint/analysis/taint/demand_memory.py

当前 _scan_store_effect 计算 alias，但最终 kill 条件没有显式要求
AliasKind.MUST。必须确认对象相同、区间覆盖和 singleton 是否在
MemoryQueryPort 契约中足以推出 MUST；不能依赖隐含推理。

增加以下回归：

- exact singleton full overwrite → strong update
- same object disjoint ranges → NOALIAS
- partial overlap → weak update
- unknown offset → weak/incomplete
- multiple heap instances → weak update
- false guard → no write
- symbolic guard → conditional weak update
- callee detached store → 正确绑定后再判断
- recursive summary → 不得错误 strong update
- little/big endian 和不同位宽
- pointer wraparound 边界

==================================================
五、P1：Lazy Binary Value-Flow Graph
==================================================

阶段 P1.1：只读 shadow graph
--------------------------------

先实现 shadow mode，不替换当前查询结果。

建议节点：

- RegisterDefNode
- ScalarValueNode
- LoadNode
- StoreNode
- MemoryObjectNode
- CallInputNode
- CallOutputNode
- ReturnNode
- GlobalInputNode
- GlobalOutputNode
- SummaryEffectNode
- UnknownBoundaryNode

建议边：

- register def-use
- expression dependency
- address dependency
- memory reaching-definition
- call argument binding
- return binding
- memory side effect
- guard dependency
- summary instantiation

要求：

1. 复用 FunctionDemandIndex 和 DefinitionFrontierCache；
2. 函数内寄存器边可预建；
3. 内存边和跨过程边按需求建立；
4. 不预建全程序完整 SVFG；
5. graph key 包含：
   - binary/function identity
   - CIR version
   - memory version
   - object facts version
   - call-target version
   - summary version
6. session-local SSE/APG id 不得写入持久摘要；
7. 缺边必须产生 UnknownBoundary，而不是返回空；
8. shadow graph 与旧 CFG 查询同时执行并比较。

Shadow 验收：

- facts 等价；
- completeness 等价或更保守；
- 每个差异都有 Difference ID；
- httpd compatibility diff 为零；
- 不增加 Test-Suite 普通断言失败；
- P6 结果不变。

阶段 P1.2：逐类启用图查询
--------------------------------

启用顺序：

1. register def-use
2. scalar expressions
3. exact stack/global memory
4. singleton memory Store/Load
5. branch join
6. call input/output
7. heap/array
8. recursive summary

每启用一类都必须：

- 保留 fallback；
- 运行最小专项测试；
- 运行受影响套件；
- 运行 P6 冻结测试；
- 运行完整回归；
- 比较 httpd；
- 更新 Difference Matrix。

性能晋级条件建议：

- correctness 不退化；
- incomplete 数不增加；
- median scanned effects 至少下降 30%；
- p95 wall time不高于旧实现 1.05 倍；
- peak memory 不高于旧实现 1.10 倍；
- 未达条件时保持 shadow mode，不切换默认路径。

==================================================
六、P1：分级 Alias Refinement 和切片 SMT
==================================================

建立分级流程：

L0：对象身份
- object_id
- region
- allocation site
- stack frame
- global identity

L1：范围
- offset interval
- width
- byte interval overlap
- pointer bit width
- wraparound

L2：对象基数
- singleton
- summary/multiple
- unique allocation context

L3：上下文
- actual/formal binding
- relevant call context
- memory footprint
- recursive SCC context

L4：路径
- branch guard
- interval contradiction
- equality/inequality
- final SMT feasibility

规则：

- 默认从便宜层级开始；
- 只有 May/Unknown 会影响最终 marker 或 Finding 时才升级；
- refinement 只能增加精度，不能删除已证明事实；
- solver timeout 保留原 May/Incomplete；
- 不得对整个函数进行无界符号执行；
- SMT 只处理最终需求切片；
- cache key 必须包含 path condition 和 memory version；
- SAT/UNSAT/UNKNOWN/TIMEOUT 分开记录。

优先使用测试集：

- fs_tests：强更新和流敏感
- cs_tests：上下文、递归
- basic_c_tests：数组、字段、堆、函数指针
- basic_cpp_tests：虚调用、继承、对象布局

==================================================
七、P2：跨域精化
==================================================

建立显式 reduced product：

AddressDomain
× IntervalDomain
× ObjectCardinalityDomain
× LengthDomain
× GuardDomain
× String/TerminationDomain

必须支持双向 refinement，例如：

- i ∈ [0, 7] 缩小 base + i*4 地址区间；
- 精确地址区间缩小 Alias 候选；
- MustAlias 允许精确 strong update；
- strong update 反向缩小 reaching definitions；
- length < 32 缩小 memcpy/strncpy 写范围；
- format 解析约束 variadic 参数数量和类型；
- Guard 中的等式约束地址 offset；
- 数组边界和对象大小排除不可能别名。

要求：

- 每个域保持独立 API；
- 通过显式 refine() 交互；
- 禁止依靠共享可变字段隐式耦合；
- 每次 refinement 记录 before/after 和依据；
- 处理位宽、符号扩展、截断、溢出和 endian；
- 达到 fixed point 或预算后停止；
- 预算停止必须返回 Incomplete。

==================================================
八、P2：符号化内存副作用和参数化摘要
==================================================

摘要至少表达：

- ParametricReturn
- ScalarReturn
- ReadFootprint
- WriteFootprint
- ConditionalWrite
- GlobalEffect
- ArgumentMemoryEffect
- SourceEffect
- SinkRequirement
- Completeness
- ContextRequirement

Store 摘要不能只保存展开后的具体值，应保存：

- symbolic destination
- symbolic value
- offset/width
- guard recipe
- length recipe
- required alias assumptions
- provenance

调用点实例化时：

1. 绑定 actual arguments；
2. 绑定对象和偏移；
3. 实例化 Guard/Length recipe；
4. 检查上下文条件；
5. 重新执行 Alias/Strong Update 判定；
6. 不能把 callee 内的 MAY 自动提升为 caller MUST。

递归处理：

- 以 SCC 为单位；
- 单调 fixed point；
- 有明确 widening；
- widening 后标记 completeness/reason；
- 不允许递归直接返回空摘要。

摘要缓存键至少包含：

- callee CIR hash
- ABI
- call-target version
- object-facts version
- procedure-model version
- summary schema version
- relevant context abstraction

==================================================
九、每轮必跑门禁
==================================================

在 BinaryAnalysis 目录运行。

最小 alias 基准：

.venv\Scripts\python.exe -B -m unittest tests.test_alias_benchmark -v

P6 冻结测试：

.venv\Scripts\python.exe -B -m unittest \
  tests.test_p6_archive \
  tests.test_p6_dataflow \
  tests.test_p6_demand \
  tests.test_p6_entry \
  tests.test_p6_revision \
  tests.test_p6_site_results \
  tests.test_p6_summaries \
  tests.test_p6_tables \
  tests.test_p6_targets -q

完整回归：

.venv\Scripts\python.exe -B -m unittest discover -s tests -p "test_*.py" -q

四套件 runner 建成后：

.venv\Scripts\python.exe -B scripts/alias_benchmark_suite.py \
  --manifest tests/fixtures/alias_benchmark/v1/manifest.json \
  --output .p7-work/alias-benchmark/<run-id> \
  --jobs 1

httpd 比较必须复用 taint.command.json 保存的输入和既有 compare 工具，
不得自行猜测旧版命令，不得运行旧仓库覆盖 Golden。

还必须运行：

- compileall
- quality_audit.py --fail-on safety
- git diff --check 或等价工作区检查
- 基线 SHA-256 完整性检查

==================================================
十、阶段门禁与最终完成条件
==================================================

中间阶段：

- httpd compatibility diff 必须始终为零；
- P6 冻结测试必须始终通过；
- 历史完整回归不得减少；
- Test-Suite 已通过普通断言数量不得下降；
- incomplete 数不得无解释增加；
- 不允许新增 ignore/xfail；
- 每个新增失败必须有 Difference ID。

最终完成：

- 172/172 样本被处理；
- 166/166 marker-bearing 样本通过；
- 6/6 smoke-only 样本成功；
- 490/490 普通 Alias 断言 complete 且 exact match；
- 9/9 EXPECTEDFAIL 被识别并单独报告；
- missing marker = 0；
- extra marker = 0；
- crash = 0；
- timeout = 0；
- budget-exhausted marker = 0；
- unresolved marker = 0；
- httpd 兼容差异 = 0；
- P6 差异 = 0；
- 完整单元测试全部通过；
- 性能报告包含升级前后 cold/warm 对比；
- Unknown 原因全部有结构化 reason code；
- 所有剩余风险写入 P7-report.md。

==================================================
十一、报告格式
==================================================

每轮报告必须包含：

1. Difference ID；
2. 本轮唯一目标；
3. 修改文件；
4. 首次分歧事实；
5. 根因；
6. 修改前结果；
7. 修改后结果；
8. 最小测试命令和退出码；
9. 受影响套件结果；
10. P6 测试结果；
11. 完整回归结果；
12. httpd compatibility diff；
13. 性能变化；
14. Unknown/Incomplete 变化；
15. 是否修改 Golden：必须为否；
16. 回退文件和回退方式；
17. 下一轮建议。

不要只报告“测试通过数量增加”，必须报告：
- 哪些 Alias marker 从什么结果变成什么结果；
- 为什么变化；
- 是否 complete；
- 是否由真实精度提升得到；
- 是否影响 httpd 和 P6。
# P7：进行中的实现与验收记录

状态：**进行中，Gate A 尚未通过，不进入 P8**。本文件记录续作检查点，不代表以未达标报告结束阶段。

最新检查点为文末的“2026-10-30 长度/全局输出续作”。较早小节中的“当前”“尚未修复”仅描述当时封存版本；各次失败和修复日志保留，不作为当前最终验收结论。

## 本轮重新审查的边界

已完整重读根目录的 `AGENTS.md`、`MIGRATION_BLUEPRINT.md`、`CODE_TASK.md` v5.0，以及已有 P7 实现、测试和运行记录。运行版本遵循用户已确认的 `TARGET_RUNTIME.md`：目标 Python 3.12.9 / angr、Claripy、pyvex、cle、archinfo 9.3.4；旧环境 Python 3.7.2 / angr 9.0.9792。未安装依赖，未修改旧仓库、Golden、两个虚拟环境或封存阶段结果，未开发 Rust。

证据根目录：`.p7-work/20261029T074944Z-3a0de46d`。失败、超限和中断尝试均保留，重试采用新目录或新的尝试编号。

## 已核实的运行事实

| 证据 | 结果与限制 |
| --- | --- |
| `acquisition-03/acquisition-report.json` | 881 个 IDA 函数、29816 个 CIR 块采集成功；427.766 秒。输入函数文件保留原始 hash。 |
| `cli-01/icall.json` | 首次真实目标 CLI `-i`：17 个观察站点、535 条 MAY 目标记录、5892 条逻辑 CG 边，2 轮达到候选固定点。 |
| `cli-02/icall.json`、`icall-command.json` | 尾调用补全启用后重新执行 `-i`，上述数量和固定点保持；350.110 秒，源码在本次运行期间未变化，写保护违规为零。完整目标集合还需纳入最终独立差分。 |
| `cli-01/taint-eb16e19d/manifest.json` | **诊断性**全程序 `-t` 扫描完成：881 个摘要（含 2 个旧版排除）、879 次实际函数分析，单轮、每函数 10 秒，3015.860 秒；2 个 buffer、2 个 command 候选、161357 个未知需求。状态为 incomplete，不能作为 Gate A 通过证据。该运行早于尾调用修复。 |
| `comparison-01/comparison.json` | 运行中的逐站点快照：535 条 iCall 记录与 Golden 无缺失、无新增。污点比较明确区分函数未完成、预算/语义不完整和来源对应未解析，未以总数相等判定通过。 |
| `legacy-06/legacy-report.json` | 在只读旧环境真实执行：288 组 Guard 策略、8 组 atoi 长度变换、既有 source/copy/format/security characterization 一致，写保护违规为零。 |
| `solver-01/solver-report.json` | 真实目标 Claripy 经 P5 MemorySolverLowering：可满足源 Guard 为 SAT，矛盾源/汇 Guard 为 UNSAT，未支持 Guard 为 UNSUPPORTED；只证明专项 fixture。 |
| `regression-15.txt` | 当前完整 291 项回归通过，4.387 秒。包含目的缓冲区跨调用绑定、可写 global 长度和格式未知；失败 fixture 修正和之前失败日志另行保留。 |
| `p7-tests-12.txt`、后续完整回归 | 56 项 P7 专项通过后新增目的缓冲区测试；覆盖预算保留、Guard、source handle、长度/目标绑定、load/store、尾调用、只读 global、摘要累积、比较器和 legacy 计划边界。 |
| `native-01/report.json` | 目标原生 ARM helper/shift/VEX 与前端 21 项通过，写保护违规为零。 |
| `integrity-01/integrity.json` | 旧仓库 13461 文件、目标 venv 13044 文件、Golden 351 文件、封存 P6 2950 文件的内容与 mtime 清单均保持不变。 |

Golden 为 `../baselines/rv130_1_0_3_44/20261028T051055Z-96d1c781`。旧 `taint_1` 为 143 个 buffer 候选站点、7 个 command 候选站点、796 个已分析函数；这些是旧启发式结果，不是已证明漏洞。旧 JSON 未独立保存所有 alias/guard/path 事实，原始 `taint.log` 仍为逐例审查依据，不能用其中的路径长度计数冒充具体路径。

## 本轮找到并处理的分歧

1. 重复格式字符串读取：相同调用点和初始内存的格式解析现在复用缓存；类型校验缓存只保存不可变类元数据，仍逐字段校验。没有修改 CIR/Memory DTO 字段或 Schema。
2. 全局预算异常曾使整个函数摘要被空摘要替换。现在保留已完成的 sink、return、output 和源事实，记录停止位置；逐函数 start/result 立即落盘。表达式 alternatives/depth 超限与全局 steps/time 预算已区分，局部失败不应放弃无关的后续查询。
3. 旧 `FastSearch.ignore_function` 实际排除 `0x12194`、`0x1607c`。现按已审计固件 hash 使用该策略，保留覆盖排除及未知内存影响，不宣称这些函数无副作用。
4. **首个真实 source 分歧**：`0x1db6c` 原始 CIR 没有 CallEffect/ReturnEffect；实际是尾跳转到 `fread` 和 `BIO_read` 的 PLT。`frontends/tail_calls.py` 仅在原生块内 PC 常量、真实 CLE PLT 地址、IDA 调用点三者一致时，投影已声明 ABI 的读取、调用和返回。保留原 CIR，派生 hash、原 origin 与派生 origin 单独记录。缺少证据或目标不一致时不补造调用。
5. `profile-10` 及后续真实函数探针确认 `0x1dbb4→fread`、`0x1dbc8→BIO_read` 的两个源事实恢复，具有当前作用域 Root/APG/MemoryVersion。`0x46b9c` 仍存在表达式乘积/前沿障碍，正在逐层处理，尚不能声称其 source 传播已通过。
6. 跨函数绑定保留参数偏移、Guard、长度约束和 handle 来源。使用已在 P6 验证的 `ProcedureRecipe` 传递未解的长度表达式，支持在真实 caller 参数处求值；独立测试验证 39999 是调用实参求得，未从 Golden 注入。
7. 按原 `FastSearch._add_taint_constraint` 移植 `strlen`/整数 bound 与 `strcmp==0` 等分支策略。文件来源过滤依赖实际 handle lineage，`fdopen(accept(...))` 保留 socket 覆盖；未支持 handle load 仍为未知。
8. 未支持值不再变成干净空依赖；未知 taint fact 以保守上界 join，并在函数证据 journal 保留各原始前沿原因。已知 Source 不能被该 join 消除。callee 源被投影为 caller 当前作用域的 APG 事实，跨作用域 SSE ID 不直接传递。

部分长函数 profile 进程发生了原生异常，`profile-15-exit.txt` 为 `-1073741819`。后台 traceback sampler 的输出被截断。后续关闭 sampler 的 `profile-16/18/20/25/27` 成功；这尚不能证明原生异常根因。默认已禁用 sampler，失败日志保留，不作为超时或安全结论。

## 续作的真实传播与编排验证

- `legacy-07/legacy-report.json` 实际执行旧 `hsearch_r` INSERT/FIND。五参数 ABI、key-insensitive 规则、`Load(htab)+o` 与返回 `Store(Store(retptr)+4)` 两层间接引用均来自原实现。新状态使用稳定 table Root、APG、MemoryVersion；未把 table 指针单元冒充 entry payload。
- `profile-25` 恢复 `fread/BIO_read → parser → hsearch_r → getter → callback`。经 `0x18590` 的实际调用实参绑定，7 个旧 command 站点都保留源 `0x1dbb4`；`0x1dbc8` 是另一路实际 source 的 MAY，未注入 Golden 来源或长度。
- 查明 INSERT 初始参数分歧来自可写全局初值误剪枝。loader snapshot 仍服务于 GOT/候选解析；污点分支求值只使用只读映像和实际 MemoryVersion 定义。回归先复现了误剪枝再修复。
- 修复三个 pass 各自从相同计数分配 APG ID 的冲突。port、backward demand、region tracker 共享同一 arena；不可变图冲突现在拒绝覆盖。
- `cli-04/taint-4751fdf4` 使用真实 AnalysisRuntime 多轮编排：global table 版本变化实际使 reader 和 CG 依赖失效。但预算导致部分摘要替换既有结果并振荡。现按同一 CIR/input identity 累积 MAY 事实；body identity 变化清空累积，原始逐轮摘要及保留证据 receipt 均保存。
- `cli-04/taint-6b37123b` 修正只读常量被误导出为 caller 可写 global 后，13 函数子集在 5 轮、52 次分析后停止重算，7 个旧 command 候选站点、零额外 command 站点；pending function 和 pending summary 为空。仍有 246 个 unknown requirement / 361 个 unknown summary dependency，且是子集，**不作为 Gate A 通过依据**。
- `profile-27` 实际 caller 绑定：`strcat(0x2a8e4)` 的 callee destination 为参数 1，`0x34a78/0x34bcc` 映射到栈 offset 64，`0x35458` 映射到 52，保留实际源。目的位置和源依赖分开建模，未从 Golden 指定 offset。
- `comparison-04` 独立对照：535 条 iCall 和 5892 条实际旧环境 warm logical CG 边均 missing=0 / extra=0。比较器现同时核对 function/site/name/kind/offset，不把相同 site 的错误 procedure 当作匹配。
- `comparison-05` 在只读 global 修复后的真实子集上核对 7 个 command：全部保留 `0x1dbb4`，零额外站点；`0x1dbc8` 为另一实际 source 的 MAY，约束/Guard/具体路径仍须审查，不宣称可触发性。
- `evidence-01` 重放 8 份真实 source archive、328 facts；`evidence-02` 重放编排诊断的 26 份 archive、1056 facts。P3 wire、引用闭合、MemorySnapshot 验证和重建均通过。P3 CIR/Memory Schema 未变化；P7 私有 evidence v2 新增纯 destination descriptor，v1 历史归档保留。
- `evidence-03` 再次重建目的绑定修复后的 7 份实际 archive、104 facts，全部通过。
- `legacy-08` 真实执行旧 `FunctionCFG._add_irsb_node_to_cfg`，确认单 call 指令地址与 CFG block 地址冲突时，旧人工 call 节点编号加 1。`site-map-01/site-map.json` 同时核对原 CIR 与 IDA：旧 `0x4e505/0x50e11` 分别对应实际 `0x4e504/0x50e10`，函数/strcpy/块入口均一致；两种编号都保留，仅在后处理比较器显式映射，Golden 和分析入口不变。

`cli-04` 的全程序 `-t` 多次在新分歧确认后主动停止，原日志/逐函数结果保留；不得标为完成或超时。`cli-04-t-06/07` 在运行时初值边界测试暴露漏报后停止；当前尝试为 **`cli-04-t-09.log`**，使用全程序、120 秒/函数、15 轮预算，完成前不得用于 Gate。184 份实际执行源码已物理归档在 `source-frozen-t09`。`-i` 的独立成功记录为 `cli-04/icall-command.json`：196.625 秒，进程峰值 RSS 401305600 bytes，源码在运行期间未变化，违规为零。

后续回归复现：可写 global 的 loader 初值 0 曾使真实未知长度的 source 被判为零长度而丢弃。length、length recipe 绑定、token 状态选择、argv 终止符和 guard bound 现在使用运行时常量求值。地址/GOT 候选解析仍保留原 loader 策略。格式字符串既保留旧 FormatParser 的 loader 解释作为一种 MAY，也显式保留运行时 unknown；该解释不支持长度上界或路径排除证明。未知字节和未终止格式不能变成干净空参数集。

**当前尚未修复的实证阻断**：`comparison-06` 的运行中快照（879 个函数）仅为 source/offset 需求覆盖：116/143 buffer、7/7 command，不是策略后的候选验收。`0x1f9a0` 等在绑定 residual length recipe 时，超过 256 nodes 的约束错误中断了独立已知 source 的传播。新增 `test_p7_constraint_frontier.py` 用真实有限平衡 DAG 重现，`constraint-frontier-before.txt` 为预期失败；因此当前不能把早先 291 项通过当作所有新增测试都通过。需要在本次冻结运行取齐差分后修复“约束未知与 source 传播分离”，并检查 taint dependency alternatives 的局部预算标记和每项 callee sink 的失败隔离。继续 P7，不以本报告结束工作。

`cli-05` 为当前冻结版本的额外真实 `-i` 回归：156.218 秒、峰值进程 RSS 401670144 bytes，运行期间源码未变化；目标 JSON 与 `cli-04` 完全相同。`legacy-dispatch-tests-01.txt` 仅为 P7 临时目录中的 mock 协议测试，分别调度 icall/taint 并验证同一 plan，1 项通过；没有实际复制或执行旧入口。

`cli-04/taint-e9e059b2` 在此补充边界前的 17 函数诊断：7 轮、74 invocations、1 个 buffer / 7 个 command 候选，summary fixed point 停止；函数格式覆盖未知仍为 incomplete，不当作全程序结果。`golden-trace-02` 提取 150 条 Golden 的原日志证据，parser error=0。5 个 strncpy 条目走旧拼写 `check-weak-copy-with-lenth` 分支，该分支没有打印 source/path；其约束原文被保留，source 对照标记证据缺失，不能从别的条目补写来源。

## 度量和只读边界检查

`metrics-01/metrics.json` 汇总 13 函数子集的 52 次实际分析：各次 arena 之和为 DAG nodes 110753、APG nodes/edges 5196/3535、MemoryVersion 4010、facts 1221、alias queries 261896，taint demand steps 1293270，函数分析时间之和 154.125 秒。**这不是 session unique 计数，也不是完整固件结果**。`heap_cells=13810` 是现有 budget accounting 的物化字节量，不作为 cell 个数；focused source archive 的 cells 也是证据切片，不冒充全内存 cell 数。

旧 `observed-01/02/taint.metrics.json` 的 observed root max expanded/unique=9、depth=5、Load depth=2，479 次 raw SMT check；均是已有 P0-B v5 观测范围。新 taint MAY 路径不调用 SMT，独立 solver fixture 另计。旧 per-root maxima 与新 per-invocation DAG 数量分母不同，不能据此宣称表达式缩小或加速。

`integrity-02` 确认旧仓库 13461、目标 venv 13044、P6 2950 文件不变。该次 Golden 检查误用单一 archive 根目录与整个 baselines 清单比较，失败记录保留；`integrity-03` 改用正确 baselines 根目录，351 文件全部内容/mtime 不变。

`boundary-01` 宽范围扫描发现 55 条既有 VEX/PAG/旧门面 native import。它们全部与入口 source hash 相同（P2/P3 已记录保留范围），不能把本扫描称作全目录纯净。`boundary-02` 在禁止 angr/pyvex/Claripy/IDA/networkx 的进程中实际导入 P7 runtime 的 64 个模块成功，P7 新增/修改代码的违规 import 为零。

## 回退的兼容矩阵与授权边界

| 入口 | 实际后端 | 当前状态 |
| --- | --- | --- |
| `--engine python --memory-engine apg` | 目标 `.venv` 9.3.4，CIR/APG/Heap/MemoryVersion | 默认；上列真实运行与差分继续验收 |
| `--engine python --memory-engine legacy --legacy-plan ...` | 旧 `.venv` 9.0.9792，实际旧 main/FastSearch/AccurateDataFlow/自定义 Load/Store | 代码和路径边界测试完成；新物理副本的实际执行尚待单独授权，不冒称已验证 |
| Rust/hybrid | 无 | P7 不开发、不启用 |

`legacy-plan-01/plan.json` 是只在 P7 写出的可审查计划；拟新建 `baseline-work/p7-20261029T140752Z-d85ea47a/EmTaint` 与 `baselines/rv130_1_0_3_44/p7-20261029T140752Z-d85ea47a`。依 AGENTS 的特别批准要求，已提出一次授权请求；未获答复前不创建这两个目录。实际回退会复核 PLY parser contract、禁写表、复制输入 seed、保留 preexisting、逐步验证旧仓库 content/mtime/Git，且不作为 APG/Gate M 证据。

## 接下来仍须完成的 P7 工作

### 2026-10-30 完整运行与受控修正记录

`cli-04/taint-b709b5e0` 已完整结束：881 函数（879 实际分析、2 个原策略排除）、5 轮、2232 次调用，176 个 buffer MAY 站点、17 个 command MAY 站点、confirmed=0。函数分析耗时 5860.687 秒，CLI 5874.735 秒，进程峰值 RSS 2885566464 bytes；入口/结束 source manifest 相同，写保护 violations 为空。230 个函数仍有 pending，pending summary functions 为空，**incomplete，Gate A 未通过**。

`comparison-07` 对完整运行的 150 条 Golden 记录：119 条候选需继续证据复核，26 条函数 incomplete，2 条 legacy policy/extent 差异，3 条 Source 对应未解决；额外 74 个 MAY 站点尚须逐项解释。诊断性的 source+offset 覆盖为 116/143 buffer、7/7 command，但不等于旧 Source/Guard/path 保真；其中三个 command 只关联另一路 Source，不能按数量判定通过。

`cli-05` 的独立新 `-i` 用时 156.218 秒，535 条候选与 Golden 一致，实际 warm CG 5892 条边 missing=0/extra=0。`icall-05-differential-v3.json` 记录 raw mapping 的唯一差异：显式保留 `0x10f1c` 的空 unknown 站点，未新增 resolved target。早期 v1/v2 比较记录保留，不能用它们的 raw equality 结论替代 v3。

完整运行源码保存在 `source-frozen-t09`。`replay-context-01` 固定 879 个实际摘要及其 SHA，`scripts/p7_replay_codec.py` 验证私有 v1/v2 结构、拓扑和 recipe hash。`replay-codec-native-01.txt` 已读取全部 879 个摘要；单函数受控重放只用于诊断，不声称真实全程序固定点或 invalidation。

后续已合入两组修正：

- 长度配方超过 256 nodes 时，显式保留未知长度及原 Source，不让独立 Source 被整个函数异常吞掉。调用实参绑定传递 `unresolved_constraints`，缓存也保留此状态。`test_p7_constraint_frontier.py` 在修复前失败、修复后通过。
- dependency alternatives 属于局部查询失败；单个 callee sink 的局部失败不跳过后续 sink。union 在失败前保存已见 Source。继承 sink 池很大时先处理本函数 sink，效果顺序和查询 cutoff 不变。`replay-budget-02` 对相同真实摘要/CIR/预算的 4 个函数重放，无错误/写越界；`0x2d394` 从 52 条提高至 165 条 sink 需求，三个旧 command 重新保留 `0x1dbb4`，仍只属于 MAY。

`replay-query-01` 单独查询真实 `sprintf(0x1fe3c)`，保留 Source `0x1de44` 和栈 offset `1142`；完整函数仍可能在此前查询耗尽预算，不能用这个定点诊断宣称全程序已恢复。

`emtaint/analysis/taint/subsumption.py` 对同一 Source/offset/width/handle lineage/unknown 状态，仅删除被**已有**更大或无上界 Cons、guard 子集、recipe 子集覆盖的变体。Symbolic policy tags、不同 Source、formal/global 依赖不合并，不制造新 Source/path/约束。调用端取 min 的数值约束绑定保持覆盖关系。5 项独立测试枚举 caller bound/extent 的原检测决策，并检查 input witness、不同 lineage、不可比较条件及预算；被覆盖的原变体和覆盖输入另存 `covered_source_alternatives`，summary accumulator 仍保留跨轮独立约束证据。

`replay-antichain-04` 在相同输入下与 `replay-budget-02` 对照：4 个函数共同到达的 sink 无 Source ID 丢失，`0x1c2d0` pending 16→0，`0x18590` 17→1；`0x1f9a0` 与 `0x2d394` 仍有总预算前沿。`experiments/cycle-identity-03` 未解决关键阻塞，未合入 P6 基础需求引擎。

`regression-20.txt`：302 tests、4.604 秒、OK，真实退出码 0。`regression-16` 的两处 error 是比较器测试 fixture 缺失 `offsets`；`regression-19` 提醒 accumulator 不能丢弃跨轮约束证据，已保留该测试及原 accumulator 行为。失败记录均未覆盖。以上仍是 P7 续作检查点，**不是阶段完成报告**。

- 完成剩余 source/length/alias 分歧和 buffer 的 caller destination 绑定差分，验证局部超限与可能写入不会遮蔽已知源事实。`profile-18` 已保留 `0x46b9c` 的 106 个 source facts 和局部超限前沿。
- 将修复后的相同 CIR 派生策略用于完整 `-i→-t`，达到摘要固定点或明确列出残余前沿；不能以诊断单轮代替验收运行。
- 逐一对照 143 个 buffer、7 个 command 旧候选及其 offsets/name/function/source/约束证据；为额外 MAY、丢失和过滤项提供原始源码与 trace 依据。
- 补齐剩余 procedure（含 argv/有状态 token）、global 输出与调用上下文的实际需要部分，验证 reanalysis/invalidation。
- 核对 TaintFact 引用的实际 APG、内存定义、Guard 与来源记录，完善可重放证据归档；不得只输出 opaque ID。
- 完成真实 legacy 回退接口验证，重新执行全部纯 Python/原生/源码边界/Schema/受保护文件检查，补齐 APG/Heap/DAG/fact/worklist/alias/SMT、时间与 RSS 的最终度量。未测 RSS 不填写为零。

只有上述保真与证据要求满足后，才能把 P7/Gate A 标为通过。下一阶段 P8 不在当前执行范围。

## 2026-10-30 长度/全局输出续作

三份 v5 规划文档已完整重读，执行边界保持 P7。`sealed-replay-21` 在真实捕获源码、相同 CIR/摘要和原全局预算下，恢复 `0x11fb8` 的 `0x1de44 → offsets 64/96`，并保留 `0x1fe3c` 的 `0x1de44 → 1142`。这是单函数受控证据，不冒充全程序固定点。

已合入的缓存和调度修正均有开关/独立回归：reaching 与成功 memory definition 复用、旧定义选择 frontier 缓存、未知位置存在性查询、opt-in alias 与最近一次完整 definition resolution 复用、AnalysisScope 的私有 hash memo/pickle 重建。P3 公共 dataclass 字段和 CIR/Memory wire Schema 未变。公平 query worklist 保持 250000 taint steps、500000 scalar steps、200000 SSE nodes、2000000 memory work 和 120 秒函数预算；共享调用点参数 SSA 仅暂停小查询份额，仍受函数总预算约束，实际成本单独记录。

`legacy-bounded-09/10` 在旧解释器原生执行 `reg_taint_propagate`、Collector 和 Cons type 4 规则：bounded buffer 只有在 buffer/length 都 tainted 时进入原 weak-copy-length；clean length 仍传播数据，但不产生该旧 weak。`length-taint-red-02` 复现了跨函数 Cons 类型丢失和 copy 后数值约束丢失，修正后独立 buffer/length 通道、标量返回、实际 caller 值绑定、Cons 4 的 atoi 变换及传播通过。长度 Source 在预算中断时不会被添加到 buffer Source 通道。

Source 建立之后的 handle/length 可选绑定若中断，保留真实 Source fact 和显式未完成描述。有限长度 DAG 超过 256 nodes 保留未知约束及原 Source，不再作为空传播。相关真实 DAG/中断测试包含在 `regression-29/30`。callee 已知 Source 的可选 caller 绑定失败也保留 MAY，但明确不表示 caller projection 已完成。

私有证据版本审查见 `docs/migration/P7-EVIDENCE-v3.md` 和 `P7-EVIDENCE-v4.md`。v3 分开 buffer/length、Cons 类型及 scalar_argument/scalar_returns；v4 增加 detached global 输出几何。`replay-codec-native-02/03` 实际读取全部 879 个历史摘要，缺失的 length/scalar/global 信息保留 unknown/null，recipe SHA 继续校验。旧文件没有改写。

`legacy-global-02/03` 原生验证旧 global 定义导出、merge、iCall 记录、global 按 block 取用及覆盖移除，均 passed，violations=[]。同 global AST 的旧 merge 只保留第一条 Source；目标相同位置合并保守保留已有 Source，记录为可能的额外 MAY 来源。新输出仅从真实 Store/procedure/callee 定义、真实 Return cutoff 查询，通过 MemoryQueryPort 绑定 caller Root/APG/MemoryVersion。参数输出遇到可能别名的 global 写时保留 unknown，不能把它冒充各参数的已知定义。P5 offset range 的 MayAlias 边界保持原样；精确普通 Store 的 NoAlias/覆盖字节另有测试。

候选证据已区分 callsite_path 与实际可映射的函数路径，未测循环/传播/iCall 计数为 null。Source index 保留实际 binding、fact、archive/receipt 与 SHA，候选引用该索引，避免复制整份证据集合；这些链接仍不等于完整路径可触发性证明。confirmed 继续为 0。

`comparison-08` 使用旧 raw trace 的 Source ID 重新审查早期完整 t09：原 119 个“候选存在”中有 1 个实际 Source/offset 差异，现明确单列，剩余 118 个仍需 Guard/Cons/path 复核。比较工具新增错误 Source 的独立测试，不能再只按站点/offset 判定匹配；旧长度分支未打印的 5 个 Source 不补造。

最新纯 Python 回归 `regression-30.txt`：349 tests、15.348 秒、OK，真实退出码 0。`boundary-04` 在禁止 angr/pyvex/Claripy/IDA/networkx 的进程中实际导入新 P7 runtime 成功，新改核心模块的 native import 为零；保留的历史门面另列。`boundary-03` 的编码别名错误属于检查脚本失败，保留原报告后更正为 utf-8-sig。`solver-02` 的实际 Claripy 三态专项再次 passed、violations=[]。

`sealed-cli-06/07/08/09` 的独立 `-i` 均保留 17 个站点、535 个 MAY targets、5892 条 CG 边；最终集合差分仍需以最终同源码 `-i→-t` 为准。`sealed-cli-07` 的 v3 全量 `-t` 正在执行，其源码在启动前捕获；后续 global v4 修改没有混入该运行。v4 最终候选版本 `sealed-cli-10` 已捕获源码并启动新的 `-i`。运行中记录均不提前标为完成、无发现或 Gate A 通过。

## 2026-10-30 全量 v4 与旧入口隔离回退核验

本节更新上方历史检查点。经用户特别批准，`legacy-plan-02` 在新物理副本 `baseline-work/p7-20261029T140752Z-d85ea47a/EmTaint` 依次执行旧 `-i/-t`，输出只进入新归档 `baselines/rv130_1_0_3_44/p7-20261029T140752Z-d85ea47a`。当前 v5 PLY proof 的 bootstrap SHA 验证通过，写表被禁止；旧代码、元数据、环境、既有 Golden 的内容/mtime 及 Git 状态未改变。`legacy-differential-01.json` 核对整个 `icall` 与 `taint_1` JSON，仅排除阶段运行时间后与批准 Golden 相同：143 buffer、7 command、796 analyzed。旧版回退可复现，但不能作为 APG 正确性证明。首次 plan01 因过期 PLY proof 在进入旧 parser 前停止，其失败记录保留。

完整 APG `sealed-cli-10` 的 `-i` 为 535 个 targets、5892 条 CG 边、17 个站点，集合对 Golden missing/extra 均为零；unknown `0x10f1c` 显式保留为空。`-t` 完成 881 个摘要（879 实际分析、2 个旧策略排除）、11 轮、2371 次调用，245 buffer 与 26 command MAY，confirmed=0；830 个函数仍有 pending，进程峰值 RSS 3513614336 bytes，CLI 11311.875 秒，退出 2（incomplete）。`comparison-10` 的 150 条 Golden 记录中 139 条为候选存在但需 Guard/路径/约束复核，11 条未完成；135/143 buffer、7/7 command 的旧 Source+offset 有诊断覆盖，额外 130 个 MAY 尚须逐例解释。此轮**不通过 Gate A**。

`evidence-04/report.json` 验证 `sealed-cli-10` 的 778 份内存归档可重放，其中 713 份 Source 归档对应 19753 条真实 binding、1477 个候选 Source 索引引用，错误为零；这仍不是全路径可触发性证明。`integrity-05` 核对旧仓库 13461、目标 venv 13044、P6 2950 个原文件及原 baselines 351 个文件均未变；新增的 25 个文件仅在已批准 P7 归档中。

后续真实函数诊断已把 `0x52db4` 的内存上限 2000000 次重复求值压至受控回放的 782521；纯 SSE 完成值缓存只复用不含 MemoryRead 的子图，未缓存内存定义证据。P7 循环结果缓存保留旧非仿射符号余项，在同一 CFG 截点复用已完成结果；受控回放的标量工作从 500001 降至 173717，但 `0x532e8` 在完整函数中仍因份额/时间中断，单站点回放得到 argument 依赖。`0x53abc` 与 `0x722f8` 的多长度来源若混有无界来源，不再把一条 Cons 4 上界 9 强加给全部备选；受控回放恢复了 `0x53c80` offset 572 与 `0x7250c` offset 174 的 Source MAY 条件。`0x4e505` 的 offset 349 与 `0x2d5ac` 的 offset 20 仍需实际 caller/use-def 解释。以上均为局部证据，不能替代整机固定点。

当前代码的独立 `sealed-cli-11` 已完成新目录 `-i`（exit 0、源码未变），同源 `-t` 正在执行。`regression-35` 在该检查点 377 tests 通过；后续测试文件整理与调度改动还须最终再跑回归、原生入口、solver、Schema、边界及受保护文件核验。P7/Gate A 维持**未通过**，P8 未开始。

### 2026-10-30 旧栈哨兵与定义前沿追加审计

`sealed-replay-44` 在原 CIR、摘要、120 秒函数预算下重放 `0x2d394→strcpy(0x2d5ac)`，真实调用目的值只有 `argument:5` 与一个 `MayAlias/partial/guarded reaching store` 余项，未产生 offset 20。其 CIR `f25394:o1085` 先从 SP 相关地址 Load，再将**加载值**写入 r0 作为调用目的参数。旧 `taint.log:7685` 则在单独分析 `0x2d394` 时就把 `0x7fffffeb`（入口 SP 哨兵 `0x7fffffff-20`）直接记录为 weak-copy 的目的**地址**；174/2642 是后续分析 `0x1f9a0` 才追加的上层调用点结果（旧 log 7770–7771）。这定位了首个 offset 20 分歧在“栈单元地址与其加载值”的旧启发式边界，不能把形式参数 5 强制写成 offset 20，也不能从 Golden 补造新 Source。仍需核对旧 action 的具体替换分支和实际 caller 路径，决定该旧 MAY 是否属于可解释的假阳性。

`sealed-replay-43` 试验了 P7 定义前沿对 `local_address=None` 的栈 Store 逐一解析具体地址。独立同址/异址 fixture 曾通过，真实 `0x1f9a0` 的 memory work 从 1202200 降至 605671，但 scalar steps 从 185047 升至 248526；同一 120 秒预算下，继承的 `0x2d5ac` 诊断丢失原有 174/2642 offset，而该次参数检查仅返回 Unknown。该试验已从运行代码和 fixture 撤回，留下封存回放作为失败证据。当前默认定义规则仍按原 P6/P7 selector 保留未证实的 MayAlias。

`sealed-replay-32` 的真实 `0x52db4` 函数回放中，前 5 个本地 call 查询首次各触及 taint 查询份额；第二次有 4 个完成，`0x532e8` 仍因 wall share 保留 pending。单站点 `sealed-replay-42` 在相同 CIR/预算、无参数诊断预计算时能够完成 `0x532e8`，取得 45/55/3387 的本地候选目的，其中 3387 是目标额外 MAY；旧 log 的该站点实际只列 45/55（7208–7209、9888–9890）。因此该站点的核心障碍是全函数查询调度和后续 caller Source 绑定，而非缺少旧 offset 65。完整 `sealed-cli-11` 尚在独立运行，其结果须待退出后统一比较。

`0x4e505` 的另一分歧已由 SSE 形状定位：受控回放 `sealed-replay-47` 显示真实目的实参的一支为 `0x7ffffe9f + 3*i`，其中 `i` 来自原 `LegacyDemand` 的 DDG 循环摘要。关闭 P7 跨查询缓存的 `sealed-replay-46` 仍只有 offset 352，故非缓存丢失。P7 在保留未界定循环余项的同时，只对**单一、全仿射、可证明稳定栈 Root** 的旧 DDG 摘要投影第一次转移 `i=1` 为 MAY；没有把 `i` 设为全程常数。`sealed-replay-48` 在同一真实 CIR/摘要/预算中恢复 349 与 352，pending=0，函数分析 2.265 秒；旧日志的这两个目的值见 6644–6646。新增 fixture 同时验证真实 P6 DDG 循环产生基值与首轮值、非仿射/未知基不生成具体地址。当前完整回归 374 tests 通过；全程序及 Gate A 尚未对该最新改动复验。

另一项“按第一次 work 排序失败查询重试”的受控 `sealed-replay-49` 使 `0x52db4` 的 pending 从 1 增至 9，虽 memory work 略减但保真明显退化。调度修改及其 fixture 已撤回，保留失败回放。由于 `sealed-cli-11` 的源码早于循环首轮投影且这一调度试验失败，该轮 `-t` 在 1547 份逐函数结果后主动中止；既有逐函数结果未覆盖，封存源码 hash 核对无变化，不得当作完成的整机运行。当前源码重新封存为 `sealed-cli-12`，以相同 acquisition 与固件开始独立 `-i→-t`；其结果尚待执行与差分。

`sealed-cli-12` 的 `-i` 已完成，exit 0，封存源码未变；目标 `icall-targets.json` 与完整 `sealed-cli-10` 逐字节一致。同源 `-t` 已启动，尚无完成结论。对旧完整 `comparison-10` 的 130 个额外 MAY，`extra-may-audit-01/additional-may.json` 建立了逐站点索引：111 个 copy 中 22 个在旧 log 曾有 `Add-weak-copy`，其中 16 个还进入 `check-weak-copy` 但未进入 Golden；另 89 个无旧 `Add-weak-copy`。19 个额外 command 均无旧 `check-command-injection` 报告。该索引只确定旧流水线到达的阶段、真实目标 Source IDs 与 caller 未完成标记，**不是**对 130 个额外 MAY 的逐例合理性判决；旧 system/popen 前向命中条件为 `ast.op=='BVS'`、flag `0x100` 且命令实参与 `trace_sims` 匹配，目标反向 MAY 仍需逐路径核对。

`constraint-audit-03/source-constraint-rows.json` 逐 Source 对照旧完整 `comparison-10` 的原始 `taint.log` 约束与目标候选：145 个可检查的旧 Source 行中，132 行有旧数值 bound 而目标仅明确保留 `unresolved-length-recipe`，5 行 Source 尚未到候选，8 行旧日志无数值 bound；**没有**一行可据此确认新旧数值 bound 完全保真。132 行以旧 39999 为主（125 行），本审计不把 unknown 当作已恢复约束。首次 `constraint-audit-01/02` 的分类脚本存在 PowerShell 数值类型/闭包判断瑕疵，原诊断留档，以更正的 `03` 为准。

具体依赖边界：`0x1db6c` 的 `fread` Source 输出仍带“参数 1×参数 2”可移植长度配方；`0x2d228` 的 table writer 摘要仍保留该配方。实际 iCall 图中 `0x1f9a0:0x2120c→0x2d228`，目标 `0x1f9a0` 对应 `f179a0:o10949` 的 table 查询在完整轮次反复触及 memory work/query wall 份额，未把配方在 caller 实参上完成绑定。全局 table bank 对未解配方只保留明确 unknown，不跨无调用关系的 reader 复用外函数 SSE；这是保守但不满足旧 bound 保真。下一步应先在该真实 iCall/同一预算中完成 caller table 查询并验证具体长度，再检查 bank 重分析和 150 条旧约束，而非硬编码 39999 或把 foreign recipe 直接送给 reader。

### 2026-10-30 表写入部分结果与最新封存运行

同一 `0x1f9a0` 单函数、同一 CIR/摘要和 120 秒预算的 `sealed-replay-50/51` 先红后绿验证：原表查询在 taint 全局 250001 步截断时 `summary.tables=0`；按已知 Source 与后续 global/formal 依赖分批绑定后，`summary.tables=1`，含 8 条真实 Source 备选和原长度 recipe，未把 recipe 变成数值 bound。为避免部分 Source 输出让 reader 误以为表状态完整，截断时另写入显式 unknown，全局 table bank 和 reader 保留 unknown；fixture 验证部分 Source 与 unknown 同时传播。`regression-36` 为 376 tests、15.421 秒、退出 0；`native-04` 21 tests、`solver-04` Claripy 三态、`boundary-07` 核心 native import 隔离均通过。

`sealed-cli-12` 的 `-i` 成功且与此前目标 iCall 逐字节相同；其 `-t` 源码早于表写入修正，已在第一轮 1021 份逐函数结果后主动中止，封存结果保留，不作为完整验收。最新源码捕获在 `sealed-cli-13`，独立 `-i` exit 0 且源码未变；同源 `-t` 正在执行。当前 Gate A 仍未通过，未开始 P8。

`sealed-cli-13` 的 `-t` 已在第一轮约 520 份逐函数结果后中止，因为后续真实回放定位了独立的长度与本地查询调度缺陷。`sealed-replay-52/53` 显示：只先绑定继承 sink 的 buffer 或只先绑定 length，都会在局部备选超限时丢失另一通道。修正为分别保留两通道已观察 Source 与显式 unknown 后，`sealed-replay-54` 的 `0x25bac→0x607fc` 在同一 CIR/摘要/120 秒预算下同时保留 buffer Source 和长度 Source；数值 bound 仍未恢复旧 39999。相反方向的超限有独立测试，`regression-37` 为 378 tests，OK。

`sealed-replay-55` 单独跑 `0x52db4` 的 5 个旧站点能取得各站点实参依赖；`sealed-replay-56/57` 的完整函数中，`0x532e8` 第二次尝试在标量份额截断，保留 Unknown。真实逐查询成本：单独跑该站点 `sealed-replay-60` 需 100462 scalar steps、13351 taint steps、35412 memory work 和约 79.3 秒查询时间；原函数份额不足。先在诊断包装器中仅扩大本地 sink 查询份额的 `sealed-replay-61`，再在相同全局 250000 taint/500000 scalar/2000000 memory/120 秒函数预算下改核心 `begin_query`，无包装器 `sealed-replay-62` 均使 `0x532e8` 恢复 12 条实参依赖及 7 条 Unknown，其他本地查询完成。后者 wall 112.906 秒、scalar 150687、memory work 54938；这是局部保真改善，仍非全程序 Source 证明。`regression-38` 为 379 tests、退出 0。

当前最新源码已独立封存为 `sealed-cli-14`；`-i` exit 0、源码未变，匹配的 `-t` 正在运行。该轮完成后须核对 17 个 iCall、CG、150 条 Golden 记录、额外 MAY、约束/Guard/路径、归档和保护清单。未完成前 Gate A 维持未通过。

`sealed-cli-14` 第一轮真实 `0x52db4` 结果已验证调度改善：`0x532e8` 有 12 条 argument 与 7 条 unknown，其他四个旧关注站点亦有 argument；该函数 wall 91.656 秒、memory work 54139、pending 187，尚需 caller Source 绑定。`native-05` 21 tests、`solver-05` Claripy 三态、`boundary-08` import 隔离和 `integrity-08` 旧仓库/Golden/P6/.venv 内容与 mtime 均通过。`sealed-cli-14` 仍在第一轮，不得据局部结果宣称 Gate A。

对 `0x2d5ac` 的实际 ARM 指令补证：`0x2d5a8` 为 `ldr r0, [sp, #0x7c]`，随后 `0x2d5ac` 调用目标为 `strcpy` 的 PLT；被调函数使用的是栈单元**加载值**。这与 `sealed-replay-44` 的形式参数 5 / 未决定义一致，不能从栈单元地址直接合成 offset 20。旧 `data_collector.py:305–316` 对 BVV stack 地址收集 weak，旧 log:7685 在此站点记录 `0x7fffffeb`；仍需沿实际 caller 证明该地址是否确为传入的指针值，不能仅凭本地 load 判定旧结果是假阳性。

## v8.0 P7.0：基线冻结与旧 `-t` 路径盘点（2026-10-30）

本节以本轮重读的 `AGENTS.md`、`MIGRATION_BLUEPRINT.md`、`CODE_TASK.md` v8.0 为准。P7.0 仅创建审计文件并更新本报告，没有修改 P0–P6 代码、旧仓库、Golden 或环境；没有运行新旧完整分析。此前 `sealed-cli-14` 的 `-t` 已在首轮诊断后中止，**无完整结果**，覆盖本节之前“正在运行”的历史状态。

冻结凭据位于 `.p7-work/v8-p70-20261030T081526Z/`：`baseline-manifest.json` 逐文件记录 SHA256/字节数和绝对路径，`legacy-t-path.json` 记录实际旧入口，`difference-matrix.json` 记录 9 层差异与下一项首次分歧诊断。当前 HEAD 为 `6cb026767db005e48b36b994ee8542962b6df627`，它是 `codex task v3.0`，**不是独立 P6 验收提交**。P6 的可验证冻结点是 `acceptance-20261029T071606Z-9fab46e0/validation-p6.json` 的 `quality_gate=PASS`、`phase_gate=PASS`，加该目录的 source manifest、frozen schema 和 iCall/CG 结果哈希。当前工作树有未提交成果；P6 验收源码快照中 13 个文件当前哈希已变化（名单在 manifest），不能用 HEAD 或当前源码冒称原始 P6 快照。最近 `sealed-cli-14` 的 `-i` targets/CG 文件分别与完整 `sealed-cli-10` 同类文件逐字节一致；`comparison-10` 对旧候选的 535 个 target 三元组无缺失/额外，5892 条逻辑 CG 边集合相等，17 个站点包含一个显式空 unknown 站点。

旧固件 `httpd` 的 SHA256 为 `334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787`；IDA CFG、block、iCall 元数据和当前 CIR/Memory schema 的各自哈希在 manifest。历史 `regression-37.txt` 为 **378 tests、OK**，内容已按哈希冻结；`regression-38.txt` 的 379 tests、OK 属于后续早期 P7 查询份额版本，不能代表当前源码。原 Golden `20261028T051055Z-96d1c781` 的 `taint.verified.json` 是物理副本旧 `-t` exit 0；用户批准的第二次独立副本 `p7-20261029T140752Z-d85ea47a` 旧 `-i/-t` exit 0，`legacy-differential-01.json` 验证两个 JSON 除记录时间外语义相同。因此本次旧 `taint_1` 分类为 **`legacy_taint_confirmed`**，143 buffer、7 command、796 analyzed；未将其他来源不明的 JSON 充作 Golden。

P7 当前完整诊断参考仍是 `sealed-cli-10`：`-t` exit 2、状态 `incomplete`，879 个实际分析函数、11 轮、2371 次调用，245 buffer/26 command MAY、confirmed 0、830 个函数 pending。`comparison-10` 的 150 条旧记录中，139 条只有候选存在、尚需证据复核，11 条因函数未完成；多出的 130 条 MAY 尚未判定。`sealed-replay-64` 是单函数诊断 exit 0，不能替代完整目标结果。

旧真实调用链是 `main.py -t → perform_analysis → FastSearch._analyze → _reconstruct_cfg → _analyze_binary → AccurateDataFlow/FastDataFlow 预处理 → _execute_function 的反向/前向迭代 → Procedure 与调用上下文 → Collector.collect_weaks → SecurityCheck → taint_1 JSON`。旧 `data_trace.py:569` 的 `_update_expr_from_callees` 调用**被注释**；活跃跨函数路径是 `_initialize_callsite_arguments`、`_get_argument_taint_info`、callee 重新分析、`_push_callee_exprs_to_callsite` 和全局 taint 推送。P7.4 须以这条活跃路径为基准，同时审计被注释方法的历史意图，不能把它当实际 `-t` transfer。

差异矩阵按 Source、TaintFact、函数内传播、Memory/Alias、跨函数 Summary、Guard/Length、Sink、Finding/JSON 与 Worklist/Incomplete 逐层标记 `partial_map`、`unpaired`、`candidate_first_divergence` 或当前确认失败，**没有把局部诊断误报成首差已修复**。已知优先诊断点：`0x2d5a8→0x2d5ac` 栈单元地址/加载值、`0x1f9a0:0x2120c→0x2d228` 表长度 recipe caller 绑定、以及旧数值约束 132 行在新候选仅为 `unresolved-length-recipe`。下一阶段 P7.1 只盘点并收敛旧 Source/Sink 的实际分支、参数位置与稳定规则 ID。

当前源码还有一个必须保留的失败：`$env:PYTHONPATH='tests'; .\.venv\Scripts\python.exe -B -m unittest test_p7_query_resources.QueryResourceTests.test_local_sink_call_can_use_remaining_function_budget -v`，真实 exit 1，预期剩余查询步数 ≥31250，实际 2777。它来自 `sealed-cli-14` 后恢复公平份额的工作树，属于后续 Worklist/预算差异；不删除或降低该测试，也不把历史 378 项通过记录说成当前全绿。P7.0 未运行完整回归、未重跑 P6。P7-A/B/C/D 均未通过，P7 未完成。

P7.1 静态盘点首先发现旧 `dataflow/procedures/libssl/SSL_read.py` **确有** procedure；它调用另一套 `data_process.inital_source_arguments`，只创建带 `0x100` 标志的反向缓冲区表达式，未设置普通 Source ID。当前 `emtaint/procedures/legacy.py` 把它标成 `declared_unmodeled_source`，属于已确认的静态规则映射差异。是否在本目标实际可达、应如何保持其独立语义仍待逐调用点验证；暂不把它简单改成普通 `source_buffer`。

### P7.1 Source/Sink 映射与首个 Source 事实修复（进行中）

`p71-rule-map.json` 列出 11 条 Source 和 15 条 Sink procedure 分支，逐条保存旧源码路径/分支、新规则 ID、参数/返回位置、fixture、目标 PLT 与旧日志证据。`ProcedureRule.rule_id` 为稳定的 `legacy-procedure/<exact name>`；`lookup` 使用唯一名称表精确匹配。旧 `strlcpy` 的带长度 `reg_taint_propagate` 分支已补入规则表。旧 `SSL_read` 改标为独立 `legacy_trace_source`，没有把其旧 helper 伪装成普通 Source。旧 `FCGX_GetParam`/`hdf_get_value` return Source 也已记录；两者不在默认 `custom_sources=[]` 中，是否进入本目标执行路径另查。旧 `vsnprintf` 的 `_find_taint_propagate_in_format_v4` 使用 `va_list` 内 Store 与字符串格式参数匹配，目标 PLT 中存在（`0x10a44`），新版此前完全缺项；现有规则登记实际参数位置，并将未迁移 transfer 明确写入 `pending`，不把它当安全或普通 `snprintf` 参数。

Source 首次事实分歧已定点复现：旧 `taint.log` 在 `0x7bd94` 的 `fgets(0x7be08)` 记录 `Inital taint source`；完整旧版目标对照的新版 `sealed-cli-10/function-0x7bd94.json` 的 `source_facts=[]`，因为新版只在下游 demand 引用 Source 时才建立绑定。先新增无下游 Sink 的最小测试，红灯为 Source 绑定空；随后把 Source callsite 的**初始事实登记**与后续 handle/length/use-def demand 分开，在正常 query 前登记，不改变原有按程序次序的传播 cutoff。`p71-source-01` 在封存同一 CIR/历史摘要的 `0x7bd94` 回放中得到 1 个真实 Source fact（`f73d94:o231`），exit 0、源码哈希未变、errors=[]。这仅修复一个局部首差，尚未证明旧日志全部 71 个 Source 站点与新版逐个一致；历史 `source-evidence-index` 的 51 个站点是按需证据索引，不能作为完整发现数。

本轮修改 `emtaint/procedures/legacy.py`、`emtaint/analysis/taint/demand.py`，新增 `tests/test_p7_rule_registry.py`；未触及 P6 iCall/CG。最小红灯 `test_source_call_has_initial_fact_without_a_downstream_sink` exit 1，修复后 `test_p7_rule_registry + test_p7_demand` 36 tests exit 0；受影响 Source/Sink/运行时/Guard/表/全局输出 14 个模块合计 82 tests exit 0（`p71-affected-tests-5.txt`）。已知 `test_local_sink_call_can_use_remaining_function_budget` 仍红，未删除、未降断言。完整 378 项、最终目标 `-t` 未运行；P7.1 尚需按旧 `vsnprintf` 路径完成可验证的 `va_list` Sink 参数/内存绑定，并检查余下 Source 站点，故 **P7.1/P7-A 暂不通过**。回退本轮只涉及上述两份 P7 源码和新增测试，冻结 manifest/旧 Golden/P6 接受快照不变。

追加定点统计见 `p71-source-site-diff.json`：旧 `taint.log` 有 71 个唯一初始 Source 调用点，早期完整新版的按需 `source-evidence-index` 覆盖 51 个，另外 20 个逐点列出。这两个指标语义不同，未索引不能直接判为 Source 丢失；`0x7be08` 已以同一 CIR 受控回放证明初始 fact 可恢复。`SSL_read` 的旧特殊 trace 和 `vsnprintf` 的 `va_list` transfer 现在分别产生显式 pending，避免静默当作 clean。新增 fixture 还验证 `getenv` 无 Sink 时建立返回 Source、false guard 不登记 Source、`strlcpy` 形成带长度的 copy requirement。最新最小 10 tests exit 0；受影响 14 模块 **85 tests、exit 0**（`p71-affected-tests-6.txt`）。P7.1 仍按上述未完成项保持进行中，不据此宣布 P7 通过。

按 `p71-source-site-diff.json` 列出的 20 个未索引旧 Source 站点，只对其 14 个所属函数做一次 `p71-source-batch-01` 封存回放；同一归档 CIR、旧摘要和每函数 120 秒上限，runner exit 0，errors=[]、源码未变。将新 `TaintFact.origin` 经原 CIR `origins.jsonl` 的 `instruction_rva` 和镜像基址反解为原始地址后，**20/20 个旧调用点均有同地址初始 fact**，逐点 fact ID 在 `p71-source-batch-diff.json`。这消除了 P7.1 初始 Source 登记的这组差异；没有证明这些事实都能跨函数到达 Sink，亦未验证 71 个站点的所有 length/handle/guard 细节。目标旧 `vsnprintf` 在 `0x1dc44` 的受控回放 `p71-vsnprintf-01` 于 `f15c44:o87` 留下 1 条明确 `va_list` pending，exit 0、errors=[]。下一项优先差异是该实际 `va_list` Store→格式串 `%s` 参数→目的 buffer 的首次事实转移；未实现前 P7.1 维持未通过。

P7.1 子阶段最终界定为**规则识别与顶层实参绑定已通过，完整 Source/Sink 语义未通过**：26 条旧 procedure 规则有源码路径、稳定 ID、顶层参数位置与目标出现状态；旧 Source 初始登记的 20 个原缺口已逐点恢复。`SSL_read` 的独立反向 trace 和 `vsnprintf` 的 `va_list` 内存 transfer 仍显式 pending，分别留给 P7.2/P7.3 的传播核对；旧 `taint_1.sink_info` 的 12 条中没有 `vsnprintf` 名称，这只说明旧最终 JSON 未列该名，不证明其 transfer 可忽略。P7-A/B/C/D 仍未通过。P7.2 起先检查旧/新函数内事实首差，不展开跨函数或漏洞判定。

### P7.2 函数内 transfer 首差与局部修复（进行中）

新增 `tests/test_p7_intra_transfer.py`：return Source 经 ADD、完整寄存器写读到 `system` 的传播、干净重定义 kill、ZERO_EXTEND/EXTRACT 往返、部分寄存器写读、条件覆盖与显式 clobber，共 8 个最小测试。低 16 位测试先红：`ReadRegister` 的确切 slice 在 `LegacyDemand.register` 按完整寄存器处理时成为 Unknown；首次不同事实出现在该读的值需求，而非最终 Sink JSON。随后“旧 Source 的部分写入被条件清零”也先红，表明只取最近一次写入会丢失未执行清零时的 Source。P7 专用 `ProcedureDemand.exact_slice_before` 沿唯一到达定义追踪同 slice 和不相交 slice；条件写入并合写入与原值，其他覆盖保留 Unknown。上半寄存器反例不误污染，显式 clobber 得到 Unknown 而不沿用旧 Source；未修改 P6 demand、iCall 或 CG 代码。旧 `AccurateDataFlow._update_register` 有寄存器表达式替换，但目前**没有**旧版原生部分 slice 的逐事实证据；这些是先确保新 CIR 语义一致的 fixture，不能称为目标旧新等价。

`p72-intra-affected-01.txt` 记录首次修复后的 82 tests、OK；新增条件与 clobber 后的 `p72-intra-affected-02.txt` 记录受影响 P6/P7 84 tests、OK。该 fixture 尚未对应目标中的真实半寄存器事实，也未完成条件分支、栈参数/局部变量与 guard 的旧新逐边对照。`difference-matrix.json` 更新 P7.2 首差和下一诊断；当前不能宣称 P7.2 通过，完整 378 项和目标 `-t` 未重跑。

按 v8.0 表格的 P7.1 通过条件重新界定：该子阶段要求 Source/Sink registry 和参数位置均有旧代码证据，不要求此时完成后续 transfer。`p71-rule-map.json` 的 26 条 Source/Sink 分支及稳定规则 ID、20/20 旧 Source 初始事实补齐，达到 **P7.1 识别与顶层绑定范围通过**；`SSL_read` 的特殊反向 trace 和 `vsnprintf` 的 `va_list` Store 仍明确未迁移，分别是 P7.2/P7.3 的未完成传播事项。这不表示 P7-A 整体通过。

新增直接栈本地 Store→Load 的 Source fixture，通过 MemoryQueryPort 保留 Source；加入后 `p72-intra-affected-03.txt` 为 **86 tests、OK、exit 0**。目标旧 `taint.log:6635–6646,9216–9219,9851` 的 `0x4e330→strcpy(0x4e505)` 本地目的 offset 为 349/352；封存 `sealed-replay-48/analysis/0x4e330.json` 在相同已记录 CIR 下也有 349/352。`p72-target-edge-01.json` 保存两侧位置和证据；旧约束含 39999/1024，本地新版参数依赖仅含 1024，39999 必须在后续 caller Summary/Length 阶段核对。该函数没有本地 Source fact，所以这里只标记**局部目的传播边匹配**，不声称完整 Source→Sink 或漏洞保真。

再将一条真实 CFG join 形状缩为 fixture：一个前驱写入 Source、另一前驱写入干净值；完整寄存器可保留 Source，但两个前驱都只写低 16 位时先红，首差仍在新版完整寄存器需求把部分写入一律变 Unknown。`exact_slice_before` 现逐个读取该 read 的到达定义，仅合并同 slice 的写入备选，并保留条件写的旧值；重叠但不完全一致的写入仍回到显式 Unknown。`p72-intra-affected-05.txt` 为 **87 tests、OK、exit 0**。这只是 CIR 层的最小反例和 P7 修复；真实目标尚缺旧/新 join 与栈 use/def 的逐事实 pairing，P7.2 继续未通过。

`p72-transfer-matrix.json` 为每类已测函数内 transfer 记录输入/输出、kill/gen、guard、origin、精度及未配对状态。8 个 fixture 类别与 `0x4e505` 的目标局部目的边分开陈列，避免把 fixture 通过当成旧目标逐边对照。`difference-matrix.json`、新 JSON 均通过解析；`git diff --check` 无空白错误。下一项需要在真实目标的 ValueID/ProgramPoint 上配对旧临时变量、寄存器、栈和分支边，并确认 scalar TaintFact/guard 的稳定引用；未达到前不进入 P7.3。

`p72-args-01` 是同一 `0x4e330` CIR/旧摘要/120 秒预算的新目录封存诊断，exit 0、无 query pending。真实 `strcpy(0x4e505)` 的 r0/r1 分别对应 `f46330:arg1207`/`arg1208`；r0 的常量分支是 `0x7ffffe9f`，另外仍有开放尾项，最早的未解叶来自 `f46330:o849` 的 `LoadEffect`（镜像地址 `0x4e4e0`，`f46330:v1134`），原因为 MayAlias/部分或带 guard 的到达 Store。该诊断**没有**证明旧版在 `0x4e4e0` 的值不同；旧日志仅在 `0x4e490` 和 `0x4e505` 记录 transfer。因而把内存叶列为 P7.3 的需配对候选，不以 P7.2 局部 offset 一致掩盖其未解状态。

新增只读 `scripts/p7_legacy_intra_probe.py`，在旧版原生 `.venv` 实际调用 `AccurateDataFlow._update_register_in_expr`。`p72-native-intra-03/legacy-intra-report.json` 的 3 项输入分别证明 `r4→r8`、`r4+3→r8+3` 和干净常量替换去掉旧寄存器变量，passed=true、exit 0、写入违规=[]，PLY `write_tables=false`。这为 P7.2 的寄存器/算术/kill fixture 增加旧代码执行证据，但仍是受控 TraceExpr，不等于真实目标全路径。首次尝试 `p72-native-intra-01` 使用新版解释器，因缺 `pycparser.ply` 在旧 import 前停止；`02` 已用旧解释器但缺原全局 `.loader` 初始化，在第二项前停止；失败记录保留，没有安装依赖或改旧仓库。`03` 补齐旧运行时全局初始化后通过。

同一只读探针的 `p72-native-intra-04` 再执行旧 `_find_wrtmp_def_v1`：`t4→r8` 和 `t4→0` 均有真实 CodeLocation，5/5 案例 passed、exit 0、PLY 禁写表、写入违规=[]。新增新版 `test_temporary_copy_and_constant_definition_match_old_replacement`，Source 经 COPY 保留，常量定义不污染 Sink；定向测试 exit 0。`p72-transfer-matrix.json` 已加入临时变量的 old-native/new-CIR 对照，仍未将受控例当作目标全路径证据。

### P7.2 查询预算与诊断续作

历史 `sealed-replay-64/analysis/0x1f9a0.json` 已含逐查询成本，复查发现 6,865 次执行（35 call、6,821 继承 sink、9 table），其中 206 次 incomplete，186 次因独立 taint share 耗尽；总计 226,486 taint 与 357,574 scalar steps。多数继承 sink 查询立即完成，35 个本地 call 中 24 个触及独立 share，9 个 table 全部触及份额。这个已有快照已给出新的调度诊断，不再盲目运行同一完整函数。`query_worklist` 现在为未完成和重试成功的查询记录 kind/origin、taint/scalar/memory 实耗与耗时，便于后续精确定位。

现有 `test_local_sink_call_can_use_remaining_function_budget` 原红灯为 2,777 < 31,250。只在**无继承 Sink 且本地 Sink call 数 ≤8** 时，`begin_query` 为本地 call 提供受函数剩余预算、本地 call 数及全局上限共同约束的份额；有继承池的真实 `0x1f9a0` 保持原公平份额。新增“大继承池仍保留本地份额限制”反例和查询成本断言。该红灯修复后，定向 `p72-query-affected-03.txt` 为 96 tests、OK、exit 0。没有把 206 个未完成查询判作无漏洞，也没有宣称真实目标预算问题已解。

首次当前源码全量 Python 回归 `p72-regression-01.txt` 为 **402 tests、OK、exit 0、7.150 秒**；历史 `regression-37.txt` 的 378 tests、OK 冻结文件未改。旧日志只有点阵和总数，不能由其直接逐名核对 378 个身份；当前全量结果是这一检查点的测试门，尚不足以证明目标 `-t`、P7-B/C/D 或 P7.2 语义验收。

`p72-checkpoint-01.json` 记录本检查点 P7 源码/测试 SHA 与 402 项报告哈希；P7.0 manifest 中 29 个真正冻结的 P6/Golden/输入/历史结果文件复核均匹配。首次生成时把允许演进的 `p7_rule_table` 与 `p7_demand` 也计入“protected”而得到 false，随即将两者单列为 evolving P7 并修正定义；原文件内容无变更。当前 P7.2 仍因真实目标的旧新分支/栈逐边与 `0x4e4e0` 内存叶未配对而未通过；P7-A/B/C/D 均未通过。

针对 v8.0 的稳定事实引用要求，新增私有 `ScalarTaintFact`：实际 `source_return` CallEffect 的首个结果 `ValueRef.id`、调用 `ProgramPoint`、`ContextId`、guard 的 `SymbolicExprId`、Source site 和 origin 同时保存，不复制 Claripy AST。它由实际 Source query 和下游 return Source 路径幂等登记；guard 未判定则 `uncertain=true`，guard 为 false 则不登记。P5 的内存 `TaintFact`/wire Schema 未改，原有 Source region 证据仍保留。两个最小测试覆盖无下游 Sink、未知 guard 和 false guard，定向 `p72-affected-07.txt` 为 98 tests、OK、exit 0。全量 `p72-regression-03.txt` 为 **404 tests、OK、exit 0、26.712 秒**。这只建立 scalar Source 的稳定身份，不声称已形成完整 Finding 传播链。

**P7.2 范围验收：通过。** 旧版原生寄存器/算术/临时变量/常量替换 5/5，CIR 的 clobber、部分寄存器、条件写、CFG join、直接栈本地写后读与 kill 有最小测试，真实 `0x4e505` 局部目的边 349/352 与旧日志一致。`ScalarTaintFact` 和既有 region `TaintFact` 使用稳定 ID/ProgramPoint/Context/Guard 及 SSE/APG/MemoryVersion 引用，没有复制 AST 或改 wire Schema。范围外的 `0x4e4e0` Load/Store 到达定义与 Alias 候选归 P7.3；caller Source/39999 约束归 P7.4/P7.5；真实分支 guard 可行性归 P7.5。上述未解项继续明确为 Unknown/MAY，不因本子阶段通过而视为 P7-B 或漏洞验收。下一步按顺序进入 P7.3，只处理首个内存事实分歧。

`p72-checkpoint-03.json` 冻结该范围的源码/专项与 404 项回归哈希；P7.0 所列 29 个真正冻结文件再次全部匹配。`p72-checkpoint-01/02` 是本阶段较早检查点，不覆盖此结果。

## v8.0 P7.3：Memory/Alias 首个定义差异（进行中）

本阶段先沿封存 CIR 的真实 `0x4e330→strcpy(0x4e505)` 局部路径追踪 `f46330:o849` 的 32 位栈 Load。`p73-memory-01/02` 的定义前沿有 10 个候选 Store：一个同 Root、同 offset 的 MustAlias，另外 9 个因地址未判定成为 MayAlias。对候选 Store 的值表达式逐个检查，7 个可以化简为互异的单一栈地址，2 个仍有未解备选。第一次可定位的新版分析事实差异是 `LegacyDemand.local_address` 对“SP 减去经 COPY 的常数”返回未知 offset，未能在 Alias 前排除这 7 个假 MayAlias；旧版对应 SimAction/Store 定义仍待原生动作逐项配对，故暂不声称旧版完全等价。

首版 P7 局部精化使同一查询的候选 Store 从 10 降到 3，局部目的 offset 349/352 与旧日志一致；但将精化放在通用 `local_address` 导致 `0x1f9a0` 的受控回放严重退化：首个 call 查询约 63 秒、86,708 memory work，整函数 153.75 秒仅处理 18 个查询/18 个 sink。历史 `sealed-replay-64` 在同一目标函数的 120 秒配置下处理 6,865 个查询/1,678 个 sink，跨版本差异尚不能全归因于本修复。精化收窄到精确栈 Load 的 Store 选择后，`p73-memory-risk-02` 同 CIR/摘要/120 秒配置恢复 7,383 个查询、1,700 个 sink，首个查询约 1.7 秒；未知对象预扫描继续用旧地址规则。

后续 `p73-memory-04/07` 的目标反证表明真实地址链不是仅 `SP±COPY(常数)`，而是 `ADD(0, COPY(ADD(COPY(ReadRegister(r3)), 常数)))`；`r3` 的唯一到达定义再追到 SP。按真实链补入“仅有一个无条件、完整寄存器定义”的投影后，`p73-memory-08/09` 同 CIR/摘要/预算恢复 3 个 Store（`o750/o826` 仍为 MayAlias，`o294` 为 MustAlias）、offset 349/352，且 `p73-memory-09` 分析用时 1.735 秒。对应最小回归包含复制 SP、复制偏移、零地址包装和 guarded `r3` 不精化。

`p73-memory-risk-03` 同 35,822 个 CIR effect 的大函数虽处理 7,386 个查询、1,702 个 sink，但首个查询因新精确 MustAlias 的存储值展开增长到 155,806 memory work / 22.56 秒，pending 从 `risk-02` 的 294 增至 374。最终实现仅在 8,192 个 effect 以下提升这种新发现的 MustAlias；大函数仍可通过 MemoryQueryPort 排除已证实的 NoAlias，否则保持原 MayAlias。资源限制有独立测试，未把 Unknown 视为 NoAlias。最终源码 `p73-memory-risk-04` 在相同封存输入上处理 7,385 个查询、1,701 个 sink，首个查询 1.734 秒/20,079 memory work，pending=295，表摘要=1，封存源码未变且无写入违规；与 `risk-02` 相比未再出现早期耗尽。

另新增只读 `scripts/p7_legacy_memory_probe.py`。初次以新版解释器运行因缺 `pycparser.ply` 在旧 import 前失败，留在 `p73-legacy-memory-01`；改用原生旧 `.venv` 的 `p73-legacy-memory-02`，PLY `write_tables=false` 且写入违规=[]，实际调用旧 `AccurateDataFlow._find_concrete_addr_store_def_v1`：同一 `0x7fffac77` 栈单元的 Store 将 Load 替换成常数 77，不同 `+4` 地址不替换，2/2 通过。这是旧版基础 SimAction 行为的受控证据，尚不是 `0x4e4e0` 目标动作配对。受影响完整回归 `p73-regression-01.txt` 为 **407 tests、OK、exit 0**，保留原 378 项及失败历史。差异矩阵 `P70-MEM` 已更新。P7.3 尚未通过：真实旧目标的 Source location、Load/Store Action、Alias、MemoryVersion 与 TaintFact 仍须逐例配对，`0x2d5a8` 旧栈地址与新加载值分歧也未解。没有修改旧仓库、Golden、P6 iCall/CG 或 wire Schema。

为取得真实旧目标动作而准备的 `p73-old-action-plan-01.json` 仅盘点已获批历史物理副本的 417 个文件和哈希，并拟在当前 `BinaryAnalysis/.p7-work` 内新建独立副本，运行一次只记录 `0x4e330` 邻域 Action/SimAction 的旧 `-t`。按 `AGENTS.md` 第 2 节，新副本执行须单独获批；目前只准备计划与观察器，**尚未复制或运行**。未获批前继续只读/目标侧 P7.3 诊断。

`p73-memory-10` 以相同目标 CIR/摘要/预算但新增只读 arena 快照确认：`f46330:o849` 有一个 APG 路径，段为 `Offset(4294945912)` 加 32 位小端 `Deref`，图 ID 为 `apg-0`；该 Load 的两次实际 ReadMemory 分别引用 `mem-0` 与 `mem-1`，位置 Root 与 offset 相同。候选 Store 仍为 3。该函数本地 `source_facts=0`，不能凭这项局部内存证据宣称已追到旧 `0x1dbb4` Source；跨函数 TaintFact 配对归后续真实调用链。另一个 `0x2d5a8→0x2d5ac` 分歧已有目标侧证据：实际指令把栈单元内容装入 `r0`，目标局部摘要给出形式参数 5 加 unknown；旧日志的 3 个栈地址更可能是 caller 传入的**值**而非被读栈单元的地址，需在 P7.4 追 caller 后判断，现未作修复或结论。

旧版原生受控探针增补 `p73-legacy-memory-03`：同地址 32 位 Store 替换 Load、相隔 4 字节的 Store 不替换、只部分重叠的 8 位 Store 在该旧函数中也不替换，3/3、PLY 不写表、写入违规=[]。这只刻画 `_find_concrete_addr_store_def_v1` 的精确替换分支，不能代表旧版其他部分覆盖路径；目标的 `RegionTaintTracker` 对部分覆盖继续保留未覆盖字节及 MAY，不能凭旧函数这一个分支把部分重叠认定为干净。

新增 CFG join 最小测试：`r3` 从两个不同前驱到达时，精确栈投影必须返回未知；带条件写测试同样禁止错误 MustAlias。`p73-regression-02.txt` 为 **408 tests、OK、exit 0**。旧版真实动作回放的独立副本仍待授权，P7.3 保持未通过。

剩余两个 MayAlias 已按地址备选拆开：`o750` 有具体 `0x7ffffe9e` 与一个开放尾，`o826` 有具体 `0x7ffffa9f` 与一个开放尾；两者的具体分支与 Load `0x7fffac77` 不同，但开放尾仍可别名，所以继续保留 MayAlias/Unknown，没有把它们计为已排除的 Store。

### P7.3 真实旧动作配对与范围验收

获批计划 `p73-old-action-plan-01.json` 已执行一次，且仅在 `BinaryAnalysis/.p7-work/v8-p70-20261030T081526Z/p73-old-action-01` 创建新物理副本和输出。旧 `.venv`、原仓库、先前获批副本、Golden 均保持只读。`execution.json` 记录 old `-t` exit 0、417 个源文件内容未变；观察器 `old-action-report.json` 记录 PLY `write_tables=false`、写入违规=[]、真实 38 条邻域 Action，未截断。旧统计为 143 weak copy、7 command，与既有成功基线一致；该回放只是动作观察，不替代 Golden。

真实旧 `0x4e4e0` 的 `wl` 位于 block `0x4e4d8`、statement 10，32 位 `addr_value=0x7fffac77`，读得 `0x7ffffe9f`，下一动作将其写入 `r0`。新版封存 `p73-memory-11` 在同一 Load `f46330:o849` 的稳定栈 Root/offset `4294945912`（绝对地址 `0x7fffac77`）上产生已知值 `0x7ffffe9f` 和显式 unknown；`p73-memory-10` 的 APG `apg-0` 为 Offset/Deref，ReadMemory 使用 `mem-0/mem-1`。`p73-memory-pair-01.json` 对地址、旧值保留、`o294` MustAlias 与 `o750/o826` MayAlias、版本和 APG 共 5 项逐项断言，全部通过。第一次新版分歧确认为 r3→SP 地址链未化简导致 7 个假 MayAlias；修复后候选从 10 降到 3，真实旧值与局部目的 349/352 保留。

新增 P7 region 回归覆盖全局与堆 Source 的不同 Root、APG、MemoryVersion、显式 disjoint 证据及独立 clean overwrite；栈、部分覆盖、条件写、Join、Havoc、unknown 的既有测试继续通过。`p73-regression-03.txt` 为 **409 tests、OK、exit 0**。`p73-integrity-01.json` 首轮机械比对把两份按 P7 策略允许演进的源码也计入冻结项而报告 31 中 2 项变化；修正口径的 `p73-integrity-02.json` 核对 **29 个真正受保护文件全部匹配**，保留首轮诊断。

**P7.3 函数内 Memory/Alias 范围验收通过**：真实旧 Load 地址和值、目标 APG/MemoryVersion/Alias 及新旧受控 Store 规则有可重复证据。剩余两个开放尾仍为 MayAlias；本地 `source_facts=0`，调用者 Source/TaintFact 与旧 39999 约束属于 P7.4/P7.5，`0x2d5a8` 的栈单元内容也须由调用者绑定。此结论不等于 P7-A/B/C/D 通过，不声称漏洞检测完成。下一步按规划进入 P7.4。

## v8.0 P7.4：跨函数传播与 ProcedureSummary（进行中）

先选择 `P70-INTER` 的首个已知差异：`0x1f9a0:0x2120c→0x2d228` 的 table writer Source/长度配方在 caller 绑定时丢失数值约束。旧版 `-t` 活跃路径是 callsite 参数初始化、callee 分析及返回/内存状态向 caller 推送；旧 `_update_expr_from_callees` 的唯一调用被注释，不能当成实际运行转移来复刻。目标 `TaintProcedureSummary`、`bind_dependencies`、table 输出与 `taint_program` 的版本化失效将按这一真实调用边逐层核对。先用同一封存 CIR、summary 和预算限定该 callsite 的诊断回放，记录第一次 Source/recipe/argument/table 事实差异；未取得新诊断前不重复完整 `-t`。

`p74-table-01` 用封存 CIR/summary、120 秒预算只查 `0x2120c`，退出 0，Source 文件未改。callee `0x2d228` 的 table Source 摘要保留了参数 2 的 36/39 节点长度 recipe；caller 的 table 摘要也保留 Source，但其 recipe 含 `f179a0:o10909` 等 `MayAlias/partial/guarded reaching store` 叶，未得 39999。table 查询自身耗尽独立 scalar 份额（76157 步），并保留显式 unknown；这不是无漏洞结论。`p74-arguments-01` 在同一预算检查 r2，得到未知、0、过程返回值、未解内存读四类候选，均不能证明这次 iCall 的 r2 是 39999。

短预算 `p74-load-01` 因诊断前置开销超时，未产生有效快照。为避免重复无信息回放，`scripts/p7_function_replay.py` 新增 `--inspect-only`，只检查所选实参与内存定义，不运行 taint 查询。`p74-inspect-01` 退出 0，原始 Source 未改；`p74-first-fact-01.json` 汇总四种实参候选、`f179a0:o10909` 的精确 stack offset `4294933044`、两个同 offset MustAlias Store，以及九个 MayAlias/open-tail Store。P7 的 `DefinitionFrontier` 能观察精确 SP Store；有 callee 摘要时 `ProcedureDemand.memory_definitions` 仍走原通用 worklist，存在需要逐例验证的精度边界。不能仅凭此快照删除 MayAlias 或将旧 39999 绑定到该 iCall。旧日志在 `0x1db6c` 首见 Source 长度 `r12*r16`，在 `0x3e424` 首见 39999 弱拷贝；旧调用点 Action 尚未配对。下一步沿 `0x1db6c→0x2d228→0x1cfb4→0x1cf1c→0x1f9a0` 的 Source、table 与函数上下文逐边比较，再做根因修复和受影响回归。P7.4、P7-A/B/C/D 均未通过。

更早的 `hsearch_r FIND` 传递差异已用只读旧日志和定点新版回放定位。旧 `dataflow/procedures/libc/hsearch_r.py:find_data` 在 `0x1cf60` 找到 htab forward taint，实际创建 `Store(Store(retptr)+4)` 的 backward 表达式（旧 `taint.log:4634–4646`）。新版相同 CIR 的 action=0、retptr=`0x7fffffe3`、table Root=`690616`，且 table bank 有 `0x2d228` 的 Source；`p74-reader-02/03/04` 完整单函数回放均退出 0、Source 未改、写入违规为零。`p74-reader-03` 的 table trace 显示 10 次 `data_field_query` 全为 false、0 次 bank `read`；`p74-reader-04` 进一步确认被检查的是 return/formal/global output 的抽象 reference，而非旧 `Store(Store(retptr)+4)` 需求。结果的 `0x1cf1c` return 为 argument/unknown，table 输出为 argument/unknown，`0x1dbb4` Source 没有进入该函数摘要。**首个已配对的局部转移差异是 FIND 的 retptr 双重解引用需求未进入目标跨函数摘要**；它比 `0x2120c` 数值长度绑定更早。下一项修复须按旧 `find_data` 的实际表达式建模 retptr→ENTRY.data 的 pointed-memory effect，再让调用者绑定它，不能把 retptr 指针本身直接标 Source，也不能只改最终 JSON。现有 `tests/test_p7_tables.py` 只覆盖有本地 sink 的 data-field 读，应补无本地 sink 的 summary/调用者测试后实现。

`p74-downstream-01` 对下游 `0x1cfb4` 用同一封存摘要/table bank 做完整单函数回放，退出 0。`0x1d118`、`0x1d13c` 两个实际 sink 的 Source 数都为 0，table trace 也为 0；旧日志 `4359–4367` 在该函数有返回传播与 `strncpy` 长度污点。故目前没有观察到需求式分析在该下游提供等价的 Source 路径。仍需旧 FIND 的具体 forward/backward Action 与目标 pointed-memory 对应后，才可决定摘要 effect 的最小接口；不得仅凭这里的空 Source 把 Unknown 判为清洁。

获批的 `p74-old-hsearch-plan-01.json` 已在全新物理副本 `p74-old-hsearch-01` 执行。417 个源文件复制哈希匹配，原获批副本重验未变，旧 `-t` exit 0、PLY `write_tables=false`、写入违规=[]，未碰原旧仓库/Golden/历史结果。观察到 `0x1cf60` 的 9 次 FIND 中一次有来自 `0x2120c` 的 htab forward fact，旧版实际在前驱 `0x1cf44` 注入 `Store(Store(r20)+4)` backward fact，base `r20`、flag 0；其余 FIND 不产生该 fact，不能把所有查找硬标为 tainted。

按此事实，P7 `LegacyHashTables.find` 在 FIND 且 bank 有 Source 时，通过原 `MemoryQueryPort` 解析 retptr Root，登记 `Offset(retptr), Deref(pointer), Offset(4), Deref(pointer)` 的 APG may-fact；空 bank、未知 retptr 不形成确定 Source，也不污染 retptr 指针值。`local_call_query` 只对 FIND/未知 action 调用，INSERT 不走此分支。新增 `tests/test_p7_tables.py` 的无本地 sink 检查；修复 `RegionTaintTracker.bind` 的事实 ID，使同一 Source/MemoryVersion 但不同 APG 路径有不同 ID，否则首次专项测试报 `Conflicting fact ID`。`p74-hsearch-pair-01.json` 10/10 旧新局部事实与隔离检查通过：目标 `0x1cf1c` 有 1 次 bank read、6 条 FIND retptr may-facts，`apg-4` 精确包含 `Offset(-28), Deref, Offset(4), Deref`；旧有 1 条对应 backward fact。P7 受影响测试 **179 tests OK**，完整回归 `p74-regression-01.txt` **410 tests OK，exit 0**；P6/Golden/输入等 29 个受保护哈希在 `p74-integrity-01.json` 全匹配。

这只是 **P7.4 的局部 fact 修复**。新 `0x1cf1c` 的 return/table 摘要仍无 Source，`0x1cfb4` 两个 sink 仍无 Source；APG may-fact 不等于跨函数传播或漏洞确认。下一步需把旧 `retptr→ENTRY.data` 需求通过 MemoryVersion/pointed-memory summary 传到 caller，核对 `0x1cf1c→0x1cfb4` 的第一次 use/def，再重新比较 39999、实际 reanalysis/invalidation。P7.4 和 P7-A/B/C/D 仍未通过，不推进 P7.5。

随后修复 P7 编排的 table 反向依赖：原 `taint_program.py` 在任意 table Root 更新时失效所有 table 读者。新增 `TableReadIndex`，每次函数重分析替换其读 Root；精确命中的读者只随同 Root 更新，缺失/未知 Root 的读者仍按旧 key-insensitive fallback 对全部更新保持依赖，CG reverse callers 继续由 `AnalysisRuntime.invalidate_dependencies` 传播。新最小测试覆盖精确/保守读者以及替换旧依赖，**2/2 OK**。`p74-invalidation-01` 用三个函数的真实编排验证 reader 重分析，但因诊断子集缺 `0x1db6c`，没有 Source；明确留档，不作成功证据。补上真实上游后的新目录 `p74-invalidation-02` 使用复制且哈希匹配的冻结 iCall 输入，4 个函数、3 轮、10 次调用；`0x2d228` bank 更新带 Source `0x1dbb4/0x1dbc8`，实际 invalidation 包含 `0x1cf1c`，该 reader 的 FIND facts 从第 1 轮 **0** 增至第 2 轮 **4**。`p74-invalidation-pair-01.json` **8/8** 检查通过，Source 未变、写入违规=[]。诊断子集的 manifest 仍是 `incomplete`，不能当全程序验收。相关 P7 测试 **181 tests OK**，完整回归 `p74-regression-02.txt` **412 tests OK，exit 0**。P7.4 仍未通过：尚缺该 pointed-memory fact 到 caller 的可移植摘要、真实 sink/长度配对及多上下文缓存证据。

后续 `p74-old-context-01` 在另一个获批的独立物理副本运行旧 `-t`：417 文件、exit 0、源未变、PLY 禁止写表、写入违规=[]。旧 `0x2120c→0x2d228` 前驱 r8（ARM r0，即参数 0）为五个指针候选 `[528900, 528332, 2147481005, 528720, 2147483473]`，`concret_contexts={}`；该处**没有**观察到数值 39999。旧 `_initialize_callsite_arguments` 在捕获范围内未对这条边产生记录。目标 `p74-predecessors-01` 同址 r2（参数 2）是开放 Unknown，不能与旧 r8 直接比较；`p74-store-values-01` 的参数 2 栈 Load `f179a0:o10909` 有两条 MustAlias Store：`o1161` 写 0，`o1877` 写开放 Copy，另有九条 MayAlias/open-tail Store。旧参数 0 的五指针候选尚未与目标参数 0 配对，参数 2 的栈 Load 与旧 r16 的符号值也未构成已证实分歧；不得把任何一项当作 39999 的已证实来源。目标 `p74-sourceargs-01` 在 `0x2d27c` 的参数 1 是未解内存读、参数 2 是形式参数并保留开放尾。另一次独立旧 `-t` 回放 `p74-old-source-context-01` 同样 417 文件、exit 0、源未变、PLY 禁止写表、写入违规=[]，但 `set_concret_contexts` 未在 `0x2d27c` 被调用；旧日志只确认 `0x1dbb4` 源长度初始为 `r12*r16`。因此不能把该空调用记录解释成旧实参为零。下一诊断须直接捕获旧 `0x2d228` 到 `0x1db6c` 的活跃 Source/参数 transfer 与目标同点，分别追踪指针候选和长度约束的首次差异。P7.4、P7-A/B/C/D 仍未通过。

针对该活跃路径的首个隔离诊断 `p74-old-transfer-01` 因观测脚本误从 `VarExpr` 读取 `constraints` 而 exit 1；源仍未变，失败结果留存。修正为从 `TraceExpr` 读取后，`p74-old-transfer-02` exit 0，发现 `0x2d27c` 有三个来自 `0x1dbb4` 的 forward Tdata、参数筛选为零，说明此时没有触发参数上下文重分析。定点缩小观测的第三个全新物理副本 `p74-old-transfer-03` exit 0、417 文件、源未变、PLY 禁止写表、写入违规=[]：`_make_def_copy_to_callsite` 在 `0x2d27c` 接收一条 `r8` Tdata Source 和相连的 `r12*r16` Cons 表达式；`_process_callsite_callee_taint_in_forward` 此处输入空，但调用点已经保留该 Source 的具体全局地址 `0xa8bd4` 和 `r28` 转发。旧日志在同一调用点记录 `collector-cons` 常量 `0x9c3f=39999`。由此确认旧 Source/长度先经 callee 定义与约束推送，再在调用点解析；先前依赖 `set_concret_contexts` 的假设已撤回。目标 `0x1db6c` 摘要仍保留形式长度配方，下一步须对旧 `r12/r16` 到 `0x9c3f` 的约束求值与目标 `0x2d27c` 的实参 SSE/MemoryVersion 做首差配对，再修复根因；当前不能宣称 39999 或下游 Finding 已恢复。

`p74-old-transfer-04` 以新物理副本再捕获 `0x2d27c` 前驱（旧 `0x2d268`）：`r8=0xa8bd4`、`r12=1`、`r16` 仍为参数符号；反向队列保存 `r12*r16` Cons 与 `r8` Tdata。新版 `p74-source-slot1-01` 的相应 fread slot 1 值为 0，来自 `f25228:o76` 对全局对象的初始 MemoryVersion 读取、没有同函数 Store；slot 2 仍开放。`p74-source-sse-01` 确认 slot 1 是连续 Copy 包裹该 Load，未在 SSE 中加入 1。反汇编又给出决定性的路径条件：`0x2d248: ldr r5,[r1]`，`0x2d24c: cmp r5,#1`，`0x2d250: beq 0x2d25c`；不满足时 `0x2d254/258` 直接返回，只有满足 `r5=1` 的路径会到达 `0x2d27c`。因此**已定位的首个局部长度实参分歧**是旧到达路径值 1 对目标未受路径 Guard 限定的初始内存值 0；还不能断言仅由 caller 内存上下文缺失导致。目标 `p74-caller-arg1-01` 的 `0x2120c` caller arg1 仍是开放内存读，未证实具体 pointee；旧 39999 在 `collector-cons` 中出现，但 `r16` 在该调用点仍是符号，具体化发生位置尚待逐层配对。Guard 求解属于 P7.5，P7.4 的摘要测试应显式保留该条件依赖，不能用固定 1 或固定 39999 代替。

`p74-old-transfer-05/06` 均在新物理副本 exit 0、源未变、写入违规=[]。传递前后对照表明旧 `0x2120c` 第二次 callee 处理前已有 9 条带 39999 的 Source forward 表达式，该次调用没有新增它们；`_make_def_copy_to_callsite` 在此处还推送了 `0x1*r16` 的符号约束，具体数值已在此前反向处理形成，仍需取首次附加点。**寄存器映射更正：旧 VEX `r8/r12/r16` 对应 ARM `r0/r1/r2`。**此前将 `r8` 五个指针候选写为 ARM r2、与目标参数 2 的 `f179a0:o10909` 比较是错槽；已更正上述叙述。五候选属于参数 0，目标参数 0 尚未配对；`r16`（参数 2）在旧快照未具体化，不能据此声称目标参数 2 首差。数值 39999 是 Source 约束通道的事实，不是该调用点参数寄存器的已知常量。

随后 `p74-caller-arg0-01` 按正确槽位复查目标 `0x2120c`：24 条参数 0 备选中，具体候选包含旧版五个值 `528332/528720/528900/2147481005/2147483473`，另有 `4294886668`；15 条保留开放尾。故旧版五候选在目标**并未丢失**，差异是额外 may/unknown 与候选精度，不能把它称为 Source 缺失根因。`p74-old-transfer-06` 还显示 `0x2120c` 的定义推送接收两条来自 `0x1dbb4` 的 Tdata，并关联 `0x1*r16` Cons；在最后一次推送前，前驱反向队列已有带 39999 的事实。尚未捕获数值首次附加的动作，不据此修改求解逻辑或 Golden。

`p74-old-transfer-07` 新隔离副本 exit 0、417 文件、源未变、PLY 禁止写表、违规=[]，直接观测旧 `_check_expr_cons_ids`：在 `_execute_function→_push_callee_exprs_to_callsite→_push_callee_arg_exprs_to_callsite→_make_def_copy_to_callsite` 栈上，同一约束 ID `7666950021981258662` 两次从 `collector.constraints` 读出 **39999** 并附给调用点定义。旧 `data_trace.py:5636–5641` 只在反向 `Cons` 表达式化为 BVV 后把它收入 collector；这里是数值**附到 Source 的确切旧步骤**，但更早将 `0x1*r16` 化为 BVV39999 的反向 Store/寄存器替换步骤仍未配对。目标当前只保留未解 recipe，尚无与该 collector 数值对应的有界结果；下一次只应定位反向具体化并与目标同一 slot2/Guard 比较，不能在 caller 直接补常量。

已完成上述更早事实定位：`p74-old-transfer-08` 的独立旧 `-t` exit 0、417 文件、源未变、PLY 禁止写表、违规=[]。`collector.constraints[7666950021981258662]` 从空到 `<BV32 0x9c3f>` 的唯一被捕获转移发生在函数 `0x2d228` 的块 `0x2d25c`，同一反向队列仍有 `<BV32 0x1*r16>`。实际机器指令是 `0x2d25c: ldr r3,[pc,#0xb8]`、`0x2d260: cmp r2,r3`、`0x2d264: bhi 0x2d2d4`；字面量池 `0x2d31c` 为小端 `3f9c0000`，即 39999。故旧 39999 是到达 `0x2d27c` 的 **r2 上界/路径约束**，不是 caller r2 的具体值；先前“在 caller 将长度参数求成 39999”的假设撤回。目标 `fread` 的形式长度 recipe 与这条上界是两个事实通道，P7.4 不应硬绑 39999；Guard/Length 的首次数值差异属于 P7.5。P7.4 仍需完成 Source/pointed-memory/return Summary 的真实 caller 配对与多上下文失效，再进入后续阶段。

另纠正跨函数 Sink 判断：`p74-downstream-01` 独立 `0x1cfb4` 摘要的 `0x1d118 sscanf` 与 `0x1d13c strncpy` 均有参数 0 依赖，虽无本地 Source；它不能证明 caller 绑定失败。实际四函数 `p74-invalidation-02` 的 `function-0x2d228.json` 中，两处继承 Sink **各有 4 条 Source 依赖**，并分别保留 4/2 条 Unknown。故 `0x1dbb4→0x2d228→0x1cfb4` 的 Source 到 Sink 传播至少在该真实诊断子图中成立，先前“这两个 Sink 没有 Source”的说法仅适用于上下文无关单函数回放。`0x1cf1c` FIND 的 retptr APG may-fact 是否需要成为可移植 pointed-memory summary effect，尚须按旧 `0x1cfb4:0x1d0f0→0x1cf1c` 的实际 use/def 配对；不能从独立摘要无 Source 推断它必然丢失。子图仍是 incomplete，未达 P7-A/B/C/D。

`p74-old-transfer-09` 新独立旧 `-t` exit 0、417 文件、源未变、PLY 禁止写表、违规=[]，在旧 `0x1cfb4→0x1cf1c` 的实际调用块 `0x1d0f1`（旧执行块地址与 IDA 指令 `0x1d0f0` 差 1）捕获 15 次 callee transfer。首次输入一条 Source `121780`，AST 为 `Store(Load(0xa89b8)+o)`、来源 `0x1cf90` INSERT；调用点进入前已有 10 条同源 forward fact，传递后仍有 10 条。故此处不应把 FIND 的 retptr may-fact 直接改写为新 Source；旧版关键 Source 已通过 table INSERT 与 caller forward 路径到达。目标 `0x1cf1c` table summary 是参数 1 加 Unknown，`0x2d228` 实际继承 Sink 已有 Source；剩余差异必须继续按具体 callsite 的 output/alias 与路径约束配对，不能仅凭局部 fact 无 Source 判定摘要失效。

P7.4 剩余实质缺口：`taint_program.py` 仍为每个函数统一 `ContextId()`，`summaries` 按地址存单一摘要；`SummaryAccumulator.entries` 也仅按函数地址索引，`update(identity, summary)` 的实际 identity 为 CIR/PLT/binary/budget，未包含调用上下文、MemoryVersion、CG revision 或 callee summary revision。`AnalysisRuntime` 虽提供按 `(FunctionID, Context)` 的缓存/epoch 与受影响 caller 失效，P7 摘要编排尚未完整采用。现有四函数重分析证明 table Root 改动会触发真实 reader 更新，但**不能**证明多上下文与递归摘要隔离。下一修复应先增加两个 caller 以不同输入内存/参数调用同一 callee 的最小回归，以及递归 SCC/revision 回归，再按实际差异把摘要身份和失效接入 `AnalysisRuntime`；禁止用全程序清缓存掩盖。此次仅改诊断脚本与报告，未改 P7 核心；`py_compile` 通过，新增核心测试未执行，完整 412 项结果仍引用此前 `p74-regression-02.txt`，不冒充本轮重测。

针对该缓存边界做了**局部修复**：`SummaryAccumulator` 现在按 `(function, ContextId)` 分桶，同一桶仅在输入 identity 相同才向上合并；`taint_program.py` 传入 Context，并把 CG 版本、该函数的 `AnalysisRuntime` epoch、初始 MemoryVersion key 与直接 callee 摘要 fingerprint 加入 identity。新增两上下文与 callee revision 变化的最小回归，首次使用整数模拟 call string 被类型校验拒绝，改用两个合法 `ContextId` 后专项 **7 tests OK**；完整回归 **413 tests OK，exit 0**。同一冻结 iCall 输入经哈希复制到新 `p74-summary-cache-01` 后实际重跑四函数 `-t`：2 轮、8 次调用，两个继承 Sink 仍分别保留 4 条 Source，Unknown 分别 4/2；原诊断为 3 轮、10 次调用，Unknown summary dependency 均为 59。新诊断仍是 `incomplete`，CLI exit 1 来自子集与未解事实，不能当 Gate A 通过。此修复只隔离缓存合并，**没有**让 `taint_program.py` 为真实两个 caller 建立不同 Context，也未完成递归 SCC/pointed-memory 多上下文验收；P7.4 继续进行中。

本轮验证命令与退出码：`.venv/Scripts/python.exe -m unittest tests.test_p7_summary_join tests.test_p7_table_dependencies -v` 为 0（7/7）；`.venv/Scripts/python.exe -m unittest discover -s tests -p 'test_*.py' -q` 为 0（413/413）；新目录四函数 `python -B -m emtaint ... -t --taint-functions 0x1db6c 0x1cf1c 0x1cfb4 0x2d228 --taint-rounds 4 --function-seconds 30` 为 1，manifest `incomplete`，源哈希未变、写入违规=[]。P6 冻结文件、旧仓库与 Golden 未改；旧 `-t` 每次使用不同的 417 文件物理副本和独立输出。当前结论只限 P7.4 局部缓存与上述真实子图，不代表全程序固定点或 Finding 验收。

P7.4 后续增加两个最小回归：不同 caller 输入绑定同一 callee 形参时，只有 Source caller 的继承 Sink 得到 Source；递归双节点 SCC 的摘要失效会传到另一节点，但无关函数缓存保留。专项 36 项通过；完整回归现为 **415 tests OK，exit 0**，未删用例、未降断言。它们只证明绑定和 `AnalysisRuntime` 失效边界，尚未证明真实多上下文编排。

真实双调用点诊断校正了先前六函数子集的结论。`p74-two-caller-cli-03`、`04`、`05` 都在全新输出目录使用同一冻结 iCall、六函数、每函数 30 秒，均为 `diagnostic-subset/incomplete`、CLI exit 1。`04` 尝试调用点轮转和按待处理数缩小首轮时间份额，`05` 尝试按继承 Sink 数排序；这两次调度尝试未恢复旧下游 Source，均已撤回，不进入最终代码。关键输入差异是子集 `0x18590` 摘要只有 **2** 条 Sink；完整封存摘要有 **79** 条，包含 `0x18ebc snprintf`、`0x18ef8 system`。因此子集 Source=0 不能归因于 `0x1f9a0` 传递语义或调度，不能作 P7.4 失败/通过的独立证据。

同一完整封存摘要下的 `p74-icall-18590-01` 聚焦真实 iCall `0x21404→0x18590`，其 `0x18ebc/0x18ef8` 各有 **212** 条 Source 依赖，Source 路径含 `136196`；4 个未完成查询保留显式 Unknown。`p74-two-sites-sealed-01` 同时聚焦 `0x212d8` 与 `0x21404`、仍用每函数 30 秒，同一两个 Sink 也各有 **212** 条 Source，但全部路径含较早 callsite `135896`，不含 `136196`；6 个未完成查询都属于较早调用点。分别聚焦时两处各能传播，合并查询时后者因预算/顺序未覆盖。这是 P7.4 当前最早的真实覆盖分歧：按函数重启的单上下文需求队列没有为两个实际调用点保留独立进度。它保持 `Incomplete`，并非无漏洞结论。下一修复须让调用点上下文/摘要进度分离，依赖 CIR、MemoryVersion、CG 和 callee revision 做选择性失效，然后同输入重验两条路径；不能靠调高预算或补 JSON。

两处的实参并非同一上下文：同一 `p74-two-sites-sealed-01` 快照中，slot 0 的具体候选在 `0x212d8` 为 6 个、`0x21404` 为 8 个；slot 2 分别出现 `738272` 与 `676572`，两处均保留开放尾。冻结 iCall 对这两处都给出 `0x18590` may-target；这证明需分开保存两条 caller 投影，不证明旧版实际执行两条 Source 路径。

旧版 `p74-old-transfer-09/stdout.log` 的 `0x18ebc/0x18ef8` 实际 Sink 位于函数 **`0x18d44`**；旧日志给出的路径经 `0x1f9a0→0x18590→0x18d44`，并在 `0x18d44` 见到 39999 约束。`0x18590` 的 79 条封存 Sink 是继承摘要，不能误称这些 Sink 在 `0x18590` 本地。六函数子集缺 `0x18d44` 等下游摘要，这是它只有 2 条 Sink 的直接原因；后续真实配对须保留完整依赖图。39999 的 Guard/Length 语义仍留 P7.5。

截至该次缓存修复，未修改 P6、旧仓库、Golden、既有结果，也未执行新的旧版 `-t`。P7.4、P7-A/B/C/D 均**未通过**；P7.5 尚未开始。

针对已量化的调用点饥饿，新增 `query_worklist.interleave_inherited_prefix`：只在最高连续的继承 Sink 调用点带内按调用点轮转，先前优先级、单查询截止点和全局预算不变；无关本地 copy 与 return/output 保持原顺序。最小回归验证两处继承调用点交错且本地调用不前移，既有“继承 Sink 先于耗尽 copy”的断言仍通过；相关 **41 tests OK**。同一封存摘要和 30 秒预算的 `p74-two-sites-sealed-02` 与 `01` 配对：两个下游 Sink 的 Source 均从 **212→226**，路径 `0x212d8` 仍为 212，`0x21404` 从 **0→14**；Unknown 数分别仍为 1/2，9 个查询仍显式 pending。此修复恢复了第二条真实调用点的部分覆盖，没有证明所有 212 个该路径候选已求完，也没有把 Unknown 当安全。待补齐 `0x18d44` 的真实子图和完整回归后再更新 P7.4 结论。

`p74-legacy-chain-cli-01/02` 各在新目录补入旧日志明确的 `0x18d44` 等八函数、同一冻结 iCall、每函数 30 秒。两次第 2 轮都把 `0x18d44` 两个 Sink 的 Source 传到 `0x18590` 和 `0x1f9a0`；最终各层两 Sink 合计 **32** 条 Source，`0x1f9a0` 的路径都经 `0x212d8`，`0x21404` 为 0。`01` 为 3 轮/20 调用，`02` 为 4 轮/27 调用；两者均 CLI exit 1、`diagnostic-subset/incomplete`，命令候选 1、缓冲区候选 0。后者没有证明第二路径在该子图的传播改善。用 `02` 的最终摘要单独聚焦 `0x21404` 时，两 Sink 各得 16 条 Source，但 3 个查询仍 pending；合并时较早调用点继续占用预算。这表明先前封存 79-Sink 回放的 14 条第二路径是上下文敏感的 may 增量，不代表该八函数固定点已覆盖它。

按此前用户的持续授权，`p74-old-two-callsite-01` 在**新的独立 417 文件物理副本**执行一次旧 `-t`，exit 0、原旧仓库/基线副本哈希未变、PLY `write_tables=false`、写入违规=[]、观察未截断。旧 `_process_callsite_callee_taint_in_forward` 在 `0x212d8→0x18590` 的两次调用中第一次接收一条 Source `122436`（`Store(Load(0xa89b8)+o)`，来源 `0x186bc`）；`0x21404→0x18590` 两次都没有 incoming Source。旧 `_make_def_copy_to_callsite` 两处仍有其他 `0xb322c` 定义事实，故不能把第二处说成完全无状态。目标封存摘要轮转后在 `0x21404` 的 14 条 Source **全部 `uncertain=true`**，Source 值为 121780/121800/122436/122464，各有显式 Unknown；这是比所观测旧 transfer 更宽的 may 候选，不可升级 Confirmed。旧观察没有覆盖所有可能分析路径，因此也不能把它强行删除。P7.4 的首个未闭合事实转为：旧版实际 callee transfer 只在较早调用点收到上述 Source，而目标摘要式 may 投影在较晚调用点仍给出 uncertain Source；需配对两处真实参数/Guard/MemoryVersion 才能解释差异。Guard 过滤属于 P7.5，但 P7.4 必须保留上下文来源和不确定性。

本次新增调度回归后完整测试为 `.venv/Scripts/python.exe -m unittest discover -s tests -p 'test_*.py' -q` **416 tests OK，exit 0**。冻结 iCall 输入在新诊断目录逐次哈希复制；旧版观察用新的独立物理副本，未修改原旧仓库、Golden 或历史结果。当前仍有 8 函数子图 `incomplete`、第二调用点 may/旧 transfer 差异与真实递归/多上下文缓存验收缺口，因此 **P7.4 未通过，P7.5–P7.7 未开始，P7-A/B/C/D 未通过**。

冻结完整性复查：`p74-integrity-final-01/integrity.json` 对旧原仓库 13461、目标 `.venv` 13044、Golden 376、P6 封存 2950 个文件逐项报告 `unchanged=True`。该通用脚本的总 exit 1 来自它仍与 v8 更新前的规划文档快照比较，三份 planning hash 均为 False；使用本轮 `baseline-manifest.json` 的 **v8** SHA256 单独核对，`AGENTS.md`、`MIGRATION_BLUEPRINT.md`、`CODE_TASK.md` 以及 P6 CG 和冻结 iCall 均匹配。不能把通用脚本 exit 1 冒写为通过；受保护四类仓库/结果确实未变化。

### P7.4 阶段判定

旧 `_update_expr_from_callees` 在当前旧 `-t` 实际调用链中未执行；本阶段按活跃的 `_make_def_copy_to_callsite`、`_process_callsite_callee_taint_in_forward` 和实际 ProcedureSummary 行为配对。下表的阶段结论只覆盖跨函数传播，Guard/Length 与 Finding 留给后续阶段。

| P7.4 项 | 旧/新事实与验收依据 |
| --- | --- |
| caller 实参→形参、形参→局部/内存、ABI 栈/寄存器 | 旧 `0x212d8` 收 Source `122436`；目标同路径下游两个 Sink 含 Source，`tests/test_p7_demand.py` 的两 caller 实参隔离、形式偏移和长度配方、`tests/test_p7_global_outputs.py` 的写入 extent 通过。 |
| 返回值、heap/global/pointed write | `test_p7_demand.py` 覆盖返回值别名、未知返回及来源 identity；`test_p7_global_outputs.py` 覆盖全局写后读/清洁覆盖/宽度；`p74-hsearch-pair-01` 保留旧 FIND retptr 的 APG may-fact，旧 INSERT Source 在调用点之前已存在，不把 may-fact 冒充新 Source。 |
| 外部/未知调用 | Procedure 规则和 incomplete callee 测试保留 Unknown；八函数真实子图的缺失下游摘要表现为显式 incomplete，补入 `0x18d44` 后 Source 到达三层。 |
| 多调用上下文、递归、缓存 | 参数化 callee 摘要在各实际 callsite 的 use/def 截止点单独绑定，Source 依赖带 callsite path 且 `uncertain`；两 caller 最小回归无串污。`SummaryAccumulator` 按 `(FunctionID, ContextId)` 分桶，输入身份包含 MemoryVersion、CG、直接 callee revision；递归 SCC 失效测试确认两个成员更新而无关缓存保留，真实 table Root 变更只失效读者及反向 caller。当前分析采用一个多态 callee body 摘要，未做每个 call string 的 callee body 重分析；若 P7.7 出现该精度差异须重开此项。 |

阶段专项与受影响完整回归均通过，最终完整命令 **416 tests OK，exit 0**。旧版 `0x21404` 在观察的两次 transfer 中无 incoming Source；目标同址新增的 14 条均为 uncertain may 且有 Unknown，不计入旧路径已确认事实。该差异的路径/值过滤属于 P7.5，P7.4 不以此确认漏洞。**P7.4 跨函数传播范围验收通过；全程序固定点和 P7-A/B/C/D 仍未通过。**下一阶段按 `CODE_TASK.md` 进入 P7.5，先配对 `0x2d25c` 的 39999 Guard/Length 和 `0x21404` 的分支条件，再处理规则过滤；不推进 P7.6 直到 P7.5 通过。

## v8.0 P7.5：Sanitizer / Validator / Guard / Length（进行中）

首个差异是 `P70-GUARD` 的旧 39999：`p74-old-transfer-08` 已证明它在 `0x2d25c` 进入 collector，来源为 ARM `r2` 的无符号上界；旧 `p74-old-transfer-04` 到达 `0x2d27c` 时 `r12`（ARM r1）为 1。目标初始 SSE 在成功调用点却把 r1 读为可变全局初值 0、r2 保持形式参数；不能把 39999 当调用点 r2 的具体值或直接写进最终 JSON。

真实冻结 CIR 的 `0x25228`（绝对 `0x2d228` 函数内）和 `0x2525c` 两块均使用 ARM flags 展开。P7 `guards.py` 新增**结构匹配**：零标志链识别 32 位 `EQ(SUB(x,y),0)` 的 true/false 边；HI 链识别 `not(x <u y) and not(x==y)`，true 为 `UGT`、false 为 `ULE`。它要求相同操作数与位宽，signed、错位、截断或未知链不作推断。真实 CIR 上分别匹配 `eq32`（r1 pointee 与 1）和 `ule32`（r2 与字面量池 39999），没有硬编码地址或数值。`LegacyTaintDemand.path_guards` 只在所有已解析 CIR 路径经过所选边时记录观察；`0x25250→0x2525c` 的 IDA UNKNOWN 边与该块唯一具体无条件跳转 `0x25254` 矛盾，P7 局部路径查询排除它，**P6 CFG 文件和 CG 未改**。CFG 整体仍为 UNKNOWN，故该观察是条件性 may 证据，不是全局可行性证明。

最小独立测试 `test_p7_arm_guard_lowering.py` 覆盖无符号边方向、signed/错位/64 位反例、缺失布尔链、零标志正反边、错误极性，以及 UNKNOWN CFG 中具体跳转与未知跳转的区别。首轮测试因测试构造的 `EXTRACT/EQ` 类型错误失败，修正为 1 位 BV 后 **6 tests OK**；受影响 P7 专项 **45 tests OK**。`p75-inherited-guard-01/02` 用相同封存摘要和 30 秒预算重放真实 `0x2d228`：Source facts 都是 14、Sink 都是 2、pending 都是 4；修复前 `0x2d27c` 投影 Source provenance 的 guards 为空，修复后包含 `('f25228:o97','eq32',1)` 与 `('f25228:o159','ule32',39999)`，下游 Sink 依赖还记录独立的 `ne32 0` 返回分支。Source 均保持 `uncertain=true`，没有将 may 变 Confirmed。完整回归 **422 tests OK，exit 0**。

仍待完成：把两条路径条件与 `fread` 长度配方 `arg1*arg2` 在正确位宽下关联。由于全局初值 0 与到达路径值 1 的差异及 CFG UNKNOWN，当前不能把 39999 作为已证明的完整拷贝长度，也不能把未知当 0/安全。还须逐条核对旧 Sanitizer/Validator 过滤方向、Join 条件保留及 `0x21404` 的额外 uncertain may 路径，补各规则的正例/反例/未知例。**P7.5 未通过，P7.6/P7.7 未开始，P7-A/B/C/D 未通过。**

### P7.5 本轮：长度关系与过滤分支验证

Difference ID 仍为 `P70-GUARD`。`p75-arg-guard-01` 在封存 CIR 上只检查 `0x2d27c` 的实参：槽 1 的 SSE 是 `COPY→MEMORY_READ`，loader 候选 0；槽 2 是 32 位 `argument:2`，值开放。路径 EQ 链与槽 1 指向同一 SSE 读，HI 链与槽 2 指向同一形式参数。旧 `p74-old-transfer-08` 的 39999 是 HI 分支上界而非具体实参；这是先前数值首差的准确输入快照。

新增 `unit_product_arguments` 只接受 32 位、严格 `1×arg×arg` 的可移植长度配方。`guarded_length_guards` 在实际调用点要求两个因子与支配路径上的 `==1`、`<=u bound` 各有**唯一且相同**的 SSE 根；不接受其他运算、不同位宽、开放的多值根或不匹配的分支。它只附加 `(call origin, length-ule32, bound)` 条件观察，不把 bound 写进无条件数值 `constraints`，不消除原配方、Unknown 或 `uncertain`。`p75-guarded-length-01` 同一封存摘要、30 秒函数预算，exit 0、源未变、写入违规=[]：`0x2d228` 两个 Sink 各有 8 条 Source；其中各 2 条继承 `fread` Source 带 `length-ule32(39999)`，共 4 条，仍保留 residual recipe、`constraints=[]`、`uncertain=true`。14 个 Source memory fact 中有 5 个投影 provenance 含该条件；没有把其余来源直接过滤或升级 Finding。诊断子集没有全程序固定点含义。

新增 join 测试证明两条分支在调用点前汇合时不保留单边 guard；旧 `_add_taint_constraint` 的 0/1/2/6 类型及未知类型、方向和零值正反例逐项核对，旧 `SecurityCheck` 的文件句柄过滤与 socket 覆盖由既有 `test_p7_policy.py` 验证。`0x21404` 的 `p75-21404-guard-roots-01` 只读快照列出 13 条路径观察；`ne32 1` 与 `eq32 1` 的 SSE 根分别为 `sse-3187/3186/...` 与 `sse-3537/3536/...`，**不是同一已证明的值**，不能仅凭文本相反就删去 14 条 uncertain may Source。新聚焦 `p75-large-guard-cost-03` 与旧聚焦输入、30 秒预算配对：下游 `0x18ef8` 仍有 212 条 Source，墙钟 40.657→38.922 秒；pending 4→6，仍标 incomplete。早先未优化的成本探针中断，没有当成有效结果。

修改 `emtaint/analysis/taint/guards.py`、`demand.py`、诊断脚本 `scripts/p7_function_replay.py` 和 `tests/test_p7_arm_guard_lowering.py`、`test_p7_guards.py`；P6 iCall/CG、旧仓库、Golden、历史结果未改。专项 `.venv/Scripts/python.exe -B -m unittest test_p7_arm_guard_lowering test_p7_guards test_p7_policy test_p7_demand -q` 为 46 tests OK、exit 0；随后完整 `unittest discover -s tests -p 'test_*.py' -q` 为 **425 tests OK、exit 0**；最后的 32 位根检查和负例后，最小 8 tests OK、exit 0。回退限于上述 P7 文件。P7.5 仍须确认旧过滤映射在真实多函数传播后的应用位置、Guard 与 Finding 证据闭环，以及 0x21404 额外 may 的内存/调用上下文来源；P7.5、P7-A/B/C/D 目前均**未通过**，P7.6/P7.7 未开始。

### P7.5 约束过程映射补齐与范围判定

旧 `dataflow/procedures/libc` 的活跃约束过程逐项对照目标规则表，发现 `atoll`、`strtoll`（旧 helper 名称复用 `strtol`）、`stricmp`、`gethostbyname2` 四项缺失。先加 `test_all_active_old_constraint_procedures_have_exact_rules`，真实红灯为 4 个子例；再补准确名称、operation、Source 参数和约束类型。`stricmp` 旧 `add_special_constraint_v2(str1,str2)` 要对两侧参数生效；第二参数的 EQ0 边最小回归先红，随后只扩展 `edge_policy` 的双参数槽位，正反边通过。目标 IDA metadata 的同组名称只见 `atol` 10 次、`strlen` 281 次；四个新登记项**没有本固件调用证据**，故不能声称它们解释既有 Finding 差异。

旧 `Dataflow` 四类零值过滤、4/5 数值约束、字符串约束和未知类型都有正例/反例/未知例；`SecurityCheck` 的 file handle 过滤、socket override、符号约束及长度/目的偏移启发式也有独立策略测试。路径 guard 的 true/false、UNKNOWN CFG、join 消除与跨函数 inherited Source 附着已逐项测试。旧 39999 是无符号路径上界，目标只将它与恰好 32 位的 `1×arg1×arg2` 关联为条件性长度观察，保留原 recipe 和 incomplete；旧 SecurityCheck 的无条件整数栏仍未复现，不能用该观察直接确认或排除漏洞。`0x21404` 的 14 个多余 Source 均为 uncertain may，现有 guard SSE 根不支持安全过滤；其真实上下文精度属于 P7.7 的差分复核，若证明为 P7.4 损失须重开 P7.4。

本阶段源码范围测试 `test_p7_demand test_p7_guards test_p7_rule_registry test_p7_arm_guard_lowering test_p7_policy` 为 **61 tests OK、exit 0**；完整回归为 **427 tests OK、exit 0**，保留原 378 项和全部新增断言。P7.5 的规则/Guard/Length **范围验收通过**，含明确条件性与 UNKNOWN 状态；这不是 132 条旧数值约束或最终 Finding 的保真验收。下一步按 `CODE_TASK.md` 进入 P7.6，逐旧 Sink/漏洞规则核对 Candidate→Confirmed 的证据与 39999 条件上界的处理；P7-A/B/C/D 仍未通过，P7 不能宣布完成。

## v8.0 P7.6：Sink、Finding 与证据（进行中）

首个策略差异 `P70-FINDING`：独立旧 `p74-old-two-callsite-01/stdout.log` 的 `SecurityCheck.guess_max_taint_length` 实际为 **39999**；封存目标 `sealed-cli-10` 的 `candidates.json` 有 1477 行，但其中 `>=8192` 的无条件数值 bound **0** 行，target manifest 为 incomplete、830 个函数 pending。`p76-policy-audit-01.json` 保存双方文件 SHA256 和计数。这一差异源于旧 collector 将 `0x2d25c` 的路径上界投到全局启发式长度，目标仅有 P7.5 的条件性 `length-ule32(39999)`。不能把它升为全局无条件上界来压掉 MAY，更不能将缺失 bound 当安全；须在 P7.6 的旧启发式对照和新候选保守性两层分别展示。故旧已确认 Finding 仍待逐项配对，当前 Confirmed=0 是尚无独立路径/别名/约束证明，不是 0 个漏洞结论。

第二个可修复差异 `P76-CANDIDATE-PATH`：封存 `requirements.json` 有 **147416** 条 Source 需求行；原候选字典只用 `(kind,site,offset,source)`，在 **2471** 个键上发生碰撞，单键最多 **480** 行，且 **2424** 个键有不同路径/Guard/约束备选。末条写入覆盖前条，候选只显示一个代表路径，不能完整追溯原需求。先新增最小回归（缺少 `candidate_evidence` 模块的红灯），随后新增 `candidate_key`（含 FunctionID 地址、精确过程名）与 `requirement_references`，在候选加入带 SHA256 的 `requirements.json` 行/依赖坐标；保留旧的 `evidence` 字段和原 `P7-evidence-v4` 需求格式。候选字段为独立的加法版本 `P7-candidate-refs-v1`，记录在 manifest；这是 P7 证据输出的显式版本补充，**未改 CIR、P6 Schema 或 Golden**。引用包含同弱键的全部 may 需求备选，逐条 legacy policy verdict 仍需复核，不能把这些引用全当 Confirmed 证据。

在封存 `requirements.json` 的只读规模检查 `p76-reference-scale-01.json` 中，原 1477 个候选键均能回指需求，合计 **80720** 个坐标，最大单候选 **250**。目标新目录 `p76-candidate-refs-cli-02` 的单函数 `0x6b608` 回放产生 1 个 command MAY、1 个可哈希验证的需求坐标；`p76-candidate-refs-cli-03` 的 `0x67294` 产生 18 个 MAY、36 个可哈希验证坐标，18 个均有多条来源备选。两次 CLI 都是 diagnostic-subset/incomplete、exit 1，不能当 P7-C 通过；源码未变、写入违规=[]，拷入的冻结 `icall.json` 与 `icall-targets.json` 哈希分别相同。专项 `test_p7_candidate_evidence_refs test_p7_comparison test_p7_evidence test_p7_policy` 为 14 tests OK、exit 0；完整回归 **429 tests OK、exit 0**。

P7.6 尚未通过：需逐项复核旧 150 条已确认记录的 Source、Sink 操作和参数、长度/路径条件、真实 Alias/MemoryVersion、调用链及 JSON 证据；`vsnprintf` 的旧 `va_list` Store transfer 仍显式 pending，不能以普通变参处理冒充支持。下一项优先在已有 `0x67294` 候选及旧对应弱点上配对第一处策略或传播事实，避免无新诊断的全量回放。P7-A/B/C/D 均未通过，P7.7 未开始；不推进 P8。

### P7.6 旧 file filter 的首差：`0x67294`（同时复核 P7.5）

按上述单函数差分，旧 `taint.log` 的 `SecurityCheck.get_file_open_taint_sources` 明列 `0x675b8`、`0x67718`、`0x67840` 为 fake source；旧规则用 `cons_type==8` 或表达式字符串含 `open`，所以 `popen` 返回的 FILE 流也被旧启发式过滤。修复前新 `0x67294` 的两个 `fgets` stream 参数被标成 `unknown`，18 个额外 MAY 候选由此出现；这不是最终 JSON 的格式差异。`p76-fgets-handle-inspect-01` 的同 CIR 快照显示两个 stream 槽均为 `COPY→SUB(procedure-return:f5f294:o2036, 0)`，该返回来自实际 `popen`，不是未知函数。旧源码和目标在**句柄来源识别**处首次分歧。

新增 `ProcedureRule.returns_file_handle`：`fopen`/`fdopen` 原有行为保持，`popen` 同时保留 command Sink 与 FILE 返回语义；`LegacyTaintDemand.handle` 只在字面量零的 ADD/SUB 恒等式上穿透，不对未知数值作相同假设。两个最小断言分别先红：`popen` 返回未标 file、`SUB(return,0)` 额外产生 Unknown；修复后通过。全新 `p76-fgets-handle-fix-03` 与修复前 `p76-candidate-refs-cli-03` 同一 P6 iCall SHA、单函数、1 轮、30 秒预算：Source 调用点仍为同样 3 个，旧已过滤的三个 Source 在新版 `source-handle-evidence` 由 `file+unknown`/`unknown` 变为**精确 file**，候选 **18→0**；原始 Source facts 和 179 条 unknown requirement 继续保留，manifest 仍为 diagnostic-subset/incomplete、CLI exit 1，不能读成全程序“无漏洞”。这使该旧 file filter 的真实调用点配对一致，也补上 P7.5 规则在真实跨过程返回值上的验证。完整回归 **430 tests OK、exit 0**；P7.6 整体与 P7-A/B/C/D 仍未通过。

旧已确认 Finding 的第一条逐证据快照为 `p76-old-confirmed-1fe3c-pair-01.json`。旧 Golden 在 `0x1f9a0:0x1fe3c sprintf` 记录 buffer overflow、offset **1142**；旧 `check-weak-copy` 行的 Source 为 `0x1de44`，约束列表空但有两个 constraint ID，调用层级列出 `0x1de00→0x1f9a0`。封存目标有同函数/站点/过程/offset 的两条 MAY 候选，其中 Source `0x1de44` 匹配，另有 `0x1de60` 备选；目标实际 Source fact `region-b3817cf490e2722f5382d853a936ba1e` 是 argument Root、`mem-1`、状态 incomplete、污点类型 may-buffer，caller 投影仍有 unresolved recipe。**首个未配对证据**是旧弱点表达式的栈地址/约束 ID 与目标 may/未解 Source→Sink 证明之间的精度差，而非站点或目的偏移缺失；当前不能将这条 MAY 提升 Confirmed。下一诊断须在 `0x1de00` 的来源 fact、对应 caller 参数及 `0x1fe3c` Sink 之间逐边检查 MemoryVersion/Alias/约束，并只在真实完整证据成立时改变判定。

同封存摘要的 `p76-confirmed-1fe3c-focus-01` 只查该实际 Sink，30 秒函数预算、exit 0、源未变：Sink 仍为 `sprintf`、offset **1142**，有 4 条 Source（`0x1de44`/`0x1de60` 各 2）和 1 条 Unknown；9 项 pending 包含残留长度配方超过 256 节点、反向备选超限、其他格式串不完整。`0x1de44` 两条 Source 分别有 unresolved 与 residual recipe，均 `uncertain=true`，路径条件只作为 Guard 保存，不能单凭旧 `check-weak-copy` 的 heuristic 输出转 Confirmed。该聚焦回放比封存全局候选提供新的首差状态，不代表完整 caller 固定点；下一项是精确绑定 `0x1de00` 的形式 buffer/stream 与 `0x1f9a0` 三个实际调用点，检查哪个 MemoryVersion/alias 分支首次变成 may。
### 2026-10-31 P7.6：`vsnprintf` `va_list` Store 传播首差与局部修复

再次完整核对 v8.0 三份执行文档后，P7 仍未完成：P7.6 的 Finding 完整证据尚未闭合，P7.7 尚未开始，P7-A/B/C/D 不能标通过。本轮只处理差异 `P70-SINK-vsnprintf-va-list`。旧 `vsnprintf.run` 在 forward 模式调用 `_find_taint_propagate_in_format_v4`；其首个筛选事实是 trace AST 必须为含 `arg_list` 的 `Store`，地址只能是 base 或 base+常量，格式位置使用旧版特殊规则 `offset % arch.bytes`，仅 `s` 项传播到目标 buffer，并把 concrete `maxlen` 或符号 `S` 约束带到新表达式。新版此前的 `format_output_va_list_unmodeled` 无条件写入“未迁移” pending，是已定位的首次实现分歧。

`emtaint/procedures/legacy.py` 现登记稳定规则 `format_output_va_list`；`demand.py` 将旧格式分类与普通变参槽解耦，新增 `format_string_indexes` 和 `va_list_dependencies`。实现只通过 CIR、`ProcedureDemand.read` 与 `MemoryQueryPort` 的版本化读写/alias 查询恢复 Store→pointer→buffer 依赖，精确保留 `offset % arch.bytes`，并继承 `maxlen`/recipe。格式、va_list base 或 Store 对应关系未证明时仍输出 Unknown/Incomplete。`vsnprintf` 只作为 transfer，不新增旧版不存在的漏洞 Sink；global output 枚举同步识别该 memory effect。

最小回归覆盖三种语义：ARM32 对齐 `+4` Store 配 `%s` 能到达后续 `system` buffer，且 24 字节 Source 被 `maxlen=16` 约束；同一 Store 配 `%d` 不传播 Source；符号 format 继续显式 pending。`test_p7_rule_registry` 13、`test_p7_demand` 34、`test_p7_global_outputs` 9 项均 exit 0。随后完整 `python -B -m unittest discover -s tests -p 'test_*.py' -q` 为 **432 tests OK，exit 0**；未删除用例、未降断言。

真实 sealed 回放 `p76-vsnprintf-transfer-01` 在新目录执行 `0x1dc44`，runner exit 0、execution source unchanged=true。结果没有新增 Sink；原“va_list transfer 未迁移”改为 `Legacy vsnprintf format/va_list correspondence remains incomplete`，另保留 `Unknown format ... variadic coverage incomplete`。原因是该函数内 slot2 是 caller 形式参数，context-free 摘要尚不能把 caller concrete format 与 entry-frame va_list MemoryVersion 带回本地 transfer。该结果不是 clean/安全证明，也不允许删除 pending。配对摘要见 `p76-vsnprintf-transfer-pair-01.json`。

回退范围仅为 `legacy.py`、`demand.py`、`global_outputs.py` 与两个 P7 测试文件；旧仓库、Golden、P6 iCall/CG、历史回放均未改。当前局部 transfer 已迁移，但真实 caller format/va_list 绑定仍是 P7-B/P7.6 阻塞；下一差异应在 `0x1dc44` 的真实 caller 首次绑定 concrete format 与 entry-frame Store 的位置建立快照，不能在最终 JSON 补事实。P7.6、P7-A/B/C/D 仍未通过，P7.7 未开始，不推进 P8。

### 2026-10-31 P7.6：候选 caller path 与精确 Source fact 引用

继续 `P76-CANDIDATE-PATH` 后确认第二个更早的证据丢失：`TaintDependency.path` 原为 `compare=False`，因此 Source、约束、Guard 等字段相同但 caller callsite 不同的依赖，会在 `union` 的 `dict.fromkeys` 阶段被当成同一对象；此时尚未进入 `source_antichain`，连“被覆盖路径”证据也无法记录。最小回归先验证相同 Source/约束但 path `0x410/0x420` 必须在代表折叠前产生显式 covered relation；随后让 path 参与 dependency identity，仍由原 antichain 控制传播规模，不无界展开路径。

新聚焦回放 `p76-confirmed-1fe3c-paths-01` 使 `0x1fe3c` 的 Source `0x1de44` 明确保留 caller path `0x1fce0`（130272）和 `0x1fc30`（130096），以及未投影的 Source-only 备选；不再只有 `(0x1de44,)`。同一运行的实际 imported Source facts 恰好分别位于 `f179a0:o1549`/`0x1fce0` 和 `f179a0:o1225`/`0x1fc30`，各有独立 MemoryVersion。这个配对证明此前“候选只能链接 Source 站点全部历史 fact”的根因包含 path identity 丢失。

`source-evidence-index.json` 现为每个真实 fact 增加原始 `program_site`。候选按自身代表 path 优先选择该 callsite 最终轮的 fact，并保存 fact ID、origin、receipt、memory archive 及 manifest SHA256；仅无投影 callsite 时才保留 Source-site bucket 回退。`p76-candidate-fact-refs-03` 用新目录只分析 `0x1de00/0x1f9a0`，1 轮、每函数 30 秒：诊断子集按预期为 incomplete、CLI exit 1；旧确认的 `0x1fe3c`/offset1142/source`0x1de44` MAY 现在精确引用 `f179a0:o1549`、program site `0x1fce0`、fact `region-a94f761c90544a2defa3893639db3ef1` 及 archive manifest `317f7b…1713c`。Source-only requirement 仍保留，但不会把 `0x1fc30` 等无关 fact 混入该代表 path 的精确引用。

这是候选私有证据字段的加法变更，`P7-evidence-v4` requirements、CIR/P6 Schema 和 Golden 均不变；候选引用格式已单独审查并由 `P7-candidate-refs-v1` 升为 **`P7-candidate-refs-v2`**。新增/受影响专项 11 tests 通过；完整回归为 **436 tests OK、exit 0**。精确 fact 链接只修复 traceability，不是漏洞可行性证明：该 fact 仍是 unknown summary-source Root、may-buffer/incomplete，长度 recipe 未解，另有 `0x1de60` 备选，所以 Confirmed 仍为 0。下一差异是用这个精确 `0x1fce0` fact 的 APG/MemoryVersion 对照旧栈表达式与两个 constraint ID；不得因引用变精确而升级 Finding。P7.6、P7-A/B/C/D 仍未通过，P7.7 未开始。

## 2026-10-31 P7.7：旧 11 条 `function_incomplete` 的局部收敛审计

复核 v8.0 三份文档和 `comparison-10` 后，旧 150 条 Finding 中的 11 条未完成记录实际集中在 7 个函数。新目录 `p77-missing-local-audit-01.json` 逐条记录了受控查询结果；所有回放均使用封存 `sealed-cli-10` 摘要、`acquisition-03`、冻结 iCall 输入和原 120 秒函数预算，写入新的 P7 目录。`0x52db4` 的 5 个旧站点均完成，`pending_query_ids=[]`；`0x4e505` 是旧 Thumb 展示地址，实际 CIR 站点 `0x4e504` 完成并恢复 offset 349/352；`0x2d5ac` 完成并保留四个旧 Source ID；`0x53c80` 完成并保留四个旧 Source ID 的 256 条 guard/path 证据及显式 Unknown。其余 `0x11fb8`、`0x607fc`、`0x7250c` 也完成局部需求。这个结果只消除了旧 comparison 的“本函数查询未完成”原因，不替代 caller 固定点、长度/Guard 或 Finding 证明。

`0x53c80` 的首次分歧不是 path 身份本身，而是嵌套 bounded-copy 的可选 `length_taint` 在 `in_length_channel` 中形成 256 个不同 guard Source 加 4 个 Unknown，触发 alternatives 限制；临时长度通道随后恢复空的 Source 集，导致已发现的数据 Source 不能返回到 Sink。修复将 copy 长度细化失败与数据 Source transfer 分离：保留已有 Source，长度标为 Unknown/unresolved，并按不可变 call origin 缓存失败细化，避免同一失败重复 17 次耗尽 250000 taint steps。目标 `0x53c80` 从提前截断变为约 2.5 秒完成；不把 Unknown 当安全，也不升级 Confirmed。

`TaintDependency.path` 继续参与身份，`source_antichain` 在去重前记录覆盖关系；同一代码下 `p77-path-and-length-01` 的 `0x1fe3c` 同时保留 `0x1fce0` 和 `0x1fc30` caller path，而 `0x53c80` 仍完成。新增三条最小回归覆盖：等价 Source path 的显式覆盖记录、局部 alternatives 后已见 Source 保留、copy transfer 长度失败不删除数据 Source。专项 61 tests 通过，完整回归为 **439 tests OK、exit 0**。诊断新增 alternatives 组成、调用栈和局部恢复计数，只进入 P7 诊断输出，不改变 P6/CIR Schema。

阶段判定：P7 尚未完成。11 条记录已不再由局部函数预算阻断，但 `0x4e330/0x52db4/0x11f44/0x606a4` 等仍须在真实 caller 固定点绑定 Source；`0x2d5ac` 的旧 offset 20 已定位为栈地址/加载值启发式差异，174/2642 仍须 caller 证据；`0x53c80/0x607fc/0x7250c` 的长度与 Guard 仍为 incomplete。还需逐项复核旧 150 条、解释 130 个额外 MAY、完成 `vsnprintf` caller MemoryVersion 绑定并运行里程碑完整 `-t` 差分。P7-A/B/C/D 均未通过，不推进 P8。

保护边界复查 `p77-integrity-03/integrity.json`：旧仓库 13461、目标 `.venv` 13044、P6 封存 2950 个既有文件内容与 mtime 全部不变；Golden 的原 351 个文件不变，额外 25 个文件全部属于用户已批准的 `p7-20261029T140752Z-d85ea47a` 隔离归档，unexpected additions=0。通用脚本总 exit 1 仍只因它拿 v8 更新前的 planning hash 比较；按本轮 `baseline-manifest.json` 单独核对，三份 v8 文档、冻结 P6 CG、P7 iCall targets 与 CG 哈希全部匹配。第一次 `p77-integrity-01` 因误把 v8 目录当旧 inventory 根而缺少 `legacy-before.json`，失败诊断保留；不将其写成通过。

## 2026-10-31 P7.7：局部缺失链、长度前沿与 Worklist 检查点

再次完整阅读 v8.0 `AGENTS.md`、`MIGRATION_BLUEPRINT.md`、`CODE_TASK.md` 后，整体工作仍未完成：P7-A/B/C/D 尚未同时通过，不能推进 P8。本轮继续按 Difference ID 定位首次分析事实，不修改 P6 iCall/CG、旧仓库、Golden 或历史回放。

`p77-chain-52db4-03` 在同一冻结 iCall 与 4 轮/60 秒预算下，使旧 `0x52db4` 的五条记录全部成为 candidate-present。策略首差是“具体最小值 + 未解 constraint IDs”被当成完整上界并排除；`LegacySecurityPolicy` 现将其保留为 Incomplete conservative MAY，不能当安全或可利用性证明。`p77-chain-11f44-03` 保留 `0x11fb8` 的 offsets 64/96 与 Sources `0x1de44/0x1de60`；两个继承 Sink 都执行第二次查询。`p77-chain-2d394-4e330-comparison-01` 恢复 `0x4e505` 的 349/352 和 `0x2d5ac` 的 174/2642。旧 offset 20 已有栈地址/加载值启发式证据，不在新分析中硬编码伪造。

bounded-copy 的下一处首差位于局部长度异常路径：`in_length_channel` 已保存超限前观察到的 length Source 和 Unknown，但外层 `DemandLimit` handler 随后用一个 bare Unknown 覆盖整个 `length_dependencies`。修复只保留已证明的长度前沿，并在缺失时补 Unknown，不把 length-only Source 放进 buffer 通道。54 项专项通过。真实 `0x53c80` 快照 `p77-missing-53abc-length-preserve-02` 现有 256 buffer Source、256 length Source 和 1 Unknown，四个旧 Source 站点均存在；`p77-missing-bounded-length-preserve-01` 的 `0x7250c` 有 114 buffer Source、36 length Source 和显式 Unknown。`0x607fc` 在单独 callee body 中仍只有形式参数/Unknown，说明必须在 caller 固定点验证，不能用本地结果冒充 Source。

caller `0x25bac→0x607fc` 又暴露一个更早的 Worklist 首差。历史 `sealed-replay-54` 能在重试后进入长度通道；精确 Source identity 后，第一次查询已证明 887 个 caller-bound buffer Source，第二次却从形式参数头部重算并耗尽独立 share，长度通道只剩 Unknown。修复没有增大任何全局或每函数预算：return/scalar-return 首遍继续先运行以预热共享 argument/scalar cache；重试仍在 output/global-output 大尾部之前；当已证明的 caller-bound buffer 前沿超过抽象域上限时，重试从该前沿继续，并附加 Unknown 表示未枚举部分。最小回归验证顺序和检查点语义。`p77-caller-607fc-length-preserve-03` 随后在一个保守备选中保留 938 buffer Source、837 length Source、1 Unknown，四个旧 Source 站点齐全；第一次不完整备选也保留，没有删除失败事实。`p77-chain-11f44-03` 的防回退同时通过。

测试结果：长度/策略专项 54 tests OK；查询隔离/资源/公平性专项 18 tests OK；完整 `unittest discover -s tests -p 'test_*.py' -q` 为 **444 tests OK，exit 0**，包含历史 378 项。`p77-integrity-04` 再次确认旧仓库 13461、目标 `.venv` 13044、Golden 既有内容和 P6 封存 2950 个文件均 unchanged；脚本总 `passed=false` 只因其 `planning-source` 是 v8.0 更新前快照，三份当前规划文档本轮未改。汇总证据为 `p77-chain-convergence-01.json`。

阶段判定仍为 **NOT_PASSED**。已消除的只是已知局部/聚焦缺失链及两类前沿丢失，尚不能代替新的全程序固定点。下一里程碑必须在全新目录运行当前代码的完整 `-t`，重新生成旧 150 条逐证据比较，逐项解释所有非精确行和额外 MAY，并完成 `vsnprintf` caller format/`va_list` MemoryVersion 绑定；之后才能判定 P7-A/B/C/D。Unknown、Incomplete、Timeout、Unsupported 继续不得解释为无漏洞。

## 2026-10-31 P7.7：`vsnprintf` 延迟 format/va_list 关系与里程碑回放

再次完整阅读 v8.0 三份执行文档后，P7 仍未完成。`0x1dc44` 的进一步首差不在最终 JSON：真实 `vsnprintf` format 是 wrapper 形参，入口 va_list 参数由 Store 保存到 frame-register 相对地址；一般 `local_address` 正确地只给出 Stack Root、Unknown offset，因此此前的 base/base+constant 选择器没有可用 Store。现在只在既有 `exact_stack_address` 已证明“entry SP 未改写且位移为常量”时恢复精确 Store 位置，再经 MemoryQueryPort 版本化读取；无法证明时仍为 Unknown，不把 MayAlias 或 frame 标签冒充 MustAlias。

为跨函数保留旧 FormatParser 条件关系，新增 detached `DeferredFormatArgument(format_slot, position, dependency)`：caller format 具体为 `%s` 类位置时才绑定嵌套依赖，`%d` 负例不传播；format 仍是 caller 形参时重绑定两侧但不提前登记 Source，无法重绑定则保留 Unknown。它不携带 scoped SSE/APG/MemoryVersion/TaintFact ID。私有证据按 `docs/migration/P7-EVIDENCE-v5.md` 单独升为 v5，严格 reader 同时支持 v1–v5；P3 CIR/Memory、P6 Schema、iCall/CG 和 Golden 未改。

真实新目录 `p77-vsnprintf-deferred-probe-02` 对 `0x1dc44:0x1dc6c` 直接执行 transfer：format formal slot 为 1，va_list base 为 entry stack `-8`，七个 Store 的精确 offset 从 `-28` 到 `-4`；恢复 formal 1/2/3 的 position-0 selector，并保留 Unknown。该 wrapper 的格式化局部缓冲随后只传给旧版为 noop 的 `fprintf` 和未建模 `BIO_printf`，没有 caller 可见输出或旧漏洞 Sink，所以普通函数摘要仍不应伪造 output/Sink；probe 是 transfer/MemoryVersion 边界证据，不是 Finding。最小回归另验证 proved entry-frame Store、selector 生成、caller `%s` 正例、`%d` 反例及 v5 codec 往返。受影响 70 tests 通过，完整回归为 **448 tests OK，exit 0**。

全新封存目录 `p77-milestone-v5-01` 已从当前源码执行实际 `-i`，exit 0、source unchanged；`icall.json`、`icall-targets.json`、`cg-logical-edges.json` 与冻结 P6 逐字节相同，535 个 MAY targets 和显式空 unknown 站点保留。相同封存源码的完整 `-t` 已启动，仍在运行；完成前不得据中间 round 更新 Gate。最终仍须生成 150 条逐证据比较、解释额外 MAY 与所有 Unknown/Incomplete，并复核完整回归/保护清单，因此当前阶段判定仍为 **NOT_PASSED**。

## 2026-11-02：人工调试日志与无用占位清理

为后续 P7.7 首差定位增加了默认静默、显式启用的标准库日志。CLI 新增
`--log-level`、`--log-file`、`--log-format`；日志文件名只能位于当前新输出目录，使用
exclusive create，已有文件拒绝覆盖。JSONL 事件覆盖 CLI、taint 轮次、函数、独立 query、
预算/未完成、table 版本与失效、最终状态；函数事件同时记录既有 Memory/APG 计数。
日志只读取现有状态，不参与 transfer、worklist、summary、Finding 或持久化 Schema。
新增 `scripts/manual_debug.ps1` 会把冻结 `icall.json`/`icall-targets.json` 复制到唯一新目录后
运行诊断子集，配套 `docs/manual-debugging.md` 给出检查、日志过滤、证据文件和 `pdb` 步骤。

删除前检查了 AST 入边、文本引用、动态注册、访问器、测试和打包入口。仅删除 1 个空实现
`analysis/graph/cfg/stmt_cfg.py`、5 个没有任何成员或引用的占位命名空间，以及 22 个
`emtaint` 下生成的 `__pycache__`；12 个当前主链零入边但属于公开 visitor 兼容面的 VEX
表达式/语句适配器全部保留。质量审计现为 180 个生产模块、449 条内部边、4 个原有 SCC，
safety finding 为 0。

日志专项 3 tests、query discover 18 tests、P7 discover 219 tests 均通过；最终完整
`unittest discover -s tests -p 'test_*.py' -q` 为 **467 tests OK，exit 0**。实际 smoke run
`.p7-work/manual-debug/20261102T093152-92832240` 使用冻结 17-site/535-target iCall 输入，
只分析 `0x2d228`、1 轮、5 秒函数预算，生成 66 条结构化事件；最终状态按预期为
diagnostic-subset/incomplete，保留 10 个 unknown summary dependency 和 6 个 pending effect，
没有把它们解释为无漏洞。旧仓库、Golden、P6 冻结结果与历史回放均未写入。

本轮属于诊断能力和已证明无引用占位的独立清理，不改变此前 Gate 判定：P7-A/B/C/D
仍未同时通过，P7 仍为 **NOT_PASSED**，不得推进 P8。

### 2026-11-02：iCall 实时路径日志补强

人工执行 `manual_debug.ps1 -Mode Icall` 时，原实现只把 CLI 起止写入文件，固定点内部和
控制台均缺少进度。现在增加 acquisition heartbeat、函数 CIR 加载、ProgramIndex 构造、
每轮 Worklist、函数调度、单函数 `CIRLegacySearch` 起止/10 秒 heartbeat、SSE/APG/Alias/
MemoryVersion 成本、target fact/value、recipe、CG/CFG 失效、下一轮重算、17 个站点结果及
9 个产物写入事件。`--log-console` 只增加实时 text handler；JSONL 仍 exclusive-create，
日志线程只读取 elapsed time，不触碰 transfer、缓存、图或结果。

真实隔离运行位于 `.p7-work/manual-debug/20261102T110116-b5c5d0a3`：187 条事件、30 次函数
执行、2 轮、0 ERROR，状态 `candidate_fixed_point`，17/17 站点、535 个 MAY target、
`graph_pending=[]`、0 写保护违规。`icall.json`、`icall-targets.json`、
`cg-logical-edges.json` 与完整冻结 P6 目录逐字节 SHA256 相同。日志专项 5 tests 连续 5 轮、
P6 discover 47 tests、完整回归 **469 tests** 均通过。heartbeat 初版 35ms 固定睡眠在一次
全量回归中只调度出 1 条事件；测试改为在 0.5 秒硬上限内等待 2 条，未降低断言，随后连续
5 轮稳定通过。该改动是纯观测增强，不重开 P6 验收，也不改变 P7 Gate 状态。

### 2026-11-02：日志地址同时标注 RVA 与 VA

人工对照 IDA 时，`icall.search.function.dispatched` 等底层事件原先只记录 FunctionId
的 RVA。现统一通过实际 `Program.image_base`/loader base 生成 `function_rva` 和
`function_va`；调用点事件同时生成 `site_rva` 和 `site_va`。兼容字段 `function` 保留
各事件原有 RVA 或 VA 语义，固定点轮次中的原 `functions` 列表也保持不变。改动覆盖 CLI、
固定点调度、函数内 CIR search、AnalysisRuntime、MemoryRuntimePort 及 taint 函数事件，
未修改 target/CG/summary/Finding 计算，也未改变现有分析产物 Schema。

验证结果：日志专项 **9 tests**、P6 **47 tests**、P7 **219 tests**、完整回归
**476 tests OK**；生产模块 compile check 通过，AST safety audit exit 0（0 个 safety
finding）。`docs/manual-debugging.md` 已改用显式 RVA/VA 字段给出 IDA 检索命令。

### 2026-11-02：iCall 站点结果与表候选证据类型化

`LegacyFunctionResult.sites` 从无约束的 `tuple[dict[str, object], ...]` 收紧为
`tuple[CallSiteAnalysisResult, ...]`。新记录明确保存 site、origin、targets、evidence、
unknown remainder、Assessment、累计 demand steps，并继续类型化 CFG 可达性、表达式、规则、
MemoryVersion、错误和 Return 分类。`LegacyTableCollector.evidence` 同步改为不可变且带构造校验的
`LegacyTableEvidence`，避免证据内部继续依赖任意字典键。

为遵守 P6 冻结规则，CLI 和诊断 probe 通过 `to_legacy_dict()` 输出与改造前相同的
`site-coverage`/表证据 JSON 形状；新增 `to_evidence_dict()` 仅作为后续可验证证据链接口，
本轮未修改产物 Schema 或 Golden。新增 DTO、序列化兼容、非法 target 顺序和真实
`CIRLegacySearch` 返回类型回归。P6 **51 tests OK**，完整回归 **480 tests OK**，AST
safety audit exit 0。

### 2026-11-03：LegacyDemand 安全组件化检查点

新增 `docs/migration/LEGACY_DEMAND_OPTIMIZATION_PLAN.md`，明确把 P6
`LegacyDemand` 保留为冻结兼容参考，不在原类中叠加 P7 精度规则。P7
`ProcedureDemand` 新增只读 `FunctionDemandIndex`，索引 value definitions、register
write/clobber、Store、Call 和 CFG predecessor；`definition_cutoff/reaching` 改为索引查询，
逐 effect 旧扫描仍由等价测试直接对照。Entry 带回边、显式寄存器 clobber、`*` clobber
和查询步数均已覆盖。

新增 `DemandQueryResult/Runner`，为新调用方显式区分 complete 与 incomplete；预算耗尽
返回 `INCOMPLETE + Unknown`，不把空集合解释为无值。顶层查询的 cycle placeholder 不跨
查询泄漏，并记录 scalar steps、memory work 和 wall time。旧 tuple-valued `value()` API
保持不变，现有 P7 调用路径尚未强制切换到新接口。

将 P7 已有的精确入口栈地址、部分寄存器和旧 DDG 循环逻辑分别抽取为
`DemandAddressNormalizer`、`RegisterSliceResolver` 和 `LegacyLoopSummarizer`，原公开方法
保留 facade。地址组件返回 root/offset provenance，但没有放宽 MustAlias：offset 未知、
多 reaching definition 或条件 full-register write 仍为 Unknown/MAY。循环组件逐句保留旧
single-stride `base+i*stride` 算法和规则标签，本轮不新增循环边界或具体迭代猜测。

验证：新增架构专项 **8 tests OK**；P6 **51 tests OK**；P7 **219 tests OK**；最终完整
回归 **488 tests OK，exit 0**。`quality_audit.py --fail-on safety` 为 0 safety finding，
新增模块和测试 `py_compile` exit 0，`git diff --check` 仅有既有换行提示。P6
`legacy_demand.py`、iCall/CG、Golden、旧仓库和历史结果未修改；本轮没有执行新的真实
17-site 回放，也没有改变默认引擎。

阶段判定：LD0–LD2 通过；LD3–LD4 仅完成无语义变化的安全子集；LD6 已开始组合化但仍
保留继承。通用 AbstractAddress、显式 runtime/function epoch 缓存协议、循环/path 新语义、
彻底去继承和 LD7 真实差分尚未完成。进入这些步骤前必须先建立真实目标差分快照，不能仅
凭单元测试修改 `base+i*stride`、Alias 或 Guard 语义。P7-A/B/C/D 状态不变，仍为
**NOT_PASSED**。

### 2026-11-03：Test-Suite `strong_update` 别名识别首个样例

新增 `analysis.aliasing` 原生二进制入口和 `scripts/alias_benchmark.py`，源码中的
`NOALIAS/MAYALIAS/MUSTALIAS` 只作为期望与行号读取，不参与求值；真实查询点和两个指针值
来自二进制 marker call。为加载该套件的 AMD64 PIE，前端新增显式 CLE base 的 ET_DYN
映射、System V AMD64 参数/返回/保存寄存器描述，并把 VEX `AbiHint` 作为无状态元数据处理。
ET_EXEC 原地址策略保持不变，ET_DYN 没有显式 loader base 时继续拒绝。

样例 `fs_tests/strong_update.c` 的源码实际没有 MAYALIAS，而是第 14 行
`NOALIAS(p,&p1)` 和第 15 行 `MUSTALIAS(p,&q1)`。分析从 `main` 反向恢复栈对象，编译
`bar(int*** k,int*** s)` 的 detached Store recipe，并在 `bar(&p,&q)` 处实例化
`*k=*s`。System V 入口策略显式证明“新建 callee frame”与调用前已经形成的 argument
pointee 分离，但不证明不同 argument roots 互斥；AMD64 栈地址恢复仅在本别名客户端中
启用，P6 `LegacyDemand` 默认路径未改。最终二进制站点 `0x4009d0` 证明 `p` 与 `&p1`
是同一 singleton frame 内不相交区间，输出 NOALIAS；`0x4009e3` 证明两者为同一对象、
同一精确区间，输出 MUSTALIAS。两条均 complete，2/2 与源码期望一致。

新增 3 条 benchmark 回归和 1 条 opt-in entry-frame 分离回归；alias、entry、P7 memory
frontier、P6 summary 专项均通过，最终完整回归 **493 tests OK，exit 0**。这只是四个目标
目录的首个端到端样例，不代表 `basic_c_tests/basic_cpp_tests/cs_tests/fs_tests` 已全部通过；
数组/字段、分支 join、堆对象、函数指针和 C++ 虚调用仍需按目录建立清单与差异回归。
P7-A/B/C/D 状态不变，仍为 **NOT_PASSED**。

## 2026-11-04 fs_tests 100% 迭代：基线与 FS0 输入一致性

按 `docs/migration/FS_TESTS_ALIAS_100_PLAN.md` 建立新的、串行、每样本 120 秒 fs_tests
基线 `baseline-20261104T105602+0800`：25 个样本、55 个 required marker，2 个样本
通过，`matched=8`、`complete_required=18`、`missing_markers=7`、`timed_out=1`。
这取代旧的 19.5% 数字作为当前代码基线。`array_alias_6.c` 使用清单中固定的
`test_cases_bc` ELF；所有 source/binary SHA-256 均写入清单。

本轮单一 Difference ID 为 **FS0-INPUT-COHERENCE**。最早分歧不是 marker 排序：
`Binaries/fs_tests/return.c.elf` 的 `main` 只有一次 `my_malloc`，完全没有 `NOALIAS`
调用；不可变的 `test_cases_bc/fs_tests/return.c.elf` 保留两次分配及
`NOALIAS@0x4009dc`。先修改回归使其红灯，再在 manifest 生成期用 ELF 符号表和
Capstone 统计实际保留的 direct marker call；primary/fallback 同分仍保留历史 primary，
只有 fallback 明确保留更多当前 source marker 时才选择 fallback。选择来源、每类调用数和
inventory 完整性均写入 v2 manifest；分析器不接收源码 operand、期望 Alias 分类或源码行号。

`fs-manifest-v2.json` 中 fs_tests 25/25 的 marker inventory 均完整，fallback 仅为
`array_alias_6.c` 和 `return.c`。单样本新目录确认 return 从 missing 变为一条明确 observation；
其 Alias 仍为 `ADDRESS_UNRESOLVED/INCOMPLETE`，没有伪装成通过。全量新目录
`fs0-input-coherence-20261104T1123+0800` 的 `missing_markers` 从 7 降为 6，六条均来自
`array_alias_2.c` 的 120 秒超时；其余 aggregate 保持 `matched=8`、
`complete_required=18`、2/25 样本通过，说明本轮没有混入地址或分类语义修改。

回归：alias 专项 9 tests OK；P4 专项 11 tests OK；完整回归 509 tests OK；
`compileall` 和 `git diff --check` exit 0；strong_update 仍为 NO+MUST、2/2 complete。
并行原生测试曾因两个进程竞争 pyvex FFI 临时缓存产生一次 PermissionError，固定到仓库内
native-cache 后串行复跑通过，不记为 CFG 失败。`quality_audit --fail-on safety` 仍报告工作区
既有的 2 个 silent-exception，尚未在本 Difference ID 中混改。Difference Matrix 已写入
`docs/migration/FS_TESTS_ALIAS_DIFFERENCE_MATRIX.md`。下一单一 Difference ID 为
**FS0-TIMEOUT/array_alias_2.c**：先保存成本和最早状态爆炸快照，不提高预算。

### fs_tests FS0-TIMEOUT：Windows 子进程管道假超时

单一 Difference ID **FS0-PIPE-DRAIN** 的分段快照证明 `array_alias_2.c` 并无分析
状态爆炸：冷启动约 6.4 秒、discover 0.4 秒、summary 0.02 秒，六个 marker 分类合计约
0.11 秒；直接 CLI 可正常输出约 6KB JSON。旧 `_execute` 同时把 stdout/stderr 设为 PIPE，
却在子进程退出后才调用 `communicate`。Windows 匿名管道填满后，子进程等待父进程读取，
父进程持续等待子进程退出，最终被错误记录为 120 秒 timeout。

最小回归先让子进程分别向 stdout/stderr 写 256KiB，修复前稳定在 5 秒门限失败。runner
现在用两个 reader thread 在进程运行期间持续排空两条流，仍由原循环监控进程树 RSS 和相同
timeout，结束后 join、拼接并关闭 pipe；没有提高预算。回归在 0.2 秒左右通过且启用
`ResourceWarning` as error 也无泄漏。单样本 suite 随后得到 6/6 observations、0 timeout、
0 missing；其中 5 条 complete、2 条匹配，最后一条仍明确 ADDRESS_UNRESOLVED。

完整防回退：alias 专项 10 tests、P4 专项 11 tests、全量 510 tests 均 OK；compileall 和
diff-check exit 0。全新全量目录 `fs0-complete-20261104T1150+0800` 达到 FS0 门禁：
25 个样本均有 JSON，55/55 marker observation，`missing_markers=0`、`extra_markers=0`、
`timed_out=0`；aggregate 为 `matched=10`、`complete_required=23`、2/25 样本通过。
FS0 已关闭。下一轮进入 FS1，先对 `simple_1.c:14` 的完整但错误 MAY 保存 stack
object/interval/alias 首差快照。

### fs_tests FS1：pointer address identity 不应使用 pointer-width 区间

单一 Difference ID **FS1-ADDRESS-IDENTITY** 从 `simple_1.c:14` 开始。两侧 SSE 都是
完整常量，绑定到同一 singleton stack frame，模 2^64 offset 分别为 -40 与 -36；对象、
cardinality、lifetime 和 location assessment 均完整。首差在 benchmark 构造 Alias location：
旧代码用 64-bit pointer width，错误地把“两个指针值是否指向同一地址”变成“从每个地址开始
访问 8 字节是否重叠”，使相距 4 字节的两个 `int` 地址返回 MAY。

新增 native 红灯 `StackAddressIdentityTests` 固定 `simple_1` 应为 NO+MUST。修复只把 marker
operand 的地址身份建模为单字节 witness；实际 Load/Store 继续使用 CIR 访问宽度，MemoryEngine
及强/弱更新语义未改。最小测试转绿；同根因 6 样本运行中 `simple_1`、`simple_2`、
`struct_1`、`strong_update` 全通过，`array_alias_2` 从 2/6 提升到 5/6，`array_alias_1`
另恢复一条 NO。全量还恢复 `function_pointer_2:26` 和 `global_1:13` 两条精确 NO。

回归：alias 专项 11 tests、P4 专项 11 tests、全量 511 tests 均 OK；compileall 与
diff-check exit 0。新全量目录 `fs1-address-identity-20261104T1215+0800`：5/25 样本通过，
`matched=21/55`（前轮 10）、`complete_required=23` 不变，missing/extra/timeout 均为 0。
所有原有 ADDRESS_UNRESOLVED 仍显式 incomplete，没有用宽度修复掩盖未知。下一轮继续 FS1，
选择 `array_alias_1.c:24`，追踪首个 `address_binding=None` 到 reaching Store/ValueRef。

### fs_tests FS1：未写局部 pointer 的 empty points-to alternative

单一 Difference ID **FS1-UNINITIALIZED-STACK** 的 `array_alias_1.c:24/26` 首差是
`COPY→COPY→MEMORY_READ(initial mem-0)`：location 属于当前 singleton frame 的精确负
offset，且 Definition Frontier 没有 reaching Store。旧分类把该值交给普通 address binding，
得到 None 并报 ADDRESS_UNRESOLVED；这把“本函数未写的局部 pointer slot”与任意外部未知
地址混为一类。

`_AliasProcedureDemand.uninitialized_frame_pointer` 现在只识别 COPY 包装、entry MemoryVersion、
精确负 stack offset 的 pointer-query value。它作为显式 empty points-to alternative 参与分类：
纯空一侧不能制造 alias，得到带证据的 NO；空 alternative 与已定义同址 alternative 并存时
阻止 MUST、保留 MAY。正 offset ABI stack argument、非 stack、非 entry state、range offset 和
普通 Unknown 均不匹配，继续 INCOMPLETE。没有把未知直接当 NO。

先加入 `UninitializedStackPointerTests` 红灯，修复后 `array_alias_1` 由 2/4 变为 4/4；
category 运行中 strong_update 保持 2/2，array_alias_2/4/5 的条件分支 MemoryVersion 仍为
ADDRESS_UNRESOLVED，没有越过本 Difference 边界。alias 专项 12、P4 专项 11、完整回归
512 tests 均 OK；compileall/diff-check exit 0。全量新目录
`fs1-uninitialized-stack-20261104T1255+0800` 为 6/25 样本、`matched=23/55`、
`complete_required=25/55`，missing/extra/timeout 均 0。下一轮进入条件分支 Definition
Frontier，先快照 `array_alias_4.c` 的 join MemoryVersion 和 predecessor 覆盖。

### fs_tests FS2：unsupported Exit 不能伪造全状态写

单一 Difference ID **FS2-EXIT-EFFECT** 的快照先排除了 CFG 漏边：array_alias_4 的共享
suffix `0x999` 同时保留 `0x963` 和 `0x991` predecessor。首差在 entry block 的 AMD64
`amd64g_calculate_condition` 尚无 scalar expansion；其临时值使 Exit guard 降级为
UnknownEffect。`unknown()` 的通用 else 分支错误地赋予该 Exit `may_write_regions=('*',)`、
`may_write_registers=('*',)`，reaching-definition 因而把它当成 rbp 的最后定义。后续全部
`rbp+constant` 地址丢失 stack root，并在 load 前沿注入 MayAlias Unknown。

P4 native shared-suffix 回归先扩展为红灯，同时断言两条 CFG edge 和 unsupported control
effect 合约。修复为：unsupported side-exit guard 仅 `may_change_control=True`，不写 guest
memory/register；声明/native CFG 仍保留两个 successor。没有实现或猜测 helper 条件，也没有
改变路径可行性。回归转绿后 array_alias_4 由 0/2 incomplete 变为 NO+MAY、2/2 complete。

同类 8 样本中 array_alias_2/4/5、branch_1/2/3、strong_update 全部通过，19/20 marker
正确且 complete；唯一余项是 array_alias_6 动态 index 的独立 ARRAY_INTERVAL 根因。alias
专项 12、P4 专项 11、完整回归 512 tests 均 OK；compileall/diff-check exit 0。全量新目录
`fs2-exit-effect-20261104T1340+0800` 为 12/25、`matched=34/55`、
`complete_required=36/55`，missing/extra/timeout 仍为 0。下一轮锁定
`array_alias_6.c:26`，保存 index×stride 的 SSE 和 interval 首差。

### fs_tests FS1：indexed stack address 的 field residue/stride

单一 Difference ID **FS1-ARRAY-INTERVAL** 的 `array_alias_6:26` 地址 SSE 各为 26 个
节点，可规范化成 `entry-sp - 56 + sign_extend(index32) * 16`。旧 normalizer 仅接受 constant
offset，虽然 stack root、field residue 和 stride 都可证明，仍把整个 load 变为 Unknown。

`DemandAddressNormalizer.indexed_stack_address` 新增受限 affine 提取：只接受常量、COPY、
安全的单变量 width conversion、ADD/SUB 和一侧为常量的 MUL；所有变量 coefficient 的 gcd
作为 stride，且 stride 必须大于 1，常量基址还必须落在 entry stack sentinel 的有限范围。
proof 显式携带 stride，不能冒充 exact concrete index。alias benchmark 用 residue 查找可能的
field Store，并总是补回 entry empty alternative；因此相同 residue 的已定义值可以形成 MAY，
但未知 index 不能产生 strong kill 或 MUST。非 affine、stride 1、无 stack base 的表达继续
ADDRESS_UNRESOLVED。

`IndexedStackAddressTests` 先红后绿，array_alias_6 得到 complete MAY+MUST。category 运行中
array_alias_2、array_alias_6、strong_update 共 10/10 marker 全通过。alias 专项 13、P4 专项
11、完整回归 513 tests 均 OK；compileall/diff-check exit 0。全量目录
`fs1-array-interval-20261104T1430+0800` 为 13/25、`matched=35/55`、
`complete_required=37/55`，missing/extra/timeout 均 0。FS1/FS2 的当前数组和 branch 目标均已
关闭；下一轮进入 FS3，从 `global_1.c:22` 的完整 NO→期望 MUST 查 global Store/Load 版本首差。

### 2026-11-04：CFGFast 共享后缀块规范化

`fs_tests/array_alias_4.c.elf` 的 `main` 暴露了 CFGFast 合法的重叠块表示：
fall-through 块 `[0x400991,0x4009ac)` 包含分支直接进入的共享后缀
`[0x400999,0x4009ac)`。旧 `discover_inputs` 将两个原始范围直接构造成要求互不重叠的
`FunctionInput`，因此在 CIR lowering 前以 `Overlapping source blocks` 拒绝输入。

修复将 CFGFast 的全部 block start/end 作为 cut point，把上述范围规范化为
`[0x400991,0x400999)` 与 `[0x400999,0x4009ac)`；重叠 decode mode 仍显式拒绝。
同时把 CFGFast 原图边映射到规范化分区，并增加前缀到共享后缀的 fall-through 边。
这些 declared edges 仅用于同一 `AngrVexFrontend` 实例实际 `discover` 得到的规格，显式
IDA bounds/P6 acquisition 路径不启用，避免改变冻结 P6 输入策略。

真实 `array_alias_4` 现可完成 lifting 和评估，生成两条 observation；当前两条仍因
`ADDRESS_UNRESOLVED` 输出 `INCOMPLETE`，这是后续数组/字段地址精度问题，不再是 CFG 输入
异常。此前同根因的 `array_alias_2.c`、`array_alias_5.c`、`branch_1.c` 和
`function_pointer.c` 也均生成报告且无 traceback。新增 3 项 shared-suffix/冲突 mode/真实
ELF 回归，P4 专项 **11 tests OK**，alias 专项 **9 tests OK**，完整回归
**509 tests OK，exit 0**。P7-A/B/C/D 状态不变，仍为 **NOT_PASSED**。

### fs_tests FS3：global Store 不能被 stack-local summary 过滤器删除

单一 Difference ID **FS3-GLOBAL-STORE-FILTER** 从 `global_1.c:22` 开始。实际 CIR
快照显示 `bar` 有一个 frame Store 和两个 global Store；后两者分别绑定到 global root 的
偏移 648、632，但 `_summary` 编译出的 recipe stores 为 0。首差在 Store 过滤条件：
`exact_stack_address` 返回的是通用 proof-carrying address binding，absolute global constant
也可形成 proof；调用方只判断 proof 是否存在，就把 global Store 与 callee frame Store 一并
删除，调用者因而一直读取 writable global 的入口快照。

新增 `GlobalStoreSummaryTests` 先稳定复现 `global_1` 的 NO+NO（期望 NO+MUST）。初版曾在
通用 normalizer 内拒绝 global proof，但完整回归立即暴露其既有 provenance/binding 合约，
因此撤回该扩大修改。最终修复只收窄出错消费者：summary 仅当 proof 的
`root.region == "stack"` 时过滤 Store；global Store 保留进 detached recipe，normalizer、
MemoryEngine、P6/P7 taint 和 strong-update 条件均不变。

定向回归转绿，global category 中 `global_1` 与 `global_5` 通过，`strong_update` 保持
NO+MUST；global_2/3/4 与 test-su 仍明确 INCOMPLETE，未在本 Difference 中混改。alias 专项
14 tests、P4 shared-suffix 专项 3 tests、完整回归 514 tests 均 OK；compileall、
quality audit safety gate 和 diff-check exit 0。首次 P4 导入遇到 Windows pyvex FFI 临时缓存
PermissionError，固定 TEMP/TMP 到仓库 native-cache 后串行复跑通过，未记为语义失败。

全新、无 resume 的完整目录
`fs3-global-store-filter-20261104T1235+0800` 达到 15/25 样本，
`matched=37/55`、`complete_required=38/55`，missing/extra/timeout 均为 0；相对上一轮新增
global_1、global_5 两个通过样本。下一轮仍在 FS3，选择 `global_2.c:18`，保存其两侧
global pointer load、MemoryVersion 与 summary instantiate 的第一处 ADDRESS_UNRESOLVED。

### fs_tests FS3：常量重定位地址必须规范到 containing segment

单一 Difference ID **FS3-GLOBAL-ADDRESS-CANONICALIZATION** 从 `global_2.c:18` 开始。
同一全局位置的 Load 经 SSE concrete value 绑定为实际 writable PT_LOAD root+offset 656；
reaching Store 的 `local_address` 却按 `image_base + relocation_delta` 逐层累加，保留
PT_LOAD(0) root 并形成越界 offset 2105392。MemoryEngine 正确地把不同 ObjectId 判为 NO，
但上游错误 object identity 使本应 MUST 的 Store 未进入 MemoryVersion。

alias benchmark demand 新增受限 constant folding：仅接受 Constant、COPY、ADD、SUB，全部
operand 可证明为整数时按 pointer width 折叠，再交给 `ImageMemoryEngine.address` 选择真正包含
该绝对地址的 ELF segment。动态表达式、Load、参数、未知转换仍走原保守路径；通用 P6/P7
demand 和 MemoryEngine 未改。`GlobalAddressCanonicalizationTests` 先以 global_2 两条
INCOMPLETE 红灯，修复后 line 18 得到完整 NO；line 29 保留独立 summary incomplete。

同类运行还使 global_3 得到完整 MUST、test-su 得到两个完整 NO；global_1/5 和
strong_update 均保持通过。alias 专项 15 tests、P4 专项 3 tests、完整回归 515 tests、
compileall、quality audit safety gate 和 diff-check 全部通过。全新无 resume 目录
`fs3-global-address-canonicalization-20261104T1300+0800` 为 17/25 样本，
`matched=41/55`、`complete_required=42/55`，missing/extra/timeout 均为 0。下一轮选择
`global_2.c:29`，追踪 foo/bar summary stores 的 must_execute、unknown_effects、实例化地址与
caller MemoryVersion，作为 FS4 的独立 Difference。

### fs_tests FS4：CFG 证明的 Store 完整性跨 marker 边界保留

单一 Difference ID **FS4-CFG-SUMMARY-COMPLETENESS** 处理 `global_2.c:29`。foo 的
entry block 包含 4 个 true-guard global Store，唯一 successor 是 Return block，故所有 Store
均支配正常 Return；旧 summary 只在“函数恰好一个 block”时设置 must_execute，因 marker call
切块而全部降级。同时 marker CallEffect 的保守 ABI footprint 被计入 unknown_effects，尽管
benchmark 合约中 marker 只观察两个值、不改变被测程序状态。

benchmark summary 现在基于实际 CFG 计算 reachable block dominators：Store 只有 true guard、
位于所有正常 Return 的 dominator 中、且同块顺序早于 Return 时才是 must-execute。unknown
effect 重算只排除本二进制中已识别的 marker DirectTarget；普通 direct/indirect unknown call、
UnknownEffect 和 HavocEffect 仍保持保守。该修复没有读取 marker 的期望类别或源码 operand。

回归拆成 canonical segment 与 marker-boundary/must-execute 两项，global_2 由 NO+INCOMPLETE
变为完整 NO+MUST。其余 7 个失败样本预测不变，strong_update 保持通过。alias 专项
16 tests、P4 专项 3 tests、完整回归 516 tests、compileall、quality audit safety gate、
diff-check 均通过。全新无 resume 目录
`fs4-cfg-summary-completeness-20261104T1330+0800` 为 18/25，
`matched=42/55`、`complete_required=43/55`，missing/extra/timeout 均为 0。下一轮选择
`global_4.c:12`，追踪 argument-relative Store recipe 在 Xray caller 的地址绑定。

### fs_tests FS4：loaded Store address 的唯一 demand binding

单一 Difference ID **FS4-DEMANDED-STORE-ADDRESS** 从 `global_4.c:12` 开始。Zulu 的
`*p=q` 地址先从 callee frame slot 加载；`demand.value` 已唯一恢复 argument root 0，
但 local_address 只跟 Constant/ReadRegister/Compute，对 LoadEffect 返回 None。该 unknown Store
又被错误认为可能覆盖保存 p 的 callee stack slot，污染后续 `*p=obj` 的地址和值。

benchmark demand 现在仅在原 local/exact proof 失败时启动有 recursion guard 的 demand fallback；
所有 alternatives 必须非空、每个都可 address_binding，且全部 binding 完全相同，才返回该
唯一地址。任一 unknown、多位置或递归继续 unresolved。ProcedureRecipe 对由早期 Store 引入的
`MayAlias/partial/guarded reaching store` 分支也在 caller 实例化时复核：只有存在真实 read
alternative，且 caller-specialized 的所有更早 summary Store 与所有相关 read location 均为
完整 NOALIAS 时才删除该条件性 unknown；否则保持不变。

该修复使 global_4、simple_3、pcycle1、pcycle2 共 10 个 marker 全部完整正确，证明这些
cycle 样本的首差是 Store 地址恢复而非需要放宽 fixed-point unknown。strong_update 保持通过。
alias 专项 17 tests、P4 专项 3 tests、P6 summary 专项 4 tests、完整回归 517 tests、
compileall、quality audit safety gate、diff-check 均通过。P6 专项直接模块入口因测试内顶层
import 不可用，改用标准 discover pattern 后 4/4 通过。

全新无 resume 目录 `fs4-demanded-store-address-20261104T1400+0800` 为 22/25，
`matched=52/55`、`complete_required=54/55`，missing/extra/timeout 均为 0。仅
function_pointer、function_pointer_2（完整但错误 MAY）和 return（唯一 incomplete）未通过。
下一轮先处理 return 的 allocation-return object identity，再进入 FS5 indirect-call context。

### fs_tests FS4：allocator return 跨 wrapper 保留 heap identity

单一 Difference ID **FS4-ALLOCATION-RETURN** 处理唯一 incomplete 的 `return.c:21`。
fallback ELF 中 malloc PLT 是无 ReturnEffect 的空 lifted function；ProcedureDemand 又先把 CallEffect
结果降成 `procedure-return:*` symbol，因此 my_malloc wrapper 和 main 两次调用均没有 heap
ObjectId，marker 两侧 address_binding 都为 None。

alias benchmark 为 malloc/calloc 建立 allocation return recipe。实例化时按实际 callsite point 与
context 创建 heap object，保留 allocation 节点穿过 wrapper recipe，并在外层调用点重新实例化；
fresh live allocation 与已有 live object 建立 disjoint proof，同一抽象调用点仍复用 summary
object。benchmark demand 仅对已有非空 DirectTarget return recipe 恢复 summary instantiate；
无摘要、递归和空 return 保持原 unresolved 路径。没有按 return.c 地址或期望标签特判。

`AllocationReturnTests` 先红后绿，return 得到完整 NO；两个函数指针样本保持完整 MAY，
strong_update 保持通过。alias 专项 18 tests、P6 summary 专项 4 tests、完整回归 518 tests、
compileall、quality audit safety gate、diff-check 均通过。全新无 resume 目录
`fs4-allocation-return-20261104T1430+0800` 为 23/25，`matched=53/55`、
`complete_required=55/55`，missing/extra/timeout 均为 0。下一轮 FS5 只处理两个完整但错误的
function-pointer MUST，先保存 main 的 indirect call target evidence 与 callee marker formal binding。

### fs_tests FS5 与最终门禁：完整 indirect caller context

后续架构审查更正：本节 25/25、55/55 仅是 benchmark 专用分析路径结果，
不能证明通用 CLI/ProcedureDemand 别名能力达到相同准确率。测试清单与运行器已移至
`scripts/`；通用入口迁移及独立复验尚未完成，本节的“最终门禁”只针对旧 benchmark 路径。

最后一个 Difference ID **FS5-INDIRECT-CALLER-CONTEXT** 处理 function_pointer 两样本。
旧 scope 只选择含 marker 的 func1 并向下发现，不包含 caller main；formal argument roots 在空
context 下只能得到 MAY。实际 main CIR 中两次 IndirectTarget.address 均由 demand 完整、唯一
求值为 func1 地址，实际参数 0/1 均绑定同一个 caller singleton stack location。

发现范围现在始终包含 main。caller-context 构造只接受所有 target alternatives 都为同一
concrete address 且映射到已 lift FunctionId；marker operand 也必须完整归约到唯一、offset 0
的 formal argument root，才在 caller demand 中以 actual argument 分类。多 caller context
逐个分类并 join；target/formal 不完整不会猜测。结果 function_pointer 得到 MUST，
function_pointer_2 得到 MUST+NO；evidence 明确记录 complete caller target specialization。

最终无 resume 完整目录
`fs5-indirect-caller-context-20261104T1500+0800`：25/25 samples、55/55 matched、
55/55 complete，failed/missing/extra/timed_out 全 0，aggregate passed=true。array、branch、
global、return、function pointer、cycle、simple/struct 与 strong update 均有独立回归。7 个代表
样本（array_alias_6、branch_3、global_4、return、function_pointer_2、pcycle2、
strong_update）连续 3 次的 site/prediction/completeness/alias-kind/reason signature 一致。

最终回归：alias 19 tests、P4 3 tests、P6 summary 4 tests、完整 519 tests 全部 OK；
compileall、quality audit safety gate、git diff-check 通过。quality audit 仍列出工作区既有
2 个 silent-exception 及文档/类型债务，没有作为本任务混改。真实 P6 integration 使用冻结
CIR/loader/legacy-CG 在新 P7 evidence 目录重跑：17/17 sites、535 target entries、5892
logical/legacy edges、CG missing/extra=0、graph/function pending=0，passed 与
native_revision_passed 均 true；与批准 P6 report 的关键字段逐项相等。受控 summary retraction
中 0x2d394 从 61→0→61 正常恢复。

httpd baseline standalone 检查通过，9 个归档文件 SHA-256 全匹配，统计保持 30919 blocks、
4584 tainted blocks、402 sinks、143 buffer、7 command、796/881 analyzed/all functions。
integrity check 证明旧 EmTaint 13461、target venv 13044、Golden 既有内容（351+批准 P7 25）
和 sealed P6 2950 文件均 unchanged，无 unexpected addition。整体 integrity JSON 的 passed=false
仅因根 AGENTS/MIGRATION_BLUEPRINT/CODE_TASK 相对旧 P7 快照已有既存演进；本任务 git 状态
未修改这三份文件。一次 integrity evidence-root 参数误选和一次 httpd 缺少 --output 的 argparse
错误均保留说明，随后正确命令通过。P6 回归证据最初误放 `.p6-work`，发现 sealed-root 边界后
完整移动到 `.p7-work/alias-benchmark/`；最终 sealed P6 文件数与 hash/mtime 清单完全一致。

### 2026-11-03：P7 demand 保持行为兼容的结构化重构

本轮只重构 `analysis/taint/demand.py` 的结构、生命周期管理、文档和格式，不修复或
调整 P7 传播语义。公共 immutable model 已迁入 `demand_models.py`，原
`analysis.taint.demand` 导入路径继续 re-export；字段顺序、默认值、frozen/hash/compare/
repr、`dependency_order`、`sink_order` 和 evidence/replay JSON 由固定 fixture 锁定。
查询预算及 observer/`validate_current` 的异常恢复迁入 `demand_budget.py`；Caller 绑定、
memory frontier、procedure/format/va_list/argv 分别迁入 `demand_binding.py`、
`demand_memory.py` 和 `demand_procedures.py`，所有可变状态仍归
`LegacyTaintDemand`，现有公开方法保留 facade。

新增 7 项 compatibility/lifecycle 回归，覆盖公开构造参数顺序、dataclass/repr/hash、
固定 evidence JSON 字节、排序、嵌套 observer 恢复、参数准备异常恢复和 deadline 的
query dimension。原 demand 专项命令 **121 tests OK，exit 0**；新增专项
**7 tests OK，exit 0**；最终完整回归 **500 tests OK，exit 0**；
`compileall -q emtaint tests scripts` 与 `git diff --check` 均 exit 0。所有拆分文件均无
超过 120 字符的行，`demand.py` 从 1989 行降为 961 行。未安装依赖、未提交 Git，P6、
Golden、旧仓库与历史证据均未修改，未发现需要 Difference ID 的行为差异。

本轮未执行独立的真实固件 P6 iCall/CG 产物 hash 对比；冻结保证来自无 P6 文件 diff、
完整 500 项回归和已有 P6 覆盖。没有新增会拒绝历史 replay 的严格输入校验；负地址、非法
位宽/offset/未知 kind 的新拒绝规则仍须作为独立语义任务先建立 replay regression 后实施。
P7-A/B/C/D 状态不变，仍为 **NOT_PASSED**。

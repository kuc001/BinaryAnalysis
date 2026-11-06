# 通用别名查询迁移矩阵

状态：进行中。`fs_tests` 已经通过通用 CLI 防回退重跑；其余三套件仍有真实差异。

Oracle 口径：源码 `MAYALIAS` 是 may 断言；用户确认完整的
`MUSTALIAS` 可满足它。每条 observation 同时保存原始 predicted、
expected、`exact_matched` 和 `matched`；汇总保留 `strict_matched`
及 `refined_may`，不得修改分析结果迎合源码标签。

固定输入：`.p7-work/alias-benchmark/general-alias-migration-20261104-manifest.json`，
172 个源码样本、490 个 required marker、9 个 expected-failure marker、6 个 smoke 样本。

| 现有行为 | 原路径 | 当前通用组件 | 迁移目标 | 首次分歧/门禁 |
| --- | --- | --- | --- | --- |
| ELF 查询调用发现、源码标签和结果匹配 | `analysis/aliasing/benchmark.py` | `AngrVexFrontend`、`aliasing/program.py`、`scripts/alias_suite_runner.py` | 测试适配器仅作 Oracle 匹配 | 源码预期不得流入分析 |
| 值反向求解、入口栈/参数绑定 | `_AliasProcedureDemand` | `AliasProcedureDemand`、`ProcedureDemand`、`legacy_entry` | 共享 demand 行为，查询模式只选择输入/预算 | 原 fs 样本无回退 |
| 全局、栈数组、间接 Store 地址 | `_AliasProcedureDemand.local_address/read/address_binding` | `DemandAddressNormalizer`、`AccessPath`、`MemoryQueryPort` | 共享地址证明和 memory frontier | Unknown 不转 MAY |
| 跨过程 Store/return/allocator | `_BenchmarkAnalyzer._summary` | `NativeAliasProgram`、`ProcedureRecipe`、`compile_recipe` | 通用摘要构造/实例化 | P6/P7 回归 |
| caller context、间接目标 | `_caller_contexts/_classify_in_callers` | `NativeAliasProgram`、CIR CallEffect、Demand | 通用调用上下文绑定 | 不完整 target 显式 INCOMPLETE |
| NO/MAY/MUST 判断 | `_classify` | `query_alias`、`MemoryQueryPort.alias`、`AliasKind` | 通用 AliasQuery 接口 | CLI 手动/扫描一致 |
| manifest、子进程、Oracle/aggregate | `scripts/alias_suite_*` | 无需生产组件 | 保持 `scripts/` | 172/490 门禁 |

每轮记录 Difference ID、二进制 SHA-256、CIR program point、ValueRef、
AccessRoot/ObjectId、offset/interval、MemoryVersion、摘要/目标、AliasResult、
首个错误事实、通用组件改动、回归和新目录 aggregate。

## 2026-11-04 检查点

- 新通用 CLI `python -m emtaint -a` 已支持配置 observer 扫描与调用点
  `arg:N` 手动查询；二者在 `strong_update` 的 NO 和 `function_pointer`
  的 MUST 上结果一致。
- 手动定位随后扩展为 `reg:NAME`、`mem:0xADDR`、`addr:0xADDR`；
  `strong_update.c` 的调用寄存器对与扫描同为 NO，`CI-global.c`
  的全局指针槽及 pointee 地址与扫描同为完整 MUST。新增 2 项
  手动/自动一致性回归通过。源码变量名与 DWARF 位置映射仍未实现，
  不接受未经证明的变量名猜测。
- `fs_tests` 经通用 CLI 的独立全量运行目录
  `.p7-work/alias-benchmark/general-alias-cli-fs-20261104-02/` 为
  25/25、55/55 complete，missing/extra/timeout 均 0。该结果发生在
  CS1 修复之前，后续必须防回退重跑。
- CS1 与标准 C++ allocation 摘要之后，`fs_tests` 在新目录
  `.p7-work/alias-benchmark/general-alias-cli-fs-20261104-03/` 防回退重跑：
  25/25、55/55 matched 且 complete，missing/extra/timeout 均 0。
- C++ vptr/heap 基数修复之后，`fs_tests` 再次在
  `.p7-work/alias-benchmark/general-alias-cli-fs-20261104-04/` 独立重跑：
  25/25、55/55 matched 且 complete，missing/extra/timeout 均 0。
- `cs_tests` 旧路径只读基线
  `.p7-work/alias-benchmark/general-alias-migration-20261104-legacy-cs/`
  为 12/35、53/116；这是迁移对照，不是通用入口验收。
- CS1-CALLEE-MULTITARGET-STRONG-KILL：`cs10.c` 第二次 `foo(x,y)` 的
  `y` 在 CFG join 后可指向两个不同的局部 pointer slot。旧
  `LegacyDemand.callee_definitions` 遇到其中一个 MustAlias 就 kill
  更早定义，导致两个 MAY 查询都误判 MUST。首差在跨过程内存定义的
  strong update，而非最终分类器。新增
  `ConditionalCalleeStoreTests` 先红（MUST/MUST），随后要求所有
  address alternatives 均完整 MustAlias 才 kill；对完整的 NO/MUST
  多目标集合移除多余 Unknown，回归 20 tests OK。
- `cs_tests` CS1 后通用 CLI 全量目录
  `.p7-work/alias-benchmark/general-alias-cli-cs-20261104-02/` 为
  17/35、70/116 matched、82/116 complete，missing/extra/timeout 均 0。
- CS1 与 C++ allocation 摘要后的 `cs_tests` 独立全量目录
  `.p7-work/alias-benchmark/general-alias-cli-cs-20261104-03/` 为
  18/35、70/116 matched、82/116 complete，missing/extra/timeout 均 0；
  smoke 样本状态改善，但核心别名查询通过数未提高。
- 调用者专门化支持 formal 与完整具体常量混合后，`cs_tests`
  `.p7-work/alias-benchmark/general-alias-cli-cs-20261104-04/`：
  19/35、71/116 matched、82/116 complete，missing/extra/timeout 均 0。
  `recur2.c` 的 `m` formal 与 `&y` 全局常量在 main/递归上下文中
  均归约为 MUST，样本从失败转为通过。
- 待诊断 CS2：`cs15.c` 的 `main → bar → foo`，foo 有两个 Store，
  bar 的现有 summary 为 `stores=0, unknown_effects=true`。两个
  MUST marker 因入口未初始化局部指针被误判 NO。首差是 wrapper 的
  传递性内存副作用未导出。尝试直接拼接 `foo` Store 到 `bar`
  后仍为 NO/NO，快照显示第二个 Store 的值依赖第一个 Store 后的
  Read；普通 detached recipe 会把它变成初始内存 Read 与 MayAlias
  Unknown，丢失时序。该未通过实现已撤回，保留红灯回归，下一步需
  以 MemoryVersion/程序点证明读写顺序再组合摘要。
- `basic_c_tests` 首轮通用 CLI 基线
  `.p7-work/alias-benchmark/general-alias-cli-basic-c-20261104-01/`：
  26/56、60/106 exact matched、84/106 complete、missing 10、extra 4、
  timeout 0。该运行使用旧“标签完全相等”验收口径。
- 新口径全量目录
  `.p7-work/alias-benchmark/general-alias-cli-basic-c-20261104-03/`：
  原始 34/56 样本、72/106 matched、60/106 strict、12 个 MAY→MUST 精化；
  排除 3 个 `INPUT_INCOHERENT` 后为 34/53 样本、69/99 matched。
  complete 84/106、missing 4、extra 4、timeout 0，仍未达到目标。
- 用户随后确认 `MAYALIAS` 可由完整、可证明的 `MUSTALIAS`
  精化满足。新适配器分别记录 `matched`、`strict_matched`、
  `refined_may`，不修改分析器预测。三样本定向复核中
  `CI-global.c` 以 `refined_may=1` 通过，`global-array.c` smoke
  通过，`branch-intra.c` 标为 `INPUT_INCOHERENT`。
- 固定 manifest 共有 6 个二进制 marker inventory 与源码不一致：
  basic C 的 `branch-intra.c`、`struct-incompab-typecast-nested.c`、
  `struct-simple.c`；basic C++ 的 `diamond-inheritance.cpp`、
  `multi-inheritance-1.cpp`、`multi-inheritance-2.cpp`。
  用户明确要求只用现有 ELF，故不重编、不计作算法通过；
  原定 `INPUT_INCOHERENT=0` 门禁在该输入约束下不可达。
  汇总同时记录全部样本和 `verifiable_*` 独立分母；不能把不可验证
  样本算作通过，也不能混入可验证样本的准确率分母。现有输入下
  可验证分母为 166 个样本、437 个 required marker；排除的 6 个
  样本共含 53 个源码 required marker。
- `basic_cpp_tests` 新 CLI 首轮基线目录
  `.p7-work/alias-benchmark/general-alias-cli-basic-cpp-20261104-01/`：
  2/56 样本、2/213 required matched，166/213 complete，missing 43，
  timeout 2，`INPUT_INCOHERENT` 3。此为真实失败，不以 C++ 源码标签代替分析。
- 可续跑的第二轮全量目录
  `.p7-work/alias-benchmark/general-alias-cli-basic-cpp-20261104-03/`：
  原始 2/56 样本、2/213 matched、166/213 complete；排除 3 个
  `INPUT_INCOHERENT` 后为 2/53 样本、2/167 matched。
  `MARKER_MISSING` 24（22 来自不一致输入、2 来自超时），
  `DEMAND_LIMIT` 15、`BUDGET_EXCEEDED` 4、timeout 2。
  预算用尽现记录为 `INCOMPLETE`，不再作为匿名进程失败。
- vptr/heap/caller 修复后四套件独立全量目录均为 `-20261104-04`；
  汇总 `.p7-work/alias-benchmark/four-suite-status-20261104-v2.json`。
  可验证样本 90/166、required 查询 254/437：fs 25/25、55/55；
  cs 19/35、71/116；basic C 34/53、69/99；basic C++ 12/53、59/167。
  C++ 三个样本 timeout；六个输入不一致样本继续单列，不混入分母。
  与上一轮 79/166、196/437 相比，净增加 11 个通过样本和 58 条
  匹配查询；仍远未达到全部可验证样本通过。
  **更正**：C++ `-04` 运行期间收紧了分配基数的未建模控制流门禁，
  前几个样本与后续样本不是同一代码快照，故该目录及 v2 汇总仅作
  探索性诊断，不作最终固定版本验收。`array-1/2/3.cpp` 先前 3/3
  的提升在严格门禁下回退为 MAY；不能为追分删除该门禁。
  固定代码快照另起 `-20261104-05` 四套件评估。
  之后 runner 新增全部 `emtaint/**/*.py` 与关键测试适配器的
  `code_sha256`，续跑校验代码与 manifest，单样本结束也核对代码未变。
  新门禁以 `code-fingerprint-smoke-20261104-01/` 的运行与续跑验证；
  `-05` 仍由旧 runner 启动，不能声称它本身已记录该指纹。
  后续 CLI/定位代码变化后，对同一 smoke 目录再次 `--resume` 按预期
  拒绝 `Cannot resume an unverified or changed code snapshot`（exit 1），
  已有样本结果未被覆盖。
- C++2-TRANSITIVE-CALLER：`constructor-1.cpp` 的 `A::f/B::f` marker
  经构造器传入的 `i` 仍是 formal；第一层 caller context 只能得到
  MAY。新增最多 8 层、带 cycle guard 的调用者实参专门化，沿
  `f ← A/B 构造器 ← main` 逐层替换，并在完整常量处停止。
  新回归先红（MAY/MAY）后绿（MUST/MUST）。定向目录
  `.p7-work/alias-benchmark/general-alias-cli-cpp-context-targeted-20261104-01/`
  中 `constructor-1.cpp` 为 2/2；`constructor-2.cpp` 仍 0/2，
  首差是包装函数 `g` 内的间接虚调用目标缺少 caller-specific vptr；
  `single-inheritance-3.cpp` 仍 4/8，未借不完整 context 凑数。
  同一 `constructor-1.cpp` 的 `A::f` 调用点 `0x400bb9` 以 CLI 手动
  `--left arg:0 --right arg:1` 查询也返回完整 MUST，与扫描结果一致；
  证据目录 `.p7-work/alias-benchmark/manual-constructor-context-20261104-01/`。
- C++3-CONTEXTUAL-VIRTUAL-TARGET（未修复）：`constructor-2.cpp`
  的 `g(A *p, int *i)` 在 `0x400b3b` 经 `p->f(i)` 间接调用。
  独立的 `g` demand 产生两个 target，均无具体地址；构造器对 `g`
  的两处 direct caller 已发现。将 `g` 的 target 值编译为
  `ProcedureRecipe` 并在构造器 caller 实例化的只读探针中，
  `B` 构造器出现具体 `0x400bcc`（`A::f`）及五个未知候选，
  `A` 构造器仍无具体候选。此时不能取唯一虚目标；首差仍在
  构造器写 vptr 的程序点内存版本与 caller-specific `this` 绑定。
- 固定分析代码版本的 `-20261104-05` 四套件结果汇总在
  `.p7-work/alias-benchmark/four-suite-status-20261104-v3.json`：
  可验证样本 88/166，required 查询 253/437。
  fs 25/25、55/55；cs 19/35、71/116；basic C 34/53、69/99；
  basic C++ 10/53、58/167，三个 timeout。六个 `INPUT_INCOHERENT`
  不计入可验证分母。与 `-04` 探索性结果相比，`array-1/2/3.cpp`
  在控制流不完整时保留 SUMMARY，并且完整新增
  `constructor-1.cpp` 的 2/2；整体仍未达标。
- 之后的未知栈索引健全性修复：`indexed_stack_address` 的 offset 是
  affine 余数，不能作为精确地址。`field-ptr-arith-varIdx.c` 先前被
  完整判为 NO，实际 `q+b` 的未知 `b` 可落到结构体第二字段；现保留
  `(stack_root, unknown_offset)` 并报告 `INCOMPLETE/ADDRESS_UNRESOLVED`。
  同一修复使 `array_alias_6.c` 的第一个 MAY 查询不再凭余数得到完整
  MAY：新固定代码快照 `general-alias-cli-fs-20261104-06` 为 24/25
  样本、53/55 查询；第二个 MUST 查询保持完整正确。`-05` 的 25/25
  是修复前的历史结果，不再代表当前代码。下一步需要共享内存引擎
  对带索引的同字段读取建立可能命中同一元素的证明，并保留源级
  路径条件及 Store/Load 时序；不能恢复精确余数捷径。
  地址加法对未知 offset 的后续修复使 `array_alias_6.c` 不再进程失败。
  四套件同一 `code_sha256=ec4ddc49aa21d088a29d10332dc37878eadb0307637c73ec42d2b682554524fd`
  的最终本轮汇总为 `.p7-work/alias-benchmark/four-suite-status-20261104-v4.json`：
  **85/166 可验证样本、249/437 查询匹配**；fs 24/25、54/55；
  cs 19/35、71/116；basic C 32/53、66/99；basic C++ 10/53、58/167。
  六个输入不一致样本单列，C++ 三个 `unordered_*` 超时；四套均无
  进程级失败。此前 `fs -06` 启动于地址加法补丁之前，哈希不同，
  仅作诊断；同版本验收使用 `fs -07`。
- C++1-VIRTUAL-CALLER：`abstract.cpp` 的 `main` 在 `0x400bd3`、
  `0x400bf1` 通过 vtable 间接调用。原先 `_Znwm` 导入桩 summary
  `returns=0`，内存 demand 不能恢复分配对象。现按标准 Itanium ABI
  `operator new/new[]` 的已导入 PLT 桩建立 allocation recipe（用户自定义
  同名函数不套用）后，两个调用点的 target
  alternatives 均出现一个具体目标（分别 `0x400c40`、`0x400c80`），
  但同时还有未知目标，因此按完整性规则仍不能将其当作唯一目标。
  六个观察点依旧均为 MAY；下一差异是构造器 vptr Store 的到达定义
  和 Unknown 副作用/弱更新传播。不能直接挑选已知目标消除未知项。
  曾尝试仅凭被调用函数存在 stores 且 `unknown_effects=false` 清除外层
  CallEffect 的未知写入，仍保留四个未知目标，且摘要本身没有证明
  嵌套副作用完整性，因此已撤回该尝试。
- C++1 后续首差：`B` 构造器先调用 `A` 构造器，后在另一基本块
  无条件写最终 vptr。全函数 `unknown_effects=true` 把前面的调用也
  当作后续不确定写入；allocation-site heap 又被一律设为 SUMMARY，
  同一对象同一 offset 的 Store/Load 只能判 MAY。现用 CFG 可达性证明
  Store 之后无未知写入，并仅在分配调用点不在 CFG 环内时以分析调用
  实例的 SINGLETON 对象建模；未知/循环路径保留 SUMMARY。
  `_caller_contexts` 进一步允许将 callee 的完整单一具体常量与 formal
  参数共同专门化，仍要求目标唯一。`abstract.cpp` 的可达 `B::f/B::g`
  四个 marker 变为预期 MUST/NO；`A::g` 无可证明 caller context，
  两个 marker 仍为 MAY，不能借 B 方法的参数制造调用事实。
  定向目录 `.p7-work/alias-benchmark/general-alias-cli-cpp-virtual-targeted-20261104-01/`
  为 2/3 样本、5/7 查询通过；其中 `array-1.cpp` 1/1，
  `virtual-call-simple.cpp` 为 smoke。
- `deque-1.cpp` 中 demand 达到预算上限时，新 CLI 将对应 marker 标为
  `INCOMPLETE/DEMAND_LIMIT`；没有将该结果误当成 MAY 或进程成功。

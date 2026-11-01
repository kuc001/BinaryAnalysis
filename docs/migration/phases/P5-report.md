# P5：Python 内存核心与 SSE 兼容 / Gate M

2026-10-28。Stage S1；上一阶段 P4 已通过其限定前端验收。**本轮 P5 Gate M：PASS，范围为本文所列 Python 内存语义、保守性、预算和 M-01～M-12 运行 fixtures。** 未执行全固件 `-i/-t`，Gate A 未验收；未开发 Rust，未进入 P6。

接口和使用限制见 [P5_MEMORY_CORE.md](../P5_MEMORY_CORE.md)。Gate M 通过不表示任意程序都能精确求值、完整恢复 points-to，或所有递归状态都收敛。遇到无法建模/超限的情况，验收的是显式 Unsupported/Incomplete 与保留候选的行为。

## 实施与源码映射

按 A→B→C→D→E→F 分层实现并逐次验证，未重写 FastSearch、Fast/AccurateDataFlow、iCall 或漏洞规则。阶段边界以新模块、测试和 `.p5-work` checkpoint 留存；没有提交 Git commit、切分支、reset、clean 或推送。

| 原符号/规则 | P5 目标/证据 | 已实现与边界 |
|---|---|---|
| `variable_expression.py:40 SimAction`，`load_use/re_store_def/get_binop_alias` | 真实旧环境 `p5_legacy_probe.py`；`compat/sse.py` | 记录 copy、def_locs 与地址匹配行为；原启发式不是新 alias 的正确性真值，保留旧路径 |
| `variable_expression.py:146 TraceExpr`，`:496 VarExpr`，`:872 replace` | `compat.sse.LegacySSEAdapter`；`analysis.sse.SymbolicExprDAG` | 真实替换结果 15、alias_id/拷贝行为 characterization；新值表示为独立 typed DAG，不迁移所有 trace 调度方法 |
| `variable_expression.py:1420 RecursiveExpr` | 原代码 shallow/deep copy characterization；`AccessGraphArena`、预算 worklist | 字段递归与上下文增长分离；不将 APG 环当成 CFG/堆对象环 |
| `parse_ast.py:654 get_all_deref_info`、`:685 extract_base_and_offset` | `LegacySSEAdapter.access_path`；P3 AccessPath + P5 path/location | 确认 `r0+8` 与 Load 的 deref 数 0/1、offset 8；嵌套未解析指针保守 unknown |
| 旧 `.venv/.../claripy/ast/bv.py:366–367` Load/Store | 旧原生 AST → 只含 JSON 的 packet → compat | Store marker 只有地址、没有 stored value，拒绝直接作为写入或求解约束 |
| P3 Heap/MemoryQueryPort | `memory/engine.py`、`memory_version.py`、`policies.py` | 持久状态、版本查询、byte defs、must/may/no/unknown、强弱更新、join/havoc/预算 |
| P3 SolverLowering | `solver/memory_lowering.py` → P1 ClaripyAdapter/SolverPort | 局部 byte definitions/BV/ITE；没有完整 SMT Array 后端；不传 raw Load/Store |
| P4 CIR memory effects | `memory/cir.py` | 显式地址 provenance 的顺序 effect harness；完整 CFG/寄存器/ABI/跨过程 transfer 属 P6 |
| P3 TaintFact | `analysis/taint/memory_facts.py` | 基于实际值/定义依赖的 Source→Store→Load→Sink may-flow；guard、版本、出处；不产生已确认漏洞 |

新增/变更交付：`memory/{policies,access_graph,engine,memory_version,cir}.py`；`analysis/sse/{__init__,dag}.py`；`analysis/taint/{__init__,memory_facts}.py`；`compat/sse.py`；`solver/memory_lowering.py`；4 个 `tests/test_p5*.py`；2 个 `tests/conformance/memory/*runtime*.py`；4 个 `scripts/p5_*.py`；本文与接口说明；`.gitignore` 仅追加 `.p5-work/`。未修改 P3 DTO/schema、已有 IR、旧 frontend 或 P4 frontends。

## 真实旧语义与差分

通过旧 Python 3.7.2 执行真实源码的只读导入，先安装 PLY 禁写与路径 write guard，跳过整个旧分析包的入口副作用。旧 CLI、guest 仿真和旧 solver 均未运行。旧环境 characterization 均成功且无写入越界；失败的目标 packet 兼容 probe 也保留，不覆盖。

- `VarExpr(r0+8).replace(r0,7)` 得到 15；target DAG lazy substitution 得到 15。Load 路径 offset=8、deref_count=1；地址路径 deref_count=0。旧 Store 缺少 value，target 明确拒绝。
- `TraceExpr.copy` 共享 expr，`deep_copy` 拷贝 expr；guard AST 共享、constraints list 分离。`RecursiveExpr.copy` 共享 inc_records，deep_copy 分离。`SimAction.copy` 分离 def_locs；原定义位置不被计为新 load use。
- 这是局部 characterization/结构差分，不是所有旧 VarExpr/RecursiveExpr 方法和原启发式 alias 的逐行迁移。新的不可变引用与旧的可变 trace 对象所有权行为有意分离；原实现继续作为 reference。

源 SHA256：

| 旧源码 | SHA256 |
|---|---|
| `dataflow/variable_expression.py` | `69e991f084b73c2f3b17cc74dde62a822763a0ac0d083101f3d690970539ffc3` |
| `dataflow/parse_ast.py` | `fa9e1c195b14c1e7c170a435725fcc98f2132c7a33221b2a5359af23ada7aca3` |
| 自定义 Claripy `ast/bv.py` | `6891be7647954e61cd6eae21f65f79305b4c9cba70a8a81eb1ef4f555e84509a` |

独立数值 oracle 使用标准 Python bytes/int，固定随机种子，在 LE/BE 下分别执行 80 次不同宽度/未对齐 store，核对重叠读取。对 16-bit 中间覆盖、模地址、pointer 值与 partial width 另有定值断言。

最终审查额外修正了两类边界：guarded read 不同定义不可被错误共享；typed `write(WriteMemory)` 不可忽略调用方 MayAlias/非唯一/非精确覆盖限制而升级强更新。后者已增加 2 项回归并重跑最终验收，先前 182 项结果作为历史保留；以最终 **184 项**为准。

## M-01～M-12 运行验收

所有条目 PASS；“预期返回 unknown/incomplete”是该条的断言，不被改写为 complete。`conformance-report.json` 分别保存实际值、精度、保守性、主 arena metrics、子用例 metrics、wall/CPU/进程峰值和回退。

| Gate | 实际断言/结果 | 完整性/精度的解释 |
|---|---|---|
| M-01 | 地址 offset 与 Deref 分离，未解析 Deref 不伪造对象 | unresolved location 为 Incomplete |
| M-02 | stack/global/heap/arg/return/unknown，7 对象；寄存器覆盖不改 Root；不同 frame 未证明则 MayAlias | ID/对象记录 exact；alias query 可为 may |
| M-03 | 旧版本未约束；新版本读到 `0x12345678`，唯一定义为新 write | exact strong update |
| M-04 | 1000 次 word 输入被 APG 接受，1001 次额外路径也接受，不同字段词拒绝 | 1 节点、1 summary；已证明语言包含，over-approx |
| M-05 | MayAlias 弱写保留 7/9 与两个到达定义；unknown location 不成 NoAlias | may 与 unknown 分开；额外 unknown 查询为 Incomplete |
| M-06 | LE/BE 中间 2-byte 覆盖均为 `0x11aabb44`；32-bit 模地址处单字节为 `0x34` | exact byte semantics；另有随机 oracle |
| M-07 | 同 CIR Store→Load 为 42；UnknownEffect 后读值未知；unlowerable helper 无 query | havoc/unsupported 为 Incomplete |
| M-08 | 链表 10/100/1000；tree/doubly-linked 字段闭包；有限循环 2 步；无限递归状态 8 步后保留 frontier | APG over-approx；无限状态分支明确 Incomplete |
| M-09 | node/edge/summary/SSE/objects/cells/states/context/alias/worklist 各预算独立拒绝；SMT 次数在 native probe 验证 | 子预算失败保持 Incomplete，无空结果成功 |
| M-10 | 局部读精化为 BVV(7,8)；1-step 限额不给 query；真实求解与状态检查见下 | 下沉失败不等于 UNSAT |
| M-11 | Source 经 guard 的 Store→Load 到 Sink；强覆盖切断旧流；false guard 排除；havoc 为 unknown；confirmed=0 | fact/依赖为 may，不声称漏洞 |
| M-12 | 同 CIR wire 往返得到相同内存快照、值、诊断；Memory-Semantics-v1 往返一致 | exact 的有界顺序样例；Rust 未执行 |

M-12 的执行 arena 指标补充在 `m12-execution-metrics.json`：两条输入各 11 个 DAG nodes、1 object、4 个已写字节、2 个 memory versions、9 次定义/执行步骤、21 次 alias 查询，facts=0、SMT=0。普通 conformance 主 arena 与子 arena 的计数分开，不能将空的外层 arena 计数当成子执行耗用。

## 表达式增长、事实与性能

| 链长 | 旧 expanded / unique / depth | 新 APG nodes / 普通 edges / summaries | 新 SSE 叶子 | 保留的输入 path segments |
|---|---|---|---|---|
| 10 | 31 / 22 / 21 | 1 / 0 / 1 | 1 | 20 |
| 100 | 301 / 202 / 201 | 1 / 0 / 1 | 1 | 200 |
| 1000 | 3001 / 2002 / 2001 | 1 / 0 / 1 | 1 | 2000 |

这组新样例只有 1 object、0 materialized cells、1 version、0 facts/alias/SMT；它证明路径表示与 MemoryRead 叶子的界，不是执行了 1000 次真实堆解引用。输入路径仍占线性空间。树/双向链表闭包主 arena 合计 2 nodes/4 summaries。M-11 的 Source→Sink 子 arena 和 native solver 样例另记真实 facts/cells/DAG/alias。全固件传播事实/Worklist、RSS/E2E 未采集，不能填 0 或推断加速倍数。

真实 solver 验证共 **14 个用例**：确定读值 SAT=42、矛盾 UNSAT、LE/BE 部分覆盖、MayAlias eval 候选 `{7,9}`、guard true/false=9/7、havoc 未约束字节、helper UNSUPPORTED、实际 1ms SMT TIMEOUT、3 个 backend UNKNOWN/TIMEOUT 注入、一次实际求解后次数限额返回 UNKNOWN。内存 lowering 的 8 次 port query 单列；压力/注入/限额测试另有 5 次真实 adapter 调用。注入的 UNKNOWN 不冒称自然出现的 unknown。SAT 和抽象 may-candidate 不升级为真实触发证明。

最终命令 wall / 50ms 采样的 launcher+children RSS：

| 命令类 | wall 秒 | 采样峰值 bytes |
|---|---|---|
| 纯内存回归 | 2.532 | 29499392 |
| 完整回归 | 8.390 | 78204928 |
| 旧 characterization | 1.453 | 42917888 |
| native probe | 2.407 | 68538368 |
| 12 个内存 fixtures + Golden table replay | 24.984 | 32354304 |

12 个 fixtures 的 shared Windows 进程累计 PeakWorkingSet 为 26804224 bytes；不是逐 fixture 独立峰值。Golden table replay 内部约 23.546 秒。原始命令、实际 CPU/wall、每条指标均保留在新证据中。frontend/lift、SMT 独占时间、FFI 和固件 E2E：未单独采集/未执行；Rust FFI 未执行。没有做统计性性能对比，也未宣称吞吐提升。

## Golden 与原始结果

只读使用批准基线 `baselines/rv130_1_0_3_44/20261028T051055Z-96d1c781/icall-targets.json`，SHA256=`3ce126b46a43e6563277a7ecf7f309c075602a240ddb46990c1f4ddb71de1a6c`。将 **14 个 callsite、535 条目标地址记录**作为合成具体指针表输入，逐字节 store/load 后每个有序目标列表一致。

这只是已知目标在内存模型中的保留回放，**不是重新发现 535 个目标**。归档 JSON 的 `add_icall_target=475` 为另一项新增计数，不与实际完整列表条数混同。全固件 `-i/-t`、CG 变化、switch/iCall 重建、旧 taint path/finding 差分未执行，不能凭此宣布 Gate A。旧 Golden 与历史结果从未改写。

## 命令、环境与不变性

从 BinaryAnalysis 使用明确解释器；最终命令均退出 0：

```powershell
./.venv/Scripts/python.exe -B -S -m unittest discover -s tests -p 'test_p5*.py' -v  # 31
./.venv/Scripts/python.exe -B -m unittest discover -s tests -v                    # 184
../EmTaint/.venv/Scripts/python.exe -B scripts/p5_legacy_probe.py --folder <fresh P5 folder>
./.venv/Scripts/python.exe -B scripts/p5_native_probe.py --folder <fresh P5 folder> --legacy-report <this run legacy-report.json>
./.venv/Scripts/python.exe -B -S scripts/p5_conformance.py --folder <fresh P5 folder>
git --no-optional-locks diff --check -- . ':!.venv'
./.venv/Scripts/python.exe -B scripts/p5_validate.py .p5-work/20261028T144038Z-ee69d677
```

全部 184 项包括原 141 项 + P5 31 项 + M-01～M-12 12 项。纯测试可在 `-S` 下运行；完整历史测试依赖既有 psutil，因此正常加载 `.venv`。开始时误用 `-S` 跑全套而缺少 psutil 的失败日志保留；正确完整前置回归 141 项通过，未安装任何包。

最终证据：`.p5-work/20261028T144038Z-ee69d677/validation-20261028T153255Z-d37210db/validation-p5.json`，Gate M=PASS。此前失败/成功 probes 和 182 项 validation 均保留；最终源文件清单/快照见同一 phase 根目录的 `final-source/` 与 `artifact-index.json`。

| 检查对象 | 文件数 | SHA256 / size / mtime_ns 前后一致 |
|---|---|---|
| 旧 EmTaint 全树 | 13461 | 是 |
| 目标 .venv | 13044 | 是 |
| Golden 全树 | 351 | 是 |
| P1 / P2 / P3 / P4 封存证据 | 214 / 55 / 78 / 80 | 是 |
| P3 IR / 原 frontend / P4 frontends | 49 / 7 / 8 | 是 |

三份用户 v5 规划文档字节不变；P3 冻结 Python/JSON contract 源与 schema 字节不变；新 memory/analysis 核心无 angr/pyvex/Claripy/Z3/IDA 原生 import。

目标 Python 3.12.9；angr/claripy/pyvex/cle/archinfo=9.3.4、z3-solver=4.13.0.0、psutil=7.2.2。旧 Python 3.7.2，固定旧 `.venv`、angr 9.0.9792/本地扩展 Claripy；未更换依赖。目标版本以用户已确认的 `TARGET_RUNTIME.md` 覆盖规划文件的 10.0.5 假设。

Git base：target=`6cb026767db005e48b36b994ee8542962b6df627`；legacy=`72a9e3081632b2f9d1881141bc7b0d43c7158033`。旧原有 dirty：`data/ida_data/.../httpd_icall.json`、`dataflow/variable_expression.py`，以及未跟踪的历史 `data/result_data/...json`，均保持原样。目标已有用户/前阶段修改完整保留，不把其 diff 归为 P5 新改动。

## 回退与下一阶段

默认保持旧路径。实验 SDK `select_memory_engine(legacy=reference)` / `select_memory_engine('apg',apg=engine)` 明确选择；未提供 reference 就报错，不能假装已有完整 target legacy CLI。未知 solver/内存结果保留 Unknown/Incomplete；不使用“零漏洞”作为成功回退。

当前主要限制：points-to 为保守 top 候选；不精确还原任意 Deref 链；MayAlias/weak/join 可能增加路径和值；没有完整 SMT Array、原子/helper/ABI/寄存器 transfer；相关定义展开仍受预算；对象 size 与生命周期只有限检查；Source/Sink 显式输入，未迁完整检测规则。快照回放的调度 frontier/累计计数/Source binding 必须由 Session 另存。上述限制均不被称为已精确支持。

下一阶段 **P6**：逐步接入 Fast/AccurateDataFlow、Switch/iCall、CG 版本及失效，验证真实 `-i` callsite→target/证据差分，继续区分 confirmed/may/unknown。P7 才进行完整 taint/CLI 与 Gate A。**本轮停止在 P5，未进入 P6 或 Rust。**

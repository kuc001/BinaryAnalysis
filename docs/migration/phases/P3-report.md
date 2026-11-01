# P3：Typed CIR / Memory Contract / Wire v1

2026-10-28。**P3 契约 Gate：PASS。** 完成纯 Python 类型、验证、接口、schema、ADR 和 M-01…M-12 契约 fixtures。**P5 Gate M 未执行，真实内存引擎未实现；本轮未进入 P4/P5。** 不安装依赖、不运行固件 `-i/-t`、不开发 Rust。

接口说明见 [P3_CONTRACT.md](../P3_CONTRACT.md)，设计决定见 [ADR-015](../ADR-015-P3-contracts.md)。

## 交付与边界

| 层 | 本轮实现 | 本轮没有实现 |
|---|---|---|
| CIR | typed BV/bool/pointer、Compute、寄存器片段/写策略、Load/Store、Call/ABI/footprint、Branch/Jump/Return、Origin、Unknown/Havoc | 真实 VEX/Microcode lowering、执行器、完整 SSA/use-def |
| Access | 稳定 Root、Offset/Deref/Index/UnknownOffset、Path、APG Node/Edge/Summary、scope 与精度诊断 | APG 构造/归纳、summary 覆盖证明、widening/收敛 |
| Heap/Memory | 对象身份、cardinality/lifetime、Location/Cell、Initial/Write/Join/Havoc/Read 与版本引用；定义 DAG、位宽/端序/guard 校验 | 真实 points-to/alias、字节更新、读值解析、heap 执行 |
| SSE/Taint | typed SymbolicExprId / DAG 描述、MemoryRead(state,location)、TaintFact 的 path/APG、context/state/guard/provenance | hash-consing/substitute 引擎、污点传播、Source→Sink 证明 |
| Ports | AbstractHeap、MemoryQueryPort、SolverLowering、预算与状态契约；显式 Unsupported 默认对象 | 内存 lowering、SMT byte-array 后端、实际分析查询 |
| Wire | CIR-Wire-v1 / Memory-Semantics-v1、严格 tagged JSON、87 个注册 record/enum 类型、结构 schema 与关联验证 | Rust/FFI、其他 schema 版本的自动迁移 |

Load/Store 是有序 effects；Access/APG 是位置/路径语言；Heap/MemoryVersion 是对象与状态定义；SSE 是值依赖。它们没有被合并成旧 Claripy Load/Store AST。`p+8` 与 `*(p+8)`、地址空间、位宽、端序和 guard 在表示中区分。

强更新除了 MustAlias、唯一目标与精确覆盖，还要求精确 location 和 singleton 对象事实；摘要/未知对象不允许凭单个 ID 做强更新。P3 校验证据声明的一致性，不生产或证明 alias/cardinality。不同根/帧/context 不自动推出 NoAlias。

AnalysisScope 重用 P2 身份并绑定 session、CFG/CG/state 版本，支持 from_session/assert_current；跨 scope、过期或悬空引用拒绝。MemoryVersion 与 SSE 联合依赖中的循环拒绝；APG 的循环合法但不证明数据流收敛。

未知外部调用默认包含所有区域写入与寄存器 clobber；UnknownEffect 必须保留范围、原因和 unsupported/incomplete。默认 AbstractHeap/MemoryQueryPort 抛 UnsupportedSemantics；默认 lowerer 返回 UNSUPPORTED 和 query=None，不返回空事实、NoAlias 或假 UNSAT。

LoweringRequest 显式保留 focus expression、guards、check/eval/min/max、limit 和预算。READY 输出目前限 P1 纯 BV SolverQuery；P5 可按局部定义/BV/ITE 实现语义。字节数组 Select/Store 未提供可用后端，必须明确扩展或保持 Unsupported，不能绕过 P1 的未 lower memory-op 拒绝。

## Schema、样例和兼容路径

- [CIR-Wire-v1 schema](../schemas/cir-wire-v1.json)
- [Memory-Semantics-v1 schema](../schemas/memory-semantics-v1.json)
- [完整 CIR + memory 合成样例](../schemas/examples/cir-memory-fixture.json)（23829 UTF-8 bytes，不含固件原件）
- [独立 memory 合成样例](../schemas/examples/memory-fixture.json)（19721 bytes）

完整包有明确版本、架构/端序、二进制身份、producer/origin、capabilities 和 assessment。未知版本/类型/字段/capability、重复 JSON key、浮点/NaN、超大整数和超限载荷均拒绝。所有字段显式传输，None/0/false 不合并，不动态导入类型或反序列化原生对象。

默认 wire 预算为 16 MiB / 100000 nodes / 64 层 / 4096-bit integer；另有 APG、SSE、heap、worklist、context、alias、SMT 的独立语义预算声明。语义预算尚没有引擎执行计数，不能据此声称终止性已经验证。

两个 JSON Schema 由确定的 registry/字段类型生成，runtime 构造器补充 scope、引用、DAG、位宽与完整性检查。目标环境未安装 jsonschema，本轮也未安装；测试使用独立的已用结构关键字 evaluator，未声称经过完整第三方 Draft 2020-12 validator。版本冻结和后续升级规则写入 ADR-015。

旧 `emtaint/ir/` 的 **46 个既有文件**（包括 VexIR、旧 Load/Store wrapper）全部内容和 mtime 不变，只新增 canonical 子目录。P2 已接受实现的源文件也保持不变（忽略文件仅追加本轮证据目录）。没有迁移原 SSE、alias、Fast/AccurateDataFlow、FastSearch 或 Taint 业务。

## 测试与 M-01…M-12

先添加契约测试并确认缺少模块时失败，再实现类型/校验；后续负例曾揭示未使用 pointer 声明、taint APG 根归属和 wire 大整数的漏检，均已补校验。最终共 **135/135** 回归通过，其中既有 99 项、本轮 24 项类型/wire 测试及 12 项内存契约 fixtures。

| fixture | P3 实际检查 | P5 运行语义状态 |
|---|---|---|
| M-01 | Offset/Deref 区分、宽度/端序/Origin、往返 | NOT_IMPLEMENTED |
| M-02 | 稳定参数根、寄存器覆盖、frame 区分 | NOT_IMPLEMENTED |
| M-03 | Write parent 与读前/读后版本引用、effect 顺序 | NOT_IMPLEMENTED：未计算实际读取值 |
| M-04 | APG summary 循环/范围/来源/precision_loss、soundness=unknown | NOT_IMPLEMENTED：未证明路径覆盖或 alias |
| M-05 | May/Unknown 只能 weak；强写必须满足完整前提 | NOT_IMPLEMENTED：未执行 weak/strong heap 更新 |
| M-06 | 不同端序、2-byte/4-byte 重叠区间、寄存器写策略、模偏移 | NOT_IMPLEMENTED：未计算真实字节覆盖值 |
| M-07 | unknown/havoc/外部 footprint 不允许无副作用省略 | NOT_IMPLEMENTED |
| M-08 | 10/100/1000 路径描述与手工 next* summary；缺省解析明确报错 | NOT_IMPLEMENTED：树/双向链表/函数递归 runtime 待 P5 |
| M-09 | 独立预算字段、耗尽 Incomplete 诊断、wire budget 拒绝 | NOT_IMPLEMENTED：未执行 worklist/heap/solver 计数 |
| M-10 | raw Load 不进入 symbolic op/lowerer，Unsupported/solver 状态不转 bool | NOT_IMPLEMENTED：没有内存 SMT 查询 |
| M-11 | may-taint 的 root/APG/context/state/guard/provenance | NOT_IMPLEMENTED：未确认漏洞 |
| M-12 | 完整 CIR+memory/独立 memory 的严格往返与诊断保留 | NOT_IMPLEMENTED：未比较实际引擎 facts |

每项输出独立的 contract_status=PASS 与 runtime_gate_m=NOT_IMPLEMENTED，保存预期/实际、保守性范围、descriptor counts、runtime null 指标和回退。手工 summary 没有被报告为从长链表自动归纳出的收敛结果，元数据往返没有被报告为完整 Python APG 引擎等价。

额外负例覆盖悬空 origin/block/value、缺失 capability、未知 opcode、副作用被标 complete、跨 scope、SSE/内存定义循环、非 singleton 强写、错误 taint root/address_space、guard/寄存器/位宽错误、未知 schema/enum/字段、duplicate key 和 wire 预算。干净 `python -B -S` 中用 import blocker 拒绝 angr/Claripy/pyvex/IDA/NetworkX，核心仍可导入。

## 命令与证据

从 `BinaryAnalysis` 使用明确目标解释器：

| 命令 | 退出码 / 结果 |
|---|---|
| `.venv/Scripts/python.exe -B -S -m unittest discover -s tests -p test_p3_contracts.py -v` | 0，24/24 |
| `.venv/Scripts/python.exe -B -S -m unittest discover -s tests/conformance -t tests -v` | 0，12/12 |
| `.venv/Scripts/python.exe -B -m unittest discover -s tests -v` | 0，135/135 |
| `git --no-optional-locks diff --check -- . ':!.venv'` | 0 |
| `.venv/Scripts/python.exe -B scripts/p3_validate.py .p3-work/20261028T090527Z-dba03447` | 0，P3 CONTRACT GATE=PASS |

最终证据：`.p3-work/20261028T090527Z-dba03447/validation-20261028T095507Z-e642d5ea/validation-p3.json`。前一份 133 测试成功检查仍保留；之后只因补充 origin 与查询操作校验/测试而重复验证，未覆盖旧证据。命令 stdout/stderr、fixture 结果、完整 JSON 样例、版本、前后清单及最终源码快照均单独封存。

本轮新增 17 个 Python 文件：shared contracts；canonical model/wire/export；memory access_path/state/abstract_heap/query_port/export；SolverLowering；conformance 包/fixtures/tests、类型/wire 测试、schema shape helper、验证脚本。另新增两个 schema、两个样例、ADR/接口说明/本报告，`.gitignore` 增加 `.p3-work/`。没有更改三份用户 v5 规划文件或历史阶段证据。

## 环境、完整性、性能与未执行项

实际目标 Python 3.12.9，包元数据 angr/claripy/pyvex/cle/archinfo 均 9.3.4，z3-solver 4.13.0.0。沿用用户 `.venv` 和 direct import claripy 决策；本轮只读元数据，不执行 native 前端分析。旧 Python/angr 版本沿用 P0/P1 证据，本轮未导入旧 native 库。

完整性前后 SHA256/size/mtime_ns 相同：EmTaint **13461** 文件、目标 `.venv` **13044** 文件、baselines **351** 文件、P1 封存证据 **214** 文件、P2 封存证据 **55** 文件、既有 VexIR/IR 文件 **46** 个。P2 source comparison=true；AGENTS/BLUEPRINT/CODE_TASK SHA 与入口一致。未 reset、clean、提交、push 或写历史结果。

Git base：目标 `6cb026767db005e48b36b994ee8542962b6df627`；旧仓库 `72a9e3081632b2f9d1881141bc7b0d43c7158033`。完成时只读复核一致。封存后仅补充本段 Git 信息，原源码/测试证据不改写；补记随文档 addendum 归档。两个完整公开样例也通过独立 schema shape evaluator 的只读复核。

最终测试 wall（含 Python 启动/测试框架）分别约 1.844 秒、0.937 秒、9.578 秒，不是固件或纯引擎性能。合成 snapshot 描述 3 APG nodes、2 edges、1 summary、4 symbolic nodes、2 MemoryVersions、1 对象描述和 1 taint 描述；这是显式构造的 descriptor 数量。运行时 APG/Heap/DAG/facts/Worklist/RSS 为 null，P3 fixtures 求解器调用为 0。

真实 Store→Load、MayAlias 更新、重叠字节值、摘要 soundness、旧自定义 Load/Store 差分、前端 lifting、Source→Sink、Golden 语义重跑和 E2E/FFI 性能均未执行。P1 的实际求解器证据仍独立保留；P3 不借它宣称内存 lowering 或 Gate M 通过。

## 回退与下一步

旧 VexIR、P2 门面与旧 EmTaint 算法保留；新 contract 不切默认引擎。未实现操作显式 Unsupported，不能自动切旧语义后将结果标为新内存模型完成。

下一阶段建议 **P4**：以 angr/Claripy 9.3.4 的实际环境，实现 angr→VEX→CIR 与只读 IDA metadata+字节→VEX→CIR；保留一个 IDA block 对多个 IRSB 的映射、opcode/位宽/端序/guard/Origin，未支持项显式 UnknownEffect/Incomplete。P5 再实现 APG/Heap/MemoryVersion/SSE/Lowering 与 M-01…M-12 runtime，完成 Gate M。**本轮止于 P3，未执行 P4/P5 或 Rust。**

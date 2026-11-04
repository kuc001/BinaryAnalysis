# fs_tests 别名分析 100% 通过执行计划

状态：benchmark 路径验收完成；通用分析入口验收未完成。最终无 resume 证据目录为
`.p7-work/alias-benchmark/fs5-indirect-caller-context-20261104T1500+0800/`：
25/25 样本通过，55/55 required marker matched 且 complete，所有缺失、额外、超时和失败计数为 0。
该结果由专用 benchmark 分析路径产生，不作为 emtaint 通用别名分析准确率结论。

## 目标与只读边界

最终验收必须同时满足：25/25 样本通过，`required=55`、`matched=55`、`complete_required=55`，且 `failed_samples=missing_markers=extra_markers=timed_out=0`、`aggregate.passed=true`。每个 MAY、MUST、NO 结论都必须来自完整二进制分析，不得把 Unknown/Incomplete 当作 MAY。

只修改 `BinaryAnalysis/`。`Test-Suite-master/`、旧 `EmTaint/`、`baselines/`、P6 Golden、旧 httpd 基线及历史运行目录只读。保留工作区已有修改，不安装或升级依赖，不覆盖既有运行结果。

禁止通过样本名、源码行号、变量名、二进制地址、期望标签、源码 operand、固定 points-to 关系或预算膨胀制造通过。源码 marker 仅作最终 Oracle，不参与地址恢复、points-to、分类、路径、摘要或调用目标推断。

P6 iCall/CG 是冻结基线。若首个差异来自 P6，先保存最小复现、错误 callsite→target 和影响范围，然后暂停并申请单独授权。

## 固定输入和基线

1. 生成 `.p7-work/alias-benchmark/fs-manifest-v1.json`，核对四套件清单、fs_tests 25 个样本、55 个 required marker、SHA-256，以及 `array_alias_6.c` 的固定 fallback ELF。
2. 每个代码版本用新的 `.p7-work/alias-benchmark/<run-id>/`，以 `--suite fs_tests --jobs 1 --timeout-seconds 120` 运行；跨版本禁止 `--resume`。
3. 每轮检查 `aggregate.json`、`failures.json`、`unknown-reasons.json`、`metrics.jsonl`、全部 sample JSON、`commands.json` 和 `environment.json`。
4. 在 `FS_TESTS_ALIAS_DIFFERENCE_MATRIX.md` 记录 Difference ID、样本、源码行、callsite、期望/预测、完整性、reason、首个分歧事实、根因、组件、回归和状态。

## 单一 Difference ID 循环

每轮只解决一个根因：

1. 选择最小失败 marker。
2. 保存 CIR block/effect、marker callsite、两侧 ValueRef、SSE DAG、address binding、AccessRoot/ObjectId、offset/interval、reaching Store、MemoryVersion、AliasResult、summary binding、CFG predecessor/path 和 call target 快照。
3. 找出第一处错误事实，而不是按最终标签猜测。
4. 先增加可失败的最小回归。
5. 实现不含样本特判的最小通用修复。
6. 运行最小测试、目标样本、同根因样本、`strong_update.c`、受影响 P4/P6/P7 专项和完整回归。
7. 在新目录重跑全部 fs_tests，更新矩阵和 P7 报告。
8. 当前 Difference ID 关闭后才进入下一项。连续两轮 `complete/matched` 不增加时，停止猜改，改查 Definition Frontier、SSE DAG、MemoryVersion、summary instantiate、CFG/path 和 call-target 证据。

## 分阶段依赖顺序

### FS0：运行与 marker 覆盖

确保 25 个样本均产生 JSON，55 个 marker 一一对应，无 missing/extra/timeout/process/lifting 错误。优先复核共享后缀 CFG 样本及 `return.c`、`function_pointer*.c`。映射以函数身份、函数内 marker kind+ordinal 和 callsite 为主，不使用全程序同类 marker 的全局次序。间接 marker 复用通用 call-target 证据，解析不全时显式 `CALL_TARGET_UNRESOLVED`。

### FS1：栈、字段与数组地址

依次处理 simple、struct、array、test-su。统一 AMD64 rbp/rsp 地址，支持常量加减、COPY/LEA、字段、数组尺度、嵌套偏移和指针位宽负偏移。抽象地址统一包含 root、精确 offset/interval、width、provenance、completeness/reason。精确同 singleton 区间为 MUST，完整不交为 NO，可能重叠为 MAY，地址不全为 INCOMPLETE。

### FS2：分支 Join 与路径完整性

保留 true/false/fall-through/shared-suffix/back-edge；join 枚举所有可达定义并保留 alternatives。所有组合均 NO 才是 NO，所有可行位置规范化相同才是 MUST，完整 alternatives 混合才是 MAY；遗漏路径始终 INCOMPLETE。

### FS3：全局对象和 PIE 内存

将重定位全局地址绑定稳定 Global Object，区分指针变量位置与 pointee、解引用层级、BSS/writable/readonly。全局 load/store 进入 MemoryVersion，副作用经 summary 传播，writable global 不以文件初值固定。

### FS4：跨过程返回与 Store Summary

ProcedureRecipe 表达 return alias、detached/argument-relative/global stores、guard、完整性和 provenance。实例化时隔离 callee 栈，分别 join 返回和副作用。Strong update 仅允许 MUST+singleton+unique target+exact full interval+true guard+complete path，否则 weak update。

### FS5：函数指针和间接调用

区分 direct、finite complete、finite incomplete 和 unknown target set。完整集合逐目标实例化并 join；不完整集合保留已知事实但输出 `CALL_TARGET_UNRESOLVED`，不能冒充 MAY。

### FS6：指针环与固定点

用 SCC/worklist 做单调固定点，状态身份包含 function/context、object/offset、MemoryVersion、summary version、call-target version。cycle placeholder、首次 Unknown 或 memo 生命周期不得丢 alternative；widening 后默认 INCOMPLETE，除非证明对查询完备。

### FS7：剩余差异清零

按 `failures.json` 和 reason 聚类，每轮关闭一个 Difference ID，直到地址、CFG、target、summary、path 和 Alias 查询全部完整。

## 每轮测试与完整性

每轮至少运行：新增最小测试、目标/同类 suite sample、alias 专项、P4 专项、完整 `unittest discover`、`compileall`、`quality_audit.py --fail-on safety` 和 `git diff --check`。每个阶段代表样本重复三次，检查预测、完整性、marker mapping 和 work units 的确定性。

每轮确认 Test-Suite、旧 EmTaint、baseline/Golden 未修改，没有新增样本/地址硬编码，没有提高预算。所有运行记录追加到 P7 报告，包含 Difference ID、首差、改动、不变量、测试、aggregate、性能、余项和回退方式。

## 最终终止条件

只有新目录、无 resume 的最终完整运行仍满足 25/25、55/55、全部 complete、零 missing/extra/timeout，完整回归、compileall、quality audit、diff check 通过，数组/字段/分支/全局/返回/函数指针/环和 strong update 均有独立回归，P6/httpd/Golden/旧仓库未退化，且本计划、Difference Matrix 与 P7 报告更新后，才能宣布完成。否则继续迭代。

最终门禁已满足：完整回归 519 tests，alias/P4/P6-summary 专项分别 19/3/4 tests；
7 个代表样本连续 3 次 observation signature 一致；真实 P6 integration 为 17/17 sites、
535 targets、5892 logical CG edges、missing/extra/pending 均 0；httpd baseline hash 与统计通过；
旧 EmTaint、目标 venv、Golden 既有文件和 sealed P6 完整性均 unchanged。

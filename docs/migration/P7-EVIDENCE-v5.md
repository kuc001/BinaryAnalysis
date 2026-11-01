# P7 私有证据 v5：延迟格式参数选择器

范围只包括 P7 的 `TaintDependency`、ProcedureSummary 与 requirements 私有证据。CIR-Wire-v1、Memory-Semantics-v1、P3 公共 DTO、P6 iCall/CG、Golden 均不变；v1–v4 历史归档不改写，严格 reader 继续原样读取。

v5 增加 `format_argument` dependency，其 value 为 `DeferredFormatArgument(format_slot, position, dependency)`。它表达旧 `vsnprintf` 规则中尚未获得 caller 具体 format 时的条件关系：只有 caller format 的 `position` 被旧 FormatParser 分类为字符串参数，嵌套 dependency 才能绑定为普通 Source/argument/global 依赖。具体 `%d` 等非字符串位置不传播；format 仍未知时保留 selector 和显式 Unknown，不能解释为 clean。

selector 只保存当前 detached procedure 的形参槽、旧格式参数位置和另一个 detached dependency。不得包含 caller 作用域的 SSE、AccessPath、APG、MemoryVersion 或 TaintFact ID。跨调用绑定时，具体只读 format 从当前映像解析；仍为 caller 形参时同时重绑定 format 槽和嵌套 dependency，但不提前登记/导入 Source。无法证明形参映射时只产生 Unknown。

va_list Store 的位置仍使用旧版 `base/base+constant` 与 `offset % arch.bytes` 规则。一般 local-address 结果的 Unknown offset 不可提升；只有既有 `exact_stack_address` 已证明未改写 entry SP 和常量位移时，才允许形成候选。版本化读取仍通过 MemoryQueryPort，MayAlias、解析失败和预算中断保持 Unknown/Incomplete。

EvidenceEncoder 对 selector 中的 dependency 递归编码，并共用原 constraint recipe 哈希仓库。v5 reader 严格校验 selector 字段与嵌套 dependency；v4 及更早 reader 语义保持不变。`requirements.json` 随 writer 升为 v5，候选引用坐标格式仍为 `P7-candidate-refs-v2`。

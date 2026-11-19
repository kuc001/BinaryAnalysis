# F1-A · 真实 CTree 审计与 HIR 契约

负责人通过 F1-01 至 F1-09 批准以下有限切片。主验收函数为 `sub_632F8`。第 1–2 节保留 F1-A 审计证据，后续章节记录批准后的实现边界。

## 1. 输入与二进制身份

| 字段 | 实测值 |
| --- | --- |
| 文件 | [ctree_632f8_39ebd8aca9.json](../../.f1-input/ctree/ctree_632f8_39ebd8aca9.json) |
| 定位方法 | 枚举目录内 JSON，以内部 `function.entry_ea == 0x632F8` 选中唯一文件 |
| 源 Schema / 文件大小 | `IDA-CTree-Source-F1-draft-v2` / 55,114 字节 |
| 文件 SHA-256 | `209e40012ce07ae79ce95847b5a3792a687536951772877fbd5847ebd06c4c3e` |
| Export Fingerprint | `86b88fbfda634919dab74241ce008ba00a424cf3d67c096e5cb5cf3ea015a0c8`，按 Exporter v2 复算匹配 |
| Exported at UTC | `2026-11-19T07:28:06.630548+00:00` |
| 导出环境 | IDA `9.3`，Hex-Rays `9.3.0.251224`，Python `3.15.2`，Processor `ARM` |
| Maturity | `CMAT_FINAL`，值 `8` |
| Diagnostics | `[]` |
| 原始输入 | `D:\Codes\firmware-binaries\rv130_v44\httpd`，626,308 字节 |
| Binary SHA-256 | `334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787`，ELF 实读、预期与 `input_file_sha256` 三方一致 |
| ELF | ELF32、Little Endian、`EM_ARM`、`ET_EXEC`，入口 VA `0x10E58` |
| 地址 | `source_address_domain = IDA_EA`，IDA image base `0x8000`，函数 EA 区间 `[0x632F8, 0x6339C)`，RVA 区间 `[0x5B2F8, 0x5B39C)` |

同一 ELF 的最低 `PT_LOAD` VA 为 `0x8000`，可执行文件映射覆盖整个函数区间。导出基址一致，并在四个调用位置用 ELF 的 ARM `BL` 验证了指令与直接目标的对应。证据支持本样例内按 `RVA = IDA_EA - IDAImageBase` 与 `LinkedVA = ELFImageBase + RVA` 转换，即 `0x632F8 = 0x8000 + 0x5B2F8`。文件偏移另按 `p_offset + (LinkedVA - p_vaddr)` 换算。此段的文件偏移恰好与 RVA 数值相同。一般化映射需要额外的段、重定位与处理器模式证据。非指令对齐的 lvar definition EA 保留为 IDA 元数据。

## 2. 完整性与覆盖

全文件严格 JSON 读取未发现重复对象键。53 个节点全部从 `node:root` 可达，52 条父子边，根入度为 0，其余入度为 1。无悬挂、重复访问或环，路径与角色索引相符。根深度取 0 时最大深度为 9。41 个节点有 EA，12 个为 `null`。全部 53 个节点为 `represented`，opaque 0、源导出报告的 unsupported/partial 节点 0，F1 方案可结构化映射全部已观察 opcode。独立 IDA visitor 记录为 13 语句、40 表达式、53 总计，状态 0。当前核查读取了记录的 visitor 结果。

| 分类 | 完整 opcode 直方图 |
| --- | --- |
| Statement · 13 | `cit_block` 4，`cit_expr` 5，`cit_for` 1，`cit_if` 2，`cit_return` 1 |
| Expression · 40 | `cot_asg` 3，`cot_call` 4，`cot_cast` 1，`cot_helper` 1，`cot_idx` 1，`cot_lnot` 1，`cot_ne` 1，`cot_num` 5，`cot_obj` 6，`cot_preinc` 1，`cot_ptr` 1，`cot_ref` 1，`cot_str` 1，`cot_var` 13 |

While、do、switch、case、member、条件表达式和 break/continue 均为 0。数组索引为 `cot_idx`。二元比较为 `cot_ne`，一元逻辑和更新分别为 `cot_lnot` 与 `cot_preinc`。

### 变量与类型

| lvar_index | 显示名 | 角色 | type_id | storage | definition_ea | 字节 |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `a1` | 参数 | `type:d6930df7c30074b40026194c10c8667512e160f4dfea7878ca6577df57f16ef1` | micro_register 8 | `0x632f8` | 4 |
| 1 | 空 | 局部 | `type:d6930df7c30074b40026194c10c8667512e160f4dfea7878ca6577df57f16ef1` | micro_register 44 | `0x63315` | 4 |
| 2 | `i` | 局部 | `type:d6930df7c30074b40026194c10c8667512e160f4dfea7878ca6577df57f16ef1` | micro_register 28 | `0x6333d` | 4 |
| 3 | `v3` | 局部 | `type:3bbcf2275d0e886f7f0347a810c9ca9e06126b6e6b6f0d686141b3394581b382` | micro_register 8 | `0x6335d` | 4 |
| 4 | 空 | 局部 | `type:d6930df7c30074b40026194c10c8667512e160f4dfea7878ca6577df57f16ef1` | micro_register 8 | `0x63381` | 4 |
| 5 | `dest` | 局部 | `type:af7d7050df60d81aaa95d311c897f5149e682f89430ae497735f15f27b4e3bda` | stack；IDA frame offset 10；raw stack offset 10 | `0x63320` | 14 |

仅 lvar 5 标记 `user_name=true`，六条变量记录的 `user_type` 均为 false。无名 lvar 1 和 4 仍保留，13 次 `cot_var` 只引用有名的四个变量。同一微寄存器编号出现在多个 lvar 上。名称、存储复用和定义地址均不足以建立变量等同。

类型共 23 条。按互斥分类统计为普通 Pointer 3、Function Pointer 4、Array 3、Function 4、Primitive 9（含 void）、Struct/Union 0、Enum 0、Unknown 0。若按 `is_ptr` 计数则为 7，含函数指针。40 个表达式均有类型引用，覆盖 12 个类型 ID。6 个变量均有类型引用，覆盖 3 个类型 ID。类型记录内部有 14 条引用，指向 9 个不同类型 ID。引用全部解析。三条数组的长度分别为 14、14、45。两个 `char[14]` 记录的元素引用不同，保持原条目身份。

导出的描述可携带宽度、数组计数、指针目标、函数参数与返回引用和部分可变参数信息。未给出完整限定符、类型来源链、调用约定与实参位置结构、参数顺序以外的求值保证、聚合布局与对齐的完整证据。样本无可验证的 DWARF/编译器类型来源，也没有可验证的结构体或枚举实例。类型状态统计为 bounded 14、descriptive 9，partial type 0。显示串仅用于展示，即使写有 `__fastcall` 或 `const`，也不能充当结构化 ABI 或限定符证据。

### 代表性真实子树

表内为完整源节点 ID 和父 ID。类型 ID 为源表内唯一前缀，精确引用通过完整节点 ID 在 JSON 中解析。子槽按 JSON 顺序列出。

| 源 Node ID | 父 Node ID | Opcode / EA | Type ref | 有序子槽 | 源语义 | HIR 提议 |
| --- | --- | --- | --- | --- | --- | --- |
| `node:root` | — | `cit_block` / `0x63320` | — | `statement[0]` cit_expr → `statement[1]` cit_for → `statement[2]` cit_return | 主体按初始化、循环、返回排列 | Block |
| `node:root/statement[0]/expression[0]` | `node:root/statement[0]` | `cot_call` / `0x63320` | `type:4bb4557e…` | `callee[0]` cot_helper → `argument[0]` cot_var → `argument[1]` cot_str | helper 和两个参数按角色分开。初始化的机器调用证据单列 | Call，目标为 helper |
| `node:root/statement[0]/expression[0]/callee[0]` | `node:root/statement[0]/expression[0]` | `cot_helper` / `null` | `type:e15c22c1…` | — | 结构化 helper 名称为 `strcpy`，EA 缺失 | HelperRef |
| `node:root/statement[0]/expression[0]/argument[0]` | `node:root/statement[0]/expression[0]` | `cot_var` / `0x6331c` | `type:4bb4557e…` | — | 引用 lvar 5。保留数组及实参位置 | VariableRef，实参转换单独记录 |
| `node:root/statement[0]/expression[0]/argument[1]` | `node:root/statement[0]/expression[0]` | `cot_str` / `null` | `type:7e3ef1e6…` | — | 字符串载荷 `ddns_enable_X`，EA 缺失 | Constant(string) |
| `node:root/statement[1]` | `node:root` | `cit_for` / `0x6333c` | — | `init[0]` cot_asg → `condition[0]` cot_ne → `step[0]` cot_preinc → `body[0]` cit_block | 存储槽序与执行序不同。执行顺序为 init、condition、body、step | Loop(for) |
| `node:root/statement[1]/init[0]` | `node:root/statement[1]` | `cot_asg` / `0x6333c` | `type:ed8a5bb6…` | `x[0]` cot_var → `y[0]` cot_num | 向 lvar 2 写入 1 | AssignExpr |
| `node:root/statement[1]/condition[0]` | `node:root/statement[1]` | `cot_ne` / `0x6337c` | `type:c07fcc34…` | `x[0]` cot_var → `y[0]` cot_num | lvar 2 与常量 5 比较 | Binary(ne) |
| `node:root/statement[1]/step[0]` | `node:root/statement[1]` | `cot_preinc` / `0x63374` | `type:ed8a5bb6…` | `x[0]` cot_var | 对 lvar 2 做前置递增，同时有读写 | Unary(preinc) |
| `node:root/statement[1]/body[0]` | `node:root/statement[1]` | `cit_block` / `0x63354` | — | `statement[0]` cit_expr → `statement[1]` cit_expr → `statement[2]` cit_if → `statement[3]` cit_if | 顺序为格式化调用、结果赋值、空指针回退、字节检查 | Block |
| `node:root/statement[1]/body[0]/statement[0]/expression[0]` | `node:root/statement[1]/body[0]/statement[0]` | `cot_call` / `0x63354` | `type:ef63a4ff…` | `callee[0]` cot_obj → `argument[0]` cot_var → `argument[1]` cot_num → `argument[2]` cot_obj → `argument[3]` cot_obj → `argument[4]` cot_var | callee 对象 EA 为 0x10390。五个参数分别为 lvar 5、14、对象 0x82EAC、对象 0x92D94、lvar 2 | Call，保留全部实参 |
| `node:root/statement[1]/body[0]/statement[1]/expression[0]` | `node:root/statement[1]/body[0]/statement[1]` | `cot_asg` / `0x6335c` | `type:4bb4557e…` | `x[0]` cot_var → `y[0]` cot_cast | 将 cast 的结果写入 lvar 3 | AssignExpr |
| `node:root/statement[1]/body[0]/statement[1]/expression[0]/y[0]` | `node:root/statement[1]/body[0]/statement[1]/expression[0]` | `cot_cast` / `0x6335c` | `type:4bb4557e…` | `x[0]` cot_call | 结果转为指针。子调用目标对象 EA 为 0x1D170，实参为 lvar 5 | Cast + Call |
| `node:root/statement[1]/body[0]/statement[2]` | `node:root/statement[1]/body[0]` | `cit_if` / `0x63364` | — | `condition[0]` cot_lnot → `then[0]` cit_block | 条件是对 lvar 3 的逻辑非，只有 then 子块 | If + Unary(logical_not) |
| `node:root/statement[1]/body[0]/statement[2]/then[0]/statement[0]/expression[0]/y[0]` | `node:root/statement[1]/body[0]/statement[2]/then[0]/statement[0]/expression[0]` | `cot_ref` / `0x63364` | `type:4bb4557e…` | `x[0]` cot_idx | 取索引表达式的地址，保留索引单位 | AddressOf |
| `node:root/statement[1]/body[0]/statement[2]/then[0]/statement[0]/expression[0]/y[0]/x[0]` | `node:root/statement[1]/body[0]/statement[2]/then[0]/statement[0]/expression[0]/y[0]` | `cot_idx` / `null` | `type:bf6e7199…` | `x[0]` cot_obj → `y[0]` cot_num | 基对象 EA 为 0x8CF60，索引为 0x2C。取址上下文中没有隐式读取 | ArrayAccess(lvalue) |
| `node:root/statement[1]/body[0]/statement[3]` | `node:root/statement[1]/body[0]` | `cit_if` / `0x63368` | — | `condition[0]` cot_ptr → `then[0]` cit_block | 解引用结果用作分支条件，只有 then 子块 | If |
| `node:root/statement[1]/body[0]/statement[3]/condition[0]` | `node:root/statement[1]/body[0]/statement[3]` | `cot_ptr` / `0x63368` | `type:bf6e7199…` | `x[0]` cot_var | 访问宽度字段为 1 字节，操作数为 lvar 3 | Dereference，附宽度证据 |
| `node:root/statement[1]/body[0]/statement[3]/then[0]/statement[0]/expression[0]` | `node:root/statement[1]/body[0]/statement[3]/then[0]/statement[0]` | `cot_call` / `0x63394` | `type:ef63a4ff…` | `callee[0]` cot_obj → `argument[0]` cot_var → `argument[1]` cot_var | 目标对象 EA 为 0x62B30。第一个实参为 lvar 0，第二个为 lvar 2 | Call |
| `node:root/statement[2]` | `node:root` | `cit_return` / `0x63388` | — | `value[0]` cot_num | value 子节点是数值 0 | Return |

机器证据以 ELF 已映射字节为准。`BL` 分别为 `0x63320 → 0xFFF4`、`0x63354 → 0x10390`、`0x6335C → 0x1D170`、`0x63394 → 0x62B30`。题给汇编将第一个机器调用标为 14 字节 `memcpy`，CTree 保留 `strcpy` helper 与两项参数。来源各自保留，关系为有证据的调用位置对应与语义差异。实际字节确认 `0x82EAC` 为 `%s_%d`、`0x92D94` 为 `ddns_enable`、`0x8CF8C` 为 NUL。ELF 中 `LDRB` 所对应的字节宽度可独立作为机器证据。函数调用内部行为、精确写集合、变量的机器寄存器或帧对象等同仍缺证据。函数的结构覆盖与后续 CIR 语义完整性独立评估。

## 3. 第一条切片与模块归属

```text
显式 Project 输入和已固定的 CTree 文件 → 身份和 schema 校验
→ CTree reader / HIR builder → HIR 序列化并重新读取
→ HIR-to-CIR + CFG + provenance → 不可变取得产物 → 独立进程只读重载与检查
```

切片端点是结构化 CIR 及供共享消费者使用的 CFG 和证据。只读消费者可用 `ControlFlowGraph.successors` 检查可达边，并查询已存 provenance。F1 复用 `emtaint/artifacts.py` 的安全路径、固定摘要校验、staging 与原子 generation 发布。F1 使用独立 Manifest codec。Alias/SSE/Taint、callee 摘要、跨前端融合、缓存和分析结果持久化属于后续任务。

Project 负责 ELF 与地址映射。Adapter 负责 JSON 版本、源节点验证、CTree 专有枚举和 HIR 构造。HIR 模型和 codec 仅依赖纯数据契约。CIR lowering 依赖 HIR 与已验证的上下文，并构建可供共享图消费者读取的 CFG。Artifact 层负责持久化与链接完整性。CLI/use case 仅编排导入、发布和检查。该依赖方向中，adapter 上游的 IDA SDK 只存在于导出进程。

## 4. HIR 数据与 CTree → HIR

通用版本为 `HIR-Wire-v1`，codec 位于 `emtaint/ir/hir/model.py`。Wire 使用 UTF-8 JSON、有类型标签的记录、以 ID 为键的表和有序槽数组。节点和变量来源地址带 domain。类型和数值证据保存在独立类型记录与结构化 payload 中。编码器与解码器共用引用和预算校验。源码绑定、地址区间和来源表在 detached bundle 读取时交叉核验。

| 记录 | 主要字段与约束 |
| --- | --- |
| HIRFunction | `schema_version, binary_id, function_id, source_artifact_id, source_fingerprint, address_map_ref, normalizer_version, entry_node_id, nodes, variables, types, assessment`。FunctionId 复用现有 BinaryId + RVA |
| HIRNode | `id, kind, category, children[{role,index,id}], value_role, type_evidence_ids, source_node_ids, source_address?, evaluation, payload, coverage`。源地址可空，求值含 ordered/conditional/unknown；结构子槽和执行次序字段独立 |
| HIRVariable | `id, function_id, source_fingerprint, lvar_index, role, storage, display_name?, definition_address?, size_evidence?, type_evidence_ids`。存储为 register/stack/unknown 带来源的描述；微寄存器与帧偏移保持其命名空间 |
| HIRType | `id, kind, display?, size_bits?, signedness?, qualifiers?, pointee?, element?, count?, return_type?, parameters?, variadic?, calling_convention?, fields?, layout_state, evidence_ids`。kind 为 Primitive、Pointer、Array、Function、Struct、Union、Unknown。字段依 kind 允许，未知参数列表区别于已知空列表 |
| TypeEvidence | `id, subject, property, value, source_kind, source_ref, confidence, completeness`。区分 Hex-Rays 推断、明确用户注解、compiler/DWARF、unknown。含混的源标记保留原枚举和不确定性。用户改名不能升级类型证据 |
| OpaqueNode | 保留原分类、opcode 名称及数值、源身份、可见子槽顺序与引用、可选载荷引用、原因和保守读/写/控制影响。被截断的子树显式标出缺失 |

源节点身份由 BinaryId、FunctionId、Export Fingerprint、原 `node:path` 与 category 组成。HIR 常规节点 ID 由确定的归一化角色路径与 kind 分配，合成节点用创建规则、父角色和序号。跨引用时需带函数与 HIR 内容摘要。变量主键为 `(FunctionId, ExportFingerprint, lvar_index)`，绑定 role 与 storage 描述并验证，一次导出内同索引只有一份定义。变量重命名或重新导出不授权跨指纹复用身份。类型 ID 绑定对应 schema 和证据记录，同 display 不能作为去重条件。

Reader 的逻辑入口 `read_ctree(bytes, verified_project, expected_export) -> ValidatedCTree`。先验证文件 pin、源版本、fingerprint、environment、入口、段范围和地址域，再校验根、层级、opcode 角色、连续序号、lvar/type 引用和统计。原始 bytes、canonical semantic fingerprint 分开校验。文件摘要 pin 由任务或外部可信 receipt 指定。已知 opcode 结构错误、引用缺失、版本不兼容、身份或指纹不符属于输入拒绝。合法未知 opcode 或 exporter 标明的不完整结构，在边界可验证时进入 Opaque，产生逐节点诊断。超过 80 MiB、100,000 节点、深度 300 或 20,000 类型的输入在构造/发布前拒绝，读写两端使用同一版本的限额。

Builder `build_hir(ValidatedCTree) -> HIRFunction` 按已观察的 19 个 opcode 转换：

- `cit_block/expr/if/for/return` → Block、ExpressionStatement、If、Loop(for)、Return。If 的 else 可空。For 字段包含 init、condition、body、step 和显式顺序。
- `cot_asg` → AssignExpr，写入目标并保留表达式结果。statement wrapper 保留源对应。`cot_preinc/lnot/ne` → Unary(preinc/logical_not)、Binary(ne)。
- `cot_var/num/str/obj/helper` → VariableRef、数值或字符串 Constant、AddressedObjectRef、HelperRef。字符串原始 bytes 可空。地址对象携带已限定的地址域和用途证据。
- `cot_call/cast/ref/ptr/idx` → Call、Cast、AddressOf、Dereference、ArrayAccess。参数保留位置，求值先后单列。lvalue/rvalue/address-only 区分取址和读取。保留元类型、推断宽度和辅助转换证据。
- MemberAccess、ConditionalExpression、Switch、Break/Continue、其他循环及其他操作符在本切片走 Opaque。结构中出现成员时保留 raw member hint，不将其等同字节偏移。

`encode_hir(HIRFunction) -> bytes` 与 `decode_hir(bytes, expected_identity) -> HIRFunction` 做确定性 round-trip，验证节点、变量、类型、源引用、版本与预算。绑定外部输入的引用在 bundle load 时交叉验证。builder 和 CIR lowerer 在系统验证中以重载后的 HIR 交接。合法 Opaque 记录也必须能 round-trip。

## 5. HIR → CIR

通用 `CIR-Wire-v2` 由 `emtaint/ir/canonical/wire_v2.py` 管理。F1 Manifest 标注生产能力 `CTree-F1-Capability-v1`，CIR body 自身使用通用 defs、uses、块参数、效果和机器证据引用。F0 继续使用 `CIR-Wire-v1`。VEX 互操作需要显式版本化转换，见 Backlog。

`lower_hir(hir, evidence)` 输出 CIR body 和块来源。共享 CFG 由该 body 投影。校验覆盖终结指令、guard、定义位置、支配关系和 phi 的精确前驱集。效果 ID 为块局部 ID 加效果序号，定义 ID 绑定 input/phi 或 effect/result 槽，use ID 绑定角色和序号，phi incoming use 绑定前驱。外部引用以 FunctionId、wire 版本和 CIR body digest 限定。共享 `ProgramBlockId` 支持 machine、source、synthetic。F1 的源锚点使用 `IDA_EA`，它与独立的机器指令 origin 分开保存。

| HIR | CIR 合同 |
| --- | --- |
| Variable read/write | 参数进入显式 InputDef。读取引用到达定义，赋值建立新定义并保留表达式值，未确定输入使用 UnknownDef。合流按前驱生成 Phi 或等效的显式 guard 定义。可能逃逸的变量用地址和值的独立记录，缺证据时保持其对象未知 |
| Constant / Logic / Arithmetic | 保留值和位宽证据。NE 与 logical-not 生成布尔 Compare；preinc 按有证据的宽度读、加、定义。未知宽度或溢出语义不足时使用 Unknown/Partial 并传播 |
| Cast | 保留源和目标类型证据。仅在源/目标宽度和转换行为受证时生成相应位向量转换。否则产生部分指针值和诊断 |
| AddressOf / pointer arithmetic | 保留基址和索引表达式，区分取址和内存效果。只有地址域、尺度和布局有证据才算确定字节偏移。否则保留符号路径并发出 Unknown/Partial |
| Dereference / Array / Member | rvalue 产生 Load，写位置产生 Store，address-only 产生地址计算。样本条件可保留有独立证据的 8 位读取和非零比较，目标对象仍未知。原始 member slot、数组 stride 或字段布局未证时，发出明确未知读写能力及保守影响 |
| Call | 保留目标表达式、参数位置、结果是否使用、guard 与保守 footprint。可用机器 BL 证明地址，是否外部符号、ABI、调用效果另证。helper 初始化保留冲突，不能直接生成特定 libc 摘要。忽略的结果不生成随后可用的伪返回值。调用未知读写和 clobber 显式表示 |
| If / Branch / Return | 按已知结构生成真假边和 join。输入为未知布尔时保留双边及 assessment。return 保留常量 0 和到达条件。未知控制用保守 successor/unknown exit 表达 |
| Loop | init → header 条件 → body 或 exit，body → latch step → header。header 对 i 合流，条件和分支体 guard 明确。源 ARM 底部比较可作为相关证据保留，与 HIR 的 for 形态分别记录 |
| Opaque / incomplete | 保留可见子节点，发出带 reason、guard、可能读/写/控制 footprint 的 UnknownEffect、UnknownDef 或 Havoc。未知读取不能折叠为空，未知写不能作强更新，未知控制不能宣称 CFG 完整 |

覆盖状态为 `LOWERED, PARTIAL, UNSUPPORTED, NO_EFFECT`。块容器和部分常量引用可记录有理由的零 effect。只要有未证调用效果、对象布局或区域副作用，样本就以 `PARTIAL` 发布。缺失证据时保持输入与输出可追溯。若对未知控制不能形成保守可解释的表示，则按 `FAILED` 拒绝发布，而非合成确定路径。

## 6. Provenance 与传播

F1 复查将控制结构、CIR 语义和机器映射分开验证。主样例的 12 块和 14 边构成 `COMPLETE` 的结构化 CFG。调用 footprint、布局和转换的不确定性仍使 CIR 为 `PARTIAL`，机器映射按节点记录。UnknownExit 和可能改变控制的 Opaque 都使结构 CFG 为 `INCOMPLETE`。早期产物在全部节点与边吻合时可保留其历史的悲观状态字段，读取时依照现有 CIR 重算结构状态。Wire 与 Manifest 版本保持原样。

F1 的 source → HIR 采用一个源身份绑定一个对应 HIR 节点，通用 provenance 图仍支持多对多。读取验证端点作用域、关系方向、lowering 覆盖、可选机器证据和冲突引用。允许的方向为 source → HIR，HIR → block/definition/use 的派生，HIR → effect/definition/use 的 lowering，以及 effect → instruction 的对应。

共享 `Representation-Provenance-v1` 保存 source、HIR、block、effect、definition、use 和 instruction 端点。表头绑定 FunctionId 和各端点类别的 artifact digest。边保存关系、方法、置信分类、mapping status 和理由。读端从已有边构建双向索引。coverage 分别记录 lowering 和机器映射状态。ARM 字节、地址转换和经审核的固定样本对应存入独立证据文件。

| 情况 | 记录 |
| --- | --- |
| 多源 → 一 HIR | 多条 `normalizes_to`，例如调用表达式与用于归一化的 operand 证据。保留可寻址的源记录 |
| 一 HIR → 多 CIR | 多条 `lowers_to`，例如 dereference 条件导致 load 并为比较及 branch 提供来源 |
| 合成 HIR / CIR | `derived_from` 绑定语义构造规则及相关源或 HIR，直接机器位置为 null |
| 零 CIR effect | coverage `NO_EFFECT` 或 `UNSUPPORTED` 带理由，区分结构容器和没有支持的 lowering |
| 一个 CIR effect → 多机器指令 | 独立 `corresponds_to` 边，例如条件语义用已核验的 load、compare、branch 字节组合；仅在有实际指令/操作数证据时产生 |
| 部分 / 歧义 / 缺失 | `PARTIAL`、`AMBIGUOUS`、`UNAVAILABLE`。保存候选集合、排除原因和缺失项。完整对应仅在证据闭合时使用 |
| Semantic Conflict | `conflict_id, fact_refs, property, affected_refs, status, reason, resolution_evidence?`。如 helper 与机器调用证据并存，局部变量类型与机器访问宽度也分别评估 |

置信标签沿用 ADR-011。类型来源额外保留 compiler/DWARF 分类和各自 evidence。禁止用源 ID、RVA 相近或 EA 相同作为唯一语义匹配依据。ELF 指令字节确认调用目标和宽度，与 Hex-Rays 的类型、变量布局和调用重写各自独立。源节点无 EA 只意味着该节点缺少直接位置证据。

## 7. 发布、重载与批准范围

提议 `ProjectSpec-F1-v1` 显式提供 `binary_path, binary_sha256, ctree_path, ctree_sha256, expected_export_fingerprint, expected_ida_ea, expected_image_base, allow_partial`。相对路径以 Project 文件所在目录为基准。JSON 内的 `input_file_path` 只保存来源。发布只读取调用方指定的 ELF 与 CTree 路径。

提议 `AcquisitionManifest-F1-v1` 绑定原样 CTree、HIR、CIR、CFG、provenance、地址映射与局部机器证据。Manifest 对每个条目记录 kind/schema、路径、长度、SHA-256。只接受 generation 内普通文件并拒绝逃逸路径和链接。完整绑定 FunctionId、地址上下文、输入 pin、导出指纹、normalizer/lowering/mapping 版本与策略。先 staging 验证，写 Manifest 后同卷发布到不存在的不可变 generation。重载从调用方固定的 Manifest 摘要校验所有绑定、文件和交叉引用，检查取得产物无需 IDA、angr、原始 ELF 或新分析。将源字节与 HIR 绑定以验证源引用。当前二进制或配置比较若被请求，差异标为 `STALE`。版本不支持为 `INCOMPATIBLE`，完整性失败拒绝。源码摘要、配置或生产者版本变化使相应后代身份失效。当前切片无重绑定、自动刷新或跨 generation ID 稳定性承诺。

负责人接受现有固定导出为有限兼容性见证，批准通用 HIR/CIR/CFG、保守类型证据、共享存储及有限 provenance。类型保留原始来源键与变量的用户标志。`hexrays_inferred_or_user` 记录为 `HEX_RAYS_REPORTED`，当前样本无经验证的用户类型、DWARF 或编译器类型证据。F0 现有实现已获负责人接受。F1 最终审查及后续 VEX 互操作单独处理。

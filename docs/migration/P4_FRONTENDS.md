# P4：两条 VEX 输入与 CIR 输出

运行版本固定为目标 `.venv` 的 angr/pyvex/cle/archinfo/claripy **9.3.4**。本模块消费 P3 v1，不修改 schema，不调用 APG、Heap、SSE 传播或求解器。旧 `emtaint/frontend/` 与 VexIR 路径保留。

## 入口与输出

新入口位于蓝图指定的 `emtaint/frontends/`：

```python
from emtaint.frontends.angr_vex import AngrVexFrontend
from emtaint.frontends.ida_vex import IdaVexFrontend
from emtaint.frontends.inputs import read_ida_cfg
from emtaint.ir.canonical.wire import dumps

# 在隔离 native worker 中，使用明确的只读输入路径。
specs = read_ida_cfg(metadata_path)
selected = tuple(s for s in specs if s.address in selected_addresses)
angr_result = AngrVexFrontend(binary_path).lift(selected)
ida_result = IdaVexFrontend(binary_path).from_metadata(
    metadata_path, function_addresses=selected_addresses)

cir_json = dumps(ida_result.module)
coverage_and_mappings = ida_result.report()
cfg_snapshots = ida_result.cfgs()
```

angr 入口由 Project loader 提供原始字节与 block.vex，逐片验证其 bytes 与绑定 ELF 相同。可另用 `.discover(addresses)` 经 CFGFast 取得有界 FunctionInput；未声明的完整函数覆盖不会自动获得证明。IDA 入口只读现有 JSON 与 ELF 文件，按虚拟地址从文件映射读取字节，经 pyvex.IRSB lifting，不访问 IDA 宿主 API。

两入口共用 `vex_lowering.py`。`FrontendResult.module` 仅含纯 CIR DTO；report 含语句/表达式 opcode、每条 lowering 状态、源函数/边/call hints、IRSB 与源 block 映射、byte SHA、Origin 和 CFG。原生 Project/IRSB 不进入 core、graph、memory 或 wire。

`report` 是前端旁路证据，不扩展 v1 wire。CFG 是 P2 ControlFlowGraph 快照，所有节点引用 CIR BlockId；未知 guard 的已知 side-exit 目标保留为 unknown 边。bounded lifting 的 CFG 始终标 incomplete，外部/计算目标和返回 ABI 尚未完整解析。

## 输入契约

FunctionInput 显式指定函数地址、名字、block 起止地址与模式，另保留原始 CFG edges/call hints。地址使用 ELF linked virtual address，转换输出 ID 时减 image_base；一个函数的源 block 不允许歧义重叠。

IDA 导出格式使用十六进制函数键和 block/jmp/call/name 表。重复键、未知字段、非法地址/边/callsite 或不完整表会报 InputError，不静默跳过。零长度 block 显式标为 boundary，生成 InputBoundary UnknownEffect，保留边和 provenance；它不读字节，不计入成功 IRSB，不当作已分析的空函数。

当前文件 byte provider 支持 ELF32/64 ET_EXEC 的文件支持且可执行 PT_LOAD 区域；架构由 ELF machine/endian 显式映射。PIE/ET_DYN、重定位、PE、非文件支持地址和歧义输入没有被猜测为可用，需后续明确扩展。实际验证覆盖 AMD64 ELF、ARM Thumb ELF、真实 ARMEL httpd 和原生 X86 VEX fixtures；其他表内架构不能据此声称已有实测覆盖。

IDA 不提供 mode 时采用明确的 default profile；Thumb 需给出 even physical address + mode=thumb，调用 native lifter 时设置 odd address/bytes_offset。IRSB 的 IMark delta 与 core BlockId.mode 都保留。

## IR 与控制流处理

每个源 block 循环 lifting，按 IRSB.size 推进，直至所给边界；不能把第一份 IRSB 当作整个 IDA block。零进度、NoDecode tail 或已知 native lifting 错误都有 failure mapping 与 UnknownEffect，不返回假空 block。源区间/实际 IRSB 区间、字节 SHA 和生成的 CIR block 列表可复核。

VEX 中途 Exit 可能早于后续 store/register write。已支持的条件拆成 BranchEffect 与续接 CIR block；相同地址使用 variant index 区分。条件未知时保留 UnknownEffect 的控制影响，并保留 native target 为 unknown CFG 边，不能删掉可能目标。

跨输入边界的已知跳转可生成明确的 ExternalControlBoundary trampoline，保存目标指针；它不是宣称该地址代码已被 lifting。生成的 boundary Origin 与真实 IMark/语句 Origin 有不同 source_opcode。

VEX 地址本来是 BV；为满足 v1 的 typed pointer 规则，使用 `0(pointer)+BV` 显式物化指针，保留位模式，不创建隐式 cast 或修改 schema。guest-state Put 按 VEX 的实际 slice 写入：整寄存器用 full，部分用 preserve_others；ISA 已在 VEX 中显式编码的零扩展不再通过寄存器名字猜测。

## 精确子集与保守边界

| VEX 输入 | P4 行为 |
|---|---|
| IMark / NoOp | 显式记录 metadata 覆盖、指令地址与 delta |
| 标量 Const/RdTmp/Get/WrTmp/Put | typed 值/寄存器 effect；未知 temp 不以 0 代替 |
| Add/Sub/Mul、位运算、比较、Not、整数截断/扩展、Concat、纯 ITE | 转为 v1 typed Compute；布尔逻辑保持 bool sort |
| Load / Store | 保留地址、宽度、端序、Origin 和 effect 顺序 |
| LoadG / StoreG | 显式 guard；LoadG 保留 alternate 与 U/S 转换；false guard 不产生内存访问 |
| CAS / LLSC / Dirty / MBE / ABIHint / GetI / PutI | 没有精确 v1 语义时保守 UnknownEffect，包含潜在内存/寄存器/控制影响；不将原子写拆成普通 Store |
| CCall、未覆盖 scalar op、浮点/向量、嵌套条件访存 | 显式 unsupported；依赖结果的后续操作继续保持未知 |
| Ijk_Call / Ijk_Ret / 跳转 | 保留调用/返回/跳转形状与来源；ABI 参数/结果恢复未完成，call footprint 默认 unknown |
| 未知 jumpkind、异常控制、decode failure | 显式 Unknown/Incomplete 与原始 control 记录 |

statement lowering 是事务式的：发生 UnsupportedVEX 时撤回该语句的局部半成品，并标记其输出 temp 未知。后续 store 若依赖它，也必须变成 unsupported；不能保留一半已知数据流。

Call hints 的字符串只是来源名字，不证明 external/direct 调用；target 由实际 VEX 表达式保留。没有执行 P6 iCall target recovery。ABI 使用 `unmodeled:<arch>`，当前不恢复完整参数、返回值或任意计算目标。

## 隔离与验证

原生测试仅通过 `scripts/p4_probe.py --folder <fresh .p4-work path>` 启动，先设私有 TEMP/TMP/cache、-B 和写 guard，再导入 native 库。`--firmware` 额外对固定的四个真实有界函数做两路径比较。`scripts/p4_validate.py <phase checkpoint>` 运行纯测试、回归、native probe、完整性与源文件冻结检查；新命令和输出始终写新目录，既有报告不可覆盖。

Python guard 是写操作拦截，不是 native ACL 沙箱；本轮还用全部受保护文件的 SHA/size/mtime 清单验证未变。没有执行旧 `main.py -i/-t`，没有调用新 heap 或 taint 引擎。

两路径共用转换器，一致性主要证明字节映射、切块和前端输入对接一致，不能独立证明全部转换语义。guarded memory 的定值/false-path 行为另由小型独立测试 oracle 检查；它仅是转换测试，不是 P5 内存实现。完整结果和已知 unsupported 见 [P4-report.md](phases/P4-report.md)。

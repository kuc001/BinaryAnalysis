# 新增架构要求：Decompiler Frontend 与 High-Level Semantic Analysis

## 一、总体目标

BinaryAnalysis 必须支持多种程序输入和程序表示。

不能只支持原始二进制指令、VEX IR 或 IDA Disassembly。

新增：

**IDA Hex-Rays Decompiler Frontend**

允许使用 IDA Pro 反编译产生的结构化伪代码，进行：

1. 程序语义分析。
2. Dataflow Analysis。
3. Def-Use / Use-Def。
4. Alias Analysis。
5. APG。
6. Memory Analysis。
7. Taint Analysis。
8. Cross-Function Analysis。
9. Vulnerability Detection。

伪代码 Frontend 必须和 Binary Frontend 共用统一的分析算法。

不能为 CTree 单独开发一套完整的 Dataflow、Alias、Taint 引擎。

## 二、必须使用结构化 CTree

禁止直接将 IDA 伪代码窗口的文本作为程序分析输入。

优先使用 IDA Hex-Rays SDK / IDAPython 提供的结构化接口：

- cfunc_t
- cinsn_t
- cexpr_t
- lvar_t
- tinfo_t

根据实际 IDA SDK 版本审查可用接口，不得假设所有版本都具有完全相同的 Python API。

必须支持：

- Expression。
- Statement。
- Local Variable。
- Global Variable。
- Function Call。
- Array Access。
- Structure Member。
- Pointer Dereference。
- Arithmetic。
- Cast。
- If / Else。
- Loop。
- Switch。
- Return。
- String Literal。
- Function Pointer。

同时保存原始伪代码文本，供人工阅读，但不得通过文本解析构建主要分析语义。

## 三、新增 HIR

建立 Frontend-independent 的 High-Level IR。

HIR 必须保留：

- 高级变量。
- 函数参数。
- 局部变量。
- 数组。
- 结构体。
- 指针。
- 高级表达式。
- 控制结构。
- 调用语义。
- 返回值。
- 类型信息。
- 类型推断来源。
- 原始 CTree 节点身份。
- 原始节点地址。

HIR 不应直接依赖 Hex-Rays Python 对象。

必须可以独立序列化、持久化和重新加载。

## 四、HIR → CIR

建立明确的 HIR-to-CIR Lowering。

重点支持：

- Assignment。
- Variable Read / Write。
- Array Read / Write。
- Struct Member Read / Write。
- Pointer Read / Write。
- Function Call。
- Function Return。
- Conditional Branch。
- Loop。
- Arithmetic。
- Cast。
- Global Read / Write。
- Stack Object。
- Heap Object。

必须保留：

- Input Operand。
- Output Definition。
- Type。
- Memory Access。
- Object。
- Access Path。
- Guard。
- Original HIR Node。
- Provenance。

不能为了降低实现复杂度而丢失高级语义。

不支持的节点必须保留为明确的 Unsupported / Partial Lowering，不允许静默丢弃。

## 五、统一 Analysis Engine

CTree 和 Binary/VEX Frontend 必须最终使用统一分析能力：

- CFG / CG。
- Dataflow。
- Alias。
- APG。
- MemoryVersion。
- SSE。
- Demand。
- Taint。
- Vulnerability Detection。

分析算法不得依赖 CTree 专属对象。

如果某个高级语义不能被当前 CIR 完整表达，必须明确标记分析精度和缺失信息。

## 六、多层 Provenance

必须建立：

CTree Node ↔ HIR Node ↔ CIR Definition ↔ VEX/Microcode ↔ Machine Instruction。

关系必须允许多对多。

不能假设：

- 一个 CTree 节点只对应一条机器指令。
- 一条机器指令只对应一个 CTree 节点。
- 所有 CTree 节点都能映射到有效 EA。

必须保留：

- Function EA / RVA。
- CTree Node EA。
- CTree Node Identity。
- Expression / Statement Kind。
- Local Variable Identity。
- Machine Instruction Range。
- IDA Image Base。
- 类型信息来源。
- 反编译器版本。
- Mapping Completeness。

对于无法映射的节点明确记录原因。

## 七、Decompiler Semantic Confidence

必须区分：

- BINARY_CONFIRMED。
- DECOMPILER_RECOVERED。
- DECOMPILER_INFERRED。
- USER_ANNOTATED。
- ANALYSIS_DERIVED。
- UNKNOWN。

例如，IDA 推断的局部变量类型不能自动等同于真实二进制类型。

不同来源发生冲突时必须保留冲突，不允许静默覆盖。

## 八、IDA Microcode

将 IDA Microcode 纳入未来 Frontend 设计。

不要求第一阶段立即实现全部 Microcode 语义，但必须分析：

1. 与 CTree 的关系。
2. 与机器指令的映射。
3. 与 CIR 的转换方式。
4. 是否能够补充寄存器、内存和控制流信息。
5. 如何与 VEX Frontend 共享统一 IR。

## 九、Acquisition 集成

IDA CTree 不应该使用单独的 P7 Acquisition。

所有 Frontend 统一通过项目级 Acquisition Service 生成 Artifact。

Artifact 必须支持：

- Binary。
- IDA CTree。
- HIR。
- CIR。
- VEX。
- Microcode。
- Provenance。
- Type Metadata。

不同 Frontend 可以独立执行，也可以联合执行。

必须设计 Artifact Fingerprint 和增量缓存。

## 十、真实案例

使用以下代码作为 CTree Frontend 设计示例：

```c
int sub_117F8()
{
    FILE *v0;
    _DWORD v2[5];

    v0 = fopen("/dev/console", "w");

    if (v0)
    {
        fwrite("\\ndo generate ca----------\\n", 1, 0x1A, v0);
        fclose(v0);
    }

    v2[0] = "ca_manage";
    v2[1] = "-n";
    v2[2] = "new";
    v2[3] = unk_A0178;

    return ((int (__fastcall *)(_DWORD *, const char *, _DWORD, _DWORD))eval)(
        v2, ">/dev/console", 0, 0);
}
```

分析它如何从 CTree 转换为 HIR、CIR，如何构建数组内存对象、Def-Use、函数参数依赖和潜在 Taint 路径。

必须区分真实证据、反编译器推断和分析假设。

## 十一、审计交付

本阶段只做设计，不修改代码。

必须交付：

1. IDA Hex-Rays Frontend 设计。
2. CTree 数据结构设计。
3. HIR Schema。
4. HIR-to-CIR Lowering 设计。
5. Multi-Level Provenance 设计。
6. Decompiler Confidence 设计。
7. Acquisition 集成设计。
8. Dataflow / Alias / Taint 共享分析架构。
9. IDA Microcode 后续集成方案。
10. 使用 sub_117F8 的完整语义转换示例。

不得仅通过新增一个 CTree Parser 就声称完成 Decompiler Frontend。

最终目标是：

**BinaryAnalysis 同时支持 Binary-Level Analysis 和 Decompiler-Level Semantic Analysis，并通过统一 CIR、统一 Memory Model 和统一 Analysis Engine 实现跨表示程序分析。**
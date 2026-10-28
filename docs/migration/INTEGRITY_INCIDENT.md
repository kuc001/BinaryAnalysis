# P0-B 阻塞：旧依赖导入重写 parser table

本文件保留首次失败事件：**当时停止旧环境执行，P0-B Gate 未通过。** 不恢复时间戳，不修改旧依赖，不改标失败 manifest。

后续用户明确授权隔离验证和新目录重采。独立验证 `20261028T050809Z-19845bc5` 已通过（legacy_unchanged=true）；具体实现与契约证据见 [PLY_ISOLATION.md](PLY_ISOLATION.md)。新采集使用独立 run ID，旧失败记录保持原样。

新采集 `20261028T051055Z-96d1c781` 已退出 0，manifest=collected，11 个逐步完整性检查及最终 13,461 文件内容/mtime/Git 状态均不变；结果与历史无非计时差异。见 [P0-B 重采报告](phases/P0-B-recapture-report.md)。此结论相对新采集开始状态成立，不恢复首次事件时间戳。

## 实际证据

基线 ID `20261028T034805Z-b5b6f765` 的六个隔离 CLI 都成功，结果逐字段一致；但最终更严格的全仓库元数据校验失败。原始 manifest 保持 `legacy_integrity_failure`，不能改成成功或将本轮快照标为已批准 Golden。

唯一差异路径：`EmTaint/.venv/Lib/site-packages/pycparser/parsetab.py`。

| 属性 | before | after |
|---|---|---|
| 大小 | 198556 | 198556 |
| SHA256 | fe2bda1b1cefee26f5401ca231fc7cf1440b6c7961015424cc1c9dbb4f53584f | 相同 |
| mtime_ns | 1793157383604146100 | 1793159780464587400 |

前后 13,461 个旧文件的路径、大小和内容哈希均相同，Git 状态也相同；只有上述 mtime 发生变化。历史结果和样本未变。即使内容相同，依赖显式重写文件仍违反旧仓库（含 .venv）不可修改约束。

P0-A 及后续只读分析的聚合校验只覆盖路径和内容，不检查 mtime，因而不能排除同内容重写。本轮记录 mtime 的清单发现了此前方法未覆盖的副作用。

## 已只读定位的触发链

1. 旧 `angr/sim_type.py:1614-1620` 在模块导入时调用 `pycparser.ply.yacc.yacc(module=_type_parser_singleton, start='parameter_declaration', debug=False, optimize=False, errorlog=...)`。
2. 没有传 `write_tables=False` 或独立 outputdir。
3. 本机 `pycparser/ply/yacc.py:3214-3216` 默认 `write_tables=True`、`outputdir=None`；`:3241-3256` 将默认输出定位到模块/包目录。
4. `:3476-3478` 调用 write_table；`:2726-2733` 直接 `open(filename, 'w')` 写 `.py` 文件。
5. `-B` / PYTHONDONTWRITEBYTECODE 只管字节码缓存，不能阻止上述显式文件写入。最后一次记录的 mtime 位于 profile taint 的启动导入期间，符合该调用链。

首次失败后的调查未再次启动旧 Python，也没有通过回写旧文件属性来掩盖变化；当时采集器对显式 --execute 提前拒绝。后续经用户授权的版本改为强制先验证 bootstrap 隔离，并在每次旧调用后检查全量内容/mtime/Git；禁止未经验证的裸旧环境导入。

## 当时提出的修复方案（后续验证见 PLY_ISOLATION.md）

只在目标维护一个 bootstrap 工具，物理复制到新 RunRoot；在任何 angr/cffi 导入前，用包装器为 `pycparser.ply.yacc.yacc` 设置 `write_tables=False`。只改变解析表落盘行为，不改变 grammar/start/optimize 或分析算法。若 lexer 也需要落盘，则显式重定向到 RunRoot 的独立 cache；不能修改原 site-packages。

先用旧解释器在隔离 RunRoot 验证导入和代表性 C 类型解析结果，再逐阶段执行前后完整性检查。任何文件内容或 mtime 差异立即中止，不能等六个阶段结束才检查。需要将修复前后的 type parser 契约、输出与启动开销分别记录。

审核通过这一加载期写入隔离方案后，才可使用新 run ID 重采两普通轮和独立 profile。保留本轮所有原始输出、失败 manifest 和 profile 作为证据；不覆盖、不删除、不改标旧 Golden。原旧仓库始终不可写，不能通过修改 ACL、安装补丁或恢复 mtime 处理此问题。

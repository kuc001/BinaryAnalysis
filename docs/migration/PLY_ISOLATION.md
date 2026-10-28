# PLY 加载期写表隔离

范围：只隔离旧环境的加载期文件输出，不修改旧 site-packages、grammar、start symbol、optimize 参数或 EmTaint 算法。当前用户已授权验证隔离，并在验证后用新目录重采 P0-B。

## Bootstrap 边界

`scripts/legacy_readonly_bootstrap.py` 兼容 Python 3.7；采集器将它物理复制为每个 RunRoot 的 `_p0b_bootstrap.py`。旧 Python 不导入目标 emtaint 包。bootstrap 校验自身位置与 CWD 均为 RunRoot，归档目录必须属于共同父目录的 baselines。

在任何 angr/cffi 导入前加载 PLY 定义并包装其入口：

- reference `redirect`：保留原有 write_tables 行为，仅将 outputdir/debugfile 指向 RunRoot 私有 cache。此模式只允许 parser probe，禁止执行分析。
- 正式 `disabled`：同样隔离 outputdir，并显式设置 `write_tables=False`；grammar/start/optimize/debug 的原值保留。lexer 输出路径也指向私有 cache。
- 使用原始函数签名绑定显式位置/关键字参数，支持旧 angr 的 lex.lex(cpp)；没有显式 module/object 的隐式调用直接失败，避免包装器改变 PLY 的调用者栈推断。
- `.pyc` 仍由 `-B` / PYTHONDONTWRITEBYTECODE 禁用；临时目录也设为该 RunRoot 的私有 cache。

Python 级 WriteGuard 拦截 builtins.open、io.open、os.open 和常见重命名/删除/链接/mtime/权限等修改入口，只允许 RunRoot 与指定归档目录。拒绝记录不因依赖捕获 IOError 而被忽略。该 guard 不是任意 native code 的 OS 沙箱，仍需每次旧调用后校验旧仓库完整性。

## 实测验收方法

独立验证已通过：`baselines/rv130_1_0_3_44/20261028T050809Z-19845bc5/manifest.json` 状态 `isolation_validated`，退出 0，legacy_unchanged=true。两次逐步校验和最终 13,461 文件清单（含 SHA256 与 mtime_ns）均一致。

四类 C 类型、完整 AST 及 parser action/goto 哈希完全一致：`90aa3c0f426412a53f394361288ae3f4f8f80b9cfc8cf50389771a568ecb6960`。reference 私有 cache 中 parsetab.py 的哈希与旧文件相同：`fe2bda1b1cefee26f5401ca231fc7cf1440b6c7961015424cc1c9dbb4f53584f`；disabled 的 cache_files 为空，两种模式 violations 都为空。

首次受控验证 `20261028T050103Z-7d878e7a` 因未支持显式位置参数 `lex.lex(cpp)` 而失败；该轮也通过旧仓库完整性校验，没有执行 -i/-t。随后按原函数签名绑定参数修正，只在新目录重试，失败证据保留。

两份独立物理副本分别执行 redirect/disabled probe，比较：

1. `int`、`unsigned int`、`char *`、`int (*)(char *, unsigned int)` 的 angr 类型类名和 C 表示。
2. typedef、struct、函数声明的完整 pycparser AST（不带源文件坐标）。
3. angr parameter_declaration parser 的 action/goto 表稳定哈希。
4. reference 确实只在自身 cache 生成 parsetab.py；disabled 不生成 .py/.pyc/parser.out。
5. 两次 probe 之后旧仓库全部文件的路径、大小、SHA256、mtime_ns 和 Git 状态均等于运行前。
6. 无拒绝写入、子进程退出 0；证明文件绑定本轮 bootstrap SHA256，后续命令发现 bootstrap 变化即拒绝。

只有所有条件通过才会生成 `isolation-proof.json`。普通 `-i/-t`、旧环境版本探测及 pip freeze/check 均经同一个 disabled bootstrap；不再通过裸 `-c 'import angr'` 探测旧环境。

## 执行与复核

```powershell
# 只读计划
.\scripts\legacy_baseline.ps1 -ValidateIsolationOnly
# 仅验证，不执行 -i/-t；新建唯一目录
.\scripts\legacy_baseline.ps1 -Execute -ValidateIsolationOnly
# 验证通过后重采；仍会在本轮新目录先重新验证隔离
.\scripts\legacy_baseline.ps1 -Execute -Profile -Repetitions 2
```

每个 probe、每次旧环境元数据命令和每个分析阶段之后，保存 `legacy-integrity-*.json`。发生内容或 mtime 差异立即中止后续旧调用，最终仍写完整 before/after 和失败 manifest。任何旧时间戳都不恢复。

全量清单计算使用 scandir 元数据和 8 个只读哈希线程；每次仍重新读取所有文件内容，不复用旧哈希。已对原 13,461 条清单证明记录及顺序完全一致；测试另覆盖同内容但 mtime 改变的情况。

## Profile 和内存口径

通过 bootstrap 内部的 cProfile 包裹原 `main.py`，不改变 argv、CWD 或调试打印。生成统计包含 loader instrumentation 的 Python 开销；与之前未隔离 profile 的时长不能直接作算法性能比较。

bootstrap 从实际 worker 内部使用 Windows GetProcessMemoryInfo 读取 kernel peak working set，保留 PID 与统计范围。它覆盖该分析 worker 的峰值，不是整个进程树的峰值；Popen 启动器指标单列，不再混作分析内存。

历史失败采集 `20261028T034805Z-b5b6f765` 的 manifest 和原始数据保持不变。后续成功记录只能使用新 run ID，不得改标历史失败结果。

完整重采 `20261028T051055Z-96d1c781` 已通过：同一隔离契约再次验证、六次 CLI 退出 0、11 份 bootstrap 报告没有禁止写入或禁写表输出，逐步及最终旧仓库完整性均不变。详见 [P0-B 重采报告](phases/P0-B-recapture-report.md)。

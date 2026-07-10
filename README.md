# Retry / Backoff 补丁脚本 — 使用说明

> 操作前先**退出正在运行的 codex / claude**；两个二进制都装在用户 npm 目录（`~/.npm-global`），**无需 sudo**；所有脚本都支持预览（统一用 `--check`）和 `--restore` 还原，打补丁前自动备份为 `<binary>.orig`。

按平台拆成 4 个脚本；每个脚本启动时会**检测当前系统环境**（`os.name`），跑错平台会直接拒绝并提示改用对应脚本：

| 工具 | Linux / macOS | Windows |
|---|---|---|
| codex | `patch-codex-retry-linux.py` | `patch-codex-retry-windows.py` |
| claude | `patch-retry-claude-linux.py` | `patch-retry-claude-windows.py` |

- codex 两版处理**真实机器码差异**：Linux 走 ELF/Mach-O 文件偏移空间；Windows 走 PE 的 VA 换算（`build_pe_off2va`）。两版都支持 `addsd` / `movsd [0.9]` 双锚点。
- claude 两版补丁本体（内嵌 JS 文本）**逐字节相同**，差异仅在二进制发现、写文件、命令提示。

---

## codex

### Linux / macOS — `patch-codex-retry-linux.py`

```bash
# 1. 预览（不修改）
python3 patch-codex-retry-linux.py --check

# 2. 打补丁：退避固定 1s + stream_max_retries 上限抬到 9999
python3 patch-codex-retry-linux.py

# 3. 还原
python3 patch-codex-retry-linux.py --restore
```

### Windows — `patch-codex-retry-windows.py`

```powershell
py patch-codex-retry-windows.py --check      # 预览
py patch-codex-retry-windows.py              # 打补丁
py patch-codex-retry-windows.py --restore    # 还原
```

> 重试间隔与 stream 上限已固定为脚本内常量 `RETRY_MS = 1000`(毫秒)、
> `STREAM_MAX_RETRIES = 9999`，**不提供 `--ms` / `--max-retries` 命令行参数**；
> 如需改值，直接编辑脚本顶部这两个常量。

实际重试**次数**仍由 `config.toml` 决定（脚本只抬高上限）：

```toml
[model_providers.custom]
stream_max_retries  = 9999
request_max_retries = 10
```

### 参数（两版通用）

| 参数 | 说明 |
|---|---|
| `--check` | 只检查打印，不写入、不备份 |
| `--restore` | 从 `.orig` 还原 |
| `--binary <路径>` | 手动指定原生 `codex` / `codex.exe` 二进制 |
| `--self-test` | 内部自检 |

### 版本适配说明（重要）

脚本靠识别二进制里特定的机器码模式来打补丁，**codex 升级后模式可能失效**。当前已验证 **codex v0.143.0 / v0.144.1**（Linux x64 ELF 与 Windows x64 PE）。

- 每次 codex 升级后，先跑对应平台的 `--check`：必须同时列出 `retry.rs::backoff` 和 `util.rs::backoff`。若报错（如 `expected exactly one 0.9 jitter constant, found N` 或 `expected at least 2 jittered backoff sites`）说明字节码又变了，需要重新适配。
- **v0.142.4 → v0.143.0 变了什么**（供下次排查参照）：
  1. 抖动 `random_range(0.9..1.1)` 的编译产物从「相邻 `0.9`/`1.1` 常量对」改成「下限 `0.9` + 区间宽度 `0.2`」，且 `0.9` 常量被两个 backoff 去重共享，旧的「相邻 0.9/1.1 对」定位失效。
  2. 两个 backoff 函数都被**内联**进各自的 async poll，不再有独立入口，旧的「覆盖函数入口写返回 stub」打法会毁掉整个 poll 函数。
- **现方案**：以全局唯一的 `0.9` 常量为锚，收集 `addsd` / `movsd xmm,[rip→0.9]` 候选，再用内联 `Duration::from_millis` 尾部（`mov rax,<reg>; shr rax,3; movabs 0x20c49ba5e353f7cf`）过滤，把中间抖动/base 计算段**就地**改成 `mov <reg>, <固定ms>` + NOP，得到与 attempt/jitter 无关的固定间隔。站点3（`stream_max_retries` 上限）字节码未变，逻辑照旧。
- **v0.144.x 起第二个 backoff 用 `movsd [0.9]`**（Linux ELF 与 Windows PE 均如此）：脚本允许 `movsd` 作为候选锚点，但只有同时匹配后续 `mulsd`、饱和转换和 `Duration::from_millis` 尾部时才接受，因此会排除二进制中无关的 `0.9` 加载。`addsd` 为强制锚点（匹配不上即报错），`movsd` 为宽松锚点（不匹配则跳过）。

#### Linux 与 Windows 拆分要点

- **RIP 相对寻址必须在虚拟地址(VA)空间解析**。Linux 版对整文件单一映射的 ELF/Mach-O 直接用文件偏移做 `i+plen+5+disp == c09` 比较即可；Windows 版必须走 `build_pe_off2va()` 换算到 VA 再比较，因为 PE 的 `.text` 与 `.rdata` 的 `VA − 文件偏移` 增量不同（`FileAlignment 0x200 ≠ SectionAlignment 0x1000`）。
- **MSVC 把毫秒值分配进扩展寄存器 `r8`/`r9`**：`from_millis` 尾部是 `4c 89 c0`（REX.W+REX.R 的 `mov rax,r8`）而非 musl 的 `48 89`。两版尾部识别都同时接受 `48`/`4c`，补丁对 `r8–r15` 加 `41`(REX.B)前缀写出 `41 b8 <imm32>`。

---

## claude

### Linux / macOS — `patch-retry-claude-linux.py`

```bash
python3 patch-retry-claude-linux.py --check       # 预览
python3 patch-retry-claude-linux.py               # 打补丁
python3 patch-retry-claude-linux.py --restore     # 还原
```

### Windows — `patch-retry-claude-windows.py`

```powershell
# 需先关闭正在运行的 claude.exe（Windows 会锁定运行中的可执行文件）
py patch-retry-claude-windows.py --check
py patch-retry-claude-windows.py
py patch-retry-claude-windows.py --restore
```

打补丁后设置环境变量再运行 claude：

```bash
export CLAUDE_CODE_MAX_RETRIES=9999            # Linux / macOS
$env:CLAUDE_CODE_MAX_RETRIES="9999"            # Windows (PowerShell)
```

> 说明：claude 的 npm 包入口文件名叫 `claude.exe`（`package.json` 的 `bin` 字段就是 `bin/claude.exe`），但在 Linux 上它其实是 ELF 二进制——`.exe` 只是官方全平台统一命名，不代表格式。

### 参数（两版通用）

| 参数 | 说明 |
|---|---|
| `--check` | 显示将要改动的内容，不修改二进制 |
| `--restore` | 从 `.orig` 备份还原 |

---

## 打坏了怎么恢复

打补丁前脚本会自动把原始二进制备份为 `<binary>.orig`，按从易到难三选一（用你平台对应的脚本名）：

```bash
# 1. 一键还原（推荐，靠 .orig 备份）
python3 patch-codex-retry-linux.py --restore
python3 patch-retry-claude-linux.py --restore

# 2. 手动从 .orig 拷回（脚本本身跑不了时）
cp <binary>.orig <binary> && chmod 755 <binary>

# 3. 重装（保底，.orig 也没了时；配置不受影响）
npm install -g @openai/codex@0.144.1                # codex（用户 npm 目录，锁定已验证版本）
npm install -g @anthropic-ai/claude-code            # claude（用户 npm 目录）
```

> 重装后是未打补丁的全新二进制；想再要补丁，重跑对应脚本即可。

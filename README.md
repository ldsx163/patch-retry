# Retry / Backoff 补丁脚本 — 使用说明

> 操作前先**退出正在运行的 codex / claude**；两个二进制都装在用户 npm 目录（`~/.npm-global`），**无需 sudo**；两个脚本都支持预览（统一用 `--check`）和 `--restore` 还原，打补丁前自动备份为 `<binary>.orig`。

---

## patch-codex-retry.py

```bash
# 1. 预览（不修改）
python3 patch-codex-retry.py --check
py      patch-codex-retry.py --check      # Windows

# 2. 打补丁：退避固定 1s + stream_max_retries 上限抬到 9999
python3 patch-codex-retry.py

# 3. 还原
python3 patch-codex-retry.py --restore
```

> 重试间隔与 stream 上限已固定为脚本内常量 `RETRY_MS = 1000`(毫秒)、
> `STREAM_MAX_RETRIES = 9999`，**不再提供 `--ms` / `--max-retries` 命令行参数**；
> 如需改值，直接编辑脚本顶部这两个常量。

实际重试**次数**仍由 `config.toml` 决定（脚本只抬高上限）：

```toml
[model_providers.custom]
stream_max_retries  = 9999
request_max_retries = 10
```

### 参数

| 参数 | 说明 |
|---|---|
| `--check` | 只检查打印，不写入、不备份 |
| `--restore` | 从 `.orig` 还原 |
| `--binary <路径>` | 手动指定原生 `codex` / `codex.exe` 二进制 |
| `--self-test` | 内部自检 |

### 版本适配说明（重要）

本脚本靠识别二进制里特定的机器码模式来打补丁，**codex 升级后模式可能失效**。当前已验证 **codex v0.143.0**（Linux x64）和 **v0.144.1**（Windows x64）。

- 每次 codex 升级后，先跑 `--check`：必须同时列出 `retry.rs::backoff` 和 `util.rs::backoff`；少于两个站点时脚本会拒绝写入。若报错（如 `expected exactly one 0.9 jitter constant, found N`）说明字节码又变了，需要重新适配。
- **v0.142.4 → v0.143.0 变了什么**（供下次排查参照）：
  1. 抖动 `random_range(0.9..1.1)` 的编译产物从「相邻 `0.9`/`1.1` 常量对」改成「下限 `0.9` + 区间宽度 `0.2`」，且 `0.9` 常量被两个 backoff 去重共享 → 旧的「相邻 0.9/1.1 对」定位失效。
  2. 两个 backoff 函数都被**内联**进各自的 async poll，不再有独立入口 → 旧的「覆盖函数入口写返回 stub」打法会毁掉整个 poll 函数。
- **现方案**：以全局唯一的 `0.9` 常量为锚，收集 `addsd` / `movsd xmm,[rip→0.9]` 候选，再用内联 `Duration::from_millis` 尾部（`mov rax,<reg>; shr rax,3; movabs 0x20c49ba5e353f7cf`）过滤，把中间抖动/base 计算段**就地**改成 `mov <reg>, <固定ms>` + NOP，得到与 attempt/jitter 无关的固定间隔。站点3（`stream_max_retries` 上限）字节码未变，逻辑照旧。

#### Windows / PE 适配（已在 v0.144.1 验证）

早期版本在 Windows 上会报 `found no jittered backoff sites (0.9..1.1)`，根因与修复：

- **RIP 相对寻址必须在虚拟地址(VA)空间解析**。旧代码用文件偏移做 `i+plen+5+disp == c09` 比较；这在整文件单一映射的 musl ELF 上恰好成立（WSL2 因此正常），但 PE 的 `.text` 与 `.rdata` 的 `VA − 文件偏移` 增量不同（`FileAlignment 0x200 ≠ SectionAlignment 0x1000`），比较必然落空。现按格式分支:**仅 PE** 走 `build_pe_off2va()` 换算到 VA 再比较；**ELF/Mach-O 保持原文件偏移逻辑，字节级不变，不影响 WSL2**。
- **MSVC 把毫秒值分配进扩展寄存器 `r8`/`r9`**：`from_millis` 尾部是 `4c 89 c0`（REX.W+REX.R 的 `mov rax,r8`)而非 musl 的 `48 89`。尾部识别现同时接受 `48`/`4c`，补丁对 `r8–r15` 加 `41`(REX.B)前缀写出 `41 b8 <imm32>`。
- **v0.144.1 的第二个 backoff 改用 `movsd [0.9]`**：脚本现在允许 `movsd` 作为候选锚点，但只有同时匹配后续 `mulsd`、饱和转换和 `Duration::from_millis` 尾部时才接受，因此会排除二进制中另外两个无关的 `0.9` 加载。当前 Windows 上两个 backoff 都会被固定为 1000ms。

---

## patch-retry-claude.py

```bash
# Linux / macOS（claude 在用户 npm 目录，无需 sudo）
python3 patch-retry-claude.py --check       # 预览
python3 patch-retry-claude.py               # 打补丁
python3 patch-retry-claude.py --restore     # 还原

# Windows（PowerShell，需关闭正在运行的 claude.exe）
python patch-retry-claude.py --check
python patch-retry-claude.py
python patch-retry-claude.py --restore
```

打补丁后设置环境变量再运行 claude：

```bash
export CLAUDE_CODE_MAX_RETRIES=9999            # Linux / macOS
$env:CLAUDE_CODE_MAX_RETRIES="9999"            # Windows (PowerShell)
```

### 参数

| 参数 | 说明 |
|---|---|
| `--check` | 显示将要改动的内容，不修改二进制 |
| `--restore` | 从 `.orig` 备份还原 |

---

## 打坏了怎么恢复

打补丁前脚本会自动把原始二进制备份为 `<binary>.orig`，按从易到难三选一：

```bash
# 1. 一键还原（推荐，靠 .orig 备份）
python3 patch-codex-retry.py --restore
python3 patch-retry-claude.py --restore

# 2. 手动从 .orig 拷回（脚本本身跑不了时）
cp <binary>.orig <binary> && chmod 755 <binary>

# 3. 重装（保底，.orig 也没了时；配置不受影响）
npm install -g @openai/codex@0.144.1                # codex（用户 npm 目录，锁定已验证版本）
npm install -g @anthropic-ai/claude-code            # claude（用户 npm 目录）
```

> 重装后是未打补丁的全新二进制；想再要补丁，重跑对应脚本即可。

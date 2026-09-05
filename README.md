# Retry / Backoff 补丁脚本 — 使用说明

> 操作前先**退出正在运行的 codex / claude**；两个二进制都装在用户 npm 目录（`~/.npm-global`），**无需 sudo**；所有脚本都支持预览（`--dry-run`）和 `--restore` 还原，打补丁前自动备份为 `<binary>.orig`。

按平台拆成 4 个脚本；每个脚本启动时会**检测当前系统环境**（`os.name`），跑错平台会直接拒绝并提示改用对应脚本：

| 工具 | Linux / macOS | Windows |
|---|---|---|
| codex | `codex-linux.py` | `codex-windows.py` |
| claude | `claude-linux.py` | `claude-windows.py` |

- codex 两版处理**真实机器码差异**：Linux 走 ELF/Mach-O 文件偏移空间；Windows 走 PE 的 VA 换算（`build_pe_off2va` / `build_pe_maps`）。两版都支持 `addsd` / `movsd [0.9]` 双锚点。
- claude 两版补丁本体（内嵌 JS 文本）**逐字节相同**，差异仅在二进制发现、写文件、命令提示。

---

## codex

codex 有 **5 处**会决定重试等待，脚本全部压成固定 1 秒：

| # | 位置 | 原行为 | 补丁 |
|---|---|---|---|
| 1 | `codex-client/src/retry.rs::backoff` | `base × 2^n × jitter` | 固定 `RETRY_MS` |
| 2 | `core/src/util.rs::backoff` | `200ms × 2^n × jitter` | 固定 `RETRY_MS` |
| 3 | `stream_max_retries().min(100)` | 上限硬编码 100 | 上限抬到 `STREAM_MAX_RETRIES` |
| 4 | `err.retry_delay().unwrap_or_else(backoff)` | 服务端 `Retry-After` 优先，站点 2 被跳过 | NOP 掉 `jne`，退避无条件生效 |
| 5 | `unbounded_connection_retries` 阶梯 | `from_secs(5)` 倍增到 60s | 每次都读成 1s |

> **只打 1、2 是不够的**：站点 4/5 是 0.153.x 里真正决定间隔的两条路。站点 4 让 codex **无视 `Retry-After`**——这正是补丁的目的，但别拿它去打会因为高频重试而惩罚你的端点。站点 5 的字段只能存整秒，`RETRY_MS` 会四舍五入到最少 1s。

### 核心规则：只改「失败之后等多久」

**补丁只允许修改「已经判定失败之后，下一次尝试前等多久」。绝不修改「什么算失败」，也绝不修改「多久才判定为失败」。** 上面 5 个站点全部落在前者，这是这个仓库的硬性约束，新增站点也必须遵守。

理由：等待时长是纯粹的数值，改错了最多是节奏不对；而失败判定改错了会把「模型正在思考」误判成断流、把成功的流当成错误中断，甚至把不可重试的致命错误变成死循环。这两类逻辑本来就有配置项，不该用改机器码的方式碰。

由此推出的三条：

1. **看到的间隔 = 判定失败耗时 + 1s**，前半段脚本管不到。最坏情况是 SSE 静默满 `stream_idle_timeout_ms`（默认 300000ms = 5 分钟），所以间隔可能是 301 秒而不是 1 秒——这不是补丁失效。
2. **想压缩前半段只能改 `config.toml`**（`stream_idle_timeout_ms`），不要去改二进制里的超时常量。
3. **审计方式**：打完补丁后 `.orig` 与新二进制的字节 diff 必须只落在下面这 9 段里；出现第 10 段就说明有签名跑偏了。

```
[0x4a62c20, 0x4a62c64)  68B  站点1    [0x69cd08b, 0x69cd08d)   2B  站点4
[0x59348cc, 0x59348ce)   2B  站点4    [0x69cdaf0, 0x69cdaf7)   7B  站点5
[0x59356d5, 0x59356dc)   7B  站点5    [0x69f7528, 0x69f7557)  47B  站点2
[0x59fa60b, 0x59fa60d)   2B  站点3    [0x6ac01ce, 0x6ac01d0)   2B  站点3
[0x5a361a0, 0x5a361a2)   2B  站点3
```
（地址随 codex 版本变化，数量和归属不该变。）

### 什么算「失败」（脚本不碰这部分，仅供对照）

判定入口是 `core/src/session/turn.rs`：`if !err.is_retryable() { return Err(err); }`，只有返回 true 的错误才会走到重试等待。分类见 `protocol/src/error.rs::is_retryable`：

| 会重试（等 1s 后再来） | 不重试（当场结束这一轮） |
|---|---|
| `Stream` — SSE 在 `response.completed` 之前断开，**空闲超时也算这一类**（`codex-api/src/sse/responses.rs` 发的是 `ApiError::Stream("idle timeout waiting for SSE")`） | `UsageLimitReached` — 套餐额度用尽 |
| `RateLimitExceeded` — 流内的上游限流 | `ServerOverloaded` — 所选模型满载 |
| `RequestTimeout` — HTTP 请求超时 | `QuotaExceeded` / `UsageNotIncluded` — 计费问题 |
| `ConnectionFailed` — 连不上（**另走站点 5 的阶梯**） | `ContextWindowExceeded` — 上下文塞满 |
| `UnexpectedStatus` — 非预期 HTTP 状态码 | `InvalidRequest` / `InvalidImageRequest` |
| `ResponseStreamFailed` | `CyberPolicy` / `MisalignmentPolicyViolation` — 策略拦截 |
| `InternalServerError` — 上游 5xx | `Interrupted` / `TurnAborted` — 用户 Ctrl-C 或中止 |
| `Io` / `Json` / `TokioJoin` — 传输和解析层 | `RetryLimit` — 已经重试到上限 |
| `Timeout` — 子进程等待超时（与网络无关） | `Sandbox` / `Spawn` — 本地执行问题 |

HTTP 请求层（站点 1，受 `request_max_retries` 管）另有一套更窄的判定，见 `codex-client/src/retry.rs::RetryOn::should_retry`：只重试 **429**、**5xx**，以及 `Timeout` / `Connection` / `Network` 三类传输错误，其他状态码一律直接返回。

> 注意 `UsageLimitReached` 不可重试，所以站点 4「无视 `Retry-After`」影响的不是真正的配额墙（那种情况直接结束，根本不等），而是 429 / 流内限流这些**可重试**错误上服务端要求的等待时间。

### Linux / macOS — `codex-linux.py`

```bash
# 1. 预览（不修改）
python3 codex-linux.py --dry-run

# 2. 打补丁：5 处退避全部固定 1s + stream_max_retries 上限抬到 9999
python3 codex-linux.py

# 3. 还原
python3 codex-linux.py --restore
```

### Windows — `codex-windows.py`

```powershell
py codex-windows.py --dry-run    # 预览
py codex-windows.py              # 打补丁
py codex-windows.py --restore    # 还原
```

> 站点 4/5 的字节签名是在 **0.153.4 的 Linux ELF** 上验证的，虽然按寄存器参数化写、没有硬编码寄存器号，但**没有在 MSVC 镜像上验证过**。Windows 上先跑 `--dry-run`：不匹配时会打印 `NOT FOUND` 并跳过（只会漏打，不会写错地方）。

> 重试间隔与 stream 上限已固定为脚本内常量 `RETRY_MS = 1000`(毫秒)、
> `STREAM_MAX_RETRIES = 9999`，**不提供 `--ms` / `--max-retries` 命令行参数**；
> 如需改值，直接编辑脚本顶部这两个常量。

实际重试**次数**仍由 `config.toml` 决定（脚本只抬高上限，不填就还是默认的 `stream_max_retries = 5` / `request_max_retries = 4`）：

```toml
[model_providers.custom]
stream_max_retries  = 9999
request_max_retries = 10
# 顺带把“多久才算这次失败”也压下来：默认 stream_idle_timeout_ms 是 300000（5 分钟），
# SSE 卡住时要耗满它才会计一次重试，看起来就像间隔远大于 1s。
stream_idle_timeout_ms = 15000
```

### 参数（两版通用）

| 参数 | 说明 |
|---|---|
| `--dry-run` | 只检查打印，不写入、不备份（`--check` 是别名） |
| `--restore` | 从 `.orig` 还原 |
| `--binary <路径>` | 手动指定原生 `codex` / `codex.exe` 二进制 |
| `--self-test` | 内部自检 |

### 版本适配说明（重要）

脚本靠识别二进制里特定的机器码模式来打补丁，**codex 升级后模式可能失效**。当前已验证 **codex v0.153.4**（Linux x64 ELF，5 个站点全部命中）以及 **v0.143.0 / v0.144.1**（Linux x64 ELF 与 Windows x64 PE 的站点 1-3）。

- 每次 codex 升级后，先跑对应平台的 `--dry-run`：站点 1/2 必须同时列出 `retry.rs::backoff` 和 `util.rs::backoff`，站点 4/5 各应有 2 处。若报错（如 `expected exactly one 0.9 jitter constant, found N` 或 `expected at least 2 jittered backoff sites`）说明字节码又变了，需要重新适配。
- **v0.142.4 → v0.143.0 变了什么**（供下次排查参照）：
  1. 抖动 `random_range(0.9..1.1)` 的编译产物从「相邻 `0.9`/`1.1` 常量对」改成「下限 `0.9` + 区间宽度 `0.2`」，且 `0.9` 常量被两个 backoff 去重共享，旧的「相邻 0.9/1.1 对」定位失效。
  2. 两个 backoff 函数都被**内联**进各自的 async poll，不再有独立入口，旧的「覆盖函数入口写返回 stub」打法会毁掉整个 poll 函数。
- **现方案**：以全局唯一的 `0.9` 常量为锚，收集 `addsd` / `movsd xmm,[rip→0.9]` 候选，再用内联 `Duration::from_millis` 尾部（`mov rax,<reg>; shr rax,3; movabs 0x20c49ba5e353f7cf`）过滤，把中间抖动/base 计算段**就地**改成 `mov <reg>, <固定ms>` + NOP，得到与 attempt/jitter 无关的固定间隔。站点3（`stream_max_retries` 上限）字节码未变，逻辑照旧。
- **v0.144.x 起第二个 backoff 用 `movsd [0.9]`**（Linux ELF 与 Windows PE 均如此）：脚本允许 `movsd` 作为候选锚点，但只有同时匹配后续 `mulsd`、饱和转换和 `Duration::from_millis` 尾部时才接受，因此会排除二进制中无关的 `0.9` 加载。`addsd` 为强制锚点（匹配不上即报错），`movsd` 为宽松锚点（不匹配则跳过）。
- **站点 4/5 怎么定位的**（0.153.4 起新增，两处都是「就地等长改写」）：
  - 站点 4 靠 `Option<Duration>` 的 niche 编码找：`nanos == 1_000_000_000` 就是 `None`，所以分支是 `cmp <r32>,0x3b9aca00 / jne <跳过 backoff>`。光有这个模式不够（整个二进制里 `cmp <r32>,1e9` 有 680 处），所以脚本**必须**跟着 `call` 走到目标函数、确认它包含站点 2 改过的抖动代码，才肯把 `jne` 换成等长 NOP。0.153.4 里 backoff 是通过 GOT 间接调用（`call [rip+…]`），所以这里需要 VA↔文件偏移双向映射。
  - 站点 5 改的是**读取**：`mov <secs64>,[<base>+0x10] / mov <nanos32>,[<base>+0x18]` → `mov <secs32>,1 / xor <nanos32>,<nanos32>`，两边都正好 7 字节。识别条件是紧跟其后的「两条 disp32 store + 一条 RIP 相对 `lea`」——那条 `lea` 是必需的：无关代码里 `mov eax,60 / xor ecx,ecx` 加两条 store 长得跟已打过补丁的站点一模一样（实测有 6 处），只有 RIP 相对 `lea`（`warn!` 的静态等级检查）能把它们排掉。命中数超过 4 处时脚本直接拒绝打站点 5。

#### Linux 与 Windows 拆分要点

- **RIP 相对寻址必须在虚拟地址(VA)空间解析**。Linux 版对整文件单一映射的 ELF/Mach-O 直接用文件偏移做 `i+plen+5+disp == c09` 比较即可；Windows 版必须走 `build_pe_off2va()` 换算到 VA 再比较，因为 PE 的 `.text` 与 `.rdata` 的 `VA − 文件偏移` 增量不同（`FileAlignment 0x200 ≠ SectionAlignment 0x1000`）。
- **MSVC 把毫秒值分配进扩展寄存器 `r8`/`r9`**：`from_millis` 尾部是 `4c 89 c0`（REX.W+REX.R 的 `mov rax,r8`）而非 musl 的 `48 89`。两版尾部识别都同时接受 `48`/`4c`，补丁对 `r8–r15` 加 `41`(REX.B)前缀写出 `41 b8 <imm32>`。

---

## claude

### Linux / macOS — `claude-linux.py`

```bash
python3 claude-linux.py --dry-run     # 预览
python3 claude-linux.py               # 打补丁
python3 claude-linux.py --restore     # 还原
```

### Windows — `claude-windows.py`

```powershell
# 需先关闭正在运行的 claude.exe（Windows 会锁定运行中的可执行文件）
py claude-windows.py --dry-run
py claude-windows.py
py claude-windows.py --restore
```

打补丁后设置环境变量再运行 claude：

```bash
export CLAUDE_CODE_MAX_RETRIES=9999            # Linux / macOS
export CLAUDE_CODE_RETRY_WATCHDOG=1            # 429/过载持续重试，并解除 15 次上限
export BUN_JSC_forceDebuggerBytecodeGeneration=1 # 让 standalone Bun 使用已修改的源码
$env:CLAUDE_CODE_MAX_RETRIES="9999"            # Windows (PowerShell)
$env:CLAUDE_CODE_RETRY_WATCHDOG="1"
$env:BUN_JSC_forceDebuggerBytecodeGeneration="1"
```

> 说明：claude 的 npm 包入口文件名叫 `claude.exe`（`package.json` 的 `bin` 字段就是 `bin/claude.exe`），但在 Linux 上它其实是 ELF 二进制——`.exe` 只是官方全平台统一命名，不代表格式。
>
> 指数退避改成约 1s 之后，429 仍会优先听从 `Retry-After` / `anthropic-ratelimit-unified-reset`（watchdog 路径里 reset 头会盖掉 1s 退避）。脚本会把这些头忽略，并把 API 重试等待写死为 1000ms。

### 参数（两版通用）

| 参数 | 说明 |
|---|---|
| `--dry-run` | 显示将要改动的内容，不修改二进制 |
| `--restore` | 从 `.orig` 备份还原 |

---

## 打坏了怎么恢复

打补丁前脚本会自动把原始二进制备份为 `<binary>.orig`，按从易到难三选一（用你平台对应的脚本名）：

```bash
# 1. 一键还原（推荐，靠 .orig 备份）
python3 codex-linux.py --restore
python3 claude-linux.py --restore

# 2. 手动从 .orig 拷回（脚本本身跑不了时）
cp <binary>.orig <binary> && chmod 755 <binary>

# 3. 重装（保底，.orig 也没了时；配置不受影响）
npm install -g @openai/codex@0.144.1                # codex（用户 npm 目录，锁定已验证版本）
npm install -g @anthropic-ai/claude-code            # claude（用户 npm 目录）
```

> 重装后是未打补丁的全新二进制；想再要补丁，重跑对应脚本即可。

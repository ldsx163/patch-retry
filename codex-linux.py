#!/usr/bin/env python3
"""
Patch Codex CLI's retry backoff interval -- Linux/macOS build (ELF / Mach-O).

Verified against codex rust-v0.143.0 (x86_64-unknown-linux-musl). This is the
Unix (ELF/Mach-O) build of the codex patcher; for the Windows PE build use
codex-windows.py. The two jittered backoffs it targets are:

  1. codex-client/src/retry.rs::backoff(base, attempt)  -- generic retry path
       `sleep(backoff(policy.base_delay, attempt+1))`.
  2. core/src/util.rs::backoff(attempt)                 -- stream-reconnect path
       ("Reconnecting N/M" delay when the server sends no explicit retry-after).

Both compute `Duration::from_millis((f64_delay * jitter) as u64)` with
`jitter = rand::rng().random_range(0.9..1.1)`, and in this build both are
INLINED into their async poll functions -- so, unlike the 0.142.x layout, there
is no standalone `backoff` entry to overwrite with a return-stub.

Instead this patcher rewrites each site *in place*. The value that flows into
the inlined `Duration::from_millis(...)` lives in a GP register right before the
tail:

    <mulsd  xmm, xmm>            ; delay_ms = f64_delay * jitter   (last reg-form mulsd)
    ... saturating f64->u64 ...  ; clamp to a u64 millisecond count
    mov     rax, <millis_reg>    ; from_millis reads the count from <millis_reg>
    shr     rax, 3
    movabs  rcx/rdx, 0x20c49ba5e353f7cf   ; /1000 magic  -> secs + nanos

We overwrite the span between the final `mulsd` and that `mov rax,<millis_reg>`
with `mov <millis_reg>, <ms>` (+ NOP padding), so the native from_millis
codegen that follows splits our constant into {secs, nanos} unchanged. The
result is a fixed retry interval independent of base delay, attempt, and jitter.

Location is anchored on the same x86-64 Rust codegen used by ELF and Mach-O:
  * the single 0.9 rodata constant from `0.9..1.1` (deduped across both sites);
  * the `addsd xmm,[rip->0.9]` that consumes it (this is what distinguishes the
    jitter sites from unrelated 0.9 uses -- a plain `movsd [0.9]` is ignored;
    the MSVC-only movsd variant lives in the Windows script);
  * the `mov rax,reg / shr rax,3 / movabs <from_millis magic>` tail.
RIP-relative operands resolve in file-offset space on the single-mapping ELF /
Mach-O images, so no VA translation is needed (that is the PE-only complication
handled by the Windows script).

Site 3 (stream_max_retries().min(100) hard cap) is unchanged from prior builds:
the inlined `unwrap_or(5).min(100)` codegen is byte-identical, so the same tail
signature locates every inlined copy and we rewrite the cap immediate to
STREAM_MAX_RETRIES so a large stream_max_retries in config.toml is honored.

Sites 1-2 alone do NOT give a fixed interval, because two other delay sources in
core/src/responses_retry.rs outrank or bypass `backoff()` entirely:

  4. `let delay = err.retry_delay().unwrap_or_else(|| backoff(retry_count));`
     A server-supplied Retry-After wins and `backoff()` is never called, so the
     wait becomes whatever the endpoint asked for. `Option<Duration>` is niche-
     encoded (nanos == 1_000_000_000 means None), so the branch reads:
         cmp  <r32>, 0x3b9aca00   ; None?
         jne  <skip the backoff call>
         ...  arg setup ...
         call <core::util::backoff>
     NOP-ing the `jne` makes the fixed backoff unconditional. Accepted only when
     the call provably lands inside a patched site-2 function, which is what
     stops a look-alike Option<Duration> unwrap from ever being rewritten.

  5. The `unbounded_connection_retries` ladder (Stable, default ON): on a
     ConnectionFailed the delay is a separate field that starts at
     `Duration::from_secs(5)` and doubles up to `from_secs(60)`. Those are plain
     whole-second constants, not `from_millis(f64 * jitter)`, so the sites 1-2
     anchors cannot see them. Rewriting the *load* pins the delay no matter what
     the ladder stored -- killing the 5s start and the doubling in one edit:
         mov <secs64>, [<base>+0x10]   ->   mov <secs32>, <whole seconds>
         mov <nanos32>,[<base>+0x18]   ->   xor <nanos32>, <nanos32>
     Both forms are exactly 7 bytes, so the stores of that pair into the async
     state machine (which is what identifies the sequence) stay in place. Site 5
     can only express whole seconds; RETRY_MS is rounded up to >=1s for it.

DESIGN RULE -- this patcher only ever changes "how long to wait after a failure
has already been declared". It must never change what counts as a failure, nor
how long detection takes (stream_idle_timeout_ms and friends are config, not
patch targets). Any site added later has to satisfy that; see README.md.

This changes the retry *interval*, not the retry *count*; use config.toml's
stream_max_retries/request_max_retries for the count (site 3 just unclamps the
stream cap so values >100 take effect).

Site 4 makes codex ignore Retry-After, so a genuine quota wall is retried every
second instead of when the server said to come back. That is the point of the
patch, but do not point it at an endpoint that will penalize the hammering.

Usage:
  python3 codex-linux.py --dry-run   (inspect only)
  sudo python3 codex-linux.py        (apply the patch)
  python3 codex-linux.py --restore
  python3 codex-linux.py --self-test

The retry interval and stream cap are fixed (RETRY_MS / STREAM_MAX_RETRIES).
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import struct
import subprocess
import sys
from pathlib import Path


PLATFORM_TARGETS = {
    ("Linux", "x86_64"): ("@openai/codex-linux-x64", "x86_64-unknown-linux-musl", "codex"),
    ("Linux", "aarch64"): ("@openai/codex-linux-arm64", "aarch64-unknown-linux-musl", "codex"),
    ("Darwin", "x86_64"): ("@openai/codex-darwin-x64", "x86_64-apple-darwin", "codex"),
    ("Darwin", "arm64"): ("@openai/codex-darwin-arm64", "aarch64-apple-darwin", "codex"),
}

# Site 3 signature (identical across System V and MSVC builds):
#   mov edx,<cap> ; cmovb rdx,rcx ; cmp byte[rax+0x10],0 ; mov eax,5 ; cmovne rax,rdx
STREAM_CAP_TAIL = bytes.fromhex("480f42d180781000b805000000480f45c2")

# core::time::Duration::from_millis divide-by-1000 reciprocal (u64 magic).
FROM_MILLIS_MAGIC = bytes.fromhex("cff753e3a59bc420")  # 0x20c49ba5e353f7cf, LE

# `mov <reg32>, imm32` opcode base; the low 3 bits select the register.
MOV_R32_IMM = 0xB8

# Site 4: `Option<Duration>` is niche-encoded -- nanos == 1_000_000_000 is None.
# (Duration::nanos is validity-restricted to 0..=999_999_999, so std reuses 1e9.)
NICHE_NONE = struct.pack("<I", 1_000_000_000)

# Same-length NOP runs, used to retire a `jne` without moving anything.
NOP_RUNS = {2: b"\x66\x90", 6: b"\x66\x0f\x1f\x44\x00\x00"}

# How far past a backoff entry a patched jitter site may sit for site 4 to accept
# the call as "this really is core::util::backoff" (its body is ~0x160 bytes).
BACKOFF_FN_WINDOW = 0x600

# Site 4: bytes of arg setup tolerated between the `jne` and the backoff `call`,
# and how far past the call the `jne` may land (the Some-path convergence).
SITE4_CALL_WINDOW = 24
SITE4_JOIN_WINDOW = 32

# Site 5 circuit breaker: 0.153.4 has exactly two copies of the ladder (sampling
# and remote-compaction). A much larger count means the signature went loose, and
# site 5 rewrites live instructions, so refuse rather than guess.
MAX_CONN_SITES = 4

# 32-bit GP register names by 4-bit register number (for readable logs).
REG_NAMES = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
             "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d")


def reg_name(reg: int) -> str:
    return REG_NAMES[reg] if 0 <= reg < len(REG_NAMES) else f"reg{reg}"

MS_MIN, MS_MAX = 1, 86_400_000  # 1ms .. 24h; also keeps the imm32 non-negative
REGION_MIN, REGION_MAX = 5, 256  # sanity bounds on the span we overwrite

# Fixed policy (no longer CLI-configurable): retry interval and stream cap.
RETRY_MS = 1000          # fixed retry interval in milliseconds
STREAM_MAX_RETRIES = 9999  # raise the stream_max_retries hard cap (default 100) to this


def die(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def require_platform() -> None:
    """Refuse to run outside Linux/macOS.

    This build only understands ELF/Mach-O images and Unix binary discovery;
    a Windows PE needs the VA translation and MSVC movsd anchor in
    codex-windows.py. Fail fast with that pointer instead of later
    dying on an unrecognized format."""
    if os.name != "posix":
        print(f"ERROR: this is the Linux/macOS build, but the current OS is "
              f"'{sys.platform}' (os.name={os.name!r}).", file=sys.stderr)
        print("Use codex-windows.py on Windows.", file=sys.stderr)
        sys.exit(1)


# ── Format / architecture detection (dispatch + safety gate) ──────────────────
def detect_format(data: bytes) -> str:
    """Return 'elf' | 'macho', or die. Refuses PE (Windows build) and non-x86-64
    binaries, since every byte pattern below is x86-64 ELF/Mach-O specific."""
    if data[:2] == b"MZ":
        die("this is a Windows PE; use codex-windows.py")
    if data[:4] == b"\x7fELF":
        if struct.unpack_from("<H", data, 18)[0] != 0x3E:
            die("ELF is not x86-64 (e_machine != 0x3E); this patch is x86-64 only")
        return "elf"
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):  # Mach-O LE
        if struct.unpack_from("<I", data, 4)[0] != 0x01000007:
            die("Mach-O is not x86_64 (arm64 uses a different ISA/ABI; unsupported)")
        return "macho"
    if data[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        die("fat/universal Mach-O not supported; extract the x86_64 slice first")
    die("unrecognized binary format (expected ELF or Mach-O)")


def validate_ms(ms: int) -> None:
    if not (MS_MIN <= ms <= MS_MAX):
        die(f"--ms must be between {MS_MIN} and {MS_MAX}")


# ── Offset <-> VA maps (only site 4 needs them) ────────────────────────────────
def load_segments(data: bytes, fmt: str) -> list[tuple[int, int, int]]:
    """[(file_off, vaddr, file_size)] for every mapped segment.

    Sites 1-3 compare RIP operands that land in the same single mapping, so they
    stay in file-offset space. Site 4 has to *dereference* a GOT slot in the
    writable segment, where `p_offset != p_vaddr` (a 0x1000 skew on this build),
    so it needs a real translation in both directions."""
    segs: list[tuple[int, int, int]] = []
    if fmt == "elf":
        phoff = struct.unpack_from("<Q", data, 0x20)[0]
        phentsize = struct.unpack_from("<H", data, 0x36)[0]
        phnum = struct.unpack_from("<H", data, 0x38)[0]
        for i in range(phnum):
            b = phoff + i * phentsize
            if struct.unpack_from("<I", data, b)[0] == 1:  # PT_LOAD
                off, va = struct.unpack_from("<QQ", data, b + 8)
                filesz = struct.unpack_from("<Q", data, b + 32)[0]
                segs.append((off, va, filesz))
    elif fmt == "macho":
        ncmds = struct.unpack_from("<I", data, 16)[0]
        p = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", data, p)
            if cmdsize <= 0:
                break
            if cmd == 0x19:  # LC_SEGMENT_64
                va, _vmsize, off, filesz = struct.unpack_from("<QQQQ", data, p + 24)
                segs.append((off, va, filesz))
            p += cmdsize
    return segs


def segment_maps(segs: list[tuple[int, int, int]]):
    """(off2va, va2off); each returns None for an address outside every segment."""
    def off2va(off: int):
        for so, sv, ss in segs:
            if so <= off < so + ss:
                return off - so + sv
        return None

    def va2off(va: int):
        for so, sv, ss in segs:
            if sv <= va < sv + ss:
                return va - sv + so
        return None

    return off2va, va2off


# ── Sites 1 & 2: in-place jitter -> fixed interval ────────────────────────────
def _find_09_constant(data: bytes) -> int:
    """File offset of the single 0.9 f64 constant (from `0.9..1.1`); die if the
    count isn't exactly one (a signature the build no longer matches)."""
    needle = struct.pack("<d", 0.9)
    offs, i = [], data.find(needle)
    while i != -1:
        offs.append(i)
        i = data.find(needle, i + 1)
    if len(offs) != 1:
        die(f"expected exactly one 0.9 jitter constant, found {len(offs)}")
    return offs[0]


def _rip_f64_sites(data: bytes, c09: int, opcode: int) -> list[int]:
    """Offsets of an SSE2 f64 instruction (opcode: 0x58 addsd / 0x10 movsd)
    reading `[rip->0.9]`. ELF/Mach-O are single-mapping images, so `[rip+disp32]`
    resolves in plain file-offset space (`next_instr_off + disp == c09`), unlike
    PE which needs VA translation."""
    sites = []
    for pref in (b"\xf2\x0f" + bytes([opcode]),
                 b"\xf2\x44\x0f" + bytes([opcode])):
        plen, i = len(pref), data.find(pref)
        while i != -1:
            modrm = data[i + plen]
            if (modrm & 0xC7) == 0x05:  # [rip+disp32]
                disp = struct.unpack_from("<i", data, i + plen + 1)[0]
                if (i + plen + 5) + disp == c09:
                    sites.append(i)
            i = data.find(pref, i + 1)
    return sites


def _addsd_09_sites(data: bytes, c09: int) -> list[int]:
    """Offsets of `addsd xmm,[rip->0.9]` -- the `random_range(0.9..1.1)`
    fingerprint. Accepted unconditionally (a bare 0.9 addsd is jitter-specific)."""
    return _rip_f64_sites(data, c09, 0x58)


def _movsd_09_sites(data: bytes, c09: int) -> list[int]:
    """Offsets of `movsd xmm,[rip->0.9]`. Newer codex builds (>=0.144.x) load the
    0.9 lower bound with movsd for one backoff path. movsd also occurs in
    unrelated math, so callers accept it only when the full from_millis chain
    downstream also matches."""
    return _rip_f64_sites(data, c09, 0x10)


def _mulsd_len(data: bytes, off: int):
    """Length of a reg-form mulsd at `off` (f2 0f 59 /r = 4, REX.R f2 44 0f 59 = 5),
    or None if `off` is not a reg-form mulsd."""
    if data[off : off + 3] == b"\xf2\x0f\x59" and data[off + 3] >= 0xC0:
        return 4
    if data[off : off + 4] == b"\xf2\x44\x0f\x59" and data[off + 4] >= 0xC0:
        return 5
    return None


def _find_from_millis_tail(data: bytes, start: int, window: int = 384):
    """From `start`, find the inlined Duration::from_millis tail:
        mov rax,<reg>  (48/4c 89 /r, rm=000)  ;  shr rax,3 (48 c1 e8 03)  ;  movabs magic
    The source reg may be r8..r15 (REX.R -> prefix 0x4c); the millis reg is then
    the full 4-bit number. Return (mov_off, millis_reg) or None."""
    i = data.find(b"\x48\xc1\xe8\x03", start, start + window)
    while i != -1:
        mv = i - 3
        # dest is rax (rm=000, no REX.B); source reg field + REX.R -> 4-bit reg.
        is_mov = (data[mv] in (0x48, 0x4c) and data[mv + 1] == 0x89
                  and (data[mv + 2] & 0xC7) == 0xC0)
        has_magic = FROM_MILLIS_MAGIC in data[i + 4 : i + 20]
        if is_mov and has_magic:
            reg = ((data[mv + 2] >> 3) & 7) | (0x8 if data[mv] == 0x4c else 0)
            return mv, reg
        i = data.find(b"\x48\xc1\xe8\x03", i + 1, start + window)
    return None


def find_jitter_sites(data: bytes) -> list[dict]:
    """Locate every `Duration::from_millis(delay*jitter)` site keyed on 0.9..1.1.
    Each dict: {anchor, region_start, region_end, reg, current}."""
    c09 = _find_09_constant(data)
    out = []
    # Newer codex builds (>=0.144.x) use `movsd [0.9]` for one backoff path.
    # Unlike `addsd`, movsd also occurs in unrelated math, so only accept it with
    # every later from_millis/mulsd/span check satisfied.
    anchors = ([(i, True, "addsd") for i in _addsd_09_sites(data, c09)]
               + [(i, False, "movsd") for i in _movsd_09_sites(data, c09)])
    for anchor, strict, kind in sorted(anchors):
        tail = _find_from_millis_tail(data, anchor)
        if tail is None:
            if strict:
                die(f"jitter add at 0x{anchor:x} has no matching from_millis tail")
            continue
        mv, reg = tail
        # Nearest reg-form mulsd before the tail: the `delay_ms = f64 * jitter` op.
        mul = None
        for j in range(mv - 1, max(anchor, mv - 320) - 1, -1):
            n = _mulsd_len(data, j)
            if n is not None:
                mul = (j, n)
                break
        if mul is None:
            if strict:
                die(f"no final mulsd before from_millis tail at 0x{mv:x}")
            continue
        region_start = mul[0] + mul[1]
        region_end = mv
        if not (REGION_MIN <= region_end - region_start <= REGION_MAX):
            if strict:
                die(f"implausible patch span [0x{region_start:x},0x{region_end:x}) "
                    f"len {region_end - region_start}; refusing to write")
            continue
        # Idempotency: an already-patched site holds `mov <reg>,imm32` at start
        # (with a REX.B prefix when reg is r8..r15).
        current = None
        base = region_start + (1 if reg >= 8 else 0)
        rex_ok = reg < 8 or data[region_start] == 0x41
        if rex_ok and (data[base] & 0xF8) == MOV_R32_IMM and (data[base] & 7) == (reg & 7):
            current = struct.unpack_from("<I", data, base + 1)[0]
        out.append({"anchor": anchor, "kind": kind, "mulsd": mul[0], "tail": mv,
                    "region_start": region_start, "region_end": region_end,
                    "reg": reg, "current": current})
    return out


def make_jitter_patch(reg: int, region_len: int, ms: int) -> bytes:
    """`mov <reg32>, ms` (zero-extended to 64-bit) padded with NOPs.
    Extended registers r8..r15 (reg>=8) need a REX.B (0x41) prefix."""
    validate_ms(ms)
    prefix = b"\x41" if reg >= 8 else b""
    patch = prefix + bytes([MOV_R32_IMM + (reg & 7)]) + struct.pack("<i", ms)
    return patch + b"\x90" * (region_len - len(patch))


# ── Site 4 (Retry-After overriding the fixed backoff) ─────────────────────────
def _call_target_off(data: bytes, off: int, off2va, va2off):
    """File offset of the function a `call` at `off` reaches, or None.

    Handles `e8 rel32` (direct) and `ff 15 disp32` (indirect through a GOT slot,
    which is what this build emits for cross-codegen-unit calls)."""
    va = off2va(off)
    if va is None:
        return None
    if data[off] == 0xE8:
        target = va + 5 + struct.unpack_from("<i", data, off + 1)[0]
        return va2off(target)
    if data[off] == 0xFF and data[off + 1] == 0x15:
        slot = va2off(va + 6 + struct.unpack_from("<i", data, off + 2)[0])
        if slot is None or slot + 8 > len(data):
            return None
        return va2off(struct.unpack_from("<Q", data, slot)[0])
    return None


def _call_len(data: bytes, off: int):
    if data[off] == 0xE8:
        return 5
    if data[off] == 0xFF and data[off + 1] == 0x15:
        return 6
    return None


def _backoff_call_after(data: bytes, start: int, in_backoff, limit: int):
    """(call_off, call_len) of the first call to core::util::backoff within
    `limit` bytes of `start`, or None."""
    for i in range(start, min(start + limit, len(data) - 6)):
        n = _call_len(data, i)
        if n is None:
            continue
        target = _call_target_off(data, i, *in_backoff[1:])
        if target is not None and in_backoff[0](target):
            return i, n
    return None


def find_retry_after_sites(data: bytes, jitter_sites: list[dict],
                           off2va, va2off) -> list[dict]:
    """Offsets of the `err.retry_delay().unwrap_or_else(|| backoff(n))` branch.

        cmp  <r32>, 0x3b9aca00   ; Option<Duration> niche: 1e9 == None
        jne  <past the backoff call>
        ...  arg setup ...
        call <core::util::backoff>

    A site is accepted only when the call target encloses one of the jitter sites
    patched by sites 1-2, i.e. it provably is `backoff`. That check -- not the
    byte pattern -- is what makes NOP-ing the `jne` safe."""
    entries = [s["region_start"] for s in jitter_sites]
    in_backoff = (lambda p: any(p <= r < p + BACKOFF_FN_WINDOW for r in entries),
                  off2va, va2off)
    out: list[dict] = []
    i = data.find(NICHE_NONE)
    while i != -1:
        # cmp r32,imm32: `81 /7 imm32` (modrm f8..ff) or the eax short form `3d`.
        cmp_off = None
        if i >= 2 and data[i - 2] == 0x81 and 0xF8 <= data[i - 1] <= 0xFF:
            cmp_off, reg = i - 2, data[i - 1] & 7
        elif i >= 1 and data[i - 1] == 0x3D:
            cmp_off, reg = i - 1, 0
        if cmp_off is not None:
            site = _classify_retry_after(data, cmp_off, i + 4, reg, in_backoff)
            if site is not None:
                out.append(site)
        i = data.find(NICHE_NONE, i + 1)
    return out


def _classify_retry_after(data: bytes, cmp_off: int, after_cmp: int, reg: int,
                          in_backoff) -> dict | None:
    """Match the `jne`-or-already-NOPed form at `after_cmp`; None if neither."""
    for length, patched in ((2, False), (6, False), (2, True), (6, True)):
        blob = data[after_cmp : after_cmp + length]
        if patched:
            if blob != NOP_RUNS[length]:
                continue
            join = None
        elif length == 2:
            if data[after_cmp] != 0x75:
                continue
            join = after_cmp + 2 + struct.unpack_from("<b", data, after_cmp + 1)[0]
        else:
            if data[after_cmp : after_cmp + 2] != b"\x0f\x85":
                continue
            join = after_cmp + 6 + struct.unpack_from("<i", data, after_cmp + 2)[0]
        found = _backoff_call_after(data, after_cmp + length, in_backoff,
                                    SITE4_CALL_WINDOW)
        if found is None:
            continue
        call_off, call_len = found
        call_end = call_off + call_len
        # The branch must jump *over* the backoff call and rejoin just past it.
        if join is not None and not (call_end <= join <= call_end + SITE4_JOIN_WINDOW):
            continue
        return {"cmp": cmp_off, "reg": reg, "jne": after_cmp, "len": length,
                "call": call_off, "patched": patched}
    return None


# ── Site 5 (unbounded connection-retry ladder: 5s doubling to 60s) ────────────
def _conn_tail_ok(data: bytes, off: int, secs_reg: int, nanos_reg: int) -> bool:
    """True when `off` holds the tail that identifies the delay load:

        mov [<base>+disp32], <secs64>    ; spill the Duration into the
        mov [<base>+disp32], <nanos32>   ;   async poll state machine
        lea <r64>, [rip+disp32]          ; static-level check of the warn! that
                                         ;   reports the wait

    The rip-relative `lea` is load-bearing: unrelated code also spills a
    {secs,nanos} pair into a state machine (a stray `mov eax,60 ; xor ecx,ecx`
    reads exactly like an already-patched site), and that code continues with
    base-relative `lea`s instead."""
    if data[off : off + 2] != b"\x48\x89":
        return False
    m1 = data[off + 2]
    if (m1 >> 6) != 0b10 or ((m1 >> 3) & 7) != secs_reg or (m1 & 7) == 0b100:
        return False
    q = off + 7  # 48 89 <modrm> <disp32>
    if data[q] != 0x89:
        return False
    m2 = data[q + 1]
    if not ((m2 >> 6) == 0b10 and ((m2 >> 3) & 7) == nanos_reg
            and (m2 & 7) == (m1 & 7)):
        return False
    lea = q + 6  # 89 <modrm> <disp32>
    return (data[lea] in (0x48, 0x4C) and data[lea + 1] == 0x8D
            and (data[lea + 2] & 0xC7) == 0x05)


def find_conn_delay_sites(data: bytes) -> list[dict]:
    """Offsets of `let retry_delay = retry_state.connection_retry_delay;`.

        mov <secs64>, [<base>+0x10]     (48 8b /r, mod=01, disp8=0x10)
        mov <nanos32>,[<base>+0x18]     (8b /r,    mod=01, disp8=0x18)

    The absent REX means both destination registers are already < 8, which is
    what lets the 7-byte replacement fit exactly. Also recognizes the patched
    form so --dry-run reports the current value instead of "not found"."""
    out: list[dict] = []
    i = data.find(b"\x48\x8b")
    while i != -1:
        m1 = data[i + 2]
        if (m1 >> 6) == 0b01 and (m1 & 7) != 0b100 and data[i + 3] == 0x10:
            secs, base = (m1 >> 3) & 7, m1 & 7
            m2 = data[i + 5]
            if (data[i + 4] == 0x8B and (m2 >> 6) == 0b01 and (m2 & 7) == base
                    and data[i + 6] == 0x18 and base != secs
                    and _conn_tail_ok(data, i + 7, secs, (m2 >> 3) & 7)):
                out.append({"off": i, "secs_reg": secs, "nanos_reg": (m2 >> 3) & 7,
                            "base_reg": base, "current": None})
        i = data.find(b"\x48\x8b", i + 1)
    out.extend(_find_patched_conn_delay_sites(data))
    return sorted(out, key=lambda s: s["off"])


def _find_patched_conn_delay_sites(data: bytes) -> list[dict]:
    """Already-patched form: `mov <secs32>,imm32 ; xor <nanos32>,<nanos32>`."""
    out: list[dict] = []
    i = data.find(b"\x31", 5)
    while i != -1:
        modrm = data[i + 1]
        reg = (modrm >> 3) & 7
        if modrm == (0xC0 | (reg << 3) | reg) and 0xB8 <= data[i - 5] <= 0xBF:
            secs = data[i - 5] - MOV_R32_IMM
            if _conn_tail_ok(data, i + 2, secs, reg):
                out.append({"off": i - 5, "secs_reg": secs, "nanos_reg": reg,
                            "base_reg": None,
                            "current": struct.unpack_from("<I", data, i - 4)[0]})
        i = data.find(b"\x31", i + 1)
    return out


def make_conn_delay_patch(secs_reg: int, nanos_reg: int, secs: int) -> bytes:
    """`mov <secs32>, secs ; xor <nanos32>, <nanos32>` -- exactly 7 bytes, the
    length of the two loads it replaces, so nothing downstream shifts."""
    if not (0 <= secs_reg < 8 and 0 <= nanos_reg < 8):
        die("site 5 needs both registers below r8 to fit in 7 bytes")
    patch = (bytes([MOV_R32_IMM + secs_reg]) + struct.pack("<I", secs)
             + bytes([0x31, 0xC0 | (nanos_reg << 3) | nanos_reg]))
    assert len(patch) == 7, patch.hex(" ")
    return patch


def conn_delay_secs(ms: int) -> int:
    """Site 5 stores a whole-second Duration, so round RETRY_MS up to >= 1s."""
    return max(1, round(ms / 1000))


# ── Site 3 (stream_max_retries cap) ───────────────────────────────────────────
def find_stream_cap_sites(data: bytes) -> list[int]:
    """Offsets of `mov edx,<cap>` for each inlined stream_max_retries().min(cap)."""
    sites, i = [], data.find(STREAM_CAP_TAIL)
    while i != -1:
        if i >= 5 and data[i - 5] == 0xBA:  # `mov edx, imm32` immediately before tail
            sites.append(i - 5)
        i = data.find(STREAM_CAP_TAIL, i + 1)
    return sites


def current_stream_caps(data: bytes) -> list[int]:
    return sorted({struct.unpack_from("<I", data, s + 1)[0]
                   for s in find_stream_cap_sites(data)})


# ── Plan ──────────────────────────────────────────────────────────────────────
SITE_LABELS = ("retry.rs::backoff", "util.rs::backoff")


def plan(data: bytes, ms: int):
    """Return (edits, report). edits: [(off, bytes)]. report: [(label, site)]."""
    edits, report = [], []
    sites = find_jitter_sites(data)
    if len(sites) < len(SITE_LABELS):
        die(f"expected at least {len(SITE_LABELS)} jittered backoff sites "
            f"(0.9..1.1), found {len(sites)}")
    for idx, s in enumerate(sites):
        label = SITE_LABELS[idx] if idx < len(SITE_LABELS) else f"backoff[{idx}]"
        patch = make_jitter_patch(s["reg"], s["region_end"] - s["region_start"], ms)
        edits.append((s["region_start"], patch))
        report.append((label, s))
    return edits, report


# ── Binary discovery ──────────────────────────────────────────────────────────
def is_native_binary(path: Path) -> bool:
    try:
        head = path.read_bytes()[:4]
    except OSError:
        return False
    return (head == b"\x7fELF"
            or head in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",
                        b"\xca\xfe\xba\xbe"))


def target_info() -> tuple[str, str, str]:
    key = (platform.system(), platform.machine())
    if key not in PLATFORM_TARGETS:
        die(f"unsupported platform {key[0]} {key[1]}")
    return PLATFORM_TARGETS[key]


def package_root_from_wrapper(wrapper: Path):
    # npm wrapper layouts: .../@openai/codex/bin/codex(.js).
    if wrapper.name in {"codex", "codex.js"} and wrapper.parent.name == "bin":
        for root in (wrapper.parent.parent,
                     wrapper.parent / "node_modules" / "@openai" / "codex"):
            if (root / "package.json").is_file():
                return root
    return None


def binary_from_package_root(root: Path):
    pkg_name, triple, exe = target_info()
    for candidate in (
        root / "node_modules" / pkg_name / "vendor" / triple / "bin" / exe,
        root / "vendor" / triple / "bin" / exe,
    ):
        if candidate.is_file():
            return candidate.resolve()
    return None


def find_binary(explicit: str | None) -> Path:
    if explicit:
        p = Path(explicit).expanduser().resolve()
        if not p.is_file():
            die(f"binary not found: {p}")
        return p

    candidates: list[Path] = []
    found = shutil.which("codex")
    if found:
        candidates.append(Path(found).resolve())
    for root in ("/usr/lib/node_modules/@openai/codex",
                 "/usr/local/lib/node_modules/@openai/codex"):
        candidates.append(Path(root))
    try:
        npm_root = subprocess.run(["npm", "root", "-g"], capture_output=True,
                                  text=True, timeout=10)
        if npm_root.returncode == 0 and npm_root.stdout.strip():
            candidates.append(Path(npm_root.stdout.strip()) / "@openai" / "codex")
    except Exception:
        pass

    seen: set[Path] = set()
    for c in candidates:
        if c in seen:
            continue
        seen.add(c)
        if c.is_file() and is_native_binary(c):
            return c
        root = c if c.is_dir() else package_root_from_wrapper(c)
        if root:
            binary = binary_from_package_root(root)
            if binary:
                return binary

    die("could not find native Codex binary; pass --binary /path/to/codex")


# ── Patch driver ──────────────────────────────────────────────────────────────
def patch_binary(binary: Path, ms: int, max_retries: int, dry_run: bool) -> None:
    validate_ms(ms)
    if not (1 <= max_retries <= 0xFFFF_FFFF):
        die("STREAM_MAX_RETRIES must be between 1 and 4294967295")
    data = bytearray(binary.read_bytes())
    fmt = detect_format(bytes(data))  # elf/macho only; PE is rejected

    print(f"Found binary: {binary}")
    print(f"Binary size:  {len(data)} bytes  [{fmt.upper()} x86-64]")

    def fmt_ms(v):
        return "unpatched" if v is None else f"{v}ms"

    # -- Sites 1 & 2: jitter -> fixed interval --------------------------------
    print()
    print("=== Jitter backoff sites (random_range 0.9..1.1) ===")
    c09 = _find_09_constant(data)
    print(f"  0.9 jitter constant @ 0x{c09:x} (single, shared by both backoffs)")
    edits, report = plan(data, ms)
    for idx, (label, s) in enumerate(report, 1):
        span = s["region_end"] - s["region_start"]
        print(f"  [{idx}] {label}")
        print(f"        anchor  : {s['kind']} xmm,[rip->0.9] @ 0x{s['anchor']:x}")
        print(f"        mulsd   : final reg-form @ 0x{s['mulsd']:x}")
        print(f"        millis  : from_millis reads {reg_name(s['reg'])} "
              f"(mov tail @ 0x{s['tail']:x})")
        print(f"        rewrite : [0x{s['region_start']:x},0x{s['region_end']:x}) "
              f"span {span}B -> mov {reg_name(s['reg'])},{ms} + NOPs")
        print(f"        current : {fmt_ms(s['current'])} -> {ms}ms")

    # -- Site 3: stream_max_retries cap ---------------------------------------
    print()
    print("=== stream_max_retries hard cap ===")
    cap_sites = find_stream_cap_sites(data)
    cap_now = current_stream_caps(data)
    if cap_sites:
        locs = ", ".join(f"0x{s:x}" for s in cap_sites)
        print(f"  {len(cap_sites)} inlined site(s): {locs}")
        print(f"  current cap: {cap_now} -> {max_retries}")
    else:
        print("  NOT FOUND - skipping (cap stays 100)")

    # -- Site 4: Retry-After outranking the fixed backoff ---------------------
    print()
    print("=== Retry-After override (responses_retry.rs: unwrap_or_else) ===")
    off2va, va2off = segment_maps(load_segments(bytes(data), fmt))
    ra_sites = find_retry_after_sites(bytes(data), [s for _, s in report],
                                      off2va, va2off)
    for idx, s in enumerate(ra_sites, 1):
        state = "already NOPed" if s["patched"] else "live"
        print(f"  [{idx}] cmp {reg_name(s['reg'])},0x3b9aca00 @ 0x{s['cmp']:x}"
              f"  (Option<Duration> None niche)")
        print(f"        branch  : {s['len']}-byte jne @ 0x{s['jne']:x} -> {state}")
        print(f"        verified: call @ 0x{s['call']:x} lands in a patched "
              f"util.rs::backoff")
        print(f"        rewrite : jne -> {s['len']}-byte NOP "
              f"(server Retry-After ignored, backoff always wins)")
    if not ra_sites:
        print("  NOT FOUND - skipping (a server Retry-After will still override "
              f"the {ms}ms interval)")
    for s in ra_sites:
        if not s["patched"]:
            edits.append((s["jne"], NOP_RUNS[s["len"]]))

    # -- Site 5: unbounded connection-retry ladder (5s -> 60s) ----------------
    secs = conn_delay_secs(ms)
    print()
    print("=== connection retry ladder (unbounded_connection_retries) ===")
    conn_sites = find_conn_delay_sites(bytes(data))
    if len(conn_sites) > MAX_CONN_SITES:
        print(f"  {len(conn_sites)} site(s) matched but at most {MAX_CONN_SITES} "
              f"are plausible - REFUSING to patch site 5 (signature went loose)")
        conn_sites = []
    for idx, s in enumerate(conn_sites, 1):
        cur = "unpatched (5s start, doubling to 60s)" if s["current"] is None \
            else f"{s['current']}s fixed"
        print(f"  [{idx}] delay load @ 0x{s['off']:x}  "
              f"secs={reg_name(s['secs_reg'])} nanos={reg_name(s['nanos_reg'])}")
        print(f"        current : {cur} -> {secs}s")
        print(f"        rewrite : 7B -> mov {reg_name(s['secs_reg'])},{secs} ; "
              f"xor {reg_name(s['nanos_reg'])},{reg_name(s['nanos_reg'])}")
    if not conn_sites:
        print("  NOT FOUND - skipping (set unbounded_connection_retries = false "
              "in config.toml instead)")
    if secs * 1000 != ms:
        print(f"  NOTE: site 5 stores whole seconds, so {ms}ms is applied as {secs}s")
    for s in conn_sites:
        if s["current"] != secs:
            edits.append((s["off"], make_conn_delay_patch(
                s["secs_reg"], s["nanos_reg"], secs)))

    # -- Summary --------------------------------------------------------------
    print()
    print("=== Summary ===")
    print(f"  jitter sites : {len(report)} to patch -> {ms}ms fixed interval")
    print(f"  stream cap   : {len(cap_sites)} site(s) -> {max_retries}")
    print(f"  retry-after  : {len(ra_sites)} site(s) -> ignored")
    print(f"  conn ladder  : {len(conn_sites)} site(s) -> {secs}s flat")
    print(f"  retry interval: {ms}ms")

    if dry_run:
        print()
        print("DRY RUN - no changes were made.")
        return

    backup = binary.with_name(binary.name + ".orig")
    if not backup.exists():
        print()
        print(f"Creating backup: {backup}")
        shutil.copy2(binary, backup)

    for off, patch in edits:
        data[off : off + len(patch)] = patch
    cap_bytes = struct.pack("<I", max_retries)
    for s in cap_sites:
        data[s + 1 : s + 5] = cap_bytes

    mode = binary.stat().st_mode  # preserve permissions (esp. the exec bit)
    tmp = binary.with_name(binary.name + ".tmp")
    tmp.write_bytes(data)
    os.chmod(tmp, mode)
    try:
        os.replace(tmp, binary)
    except PermissionError:
        tmp.unlink(missing_ok=True)
        die("could not replace binary (is codex running, or lacking permission?). "
            "Close codex and retry.")
    print()
    print(f"Patched successfully: {len(report)} jitter + {len(ra_sites)} "
          f"retry-after + {len(conn_sites)} conn-ladder + {len(cap_sites)} cap "
          f"site(s) ({len(edits)} edit(s) written).")
    print(f"Restore with: {Path(sys.executable).name} {Path(sys.argv[0]).name} --restore")


def restore_binary(binary: Path) -> None:
    backup = binary.with_name(binary.name + ".orig")
    if not backup.is_file():
        die(f"no backup found: {backup}")
    shutil.copy2(backup, binary)
    print(f"Restored {binary} from {backup}")


def self_test() -> None:
    # jitter patch: `mov ecx, 1500` (=0x5dc), NOP-padded to region length
    p = make_jitter_patch(1, 20, 1500)  # reg=1 -> ecx
    assert p[0] == 0xB9 and struct.unpack_from("<i", p, 1)[0] == 1500, p.hex(" ")
    assert len(p) == 20 and p[5:] == b"\x90" * 15
    p2 = make_jitter_patch(7, 12, 1000)  # reg=7 -> edi
    assert p2[0] == 0xBF and struct.unpack_from("<i", p2, 1)[0] == 1000
    # extended reg r8 (>=8) -> REX.B prefix `41 b8 imm32`
    p3 = make_jitter_patch(8, 12, 1000)  # reg=8 -> r8d
    assert p3[:2] == b"\x41\xb8" and struct.unpack_from("<i", p3, 2)[0] == 1000
    assert len(p3) == 12 and p3[6:] == b"\x90" * 6
    # synthetic site: addsd xmm0,[rip->0.9] ; mulsd xmm2,xmm1 ; <clamp> ;
    #                 mov rax,rcx ; shr rax,3 ; movabs magic
    addsd = b"\xf2\x0f\x58\x05\x00\x00\x00\x00"      # disp32 filled in below
    mul = b"\xf2\x0f\x59\xd1"                          # mulsd xmm2,xmm1 (reg-form)
    junk = b"\x66\x0f\x57\xc0" * 5                     # 20 bytes of clamp filler
    tail = b"\x48\x89\xc8\x48\xc1\xe8\x03" + b"\x48\xba" + FROM_MILLIS_MAGIC
    code = addsd + mul + junk + tail
    a_off = 64                                        # addsd position in the buffer
    c09 = 64 + len(code) + 32                          # 0.9 constant, clear of the code
    blob = bytearray(b"\x00" * 64 + code + b"\x00" * 64)
    struct.pack_into("<i", blob, a_off + 4, c09 - (a_off + 8))  # rip disp -> c09
    struct.pack_into("<d", blob, c09, 0.9)
    # ensure exactly one 0.9 in the buffer
    assert bytes(blob).count(struct.pack("<d", 0.9)) == 1
    sites = find_jitter_sites(bytes(blob))
    assert len(sites) == 1, sites
    s = sites[0]
    assert s["reg"] == 1  # mov rax,rcx -> millis reg = ecx
    assert s["region_start"] == a_off + len(addsd) + len(mul)
    assert s["region_end"] == a_off + len(addsd) + len(mul) + len(junk)
    assert s["current"] is None
    # apply and confirm idempotent re-read
    patched = bytearray(blob)
    patch = make_jitter_patch(s["reg"], s["region_end"] - s["region_start"], 2500)
    patched[s["region_start"]:s["region_end"]] = patch
    s2 = find_jitter_sites(bytes(patched))[0]
    assert s2["current"] == 2500, s2
    # Newer codex layout loads the 0.9 lower bound with movsd before multiplying.
    movsd_blob = bytearray(blob)
    movsd_blob[a_off + 2] = 0x10  # f2 0f 58 (addsd) -> f2 0f 10 (movsd)
    movsd_sites = find_jitter_sites(bytes(movsd_blob))
    assert len(movsd_sites) == 1 and movsd_sites[0]["anchor"] == a_off
    # A bare movsd of 0.9 is not enough: unrelated loads have no from_millis tail.
    unrelated = bytearray(movsd_blob)
    magic = unrelated.find(FROM_MILLIS_MAGIC)
    unrelated[magic:magic + len(FROM_MILLIS_MAGIC)] = b"\x00" * len(FROM_MILLIS_MAGIC)
    assert find_jitter_sites(bytes(unrelated)) == []
    _self_test_site4()
    _self_test_site5()
    # format detection: ELF accepted, PE rejected via die()/SystemExit.
    assert detect_format(b"\x7fELF" + b"\x00" * 14 + b"\x3e\x00" + b"\x00" * 8) == "elf"
    try:
        detect_format(b"MZ" + b"\x00" * 64)
    except SystemExit:
        pass
    else:
        raise AssertionError("PE should be rejected by the Linux build")
    print("self-test OK")


def _self_test_site4() -> None:
    """Synthetic `err.retry_delay().unwrap_or_else(|| backoff(n))` branch:
        cmp ecx,1e9 ; jne +0x0b ; mov rdi,rcx ; call F ; <3B join pad>
    with identity off<->VA maps (a real image needs segment_maps)."""
    ident = lambda x: x
    F = 0x100                                   # pretend backoff entry
    C = 0x400                                   # the cmp
    blob = bytearray(b"\x90" * 0x600)
    body = (b"\x81\xf9" + NICHE_NONE            # cmp ecx, 1_000_000_000
            + b"\x75\x0b"                       # jne  -> C+0x13
            + b"\x48\x89\xcf"                   # mov rdi,rcx
            + b"\xe8" + struct.pack("<i", F - (C + 16)))
    blob[C : C + len(body)] = body
    assert bytes(blob).count(NICHE_NONE) == 1
    jitter = [{"region_start": F + 0x10}]       # sits inside the "function"
    sites = find_retry_after_sites(bytes(blob), jitter, ident, ident)
    assert len(sites) == 1, sites
    s = sites[0]
    assert (s["cmp"], s["jne"], s["len"], s["reg"]) == (C, C + 6, 2, 1), s
    assert s["patched"] is False and s["call"] == C + 11
    # a call that does not land in a patched backoff must be rejected outright
    far = bytearray(blob)
    assert find_retry_after_sites(bytes(far), [{"region_start": F + 0x900}],
                                  ident, ident) == []
    # the indirect form this build actually emits: `call [rip+GOT]`, where the
    # slot holds the backoff entry (identity maps still exercise both hops).
    G = 0x300
    ind = bytearray(b"\x90" * 0x600)
    ind[G : G + 8] = struct.pack("<Q", F)
    indirect = (b"\x81\xf9" + NICHE_NONE      # cmp ecx, 1_000_000_000
                + b"\x75\x0c"                 # jne  -> C+0x14
                + b"\x48\x89\xcf"              # mov rdi,rcx
                + b"\xff\x15" + struct.pack("<i", G - (C + 17)))
    ind[C : C + len(indirect)] = indirect
    via_got = find_retry_after_sites(bytes(ind), jitter, ident, ident)
    assert len(via_got) == 1, via_got
    assert via_got[0]["call"] == C + 11 and via_got[0]["patched"] is False
    # apply and confirm the NOPed form is still recognized (idempotency)
    patched = bytearray(blob)
    patched[s["jne"] : s["jne"] + 2] = NOP_RUNS[2]
    again = find_retry_after_sites(bytes(patched), jitter, ident, ident)
    assert len(again) == 1 and again[0]["patched"] is True, again


def _self_test_site5() -> None:
    """Synthetic connection-delay load plus the tail that identifies it."""
    load = b"\x48\x8b\x48\x10" + b"\x8b\x40\x18"          # rcx <- secs, eax <- nanos
    tail = (b"\x48\x89\x8b" + struct.pack("<i", 0x1b8)     # mov [rbx+0x1b8],rcx
            + b"\x89\x83" + struct.pack("<i", 0x1c0)       # mov [rbx+0x1c0],eax
            + b"\x48\x8d\x05" + struct.pack("<i", 0x40))   # lea rax,[rip+0x40]
    at = 0x40
    blob = bytearray(b"\x00" * at + load + tail + b"\x00" * 0x40)
    sites = find_conn_delay_sites(bytes(blob))
    assert len(sites) == 1, sites
    s = sites[0]
    assert (s["off"], s["secs_reg"], s["nanos_reg"], s["base_reg"]) == (at, 1, 0, 0), s
    assert s["current"] is None
    patch = make_conn_delay_patch(s["secs_reg"], s["nanos_reg"], 1)
    assert patch == b"\xb9\x01\x00\x00\x00\x31\xc0", patch.hex(" ")
    assert len(patch) == len(load)
    patched = bytearray(blob)
    patched[at : at + len(patch)] = patch
    s2 = find_conn_delay_sites(bytes(patched))
    assert len(s2) == 1 and s2[0]["current"] == 1 and s2[0]["off"] == at, s2
    # the load pair alone is not enough: without the paired tail it is skipped
    lone = bytearray(b"\x00" * at + load + b"\x00" * 0x40)
    assert find_conn_delay_sites(bytes(lone)) == []
    # unrelated `mov eax,60 ; xor ecx,ecx` spilling a Duration reads like an
    # already-patched site until the rip-relative lea is required.
    decoy = (b"\xb8\x3c\x00\x00\x00\x31\xc9"
             + b"\x48\x89\x83" + struct.pack("<i", 0x508)
             + b"\x89\x8b" + struct.pack("<i", 0x510)
             + b"\x4c\x8d\xb3" + struct.pack("<i", 0x518))  # lea r14,[rbx+..]
    assert find_conn_delay_sites(b"\x00" * at + decoy + b"\x00" * 0x40) == []
    assert conn_delay_secs(1000) == 1 and conn_delay_secs(1) == 1
    assert conn_delay_secs(2400) == 2


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Patch Codex native binary retry backoff interval "
                    "(Linux/macOS ELF/Mach-O, x86-64)")
    parser.add_argument("--binary", help="path to native codex binary")
    parser.add_argument("--dry-run", "--check", dest="dry_run", action="store_true",
                        help="inspect only; do not write or back up")
    parser.add_argument("--restore", action="store_true", help="restore binary from .orig backup")
    parser.add_argument("--self-test", action="store_true", help="run small internal checks")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    require_platform()
    binary = find_binary(args.binary)
    if args.restore:
        restore_binary(binary)
    else:
        patch_binary(binary, RETRY_MS, STREAM_MAX_RETRIES, args.dry_run)


if __name__ == "__main__":
    main()

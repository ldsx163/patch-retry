#!/usr/bin/env python3
"""
Patch Codex CLI's retry backoff interval -- Linux/macOS build (ELF / Mach-O).

Verified against codex rust-v0.143.0 (x86_64-unknown-linux-musl). This is the
Unix (ELF/Mach-O) build of the codex patcher; for the Windows PE build use
patch-codex-retry-windows.py. The two jittered backoffs it targets are:

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

This changes the retry *interval*, not the retry *count*; use config.toml's
stream_max_retries/request_max_retries for the count (site 3 just unclamps the
stream cap so values >100 take effect).

Usage:
  python3 patch-codex-retry-linux.py --check     (inspect only)
  sudo python3 patch-codex-retry-linux.py        (apply the patch)
  python3 patch-codex-retry-linux.py --restore
  python3 patch-codex-retry-linux.py --self-test

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
    patch-codex-retry-windows.py. Fail fast with that pointer instead of later
    dying on an unrecognized format."""
    if os.name != "posix":
        print(f"ERROR: this is the Linux/macOS build, but the current OS is "
              f"'{sys.platform}' (os.name={os.name!r}).", file=sys.stderr)
        print("Use patch-codex-retry-windows.py on Windows.", file=sys.stderr)
        sys.exit(1)


# ── Format / architecture detection (dispatch + safety gate) ──────────────────
def detect_format(data: bytes) -> str:
    """Return 'elf' | 'macho', or die. Refuses PE (Windows build) and non-x86-64
    binaries, since every byte pattern below is x86-64 ELF/Mach-O specific."""
    if data[:2] == b"MZ":
        die("this is a Windows PE; use patch-codex-retry-windows.py")
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

    # -- Summary --------------------------------------------------------------
    print()
    print("=== Summary ===")
    print(f"  jitter sites : {len(report)} to patch -> {ms}ms fixed interval")
    print(f"  stream cap   : {len(cap_sites)} site(s) -> {max_retries}")
    print(f"  retry interval: {ms}ms")

    if dry_run:
        print()
        print("CHECK ONLY - no changes were made.")
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
    print(f"Patched successfully: {len(edits)} jitter site(s) + "
          f"{len(cap_sites)} cap site(s).")
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
    # format detection: ELF accepted, PE rejected via die()/SystemExit.
    assert detect_format(b"\x7fELF" + b"\x00" * 14 + b"\x3e\x00" + b"\x00" * 8) == "elf"
    try:
        detect_format(b"MZ" + b"\x00" * 64)
    except SystemExit:
        pass
    else:
        raise AssertionError("PE should be rejected by the Linux build")
    print("self-test OK")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Patch Codex native binary retry backoff interval "
                    "(Linux/macOS ELF/Mach-O, x86-64)")
    parser.add_argument("--binary", help="path to native codex binary")
    parser.add_argument("--check", action="store_true", help="inspect only; do not write or back up")
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
        patch_binary(binary, RETRY_MS, STREAM_MAX_RETRIES, args.check)


if __name__ == "__main__":
    main()

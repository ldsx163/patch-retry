#!/usr/bin/env python3
"""
claude-linux.py - Patch Claude Code binary (Linux/macOS) to:
  1. Remove the retry cap so CLAUDE_CODE_MAX_RETRIES=9999 works
  2. Replace exponential backoff with fixed 1s interval
  3. Patch the Anthropic SDK's built-in retry backoff
  4. Lower rate-limit fallback delays

Linux/macOS-only build of patch-retry-claude. The byte patches are the minified
JS text embedded in the binary and are identical on every platform; only binary
discovery, the atomic write's exec bit, and the command hints are Unix-specific
here. For Windows use claude-windows.py.

Usage:
  sudo python3 claude-linux.py [--dry-run] [--restore] [--binary PATH]

Options:
  --dry-run   Show what would be changed without modifying the binary.
              Also works on an already-patched binary, to report its state.
  --restore   Restore the original binary from backup
  --binary    Patch this file instead of the auto-discovered one

Environment variables (after patching):
  CLAUDE_CODE_MAX_RETRIES=9999      - Max retry attempts (internal cap disabled)

Version-agnostic: This script dynamically discovers minified variable names
by searching for code structure patterns (e.g. "clamped to ${VAR}" near
"CLAUDE_CODE_MAX_RETRIES") rather than hardcoding variable names. This
allows it to work across versions where minification produces different names.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys

PROC_NAME = "claude"
STOP_HINT = "Stop it first."


def require_platform() -> None:
    """Refuse to run outside Linux/macOS.

    This build hardcodes Unix binary discovery (`which`, POSIX npm paths) and
    sets the exec bit on write; running it on Windows would mis-locate the
    binary and produce a non-executable file. Direct Windows users to the
    dedicated script instead of failing later with a confusing error.
    """
    if os.name != "posix":
        print(f"ERROR: this is the Linux/macOS build, but the current OS is "
              f"'{sys.platform}' (os.name={os.name!r}).", file=sys.stderr)
        print("Use claude-windows.py on Windows.", file=sys.stderr)
        sys.exit(1)


def require_unix_image(data: bytes, binary_path: str) -> None:
    """Reject a Windows PE image, identified by magic bytes rather than name.

    Upstream names the launcher `claude.exe` on every platform, so the suffix
    says nothing about the format -- only the header does. The byte patches
    themselves are platform-independent minified JS, but this build sets the
    Unix exec bit on write and prints Unix hints, so send PE users next door.
    """
    if data[:2] == b"MZ":
        print(f"ERROR: {binary_path} is a Windows PE image.", file=sys.stderr)
        print("Use claude-windows.py for it.", file=sys.stderr)
        sys.exit(1)
    if data[:4] != b"\x7fELF" and data[:4] not in (
        b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",   # Mach-O 64/32 LE
        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",   # Mach-O universal
    ):
        print(f"  WARN: {binary_path} is neither ELF nor Mach-O "
              f"(magic {data[:4].hex()}); continuing anyway.", file=sys.stderr)


def find_binary() -> str:
    """Find the Claude Code binary path (Linux/macOS)."""
    candidates = []

    # Try `which claude` first
    try:
        result = subprocess.run(
            ["which", "claude"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            path = os.path.realpath(result.stdout.strip())
            if os.path.isfile(path):
                return path
    except Exception:
        pass

    # Fallback: look in npm global packages
    try:
        result = subprocess.run(
            ["npm", "root", "-g"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            npm_root = result.stdout.strip()
            candidates += [
                os.path.join(npm_root, "@anthropic-ai/claude-code-linux-x64/claude"),
                os.path.join(npm_root, "@anthropic-ai/claude-code-linux-arm64/claude"),
                os.path.join(npm_root, "@anthropic-ai/claude-code-darwin-arm64/claude"),
                os.path.join(npm_root, "@anthropic-ai/claude-code-darwin-x64/claude"),
            ]
    except Exception:
        pass

    for c in candidates:
        if os.path.isfile(c):
            return os.path.realpath(c)

    print("ERROR: Could not find Claude Code binary. Is it installed?", file=sys.stderr)
    print("Try: npm install -g @anthropic-ai/claude-code", file=sys.stderr)
    sys.exit(1)


def find_all(data: bytes, pattern: bytes) -> list[int]:
    """Find all offsets of a byte pattern in data."""
    offsets = []
    start = 0
    while True:
        idx = data.find(pattern, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets


def find_nearest(data: bytes, pattern: bytes, ref_offset: int, max_dist: int) -> int | None:
    """Find the offset of pattern closest to ref_offset, within max_dist.

    max_dist is inclusive and must be > 0; it is a required argument because a
    zero window can never match and would silently look like "pattern absent".
    """
    if max_dist <= 0:
        raise ValueError(f"max_dist must be > 0 (got {max_dist})")
    best = None
    best_dist = max_dist
    for off in find_all(data, pattern):
        dist = abs(off - ref_offset)
        if dist <= best_dist:
            best_dist = dist
            best = off
    return best


def apply_byte_patch(data: bytearray, desc: str, search: bytes, replace: bytes,
                     stats: dict, hint_offset: int | None = None,
                     max_dist: int | None = None) -> bytearray:
    """Apply a single search->replace byte patch. Returns modified data.

    If hint_offset is provided, finds the search pattern nearest to that offset
    within max_dist (which is then required). Otherwise, uses the first
    occurrence.
    """
    if len(search) != len(replace):
        print(f"  SKIP: {desc} - byte length mismatch ({len(search)} vs {len(replace)})", file=sys.stderr)
        stats["failed"] += 1
        return data

    if hint_offset is not None and not max_dist:
        raise ValueError(f"max_dist is required when hint_offset is given ({desc})")

    def _already():
        if hint_offset is not None:
            return find_nearest(data, replace, hint_offset, max_dist)
        hits = find_all(data, replace)
        return hits[0] if hits else None

    if hint_offset is not None:
        offset = find_nearest(data, search, hint_offset, max_dist)
        if offset is None:
            already = _already()
            if already is not None:
                print(f"  OK {desc} @ offset {already} (already patched)")
                stats["applied"] += 1
                return data
            print(f"  WARN: Could not find pattern near hint for: {desc}", file=sys.stderr)
            stats["failed"] += 1
            return data
    else:
        offsets = find_all(data, search)
        if not offsets:
            already = _already()
            if already is not None:
                print(f"  OK {desc} @ offset {already} (already patched)")
                stats["applied"] += 1
                return data
            print(f"  WARN: Could not find pattern for: {desc}", file=sys.stderr)
            stats["failed"] += 1
            return data
        offset = offsets[0]

    # Verify the bytes at the offset match
    actual = data[offset:offset + len(search)]
    if actual != search:
        print(f"  SKIP: {desc} - byte mismatch at offset {offset}", file=sys.stderr)
        print(f"    Expected: {search.hex()}", file=sys.stderr)
        print(f"    Actual:   {actual.hex()}", file=sys.stderr)
        stats["failed"] += 1
        return data

    print(f"  OK {desc} @ offset {offset}")
    data[offset:offset + len(replace)] = replace
    stats["applied"] += 1
    return data


# --- Dynamic pattern discovery ------------------------------------------------
# These functions discover minified variable names by searching for code
# structure patterns that are stable across versions (the logic stays the
# same even as minifier output changes variable names).

def discover_retry_cap(data: bytes) -> tuple[int, bytes] | None:
    """Locate the retry cap warning and its cap variable in one pass.

    The code contains:
        `CLAUDE_CODE_MAX_RETRIES=${e} clamped to ${VARNAME}`
    where VARNAME is the cap variable used by the clamp we disable.

    Returns (warning_offset, cap_var). Every other cap lookup must anchor to
    THIS offset: picking the warning independently with data.find() would take
    the first occurrence even when a later one is the real clamp site, so two
    helpers could silently work on different sites once a build mentions the
    env var more than once.
    """
    for m in re.finditer(rb'CLAUDE_CODE_MAX_RETRIES=\$\{', data):
        ctx = data[m.start():m.start() + 200]
        clamped = re.search(rb'clamped to \$\{([a-zA-Z_$][a-zA-Z0-9_$]*)\}', ctx)
        if clamped:
            return m.start(), clamped.group(1)
    return None


def discover_retry_cap_clamp(data: bytes, warn_offset: int, cap_var: bytes) -> bytes | None:
    """Discover the actual clamp comparison expression, e.g. b't>gaa'.

    The parse variable in `if(PARSE>CAP&&...` differs across minifier runs
    (older builds used `e`, newer ones `t`), so we can't hardcode it. Locate
    the `if(<name><CAP>&&` guard just before the clamp warning at warn_offset
    and return the full `<name>><CAP>` slice so callers can neutralize it with
    a same-length always-false replacement.
    """
    before = data[max(0, warn_offset - 200):warn_offset]
    m = re.search(rb'if\((' + rb'[a-zA-Z_$][a-zA-Z0-9_$]*' + rb'>' + re.escape(cap_var) + rb')&&', before)
    if m:
        return m.group(1)
    return None


def discover_backoff_base_var(data: bytes) -> bytes | None:
    """Discover the backoff base variable name from the retry delay formula.

    Older builds contain:
        Math.min(VARNAME*Math.pow(2,e-1),n)
    where VARNAME=500 is the base delay in ms.

    Newer builds inline the literal (`500*Math.pow(2,e-1)`); that path does not
    use this helper.
    """
    for m in re.finditer(rb'Math\.min\(([a-zA-Z_$][a-zA-Z0-9_$]*)\*Math\.pow\(2,e-1\)', data):
        return m.group(1)
    return None


def discover_sdk_backoff(data: bytes) -> tuple[bytes, bytes] | None:
    """SDK retry: `0.5*Math.pow(2,IDENT)` -> `1.0*Math.pow(1,IDENT)`.

    IDENT used to be `o`; newer SDK minifies it to `n`.
    """
    m = re.search(rb'0\.5\*Math\.pow\(2,([a-zA-Z_$][a-zA-Z0-9_$]*)\)', data)
    if not m:
        return None
    ident = m.group(1)
    return (b"0.5*Math.pow(2," + ident + b")",
            b"1.0*Math.pow(1," + ident + b")")


def retry_cap_already_disabled(data: bytes, warn_offset: int) -> bool:
    """True if the clamp guard at warn_offset is already `if(!1 ...)`."""
    before = data[max(0, warn_offset - 200):warn_offset]
    return re.search(rb'if\(!1 *&&', before) is not None


def backoff_already_patched(data: bytes) -> bool:
    """True if Patch 2 is already applied.

    Both routes -- the inlined literal (`1e3*Math.pow(1,e-1)`) and the older
    two-step (`VAR=1e3` plus `Math.pow(1,e-1)`) -- leave `Math.pow(1,e-1)`
    behind, which never appears in unpatched code.
    """
    return b"Math.pow(1,e-1)" in data


def sdk_backoff_already_patched(data: bytes) -> bool:
    """True if Patch 3 is already applied (`1.0*Math.pow(1,IDENT)`)."""
    return re.search(rb'1\.0\*Math\.pow\(1,[a-zA-Z_$][a-zA-Z0-9_$]*\)', data) is not None


def discover_rate_limit_vars(data: bytes) -> tuple[bytes | None, bytes | None, bytes | None]:
    """Discover rate-limit variable names from the rate-limit handling code.

    The code always contains:
        RETRY_VAR!==null&&RETRY_VAR<THRESHOLD_VAR
        Math.max(RETRY_VAR??FALLBACK_VAR,MIN_VAR)
    near the string "rate_limit".

    Returns (fallback_var, min_var, threshold_var) or Nones.
    """
    fallback_var = None
    min_var = None
    threshold_var = None

    idx = data.find(b'rate_limit')
    while idx != -1:
        before = data[max(0, idx - 500):idx]
        if b'Math.max' in before:
            # Extract Math.max(RETRY_VAR??FALLBACK_VAR,MIN_VAR)
            name = rb'[a-zA-Z_$][a-zA-Z0-9_$]*'
            m = re.search(rb'Math\.max\((' + name + rb')\?\?(' + name + rb'),(' + name + rb')\)', before)
            if m:
                retry_var = m.group(1)
                fallback_var = m.group(2)
                min_var = m.group(3)

                # Extract RETRY_VAR!==null&&RETRY_VAR<THRESHOLD_VAR
                m2 = re.search(re.escape(retry_var) + rb'!==null&&' + re.escape(retry_var) + rb'<(' + name + rb')', before)
                if m2:
                    threshold_var = m2.group(1)

            if fallback_var and min_var and threshold_var:
                return fallback_var, min_var, threshold_var

        idx = data.find(b'rate_limit', idx + 1)

    return fallback_var, min_var, threshold_var


def looks_already_patched(data: bytes) -> bool:
    """Return True if the binary already contains this script's own edits.

    These exact strings are *replacements* this script writes; they don't occur
    in unpatched code (raising 1 to a power -- Math.pow(1,...) -- is pointless
    real code).

    Patching again would be a no-op at best, so the write path refuses and asks
    for a --restore first. --dry-run is allowed through: it writes nothing, and
    reporting the current per-patch state is exactly what it's for.
    """
    sentinels = (b"1.0*Math.pow(1,", b"Math.pow(1,e-1)")
    return any(s in data for s in sentinels)


def write_patched(binary_path: str, data: bytearray) -> None:
    """Atomically replace the binary with the patched bytes.

    Uses a temp file + os.replace(), which is atomic and overwrites the
    destination. On Linux this swaps the inode, so a running process keeps its
    old mapping.

    Because the inode is swapped, the new file does NOT inherit the original's
    owner/mode: mkstemp creates it 0600 owned by the caller (root under sudo),
    while npm installs are often user-owned. Copy both across so a later
    `npm update` isn't left with a root-owned binary.
    """
    import tempfile
    st = os.stat(binary_path)
    binary_dir = os.path.dirname(binary_path)
    fd, tmp_path = tempfile.mkstemp(dir=binary_dir, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        # Keep the original mode, but guarantee the exec bit.
        os.chmod(tmp_path, (st.st_mode & 0o7777) | 0o111)
        if hasattr(os, "chown") and (st.st_uid != os.getuid() or st.st_gid != os.getgid()):
            try:
                os.chown(tmp_path, st.st_uid, st.st_gid)
            except (OSError, AttributeError) as e:
                print(f"  WARN: could not restore owner {st.st_uid}:{st.st_gid} "
                      f"on the patched binary: {e}", file=sys.stderr)
        os.replace(tmp_path, binary_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def main():
    parser = argparse.ArgumentParser(
        description="Patch Claude Code binary (Linux/macOS): allow 9999 retries, fix backoff to 1s interval"
    )
    parser.add_argument("--dry-run", action="store_true", help="Show changes without modifying the binary")
    parser.add_argument("--restore", action="store_true", help="Restore the original binary from backup")
    parser.add_argument("--binary", help="Patch this file instead of the auto-discovered one")
    args = parser.parse_args()

    require_platform()

    if args.binary:
        binary_path = os.path.realpath(os.path.expanduser(args.binary))
        if not os.path.isfile(binary_path):
            print(f"ERROR: no such file: {binary_path}", file=sys.stderr)
            sys.exit(1)
    else:
        binary_path = find_binary()
    print(f"Found binary: {binary_path}")
    print(f"Binary size: {os.path.getsize(binary_path)} bytes")

    backup_path = binary_path + ".orig"

    # -- Restore mode ----------------------------------------------------------
    if args.restore:
        if not os.path.isfile(backup_path):
            print(f"ERROR: No backup found at {backup_path}", file=sys.stderr)
            sys.exit(1)
        print(f"Restoring original binary from {backup_path} ...")
        try:
            shutil.copy2(backup_path, binary_path)
            os.chmod(binary_path, 0o755)
            print("Restored successfully.")
        except OSError as e:
            print(f"ERROR: Failed to restore: {e}", file=sys.stderr)
            print(f"Is {PROC_NAME} running? {STOP_HINT}", file=sys.stderr)
            sys.exit(1)
        return

    # -- Read binary -----------------------------------------------------------
    with open(binary_path, "rb") as f:
        data = bytearray(f.read())

    require_unix_image(data, binary_path)

    # -- Already patched: refuse to write, but let --dry-run report the state ---
    # Checked before the backup so a patched binary is never copied over a good
    # .orig (--dry-run never reaches the backup step at all).
    already_patched = looks_already_patched(data)
    if already_patched:
        if not args.dry_run:
            print()
            print("This binary already appears to be patched by this script.")
            print("Restore the original first, then re-run:")
            print(f"  sudo python3 {sys.argv[0]} --restore")
            sys.exit(1)
        print()
        print("NOTE: already patched - reporting current state (nothing will be written).")

    # -- Create backup (skip in --dry-run: it must not touch disk) --------------
    if not args.dry_run and not os.path.isfile(backup_path):
        print(f"Creating backup at {backup_path} ...")
        try:
            shutil.copy2(binary_path, backup_path)
        except OSError as e:
            print(f"ERROR: Failed to create backup: {e}", file=sys.stderr)
            print(f"Is {PROC_NAME} running? {STOP_HINT}", file=sys.stderr)
            sys.exit(1)

    # -- Discover minified variable names dynamically --------------------------
    print()
    print("=== Discovering version-specific patterns ===")

    cap_site = discover_retry_cap(data)
    retry_cap_warn_offset, retry_cap_var = cap_site if cap_site else (None, None)
    if retry_cap_var:
        print(f"  Retry cap variable: {retry_cap_var.decode()} "
              f"(clamp warning @ {retry_cap_warn_offset})")
    else:
        print("  WARN: Could not discover retry cap variable", file=sys.stderr)

    backoff_literal = b"500*Math.pow(2,e-1)" in data
    backoff_base_var = None if backoff_literal else discover_backoff_base_var(data)
    backoff_done = backoff_already_patched(data)
    if backoff_literal:
        print("  Backoff formula: 500*Math.pow(2,e-1) (literal)")
    elif backoff_base_var:
        print(f"  Backoff base variable: {backoff_base_var.decode()}")
    elif backoff_done:
        print("  Backoff formula: already patched (Math.pow(1,e-1) present)")
    else:
        print("  WARN: Could not discover backoff base variable", file=sys.stderr)

    sdk_pair = discover_sdk_backoff(data)
    sdk_done = sdk_backoff_already_patched(data)
    if sdk_pair:
        print(f"  SDK backoff: {sdk_pair[0].decode()}")
    elif sdk_done:
        print("  SDK backoff: already patched (1.0*Math.pow(1,...) present)")
    else:
        print("  WARN: Could not discover SDK backoff", file=sys.stderr)

    rl_fallback_var, rl_min_var, rl_threshold_var = discover_rate_limit_vars(data)
    if rl_fallback_var:
        print(f"  Rate-limit fallback variable: {rl_fallback_var.decode()}")
    if rl_min_var:
        print(f"  Rate-limit minimum variable: {rl_min_var.decode()}")
    if rl_threshold_var:
        print(f"  Rate-limit threshold variable: {rl_threshold_var.decode()}")
    if not rl_fallback_var or not rl_min_var or not rl_threshold_var:
        print("  WARN: Could not discover all rate-limit variables", file=sys.stderr)

    # -- Save hint offset for Math.pow patch before backoff base is overwritten --
    backoff_base_hint_offset = None
    if backoff_base_var:
        search = backoff_base_var + b"=500"
        hits = find_all(data, search)
        if hits:
            backoff_base_hint_offset = hits[0]
            print(f"  Saved backoff base hint offset: {backoff_base_hint_offset}")

    # -- Apply patches ---------------------------------------------------------
    stats = {"applied": 0, "failed": 0}
    # Per-patch success flags. These drive the final "Retry behavior" table so
    # it reflects what was actually patched instead of a hardcoded description.
    ok = {
        "max_retries": False,   # Patch 1 -> Max retries row
        "backoff_base": False,  # Patch 2 (base 500->1000)  -> General retry delay row
        "backoff_pow": False,   # Patch 2 (pow 2->1)        -> General retry delay row
        "sdk": False,           # Patch 3 -> SDK-level retry delay row
        "rl_fallback": False,   # Patch 4 (fallback)  -> Rate-limit retry delay row
        "rl_min": False,        # Patch 4 (minimum)   -> Rate-limit retry delay row
        "rl_threshold": False,  # Patch 4 (threshold) -> Rate-limit retry delay row
    }

    # -- Patch 1: Remove retry cap --------------------------------------------
    print()
    print("=== Patch 1: Remove retry cap ===")
    if retry_cap_var:
        clamp_expr = discover_retry_cap_clamp(data, retry_cap_warn_offset, retry_cap_var)
        if clamp_expr:
            # Neutralize `<parse>><cap>` -> `!1` + padding (always false), so the
            # clamp branch never runs and `return <parse>` passes the raw value.
            search = clamp_expr
            replace = b"!1" + b" " * (len(search) - 2)
            _n = stats["applied"]
            data = apply_byte_patch(
                data,
                f"Disable retry cap clamp so CLAUDE_CODE_MAX_RETRIES=9999 works ({clamp_expr.decode()})",
                search,
                replace,
                stats,
                hint_offset=retry_cap_warn_offset,
                max_dist=500,
            )
            ok["max_retries"] = stats["applied"] > _n
        elif retry_cap_already_disabled(data, retry_cap_warn_offset):
            print("  OK Disable retry cap clamp (already patched)")
            stats["applied"] += 1
            ok["max_retries"] = True
        else:
            print("  SKIP: Could not locate retry cap clamp expression", file=sys.stderr)
            stats["failed"] += 1
    else:
        print("  SKIP: Retry cap variable not discovered", file=sys.stderr)
        stats["failed"] += 1

    # -- Patch 2: Replace exponential backoff with fixed 1s interval -----------
    print()
    print("=== Patch 2: Replace exponential backoff with fixed 1s interval ===")
    if backoff_literal:
        # Newer builds inline the 500ms base. One same-length swap does base+pow.
        # `500*` makes the search unique, so no hint offset is needed here (the
        # bare Math.pow(2,e-1) below is the ambiguous one).
        _n = stats["applied"]
        data = apply_byte_patch(
            data,
            "Change 500*pow(2,e-1) to 1e3*pow(1,e-1) (fixed 1s)",
            b"500*Math.pow(2,e-1)",
            b"1e3*Math.pow(1,e-1)",
            stats,
        )
        ok["backoff_base"] = ok["backoff_pow"] = stats["applied"] > _n
    elif backoff_base_var:
        search = backoff_base_var + b"=500"
        replace = backoff_base_var + b"=1e3"
        _n = stats["applied"]
        data = apply_byte_patch(data, f"Change backoff base from 500ms to 1000ms ({backoff_base_var.decode()})", search, replace, stats)
        ok["backoff_base"] = stats["applied"] > _n
        # Math.pow(2,e-1) -> Math.pow(1,e-1)  (pow(1,n) always = 1)
        # REQUIRES the hint offset from the backoff base variable: there are several
        # Math.pow(2,e-1) in the binary (one is an unrelated calculateDelay backoff).
        if backoff_base_hint_offset is not None:
            _n = stats["applied"]
            data = apply_byte_patch(
                data,
                "Change pow base 2->1 (disables exponential growth)",
                b"Math.pow(2,e-1)",
                b"Math.pow(1,e-1)",
                stats,
                hint_offset=backoff_base_hint_offset,
                max_dist=100000,
            )
            ok["backoff_pow"] = stats["applied"] > _n
        else:
            print("  SKIP: no backoff-base hint; skipping pow(2->1) to avoid mis-patching an unrelated site", file=sys.stderr)
            stats["failed"] += 1
    elif backoff_done:
        print("  OK Replace exponential backoff with fixed 1s (already patched)")
        stats["applied"] += 1
        ok["backoff_base"] = ok["backoff_pow"] = True
    else:
        print("  SKIP: Backoff pattern not discovered", file=sys.stderr)
        stats["failed"] += 1

    # -- Patch 3: Patch Anthropic SDK built-in retry backoff -------------------
    print()
    print("=== Patch 3: Patch Anthropic SDK built-in retry backoff ===")
    if sdk_pair:
        search, replace = sdk_pair
        _n = stats["applied"]
        data = apply_byte_patch(
            data,
            f"Change SDK backoff {search.decode()} -> {replace.decode()} (fixed ~1s delay)",
            search,
            replace,
            stats,
        )
        ok["sdk"] = stats["applied"] > _n
    elif sdk_done:
        print("  OK Patch SDK backoff (already patched)")
        stats["applied"] += 1
        ok["sdk"] = True
    else:
        print("  SKIP: SDK backoff pattern not discovered", file=sys.stderr)
        stats["failed"] += 1

    # -- Patch 4: Lower rate-limit fallback delays -----------------------------
    print()
    print("=== Patch 4: Lower rate-limit fallback delays ===")
    if rl_fallback_var:
        # Fallback: 1800000ms (30min) -> 10000ms (10s), space-padded to equal length.
        # Do NOT pad with leading zeros: `0010000` is a legacy octal literal in
        # sloppy-mode JS (= 4096, not 10000) and a SyntaxError under strict/ESM.
        search = rl_fallback_var + b"=1800000"
        replace = rl_fallback_var + b"=10000  "
        if rl_fallback_var + b"=0010000" in data:
            print(f"  SKIP: {rl_fallback_var.decode()} holds =0010000, written by an older "
                  f"version of this script; that is octal 4096ms, not 10000ms. "
                  f"--restore and re-run to correct it.", file=sys.stderr)
            stats["failed"] += 1
        else:
            _n = stats["applied"]
            data = apply_byte_patch(data, f"Lower rate-limit fallback from 30min to 10s ({rl_fallback_var.decode()})", search, replace, stats)
            ok["rl_fallback"] = stats["applied"] > _n
    else:
        print("  SKIP: Rate-limit fallback variable not discovered", file=sys.stderr)
        stats["failed"] += 1

    if rl_min_var:
        # Minimum: 600000ms (10min) -> 1000ms (1s), space-padded (see above:
        # `001000` would be octal 512, not 1000).
        search = rl_min_var + b"=600000"
        replace = rl_min_var + b"=1000  "
        if rl_min_var + b"=001000" in data:
            print(f"  SKIP: {rl_min_var.decode()} holds =001000, written by an older "
                  f"version of this script; that is octal 512ms, not 1000ms. "
                  f"--restore and re-run to correct it.", file=sys.stderr)
            stats["failed"] += 1
        else:
            _n = stats["applied"]
            data = apply_byte_patch(data, f"Lower rate-limit minimum from 10min to 1s ({rl_min_var.decode()})", search, replace, stats)
            ok["rl_min"] = stats["applied"] > _n
    else:
        print("  SKIP: Rate-limit minimum variable not discovered", file=sys.stderr)
        stats["failed"] += 1

    if rl_threshold_var:
        # Threshold: 20000ms (20s) -> 99999ms (100s)
        search = rl_threshold_var + b"=20000"
        replace = rl_threshold_var + b"=99999"
        _n = stats["applied"]
        data = apply_byte_patch(data, f"Raise rate-limit env-var threshold from 20s to 100s ({rl_threshold_var.decode()})", search, replace, stats)
        ok["rl_threshold"] = stats["applied"] > _n
    else:
        print("  SKIP: Rate-limit threshold variable not discovered", file=sys.stderr)
        stats["failed"] += 1

    # -- Summary ---------------------------------------------------------------
    print()
    print("===========================================================")
    print(f"  Patches {'in place' if already_patched else 'applied'}: {stats['applied']}")
    print(f"  Patches skipped: {stats['failed']}")
    print("===========================================================")

    if args.dry_run:
        print()
        if already_patched:
            print("DRY RUN - binary is already patched; nothing to do.")
            print(f"To re-apply from scratch: sudo python3 {sys.argv[0]} --restore")
        else:
            print("DRY RUN - no changes were made.")
            print("Run without --dry-run to apply patches.")
        return

    # -- Nothing patched: bail out instead of printing misleading success text -
    if stats["applied"] == 0:
        print()
        print("ERROR: No patches were applied; the binary is unchanged.", file=sys.stderr)
        print("Claude Code was likely updated and the byte patterns no longer match.", file=sys.stderr)
        sys.exit(1)

    # -- Write patched binary --------------------------------------------------
    try:
        write_patched(binary_path, data)
        print()
        print("Patches applied successfully!")
        print("(Running claude sessions still use the old binary; new sessions will use the patched one.)")
    except OSError as e:
        print(f"\nERROR: Failed to write patched binary: {e}", file=sys.stderr)
        print(f"Is {PROC_NAME} running? {STOP_HINT} Then re-run this script.", file=sys.stderr)
        sys.exit(1)

    # -- Final hints -----------------------------------------------------------
    print()
    print("To restore the original binary:")
    print(f"  sudo python3 {sys.argv[0]} --restore")
    print()
    print("Set this environment variable before running claude:")
    print("  export CLAUDE_CODE_MAX_RETRIES=9999       # Max retry attempts (internal cap disabled)")
    print()
    print("Retry behavior after patching:")
    sep = "  +-------------------------+----------------------------------+"

    def _row(setting, behavior):
        return f"  | {setting:<24}| {behavior:<33}|"

    def _behavior(flags, patched_text):
        done = sum(1 for f in flags if f)
        if done == len(flags):
            return patched_text
        if done == 0:
            return "unchanged (patch skipped)"
        return f"partially patched ({done}/{len(flags)})"

    print(sep)
    print(_row("Setting", "Behavior"))
    print(sep)
    print(_row("Max retries",
               _behavior([ok["max_retries"]], "CLAUDE_CODE_MAX_RETRIES (=9999)")))
    print(_row("General retry delay",
               _behavior([ok["backoff_base"], ok["backoff_pow"]], "Fixed ~1 second")))
    print(_row("Rate-limit retry delay",
               _behavior([ok["rl_fallback"], ok["rl_min"], ok["rl_threshold"]], "Fixed ~1 second")))
    print(_row("SDK-level retry delay",
               _behavior([ok["sdk"]], "Fixed ~0.75-1 second")))
    print(sep)
    print()
    print("NOTE: After updating Claude Code (npm update), re-run this script.")


if __name__ == "__main__":
    main()

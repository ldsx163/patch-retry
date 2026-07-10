#!/usr/bin/env python3
"""
patch-retry-claude.py - Patch Claude Code binary to:
  1. Remove the retry cap so CLAUDE_CODE_MAX_RETRIES=9999 works
  2. Replace exponential backoff with fixed 1s interval
  3. Patch the Anthropic SDK's built-in retry backoff
  4. Lower rate-limit fallback delays

Cross-platform: works on Linux, macOS, and Windows. Platform-specific
behaviour (binary discovery, atomic write, command hints) is selected at
runtime via os.name.

Usage:
  Linux/macOS:  sudo python3 patch-retry-claude.py [--check] [--restore]
  Windows:      python patch-retry-claude.py [--check] [--restore]

Options:
  --check     Show what would be changed without modifying the binary
  --restore   Restore the original binary from backup

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

IS_WINDOWS = os.name == "nt"
PROC_NAME = "claude.exe" if IS_WINDOWS else "claude"
STOP_HINT = "Close it first." if IS_WINDOWS else "Stop it first."


def find_binary() -> str:
    """Find the Claude Code binary path (Windows or Unix)."""
    candidates = []

    if IS_WINDOWS:
        # Try npm shim location first, e.g. %APPDATA%\npm\claude.cmd
        for shim in (shutil.which("claude"), shutil.which("claude.cmd"), shutil.which("claude.exe")):
            if not shim:
                continue
            if os.path.basename(shim).lower() == "claude.exe" and os.path.isfile(shim):
                return os.path.realpath(shim)
            candidates.append(os.path.join(
                os.path.dirname(shim),
                "node_modules", "@anthropic-ai", "claude-code", "bin", "claude.exe",
            ))

        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.append(os.path.join(
                appdata, "npm", "node_modules", "@anthropic-ai",
                "claude-code", "bin", "claude.exe",
            ))
    else:
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

    # Fallback: look in npm global packages (both platforms)
    try:
        result = subprocess.run(
            ["npm", "root", "-g"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            npm_root = result.stdout.strip()
            if IS_WINDOWS:
                candidates.append(os.path.join(
                    npm_root, "@anthropic-ai", "claude-code", "bin", "claude.exe",
                ))
            else:
                candidates += [
                    os.path.join(npm_root, "@anthropic-ai/claude-code/bin/claude.exe"),
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
    """Find the offset of pattern closest to ref_offset, within max_dist."""
    offsets = find_all(data, pattern)
    best = None
    best_dist = max_dist
    for off in offsets:
        dist = abs(off - ref_offset)
        if dist < best_dist:
            best_dist = dist
            best = off
    return best


def apply_byte_patch(data: bytearray, desc: str, search: bytes, replace: bytes,
                     stats: dict, hint_offset: int | None = None,
                     max_dist: int = 0) -> bytearray:
    """Apply a single search->replace byte patch. Returns modified data.

    If hint_offset is provided, finds the search pattern nearest to that offset
    within max_dist. Otherwise, uses the first occurrence.
    """
    if len(search) != len(replace):
        print(f"  SKIP: {desc} - byte length mismatch ({len(search)} vs {len(replace)})", file=sys.stderr)
        stats["failed"] += 1
        return data

    if hint_offset is not None:
        offset = find_nearest(data, search, hint_offset, max_dist)
        if offset is None:
            print(f"  WARN: Could not find pattern near hint for: {desc}", file=sys.stderr)
            stats["failed"] += 1
            return data
    else:
        offsets = find_all(data, search)
        if not offsets:
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

def discover_retry_cap_var(data: bytes) -> bytes | None:
    """Discover the retry cap variable name from the 'clamped to' message.

    The code always contains:
        `CLAUDE_CODE_MAX_RETRIES=${e} clamped to ${VARNAME}`
    where VARNAME is the cap variable used by the clamp we disable.
    """
    for m in re.finditer(rb'CLAUDE_CODE_MAX_RETRIES=\$\{', data):
        ctx = data[m.start():m.start() + 200]
        clamped = re.search(rb'clamped to \$\{([a-zA-Z_$][a-zA-Z0-9_$]*)\}', ctx)
        if clamped:
            return clamped.group(1)
    return None


def discover_retry_cap_clamp(data: bytes, cap_var: bytes) -> bytes | None:
    """Discover the actual clamp comparison expression, e.g. b't>gaa'.

    The parse variable in `if(PARSE>CAP&&...` differs across minifier runs
    (older builds used `e`, newer ones `t`), so we can't hardcode it. Locate
    the `if(<name><CAP>&&` guard just before the clamp warning and return the
    full `<name>><CAP>` slice so callers can neutralize it with a same-length
    always-false replacement.
    """
    warn = data.find(b"CLAUDE_CODE_MAX_RETRIES=${")
    if warn == -1:
        return None
    before = data[max(0, warn - 200):warn]
    m = re.search(rb'if\((' + rb'[a-zA-Z_$][a-zA-Z0-9_$]*' + rb'>' + re.escape(cap_var) + rb')&&', before)
    if m:
        return m.group(1)
    return None


def discover_backoff_base_var(data: bytes) -> bytes | None:
    """Discover the backoff base variable name from the retry delay formula.

    The code always contains:
        Math.min(VARNAME*Math.pow(2,e-1),n)
    where VARNAME=500 is the base delay in ms.
    """
    for m in re.finditer(rb'Math\.min\(([a-zA-Z_$][a-zA-Z0-9_$]*)\*Math\.pow\(2,e-1\)', data):
        return m.group(1)
    return None


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
    real code). Re-running on an already-patched binary would lose the hint that
    disambiguates Patch 2b and mis-target an unrelated backoff, so we refuse.
    """
    sentinels = (b"1.0*Math.pow(1,o)", b"Math.pow(1,e-1)")
    return any(s in data for s in sentinels)


def write_patched(binary_path: str, data: bytearray) -> None:
    """Atomically replace the binary with the patched bytes.

    Uses a temp file + os.replace(), which is atomic and overwrites the
    destination on both POSIX and Windows. On Linux this swaps the inode, so
    a running process keeps its old mapping; on Windows os.replace fails if
    the target is locked (claude.exe running).
    """
    import tempfile
    binary_dir = os.path.dirname(binary_path)
    fd, tmp_path = tempfile.mkstemp(dir=binary_dir, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        if not IS_WINDOWS:
            os.chmod(tmp_path, 0o755)
        os.replace(tmp_path, binary_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def main():
    parser = argparse.ArgumentParser(
        description="Patch Claude Code binary: allow 9999 retries, fix backoff to 1s interval"
    )
    parser.add_argument("--check", action="store_true", help="Show changes without modifying the binary")
    parser.add_argument("--restore", action="store_true", help="Restore the original binary from backup")
    args = parser.parse_args()

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
            if not IS_WINDOWS:
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

    # -- Refuse if already patched by this script (avoid double-patching) -------
    # Done before backup so a patched binary is never copied over a good .orig.
    if looks_already_patched(data):
        py = "python" if IS_WINDOWS else "python3"
        sudo = "" if IS_WINDOWS else "sudo "
        print()
        print("This binary already appears to be patched by this script.")
        print("Restore the original first, then re-run:")
        print(f"  {sudo}{py} {sys.argv[0]} --restore")
        sys.exit(1)

    # -- Create backup (skip in --check: it must not touch disk) ----------------
    if not args.check and not os.path.isfile(backup_path):
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

    retry_cap_var = discover_retry_cap_var(data)
    if retry_cap_var:
        print(f"  Retry cap variable: {retry_cap_var.decode()}")
    else:
        print("  WARN: Could not discover retry cap variable", file=sys.stderr)

    backoff_base_var = discover_backoff_base_var(data)
    if backoff_base_var:
        print(f"  Backoff base variable: {backoff_base_var.decode()}")
    else:
        print("  WARN: Could not discover backoff base variable", file=sys.stderr)

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
        "max_retries": False,   # Patch 1  -> Max retries row
        "backoff_base": False,  # Patch 2a -> General retry delay row
        "backoff_pow": False,   # Patch 2b -> General retry delay row
        "sdk": False,           # Patch 3  -> SDK-level retry delay row
        "rl_fallback": False,   # Patch 4a -> Rate-limit retry delay row
        "rl_min": False,        # Patch 4b -> Rate-limit retry delay row
        "rl_threshold": False,  # Patch 4c -> Rate-limit retry delay row
    }

    # -- Patch 1: Remove retry cap --------------------------------------------
    print()
    print("=== Patch 1: Remove retry cap ===")
    if retry_cap_var:
        clamp_expr = discover_retry_cap_clamp(data, retry_cap_var)
        if clamp_expr:
            # Neutralize `<parse>><cap>` -> `!1` + padding (always false), so the
            # clamp branch never runs and `return <parse>` passes the raw value.
            retry_cap_hint_offset = data.find(b"CLAUDE_CODE_MAX_RETRIES=${")
            search = clamp_expr
            replace = b"!1" + b" " * (len(search) - 2)
            _n = stats["applied"]
            data = apply_byte_patch(
                data,
                f"Disable retry cap clamp so CLAUDE_CODE_MAX_RETRIES=9999 works ({clamp_expr.decode()})",
                search,
                replace,
                stats,
                hint_offset=retry_cap_hint_offset,
                max_dist=500,
            )
            ok["max_retries"] = stats["applied"] > _n
        else:
            print("  SKIP: Could not locate retry cap clamp expression", file=sys.stderr)
            stats["failed"] += 1
    else:
        print("  SKIP: Retry cap variable not discovered", file=sys.stderr)
        stats["failed"] += 1

    # -- Patch 2a: Change backoff base from 500ms to 1000ms --------------------
    print()
    print("=== Patch 2: Replace exponential backoff with fixed 1s interval ===")
    if backoff_base_var:
        search = backoff_base_var + b"=500"
        replace = backoff_base_var + b"=1e3"
        _n = stats["applied"]
        data = apply_byte_patch(data, f"Change backoff base from 500ms to 1000ms ({backoff_base_var.decode()})", search, replace, stats)
        ok["backoff_base"] = stats["applied"] > _n
    else:
        print("  SKIP: Backoff base variable not discovered", file=sys.stderr)
        stats["failed"] += 1

    # -- Patch 2b: Disable exponential growth ----------------------------------
    # Math.pow(2,e-1) -> Math.pow(1,e-1)  (pow(1,n) always = 1)
    # REQUIRES the hint offset from the backoff base variable: there are several
    # Math.pow(2,e-1) in the binary (one is an unrelated calculateDelay backoff).
    # Without the hint we'd blindly take the first match and mis-patch that
    # unrelated site, so skip instead of guessing.
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

    # -- Patch 3: Patch Anthropic SDK built-in retry backoff -------------------
    # 0.5*Math.pow(2,o) -> 1.0*Math.pow(1,o)
    # This is in the SDK code, not minified app code, so the pattern is stable
    print()
    print("=== Patch 3: Patch Anthropic SDK built-in retry backoff ===")
    _n = stats["applied"]
    data = apply_byte_patch(
        data,
        "Change SDK backoff from 0.5*2^o to 1.0*1^o (fixed ~1s delay)",
        b"0.5*Math.pow(2,o)",
        b"1.0*Math.pow(1,o)",
        stats,
    )
    ok["sdk"] = stats["applied"] > _n

    # -- Patch 4: Lower rate-limit fallback delays -----------------------------
    print()
    print("=== Patch 4: Lower rate-limit fallback delays ===")
    if rl_fallback_var:
        # Fallback: 1800000ms (30min) -> 0010000ms (10s)
        search = rl_fallback_var + b"=1800000"
        replace = rl_fallback_var + b"=0010000"
        _n = stats["applied"]
        data = apply_byte_patch(data, f"Lower rate-limit fallback from 30min to 10s ({rl_fallback_var.decode()})", search, replace, stats)
        ok["rl_fallback"] = stats["applied"] > _n
    else:
        print("  SKIP: Rate-limit fallback variable not discovered", file=sys.stderr)
        stats["failed"] += 1

    if rl_min_var:
        # Minimum: 600000ms (10min) -> 001000ms (1s)
        search = rl_min_var + b"=600000"
        replace = rl_min_var + b"=001000"
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
    print(f"  Patches applied: {stats['applied']}")
    print(f"  Patches skipped: {stats['failed']}")
    print("===========================================================")

    if args.check:
        print()
        print("CHECK MODE - no changes were made.")
        print("Run without --check to apply patches.")
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

    # -- Final hints (platform-specific) ---------------------------------------
    py = "python" if IS_WINDOWS else "python3"
    sudo = "" if IS_WINDOWS else "sudo "
    print()
    print("To restore the original binary:")
    print(f"  {sudo}{py} {sys.argv[0]} --restore")
    print()
    if IS_WINDOWS:
        print("Set this PowerShell environment variable before running claude:")
        print('  $env:CLAUDE_CODE_MAX_RETRIES="9999"       # Max retry attempts (internal cap disabled)')
    else:
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

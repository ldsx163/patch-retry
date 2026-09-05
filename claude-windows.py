#!/usr/bin/env python3
"""
claude-windows.py - Patch Claude Code binary (Windows) to:
  1. Remove the retry cap so CLAUDE_CODE_MAX_RETRIES=9999 works
  2. Replace exponential backoff with fixed 1s interval
  3. Patch the Anthropic SDK's built-in retry backoff
  4. Lower rate-limit fallback delays
  5. Ignore Retry-After / ratelimit-reset so 429s also wait ~1s
  6. Pin the API retry loop's delay to 1000ms at the assignment

Windows-only build of patch-retry-claude. The byte patches are the minified JS
text embedded in the binary and are identical on every platform; only binary
discovery, the atomic write, and the command hints are Windows-specific here.
For Linux/macOS use claude-linux.py.

Usage:
  python claude-windows.py [--dry-run] [--restore] [--binary PATH]

Options:
  --dry-run   Show what would be changed without modifying the binary.
              Also works on an already-patched binary, to report its state.
  --restore   Restore the original binary from backup
  --binary    Patch this file instead of the auto-discovered one

Environment variables (after patching):
  CLAUDE_CODE_MAX_RETRIES=9999      - Max retry attempts (internal cap disabled)
  CLAUDE_CODE_RETRY_WATCHDOG=1      - Persistent 429/overloaded retry (lifts the 15 cap)
  BUN_JSC_forceDebuggerBytecodeGeneration=1 - Recompile patched source in Bun

Every patch site is located by CODE SHAPE, never by a minified identifier or a
magic number. Bundler-generated names (`rle`, `xEf`, `wEf`, ...) change on every
release; the structure around them does not. So each detector matches a
skeleton -- "a function whose first parameter is the attempt counter and whose
body starts with Math.min(BASE*Math.pow(2,attempt-1), CAP)" -- and reads the
names and the numbers out of the match rather than hardcoding them. Names in
docstrings below are only "what it was called in the build this was written
against", never something the code depends on.

Every detector is also required to be UNIQUE: if a shape matches zero or more
than one place, the patch is skipped with a diagnostic instead of guessing.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys

PROC_NAME = "claude.exe"
STOP_HINT = "Close it first."

# Every retry delay this script writes, in milliseconds.
TARGET_DELAY_MS = 1000
# Retry-After values below this are slept verbatim; raising it means a header
# we failed to neutralize still costs seconds rather than the 10min fallback.
RATE_LIMIT_THRESHOLD_MS = 99999

_IDENT = rb'[a-zA-Z_$][a-zA-Z0-9_$]*'
# A JS numeric literal, including the exponential forms this script writes back
# (`1e3`), so a re-read of an already-patched site parses instead of missing.
_NUMBER = rb'[0-9][0-9.eE+]*'
# "not preceded by an identifier character" -- keeps `VAR=` from matching the
# tail of a longer name such as `myVAR=`.
_NOT_IDENT = rb'(?<![A-Za-z0-9_$])'


def require_platform() -> None:
    """Refuse to run outside Windows.

    This build hardcodes Windows binary discovery (npm shims, %APPDATA%,
    claude.exe) and a locked-file-aware write; running it on Linux/macOS would
    mis-locate the binary. Direct Unix users to the dedicated script instead of
    failing later with a confusing error.
    """
    if os.name != "nt":
        print(f"ERROR: this is the Windows build, but the current OS is "
              f"'{sys.platform}' (os.name={os.name!r}).", file=sys.stderr)
        print("Use claude-linux.py on Linux/macOS.", file=sys.stderr)
        sys.exit(1)


def require_pe_image(data: bytes, binary_path: str) -> None:
    """Reject an ELF/Mach-O image, identified by magic bytes rather than name.

    Upstream names the launcher `claude.exe` on every platform, so the suffix
    says nothing about the format -- only the header does. The byte patches
    themselves are platform-independent minified JS, but this build uses
    Windows binary discovery and prints Windows hints, so send Unix images
    next door.
    """
    if data[:4] == b"\x7fELF" or data[:4] in (
        b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",   # Mach-O 64/32 LE
        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",   # Mach-O universal
    ):
        print(f"ERROR: {binary_path} is an ELF/Mach-O image, not a Windows PE.",
              file=sys.stderr)
        print("Use claude-linux.py for it.", file=sys.stderr)
        sys.exit(1)
    if data[:2] != b"MZ":
        print(f"  WARN: {binary_path} is not a PE image "
              f"(magic {data[:4].hex()}); continuing anyway.", file=sys.stderr)


def find_binary() -> str:
    """Find the Claude Code binary path (Windows)."""
    candidates = []

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

    # Fallback: look in npm global packages
    try:
        result = subprocess.run(
            ["npm", "root", "-g"], capture_output=True, text=True, timeout=5, shell=True
        )
        if result.returncode == 0:
            npm_root = result.stdout.strip()
            candidates.append(os.path.join(
                npm_root, "@anthropic-ai", "claude-code", "bin", "claude.exe",
            ))
    except Exception:
        pass

    for c in candidates:
        if os.path.isfile(c):
            return os.path.realpath(c)

    print("ERROR: Could not find Claude Code binary. Is it installed?", file=sys.stderr)
    print("Try: npm install -g @anthropic-ai/claude-code", file=sys.stderr)
    sys.exit(1)


# --- Same-length rewriting helpers -------------------------------------------
# Every patch must keep the file size identical, so a replacement is always the
# same byte length as what it overwrites. Numbers get an exponential form or
# trailing spaces; JS accepts whitespace anywhere an operator or comma follows.

def fit_literal(candidates: list[str], width: int) -> bytes | None:
    """First candidate that fits `width`, right-padded with spaces.

    Do NOT pad numbers with leading zeros: `0010000` is a legacy octal literal
    in sloppy-mode JS (= 4096, not 10000) and a SyntaxError under strict/ESM.
    """
    for c in candidates:
        if len(c) <= width:
            return (c + " " * (width - len(c))).encode()
    return None


def js_number(value: int, width: int) -> bytes | None:
    """Render `value` as a JS numeric literal occupying exactly `width` bytes.

    Prefers plain decimal; falls back to the shortest exponential form when the
    slot is too narrow (500 -> 1e3 keeps a 3-byte slot).
    """
    s = str(value)
    trailing_zeros = len(s) - len(s.rstrip("0"))
    exponential = sorted(
        (f"{s[:len(s) - k]}e{k}" for k in range(1, trailing_zeros + 1)),
        key=len,
    )
    return fit_literal([s] + exponential, width)


def parse_number(raw: bytes) -> float | None:
    try:
        return float(raw)
    except ValueError:
        return None


def find_unique(data: bytes, pattern: bytes, what: str, warn_on_zero: bool = True):
    """Return the single match of `pattern`, or None (with a diagnostic).

    Uniqueness is a load-bearing part of every detector here: a shape that
    suddenly matches twice means the assumption behind it broke, and picking
    the first hit would silently patch the wrong place -- which is exactly how
    an earlier version of this script ended up rewriting an unrelated OAuth
    helper. Refusing is the correct outcome.

    Pass ``warn_on_zero=False`` when a zero-hit outcome is expected -- i.e.
    detectors that first try the unpatched shape and then fall through to a
    "(patched)" shape: on an already-patched binary the unpatched lookups
    match zero times by design. Two or more hits still warn either way.
    """
    hits = list(re.finditer(pattern, data))
    if len(hits) == 1:
        return hits[0]
    if len(hits) == 0 and not warn_on_zero:
        return None
    print(f"  WARN: {what}: expected 1 structural match, found {len(hits)}",
          file=sys.stderr)
    return None


# --- Site model ---------------------------------------------------------------
# A "site" is one same-length byte rewrite at a known absolute offset, produced
# by a structural detector that has already verified what is there. Discovery
# and application are separate so --dry-run can report exactly what would be
# written without a second, differently-shaped code path.

def site(key: str, desc: str, offset: int, old: bytes, new: bytes) -> dict:
    return {"key": key, "desc": desc, "offset": offset, "old": old, "new": new,
            "state": "todo"}


def site_done(key: str, desc: str) -> dict:
    return {"key": key, "desc": desc, "offset": None, "old": None, "new": None,
            "state": "done"}


def apply_site(data: bytearray, s: dict, stats: dict) -> None:
    """Write one site into `data`, or account for it as already applied."""
    if s["state"] == "done":
        print(f"  OK {s['desc']} (already patched)")
        stats["applied"] += 1
        return
    off, old, new = s["offset"], s["old"], s["new"]
    if len(old) != len(new):
        print(f"  SKIP: {s['desc']} - byte length mismatch "
              f"({len(old)} vs {len(new)})", file=sys.stderr)
        stats["failed"] += 1
        s["state"] = "failed"
        return
    actual = bytes(data[off:off + len(old)])
    if actual != old:
        print(f"  SKIP: {s['desc']} - byte mismatch at offset {off}", file=sys.stderr)
        print(f"    Expected: {old!r}", file=sys.stderr)
        print(f"    Actual:   {actual!r}", file=sys.stderr)
        stats["failed"] += 1
        s["state"] = "failed"
        return
    print(f"  OK {s['desc']} @ offset {off}")
    print(f"       {old.decode('utf-8', 'replace')}")
    print(f"    -> {new.decode('utf-8', 'replace')}")
    data[off:off + len(new)] = new
    stats["applied"] += 1
    s["state"] = "applied"


# --- Detector 1: retry cap ----------------------------------------------------

def discover_retry_cap(data: bytes) -> tuple[str, dict | None]:
    """Decide whether CLAUDE_CODE_MAX_RETRIES is clamped, and neutralize it.

    Two shapes exist in the wild:

    a) clamped -- the env value is compared against a cap and a warning
       `CLAUDE_CODE_MAX_RETRIES=${n} clamped to ${CAP}` is emitted. The guard
       `if(PARSED>CAP&&...` is rewritten to `if(!1 ...` so the clamp branch
       is dead and the raw value passes through.

    b) uncapped -- the reader returns the parsed value directly. Current builds
       look like this, so there is nothing to disable. That is VERIFIED, not
       assumed: the reader body is matched in full and checked for the absence
       of a clamp, so a cap reintroduced in a future build cannot be silently
       reported as "fine".

    Returns (status, site) with status in {"clamped", "uncapped", "unknown"}.
    """
    # (a) A clamp that announces itself.
    for m in re.finditer(rb'CLAUDE_CODE_MAX_RETRIES=\$\{', data):
        ctx = data[m.start():m.start() + 200]
        clamped = re.search(rb'clamped to \$\{(' + _IDENT + rb')\}', ctx)
        if not clamped:
            continue
        cap_var = clamped.group(1)
        before = data[max(0, m.start() - 200):m.start()]
        guard = re.search(rb'if\((' + _IDENT + rb'>' + re.escape(cap_var) + rb')\)&&', before)
        guard = guard or re.search(
            rb'if\((' + _IDENT + rb'>' + re.escape(cap_var) + rb')&&', before)
        if guard:
            off = max(0, m.start() - 200) + guard.start(1)
            old = guard.group(1)
            new = fit_literal(["!1"], len(old))
            return "clamped", site(
                "max_retries",
                f"Disable retry cap clamp against {cap_var.decode()}",
                off, old, new)
        if re.search(rb'if\(!1 *&&', before):
            return "clamped", site_done("max_retries", "Disable retry cap clamp")
        return "unknown", None

    # (b) No warning anywhere: prove the reader is genuinely uncapped.
    reader = find_unique(
        data,
        rb'function (' + _IDENT + rb')\(\)\{if\(process\.env\.CLAUDE_CODE_MAX_RETRIES\)'
        rb'\{let (' + _IDENT + rb')=parseInt\(process\.env\.CLAUDE_CODE_MAX_RETRIES,10\);'
        rb'([^{}]{0,160})\}return (' + _IDENT + rb')\}',
        "CLAUDE_CODE_MAX_RETRIES reader",
    )
    if reader is None:
        return "unknown", None
    body = reader.group(3)
    if b"Math.min" in body or b"Math.max" in body:
        print("  WARN: the env reader clamps the value in a shape this script "
              "does not recognize; refusing to guess", file=sys.stderr)
        return "unknown", None
    return "uncapped", site_done(
        "max_retries",
        f"Retry cap: none in this build ({reader.group(1).decode()} returns "
        f"CLAUDE_CODE_MAX_RETRIES unclamped)")


# --- Detector 2: the API retry backoff helper --------------------------------

def discover_backoff_fn(data: bytes) -> dict | None:
    """Locate the API retry backoff helper by shape, not by name.

    The skeleton (minified as `rle` in the build this was written against):

        function NAME(attempt, retryAfter, cap = 32000) {
            let d = Math.min(BASE * Math.pow(2, attempt - 1), cap),
                jitter = d + Math.random() * 0.25 * d;
            if (retryAfter) {
                let s = parseInt(retryAfter, 10);
                if (!isNaN(s)) return Math.max(s * 1000, jitter)   // header wins
            }
            return jitter
        }

    Three things identify it and nothing else in the binary satisfies all
    three: the min() over an exponential in the function's OWN first parameter,
    a `Math.random()` jitter term right after it, and the enclosing `function`
    header whose first parameter is that same attempt counter. Nine other
    `Math.pow(2,n-1)` backoffs exist in the binary (MCP reconnect, OAuth
    refresh, session persistence, ...) and every one of them is rejected.

    Returns {name, body_start, base, pow, header} or None.
    """
    candidates = []
    for m in re.finditer(
        rb'Math\.min\((?:(' + _IDENT + rb')|(' + _NUMBER + rb'))'
        rb'\*Math\.pow\(([12]),(' + _IDENT + rb')-1\),', data
    ):
        attempt = m.group(4)
        # The jitter term must follow within the same statement.
        if not re.match(rb'[^;]{0,80}?Math\.random\(\)', data[m.end():m.end() + 120]):
            continue
        window_start = max(0, m.start() - 400)
        header = None
        for f in re.finditer(rb'function (' + _IDENT + rb')\((' + _IDENT + rb')',
                             data[window_start:m.start()]):
            header = f
        if header is None or header.group(2) != attempt:
            continue
        candidates.append((window_start + header.start(), header.group(1), m))

    if len(candidates) != 1:
        print(f"  WARN: API retry backoff helper: expected 1 structural match, "
              f"found {len(candidates)}", file=sys.stderr)
        return None

    body_start, name, m = candidates[0]
    info = {"name": name, "body_start": body_start, "pow": None,
            "base": None, "header": None}

    # -- base: `Math.pow` multiplier, either a shared const or an inline literal
    if m.group(1) is not None:
        base_var = m.group(1)
        decl = find_unique(
            data, _NOT_IDENT + re.escape(base_var) + rb'=(' + _NUMBER + rb')',
            f"backoff base declaration {base_var.decode()}")
        if decl is not None:
            info["base"] = {"var": base_var, "offset": decl.start(1),
                            "raw": decl.group(1)}
    else:
        info["base"] = {"var": None, "offset": m.start(2), "raw": m.group(2)}

    # -- exponent base: 2 (exponential growth) or 1 (already flattened)
    info["pow"] = {"offset": m.start(3), "raw": m.group(3)}

    # -- Retry-After override inside the same body
    body = data[body_start:body_start + 600]
    hdr = re.search(rb'return Math\.max\((' + _IDENT + rb')\*1000,(' + _IDENT + rb')\)', body)
    if hdr:
        info["header"] = {"offset": body_start + hdr.start(), "raw": hdr.group(0),
                          "jitter": hdr.group(2), "patched": False}
    else:
        # Patched shape: the Math.max is gone and the jitter is returned bare.
        done = re.search(rb'if\(!isNaN\((' + _IDENT + rb')\)\)return (' + _IDENT
                         + rb') {2,}\}return \2', body)
        if done:
            info["header"] = {"patched": True}
    return info


def backoff_sites(data: bytes, fn: dict) -> list[dict]:
    """Turn a discovered backoff helper into concrete rewrites."""
    sites = []

    base = fn["base"]
    if base is None:
        print("  WARN: backoff base literal not resolved", file=sys.stderr)
    else:
        current = parse_number(base["raw"])
        where = (f"const {base['var'].decode()}" if base["var"]
                 else f"inline literal in {fn['name'].decode()}()")
        if current == TARGET_DELAY_MS:
            sites.append(site_done("backoff_base", f"Backoff base already {TARGET_DELAY_MS}ms ({where})"))
        else:
            new = js_number(TARGET_DELAY_MS, len(base["raw"]))
            if new is None:
                print(f"  WARN: cannot fit {TARGET_DELAY_MS} into the "
                      f"{len(base['raw'])}-byte backoff base slot", file=sys.stderr)
            else:
                sites.append(site(
                    "backoff_base",
                    f"Backoff base {base['raw'].decode()} -> {TARGET_DELAY_MS}ms ({where})",
                    base["offset"], base["raw"], new))

    pw = fn["pow"]
    if pw["raw"] == b"1":
        sites.append(site_done("backoff_pow", "Exponential growth already disabled (pow base 1)"))
    else:
        sites.append(site(
            "backoff_pow",
            "Disable exponential growth (pow base 2 -> 1; pow(1,n) is always 1)",
            pw["offset"], pw["raw"], b"1"))

    hdr = fn["header"]
    if hdr is None:
        print("  WARN: Retry-After override inside the backoff helper not found",
              file=sys.stderr)
    elif hdr.get("patched"):
        sites.append(site_done("retry_after_backoff",
                               "Retry-After already ignored in the backoff helper"))
    else:
        old = hdr["raw"]
        new = fit_literal(["return " + hdr["jitter"].decode()], len(old))
        sites.append(site(
            "retry_after_backoff",
            "Ignore Retry-After in the backoff helper (return the ~1s jitter, "
            "not the header's seconds)",
            hdr["offset"], old, new))
    return sites


# --- Detector 3: pin the retry loop's delay assignments ----------------------

def discover_delay_pins(data: bytes, fn_name: bytes) -> list[dict]:
    """Pin every "how long until the next attempt" assignment to 1000ms.

    Anchored on the retry telemetry event, which names the delay variable in
    its own payload and so survives any renaming:

        G("tengu_api_retry", { attempt: I, delayMs: x, ... })

    Everything assigned to that variable just above -- in the build this was
    written against:

        x = resetHeaderMs(err) ?? Math.min(backoff(n, retryAfter, cap), ceil)
        x = Math.min(backoff(n, retryAfter, cap), ceil)
        x = backoff(attempt, retryAfter)

    -- becomes a literal 1000. Rewriting the ASSIGNMENT rather than only the
    backoff helper matters because of the `??`: a non-null reset header
    short-circuits the helper entirely, so patching the helper alone leaves
    that path waiting minutes.
    """
    anchor = find_unique(
        data,
        rb'"tengu_api_retry",\{attempt:' + _IDENT + rb',delayMs:(' + _IDENT + rb')[,}]',
        "API retry telemetry (delay variable)",
    )
    if anchor is None:
        return []
    var = anchor.group(1)
    lo = max(0, anchor.start() - 900)
    region = data[lo:anchor.start()]

    assign = (_NOT_IDENT + re.escape(var) + rb'=(?:' + _IDENT + rb'\(' + _IDENT
              + rb'\)\?\?)?(?:Math\.min\()?' + re.escape(fn_name) + rb'\(' + _IDENT
              + rb'(?:,' + _IDENT + rb')*\)(?:,' + _IDENT + rb'\))?')
    pinned = _NOT_IDENT + re.escape(var) + re.escape(b"=%d" % TARGET_DELAY_MS) + rb' {2,}'

    sites = []
    for i, m in enumerate(re.finditer(assign, region), 1):
        old = m.group(0)
        new = fit_literal([f"{var.decode()}={TARGET_DELAY_MS}"], len(old))
        if new is None:
            print(f"  WARN: delay assignment {i} is too short to pin", file=sys.stderr)
            continue
        sites.append(site(
            f"delay_pin_{i}",
            f"Pin retry delay assignment {i} to {TARGET_DELAY_MS}ms",
            lo + m.start(), old, new))
    if sites:
        return sites
    for i, _ in enumerate(re.finditer(pinned, region), 1):
        sites.append(site_done(f"delay_pin_{i}",
                               f"Retry delay assignment {i} already pinned"))
    if not sites:
        print("  WARN: no retry delay assignment found near the telemetry anchor",
              file=sys.stderr)
    return sites


# --- Detector 4: rate-limit fallback delays ----------------------------------

def discover_rate_limit(data: bytes, ms_parser_name: bytes | None) -> list[dict]:
    """Shorten the long-wait path taken when a 429 is not retried inline.

        let ms = retryAfterMs(err);
        if (ms !== null && ms < THRESHOLD) { await sleep(ms); continue }
        let until = Math.max(ms ?? FALLBACK, MINIMUM)

    FALLBACK (30min) and MINIMUM (10min) drop to 1s; THRESHOLD rises so a
    header we failed to neutralize still costs seconds, not the 10min floor.
    All three current values are read out of the binary and rewritten in
    place -- nothing here searches for `=1800000`.
    """
    guard = find_unique(
        data,
        rb'let (' + _IDENT + rb')=(' + _IDENT + rb')\(' + _IDENT
        + rb'\);if\(\1!==null&&\1<(' + _IDENT + rb')\)\{',
        "rate-limit threshold guard",
    )
    fallback = find_unique(
        data,
        rb'\}let ' + _IDENT + rb'=Math\.max\((' + _IDENT + rb')\?\?(' + _IDENT
        + rb'),(' + _IDENT + rb')\)',
        "rate-limit fallback/minimum",
    )
    if guard is None or fallback is None:
        return []
    if guard.group(1) != fallback.group(1):
        print("  WARN: rate-limit guard and fallback refer to different "
              "variables; refusing to guess", file=sys.stderr)
        return []
    if ms_parser_name is not None and guard.group(2) != ms_parser_name:
        print(f"  WARN: rate-limit guard reads {guard.group(2).decode()}, not the "
              f"Retry-After parser {ms_parser_name.decode()}; refusing to guess",
              file=sys.stderr)
        return []

    wanted = [
        ("rl_threshold", guard.group(3), RATE_LIMIT_THRESHOLD_MS,
         "Rate-limit inline-sleep threshold"),
        ("rl_fallback", fallback.group(2), TARGET_DELAY_MS,
         "Rate-limit fallback wait"),
        ("rl_min", fallback.group(3), TARGET_DELAY_MS,
         "Rate-limit minimum wait"),
    ]
    sites = []
    for key, var, target, label in wanted:
        decl = find_unique(data, _NOT_IDENT + re.escape(var) + rb'=(' + _NUMBER + rb')',
                           f"{label} declaration {var.decode()}")
        if decl is None:
            continue
        raw = decl.group(1)
        current = parse_number(raw)
        if current == target:
            sites.append(site_done(key, f"{label} already {target}ms ({var.decode()})"))
            continue
        new = js_number(target, len(raw))
        if new is None:
            print(f"  WARN: cannot fit {target} into the {len(raw)}-byte "
                  f"{var.decode()} slot", file=sys.stderr)
            continue
        sites.append(site(
            key,
            f"{label} {raw.decode()} -> {target}ms ({var.decode()})",
            decl.start(1), raw, new))
    return sites


# --- Detector 5: Retry-After / ratelimit-reset parsers -----------------------

def discover_retry_after_ms_parser(data: bytes) -> tuple[bytes | None, dict | None]:
    """Stop the Retry-After header from being consumed as a sleep duration.

        function NAME(err) {
            let h = header(err);
            if (h) { let s = parseInt(h, 10); if (!isNaN(s)) return s * 1000 }
            return null
        }

    Forcing the `null` return sends the caller to the (now 1s) backoff path.
    Returns (function name, site) -- the name is fed back into the rate-limit
    detector so the two are proven to be the same code path.
    """
    m = find_unique(
        data,
        rb'function (' + _IDENT + rb')\((' + _IDENT + rb')\)\{let (' + _IDENT + rb')='
        + _IDENT + rb'\(\2\);if\(\3\)\{let (' + _IDENT + rb')=parseInt\(\3,10\);'
        + rb'if\(!isNaN\(\4\)\)(return \4\*1000)\}return null\}',
        "Retry-After milliseconds parser", warn_on_zero=False,
    )
    if m is not None:
        old = m.group(5)
        new = fit_literal(["return null"], len(old))
        if new is None:
            return m.group(1), None
        return m.group(1), site(
            "retry_after_ms",
            f"Ignore Retry-After in {m.group(1).decode()}() "
            f"(return null instead of the header's seconds)",
            m.start(5), old, new)

    done = find_unique(
        data,
        rb'function (' + _IDENT + rb')\((' + _IDENT + rb')\)\{let (' + _IDENT + rb')='
        + _IDENT + rb'\(\2\);if\(\3\)\{let (' + _IDENT + rb')=parseInt\(\3,10\);'
        + rb'if\(!isNaN\(\4\)\)return null +\}return null\}',
        "Retry-After milliseconds parser (patched)",
    )
    if done is not None:
        return done.group(1), site_done(
            "retry_after_ms", "Retry-After already ignored in the ms parser")
    return None, None


def discover_ratelimit_reset(data: bytes) -> dict | None:
    """Stop `anthropic-ratelimit-unified-reset` from setting the retry delay.

        let t = headers.get?.("anthropic-ratelimit-unified-reset");
        if (!t) return null

    The header NAME is a wire protocol string, not a minified identifier, so
    matching on it is stable across builds. Forcing `if(!0)` takes the null
    branch and falls through to the ~1s backoff.
    """
    m = find_unique(
        data,
        rb'get(?:\?\.)?\("anthropic-ratelimit-unified-reset"\);(if\(!(' + _IDENT
        + rb')\))return null',
        "ratelimit-unified-reset guard", warn_on_zero=False,
    )
    if m is not None:
        old = m.group(1)
        new = fit_literal(["if(!0)"], len(old))
        if new is None:
            return None
        return site(
            "ratelimit_reset",
            "Ignore anthropic-ratelimit-unified-reset (take the null branch)",
            m.start(1), old, new)
    if re.search(rb'get(?:\?\.)?\("anthropic-ratelimit-unified-reset"\);if\(!0\)', data):
        return site_done("ratelimit_reset",
                         "anthropic-ratelimit-unified-reset already ignored")
    return None


# --- Detector 6: the bundled Anthropic SDK -----------------------------------
# The SDK is bundled from TypeScript source with its class methods intact, so
# `retryRequest` / `calculateDefaultRetryTimeoutMillis` are real API names, not
# minifier output -- stable anchors. Only the locals inside are minified.

def discover_sdk_backoff(data: bytes) -> dict | None:
    """SDK: `Math.min(0.5*Math.pow(2,n), 8)` seconds -> a flat ~1s.

        calculateDefaultRetryTimeoutMillis(e, t) {
            let n = t - e, s = Math.min(0.5 * Math.pow(2, n), 8),
                jitter = 1 - Math.random() * 0.25;
            return s * jitter * 1000
        }

    Setting the coefficient to 1 and the exponent base to 1 leaves
    1 * (0.75..1) * 1000 ms.
    """
    m = find_unique(
        data,
        rb'calculateDefaultRetryTimeoutMillis\(' + _IDENT + rb',' + _IDENT + rb'\)\{'
        rb'let (' + _IDENT + rb')=' + _IDENT + rb'-' + _IDENT + rb',' + _IDENT
        + rb'=Math\.min\((' + _NUMBER + rb')\*Math\.pow\(([12]),\1\),' + _NUMBER + rb'\)',
        "SDK calculateDefaultRetryTimeoutMillis",
    )
    if m is None:
        return None
    coeff_raw, pow_raw = m.group(2), m.group(3)
    if parse_number(coeff_raw) == 1 and pow_raw == b"1":
        return site_done("sdk", "SDK backoff already flat (~1s)")
    old = data[m.start(2):m.end(3)]
    coeff_new = fit_literal(["1.0", "1", "1e0"], len(coeff_raw))
    if coeff_new is None:
        return None
    new = coeff_new + old[len(coeff_raw):-1] + b"1"
    return site(
        "sdk",
        f"SDK backoff {coeff_raw.decode()}*pow({pow_raw.decode()},n) -> "
        f"{coeff_new.decode().strip()}*pow(1,n) (fixed ~0.75-1s)",
        m.start(2), old, new)


def discover_sdk_retry_after(data: bytes) -> list[dict]:
    """SDK retryRequest: skip both Retry-After headers.

        async retryRequest(opts, left, logId, headers) {
            let ms, a = headers?.get("retry-after-ms");
            if (a) { ... ms = parseFloat(a) }
            let b = headers?.get("retry-after");
            if (b && !ms) { ... }
            ...
        }

    Both guards are forced false so the SDK falls through to
    calculateDefaultRetryTimeoutMillis, which the patch above pins to ~1s.
    The header names are wire protocol strings, so they anchor reliably.
    """
    sites = []
    ms = find_unique(
        data,
        rb'retryRequest\((?:' + _IDENT + rb',){3}' + _IDENT + rb'\)\{let ' + _IDENT
        + rb',(' + _IDENT + rb')=' + _IDENT + rb'(?:\?\.)?get\("retry-after-ms"\);'
        + rb'(if\(\1\))\{',
        "SDK retry-after-ms guard", warn_on_zero=False,
    )
    if ms is not None:
        old = ms.group(2)
        new = fit_literal(["if(0)"], len(old))
        if new is not None:
            sites.append(site("sdk_ra_ms", "Ignore SDK retry-after-ms header",
                              ms.start(2), old, new))
    elif re.search(rb'get(?:\?\.)?\("retry-after-ms"\);if\(0\)', data):
        sites.append(site_done("sdk_ra_ms", "SDK retry-after-ms already ignored"))

    ra = find_unique(
        data,
        rb'let (' + _IDENT + rb')=' + _IDENT + rb'(?:\?\.)?get\("retry-after"\);'
        rb'(if\(\1&&!(' + _IDENT + rb')\))\{let ' + _IDENT + rb'=parseFloat\(\1\)',
        "SDK retry-after guard", warn_on_zero=False,
    )
    if ra is not None:
        old = ra.group(2)
        new = fit_literal([f"if(0&&!{ra.group(3).decode()})"], len(old))
        if new is not None:
            sites.append(site("sdk_ra", "Ignore SDK retry-after / HTTP-date header",
                              ra.start(2), old, new))
    elif re.search(rb'get(?:\?\.)?\("retry-after"\);if\(0&&', data):
        sites.append(site_done("sdk_ra", "SDK retry-after already ignored"))
    return sites


# --- Orchestration ------------------------------------------------------------

def discover_all(data: bytes) -> list[dict]:
    """Run every detector and return the full list of sites, in patch order."""
    sites: list[dict] = []

    print("=== Patch 1: Retry cap (CLAUDE_CODE_MAX_RETRIES) ===")
    status, cap_site = discover_retry_cap(data)
    if cap_site is not None:
        sites.append(cap_site)
        if status == "uncapped":
            print(f"  {cap_site['desc']}")
    else:
        print("  SKIP: could not determine whether the retry cap is enforced",
              file=sys.stderr)

    print("=== Patch 2: Exponential backoff -> fixed 1s ===")
    fn = discover_backoff_fn(data)
    if fn is not None:
        print(f"  backoff helper: {fn['name'].decode()}() @ {fn['body_start']}")
        sites += backoff_sites(data, fn)
    else:
        print("  SKIP: API retry backoff helper not located", file=sys.stderr)

    print("=== Patch 3: Bundled Anthropic SDK backoff ===")
    sdk = discover_sdk_backoff(data)
    if sdk is not None:
        sites.append(sdk)
    else:
        print("  SKIP: SDK backoff not located", file=sys.stderr)

    print("=== Patch 4: Retry-After / ratelimit-reset ===")
    ms_name, ms_site = discover_retry_after_ms_parser(data)
    if ms_site is not None:
        sites.append(ms_site)
    else:
        print("  SKIP: Retry-After milliseconds parser not located", file=sys.stderr)
    reset_site = discover_ratelimit_reset(data)
    if reset_site is not None:
        sites.append(reset_site)
    else:
        print("  SKIP: ratelimit-unified-reset guard not located", file=sys.stderr)
    sdk_ra = discover_sdk_retry_after(data)
    if len(sdk_ra) == 2:
        sites += sdk_ra
    else:
        print(f"  SKIP: expected 2 SDK Retry-After guards, located {len(sdk_ra)}",
              file=sys.stderr)

    print("=== Patch 5: Rate-limit fallback delays ===")
    rl = discover_rate_limit(data, ms_name)
    if len(rl) == 3:
        sites += rl
    else:
        print(f"  SKIP: expected 3 rate-limit constants, located {len(rl)}",
              file=sys.stderr)

    print("=== Patch 6: Pin the retry loop's delay to 1s ===")
    if fn is not None:
        pins = discover_delay_pins(data, fn["name"])
        sites += pins
        if pins:
            print(f"  delay assignments: {len(pins)}")
    else:
        print("  SKIP: needs the backoff helper from Patch 2", file=sys.stderr)

    return sites


def looks_already_patched(sites: list[dict]) -> bool:
    """True when every located site is already in its patched state.

    Patching again would be a no-op at best, so the write path refuses and asks
    for a --restore first. --dry-run is allowed through: it writes nothing, and
    reporting the current per-site state is exactly what it is for.
    """
    return bool(sites) and all(s["state"] == "done" for s in sites)


def write_patched(binary_path: str, data: bytearray) -> None:
    """Atomically replace the binary with the patched bytes.

    Uses a temp file + os.replace(), which is atomic and overwrites the
    destination. On Windows os.replace fails if the target is locked
    (claude.exe running).
    """
    import tempfile
    binary_dir = os.path.dirname(binary_path)
    fd, tmp_path = tempfile.mkstemp(dir=binary_dir, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp_path, binary_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def print_summary(sites: list[dict]) -> None:
    """Report what each behavior actually ended up as."""
    state = {}
    for s in sites:
        state.setdefault(s["key"], s["state"] in ("applied", "done"))

    def row(setting, keys, patched_text):
        flags = [state[k] for k in keys if k in state]
        missing = len([k for k in keys if k not in state])
        total = len(flags) + missing
        done = sum(1 for f in flags if f)
        if total == 0:
            behavior = "not located"
        elif done == total:
            behavior = patched_text
        elif done == 0:
            behavior = "unchanged (patch skipped)"
        else:
            behavior = f"partially patched ({done}/{total})"
        return f"  | {setting:<24}| {behavior:<33}|"

    pin_keys = [k for k in state if k.startswith("delay_pin_")]
    sep = "  +-------------------------+----------------------------------+"
    print(sep)
    print(f"  | {'Setting':<24}| {'Behavior':<33}|")
    print(sep)
    print(row("Max retries", ["max_retries"], "CLAUDE_CODE_MAX_RETRIES (=9999)"))
    print(row("General retry delay", ["backoff_base", "backoff_pow"], "Fixed ~1 second"))
    print(row("API retry loop delay", pin_keys or ["delay_pin_1"], "Pinned to 1000ms"))
    print(row("Rate-limit retry delay",
              ["rl_fallback", "rl_min", "rl_threshold"], "Fixed ~1 second"))
    print(row("SDK-level retry delay", ["sdk"], "Fixed ~0.75-1 second"))
    print(row("Retry-After / reset",
              ["retry_after_backoff", "retry_after_ms", "ratelimit_reset",
               "sdk_ra_ms", "sdk_ra"], "ignored (always ~1s)"))
    print(sep)


def main():
    parser = argparse.ArgumentParser(
        description="Patch Claude Code binary (Windows): allow 9999 retries, fix backoff to 1s interval"
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
            print("Restored successfully.")
        except OSError as e:
            print(f"ERROR: Failed to restore: {e}", file=sys.stderr)
            print(f"Is {PROC_NAME} running? {STOP_HINT}", file=sys.stderr)
            sys.exit(1)
        return

    # -- Read binary -----------------------------------------------------------
    with open(binary_path, "rb") as f:
        data = bytearray(f.read())

    require_pe_image(data, binary_path)

    # -- Locate every site by structure ----------------------------------------
    print()
    print("=== Locating patch sites by code structure ===")
    print()
    sites = discover_all(bytes(data))

    # -- Already patched: refuse to write, but let --dry-run report the state ---
    # Checked before the backup so a patched binary is never copied over a good
    # .orig (--dry-run never reaches the backup step at all).
    already_patched = looks_already_patched(sites)
    if already_patched:
        if not args.dry_run:
            print()
            print("This binary already appears to be patched by this script.")
            print("Restore the original first, then re-run:")
            print(f"  python {sys.argv[0]} --restore")
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

    # -- Apply -----------------------------------------------------------------
    print()
    print("=== Applying patches ===")
    stats = {"applied": 0, "failed": 0}
    for s in sites:
        apply_site(data, s, stats)

    print()
    print("===========================================================")
    print(f"  Patches {'in place' if already_patched else 'applied'}: {stats['applied']}")
    print(f"  Patches skipped: {stats['failed']}")
    print("===========================================================")

    if args.dry_run:
        print()
        print_summary(sites)
        print()
        if already_patched:
            print("DRY RUN - binary is already patched; nothing to do.")
            print(f"To re-apply from scratch: python {sys.argv[0]} --restore")
        else:
            print("DRY RUN - no changes were made.")
            print("Run without --dry-run to apply patches.")
        return

    # -- Nothing patched: bail out instead of printing misleading success text -
    if stats["applied"] == 0:
        print()
        print("ERROR: No patches were applied; the binary is unchanged.", file=sys.stderr)
        print("Claude Code was likely updated and the code shapes no longer match.", file=sys.stderr)
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
    print(f"  python {sys.argv[0]} --restore")
    print()
    print("Set these environment variables before running claude:")
    print('  $env:CLAUDE_CODE_MAX_RETRIES="9999"       # Max retry attempts (internal cap disabled)')
    print('  $env:CLAUDE_CODE_RETRY_WATCHDOG="1"       # Persistent 429/overloaded retry')
    print('  $env:BUN_JSC_forceDebuggerBytecodeGeneration="1"  # Recompile patched source in Bun')
    print()
    print("Retry behavior after patching:")
    print_summary(sites)
    print()
    print("NOTE: After updating Claude Code (npm update), re-run this script.")


if __name__ == "__main__":
    main()

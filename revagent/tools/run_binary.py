import os
import re
import shlex
import shutil
import subprocess

from .bash import MAX_TIMEOUT, run_cmd

# Substrings that indicate the OS/loader could not even start the target (as opposed to the
# target running and exiting non-zero because the guess was wrong). Only these, in a short
# loader-shaped body — plus a fatal-signal exit status with no output at all — count as a start
# failure; "exit 1, no output" and "exit 255, prints Wrong" are normal wrong-answer patterns for
# check binaries and must not trip env_blocked.
START_FAILURE_MARKERS = (
    "error while loading shared libraries",
    "cannot execute binary file",
    "Exec format error",
    "No such file or directory",
    "err:module:",
    "Bad EXE format",
    "not a valid Win32",
)

# Exit statuses that mean "killed by a fatal signal": bash reports 128+N, run_cmd -N.
# ILL(4), ABRT(6), BUS(7), FPE(8), SEGV(11).
FATAL_SIGNAL_STATUSES = {132, 134, 135, 136, 139}
# A loader failure says its piece and stops; a program printing more than this is running.
MAX_START_FAILURE_BODY_LINES = 3

SCHEMA = {
    "type": "function",
    "function": {
        "name": "run_binary",
        "description": (
            "Execute a challenge binary (x86-64 ELF or script) with given argv and stdin, return exit code, "
            "stdout and stderr. Use it to observe behaviour and to VERIFY a candidate answer before "
            "submit_flag. Windows PE runs under wine inside the sandbox (64-bit only: wine64, no 32-bit "
            "wine); GUI programs: use run_gui. Non-x86-64 ELF and 32-bit Windows PE cannot run here; "
            "the tool tells you."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "path relative to the challenge directory"},
                "args": {"type": "array", "items": {"type": "string"}, "description": "argv (default [])"},
                "stdin": {"type": "string", "description": "text fed to stdin (default empty)"},
                "timeout": {"type": "integer", "description": "seconds (default 10, max 900)"},
            },
            "required": ["path"],
        },
    },
}


def run(ctx, path: str, args: list[str] | None = None, stdin: str = "", timeout: int = 10) -> str:
    out = _run(ctx, path, args, stdin, timeout)
    _observe(ctx, path, out)
    return out + ctx.env_note()


def _observe(ctx, path: str, out: str) -> None:
    if out.startswith("[cannot run here]"):
        ctx.block_env(path)
        ctx.observe(f"run_binary {path}: [cannot run here]")
        return
    if out.startswith("[tool error]"):
        return
    first = out.splitlines()[0] if out else ""
    m = re.match(r"\[exit (-?\d+)\]", first)
    code = m.group(1) if m else "?"
    body = "\n".join(out.splitlines()[1:]).strip()
    stdout_first = body.splitlines()[0][:80] if body else ""
    if _is_start_failure(code, body):
        ctx.note_start_failure(path)
    ctx.observe(f"run_binary {path}: exit {code}, stdout {stdout_first!r}")


def _is_start_failure(code: str, body: str) -> bool:
    """True only when the evidence says the OS/loader never got the program running.

    Both rules are gated on the program's own output, because a program that printed something
    ran. The numeric rule covers a fatal-signal death only (run_cmd reports it as -N, bash as
    128+N) and only with no output at all: `exit(255)` / `return -1` from a failed check is one
    of the commonest shapes in CTF binaries and is an ordinary wrong answer, not a start failure.
    The marker rule needs a loader-shaped body (at most MAX_START_FAILURE_BODY_LINES non-empty
    lines), so "No such file or directory" printed by the program among its own output does not
    count either."""
    try:
        n = int(code)
    except ValueError:
        n = None
    lines = [l for l in body.splitlines() if l.strip()]
    if not lines:
        return n is not None and (n < 0 or n in FATAL_SIGNAL_STATUSES)
    if len(lines) <= MAX_START_FAILURE_BODY_LINES:
        return any(marker in body for marker in START_FAILURE_MARKERS)
    return False


def _run(ctx, path: str, args: list[str] | None = None, stdin: str = "", timeout: int = 10) -> str:
    problem_dir = ctx.problem_dir.resolve()
    p = (ctx.problem_dir / path).resolve()
    if not p.is_relative_to(problem_dir):
        return f"[tool error] path escapes the challenge directory: {path}"
    if not p.is_file():
        return f"[tool error] no such file: {path}"
    try:
        kind = subprocess.run(["file", "-b", str(p)], capture_output=True, text=True).stdout.strip()
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        kind = ""
    with p.open("rb") as f:
        magic = f.read(2)
    timeout = max(1, min(int(timeout), MAX_TIMEOUT))
    if "PE32" in kind or "MS Windows" in kind or magic == b"MZ":
        if shutil.which("wine") is None:
            return (f"[cannot run here] {kind} — Windows PE and wine is not installed on the host. "
                    f"Run with --sandbox (the image has wine), or analyze statically / emulate with unicorn.")
        if "80386" in kind or ("x86-64" not in kind and "PE32+" not in kind):
            return ("[cannot run here] 32-bit Windows PE: the image has wine64 only. "
                     "Analyze statically / emulate with unicorn (x86 32-bit), or re-implement the check.")
        if not os.access(p, os.X_OK):
            p.chmod(p.stat().st_mode | 0o111)
        cmd = "WINEDEBUG=-all wine " + " ".join(shlex.quote(x) for x in [str(p), *(args or [])])
        return run_cmd(cmd, cwd=ctx.problem_dir, timeout=timeout, stdin_text=stdin)
    if "ELF" in kind and "x86-64" not in kind:
        return (f"[cannot run here] {kind} — not x86-64. Try `which qemu-aarch64 qemu-arm` via bash, "
                f"otherwise static analysis / unicorn.")
    if not os.access(p, os.X_OK):
        p.chmod(p.stat().st_mode | 0o111)
    cmd = " ".join(shlex.quote(x) for x in [str(p), *(args or [])])
    return run_cmd(cmd, cwd=ctx.problem_dir, timeout=timeout, stdin_text=stdin)

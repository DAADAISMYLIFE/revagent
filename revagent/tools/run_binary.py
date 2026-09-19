import os
import shlex
import shutil
import subprocess

from .bash import MAX_TIMEOUT, run_cmd

SCHEMA = {
    "type": "function",
    "function": {
        "name": "run_binary",
        "description": (
            "Execute a challenge binary (x86-64 ELF or script) with given argv and stdin, return exit code, "
            "stdout and stderr. Use it to observe behaviour and to VERIFY a candidate answer before "
            "submit_flag. Windows PE runs under wine inside the sandbox; GUI programs: use run_gui. "
            "Non-x86-64 ELF cannot run here; the tool tells you."
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

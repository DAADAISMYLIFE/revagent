import os
import shlex
import subprocess

from .bash import run_cmd

SCHEMA = {
    "type": "function",
    "function": {
        "name": "run_binary",
        "description": (
            "Execute a challenge binary (x86-64 ELF or script) with given argv and stdin, return exit code, "
            "stdout and stderr. Use it to observe behaviour and to VERIFY a candidate answer before "
            "submit_flag. Windows PE and non-x86-64 ELF cannot run here; the tool tells you."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "path relative to the challenge directory"},
                "args": {"type": "array", "items": {"type": "string"}, "description": "argv (default [])"},
                "stdin": {"type": "string", "description": "text fed to stdin (default empty)"},
                "timeout": {"type": "integer", "description": "seconds (default 10)"},
            },
            "required": ["path"],
        },
    },
}


def run(ctx, path: str, args: list[str] | None = None, stdin: str = "", timeout: int = 10) -> str:
    p = ctx.problem_dir / path
    if not p.is_file():
        return f"[tool error] no such file: {path}"
    kind = subprocess.run(["file", "-b", str(p)], capture_output=True, text=True).stdout.strip()
    if "PE32" in kind or "MS Windows" in kind or p.read_bytes()[:2] == b"MZ":
        return (f"[cannot run here] {kind} — Windows PE, no wine. Use static analysis, unicorn emulation "
                f"(ctfpy), or re-implement the check in Python and verify against it.")
    if "ELF" in kind and "x86-64" not in kind:
        return (f"[cannot run here] {kind} — not x86-64. Try `which qemu-aarch64 qemu-arm` via bash, "
                f"otherwise static analysis / unicorn.")
    if not os.access(p, os.X_OK):
        p.chmod(p.stat().st_mode | 0o111)
    cmd = " ".join(shlex.quote(x) for x in [str(p), *(args or [])])
    return run_cmd(cmd, cwd=ctx.problem_dir, timeout=int(timeout), stdin_text=stdin)

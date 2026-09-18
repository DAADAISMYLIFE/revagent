import os
import signal
import subprocess
from pathlib import Path

SCHEMA = {
    "type": "function",
    "function": {
        "name": "bash",
        "description": (
            "Run a shell command in the challenge directory. Use it for file, strings, readelf, "
            "objdump -d -M intel, gdb -batch -ex ..., python3 (has angr, z3, pycryptodome), "
            "ctfpy (pwntools, capstone, unicorn, pefile), gcc. stdout+stderr are returned with the exit "
            "code on the first line. Output over 12000 chars is truncated and saved to a file you can "
            "page with sed -n 'A,Bp'. stdin is closed; feed input via a pipe or run_binary."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "cmd": {"type": "string", "description": "bash command line"},
                "timeout": {"type": "integer", "description": "seconds (default 120)"},
            },
            "required": ["cmd"],
        },
    },
}


def run_cmd(cmd: str, cwd: Path, timeout: int, stdin_text: str | None = None) -> str:
    p = subprocess.Popen(
        cmd, shell=True, executable="/bin/bash", cwd=str(cwd),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        out, _ = p.communicate(input=(stdin_text or "").encode(), timeout=timeout)
        return f"[exit {p.returncode}]\n" + out.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, _ = p.communicate()
        return f"[timeout after {timeout}s]\n" + (out or b"").decode("utf-8", errors="replace")


def run(ctx, cmd: str, timeout: int = 120) -> str:
    return run_cmd(cmd, cwd=ctx.problem_dir, timeout=int(timeout))

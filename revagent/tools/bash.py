import os
import signal
import subprocess
from pathlib import Path

MAX_TIMEOUT = 900
# Never handed to a child process: the model's own bash/wine must not be able to read the
# server credentials, nor the path of the .secure file they were loaded from.
SCRUB_ENV = ("QWEN", "URL", "MODEL", "REVAGENT_SECURE")

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
                "timeout": {"type": "integer", "description": "seconds (default 120, max 900)"},
            },
            "required": ["cmd"],
        },
    },
}


def run_cmd(cmd: str, cwd: Path, timeout: int, stdin_text: str | None = None) -> str:
    env = {k: v for k, v in os.environ.items() if k not in SCRUB_ENV}
    p = subprocess.Popen(
        cmd, shell=True, executable="/bin/bash", cwd=str(cwd),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True, env=env,
    )
    try:
        out, _ = p.communicate(input=(stdin_text or "").encode(), timeout=timeout)
        return f"[exit {p.returncode}]\n" + out.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, _ = p.communicate()
        return f"[timeout after {timeout}s]\n" + (out or b"").decode("utf-8", errors="replace")


def run(ctx, cmd: str, timeout: int = 120) -> str:
    timeout = max(1, min(int(timeout), MAX_TIMEOUT))
    return run_cmd(cmd, cwd=ctx.problem_dir, timeout=timeout)

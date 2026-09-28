import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path

MAX_TIMEOUT = 900
MAX_OUTPUT_BYTES = 32 * 2**20   # past this the command is killed: nothing useful prints 32 MB
READ_BYTES = 2 * 2**20          # returned to truncate(), which keeps 12000 chars and spills the rest to a file
POLL_SECONDS = 0.2
# Never handed to a child process: the model's own bash/wine must not be able to read the
# server credentials, nor the path of the .secure file they were loaded from.
SCRUB_ENV = ("QWEN", "URL", "MODEL", "REVAGENT_SECURE")

SCHEMA = {
    "type": "function",
    "function": {
        "name": "bash",
        "description": (
            "Run a shell command in the challenge directory. Use it for file, strings, readelf, "
            "objdump -d -M intel, gdb -batch -ex ..., python3 (angr, z3, unicorn, capstone, pwntools, pefile, "
            "pycryptodome), gcc. stdout+stderr are returned with the exit "
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


def scrubbed_env() -> dict[str, str]:
    """os.environ minus SCRUB_ENV: the environment every child process of a tool gets."""
    return {k: v for k, v in os.environ.items() if k not in SCRUB_ENV}


def _read_head(f, limit: int) -> str:
    f.seek(0)
    return f.read(limit).decode("utf-8", errors="replace")


def run_cmd(cmd: str, cwd: Path, timeout: int, stdin_text: str | None = None) -> str:
    """Run `cmd` under bash; returns `[exit N]` (or `[timeout after Ns]`, or `[output limit ...]`) plus the
    output. Output goes to a temp file, not a pipe: a runaway loop printing forever used to fill the container's
    memory through communicate() before the timeout came (bronze chall2, 2026-09-28: OOM kill, exit 137, the run
    and its result lost). Past MAX_OUTPUT_BYTES the process group is killed; at most READ_BYTES are returned
    (truncate() then keeps the head and saves the rest)."""
    env = scrubbed_env()
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as inp:
        inp.write((stdin_text or "").encode())
        inp.seek(0)
        p = subprocess.Popen(
            cmd, shell=True, executable="/bin/bash", cwd=str(cwd),
            stdin=inp, stdout=out, stderr=subprocess.STDOUT,
            start_new_session=True, env=env,
        )
        deadline = time.monotonic() + timeout
        head = None
        while True:
            try:
                p.wait(timeout=POLL_SECONDS)
                break
            except subprocess.TimeoutExpired:
                pass
            size = os.fstat(out.fileno()).st_size
            if size > MAX_OUTPUT_BYTES:
                head = (f"[output limit: killed after {size // 2**20} MB of output; a loop that never advances "
                        f"(e.g. `off += size` with size 0) prints forever. Fix the loop or pipe through head]\n")
            elif time.monotonic() > deadline:
                head = f"[timeout after {timeout}s]\n"
            else:
                continue
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait()
            break
        if head is None:
            head = f"[exit {p.returncode}]\n"
        return head + _read_head(out, READ_BYTES)


def run(ctx, cmd: str, timeout: int = 120) -> str:
    timeout = ctx.clamp_timeout(max(1, min(int(timeout), MAX_TIMEOUT)))
    return run_cmd(cmd, cwd=ctx.problem_dir, timeout=timeout)

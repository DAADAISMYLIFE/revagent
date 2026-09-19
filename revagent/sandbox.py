"""Run the agent inside the revagent-sandbox Docker image (spec: sandbox-design §3.2)."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .llm import Secure

IMAGE = "revagent-sandbox"

MSG_NO_CLI = ("docker not found. On WSL: Docker Desktop → Settings → Resources → WSL integration → "
              "enable this distro, then reopen the shell.")
MSG_NO_DAEMON = "Docker daemon not reachable. Is Docker Desktop running?"
MSG_NO_IMAGE = f"image {IMAGE} not found. Build it first: bash scripts/sandbox-build.sh"


def container_desc_arg(problem_dir: Path, desc: str | None) -> str | None:
    """Map a host --desc path into the container mount; None passes through."""
    if desc is None:
        return None
    root = problem_dir.resolve()
    p = Path(desc).resolve()
    if not p.is_relative_to(root):
        raise ValueError("with --sandbox, --desc must be inside the problem dir")
    return f"/work/{root.name}/{p.relative_to(root).as_posix()}"


def build_sandbox_cmd(problem_dir: Path, passthrough: list[str], secure: Secure,
                      interactive: bool, dev_repo: Path | None,
                      extra_ca: Path | None = None) -> list[str]:
    """Assemble the docker run command. Pure: nothing is executed."""
    root = problem_dir.resolve()
    cmd = ["docker", "run", "--rm", "--init", "-it" if interactive else "-i",
           "-v", f"{root}:/work/{root.name}"]
    # names only, no values: docker run argv is visible to any local user via `ps`/the process table.
    # Values travel separately through run_sandbox's env_extra (the docker CLI's own environment).
    for k in ("QWEN", "URL", "MODEL"):
        cmd += ["-e", k]
    if dev_repo is not None:
        cmd += ["-v", f"{dev_repo.resolve()}:/app"]
    if extra_ca is not None:
        cmd += ["-v", f"{extra_ca.resolve()}:/usr/local/share/ca-certificates/extra-ca.crt:ro"]
    cmd += [IMAGE, "solve", f"/work/{root.name}", *passthrough]
    return cmd


def check_docker(run=subprocess.run, which=shutil.which) -> str | None:
    """Return a user-facing message if docker cannot run the sandbox, else None."""
    if which("docker") is None:
        return MSG_NO_CLI
    try:
        if run(["docker", "info"], capture_output=True, text=True, timeout=20).returncode != 0:
            return MSG_NO_DAEMON
        if run(["docker", "image", "inspect", IMAGE], capture_output=True, text=True,
               timeout=20).returncode != 0:
            return MSG_NO_IMAGE
    except subprocess.TimeoutExpired:
        return MSG_NO_DAEMON
    return None


def run_sandbox(cmd: list[str], env_extra: dict[str, str] | None = None) -> int:
    """Run the container in the foreground; SIGINT reaches the docker CLI, which stops the container.
    env_extra (e.g. QWEN/URL/MODEL) is passed via the docker CLI's own environment, not argv, so the
    secret never appears in the host process table (`ps`, /proc/<pid>/cmdline)."""
    return subprocess.run(cmd, env={**os.environ, **(env_extra or {})}).returncode


def is_interactive_tty() -> bool:
    return sys.stdin.isatty()

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

from revagent.llm import Secure
from revagent.sandbox import (IMAGE, MSG_NO_CLI, MSG_NO_DAEMON, MSG_NO_IMAGE, build_sandbox_cmd,
                              check_docker, container_desc_arg, run_sandbox)

SEC = Secure(key="k1", url="https://h", model="m/x")


def test_build_cmd_basic(tmp_path):
    d = tmp_path / "revlogin"
    d.mkdir()
    cmd = build_sandbox_cmd(d, ["--no-ask", "--max-steps", "5"], SEC, interactive=False, dev_repo=None)
    assert cmd[:4] == ["docker", "run", "--rm", "--init"]
    assert "-i" in cmd and "-it" not in cmd
    assert cmd[cmd.index("-v") + 1] == f"{d.resolve()}:/work/revlogin"
    env = [cmd[i + 1] for i, x in enumerate(cmd) if x == "-e"]
    assert env == ["QWEN", "URL", "MODEL"]
    assert "k1" not in cmd and "https://h" not in cmd and "m/x" not in cmd
    assert cmd[-6:] == [IMAGE, "solve", "/work/revlogin", "--no-ask", "--max-steps", "5"]
    # gdb inside the container must be able to disable ASLR (personality(ADDR_NO_RANDOMIZE)) and
    # ptrace: without these, runs whose data depends on the load address are not reproducible.
    assert cmd[cmd.index("--cap-add") + 1] == "SYS_PTRACE"
    assert cmd[cmd.index("--security-opt") + 1] == "seccomp=unconfined"
    assert cmd.index("--security-opt") < cmd.index(IMAGE)


def test_build_cmd_interactive_and_dev(tmp_path):
    d = tmp_path / "p"
    d.mkdir()
    repo = tmp_path / "repo"
    repo.mkdir()
    cmd = build_sandbox_cmd(d, [], SEC, interactive=True, dev_repo=repo)
    assert "-it" in cmd and "-i" not in cmd
    assert f"{repo.resolve()}:/app" in cmd
    assert cmd.index(f"{repo.resolve()}:/app") < cmd.index(IMAGE)


def test_build_cmd_extra_ca(tmp_path):
    d = tmp_path / "p"
    d.mkdir()
    crt = tmp_path / "corp.crt"
    crt.write_text("cert")
    cmd = build_sandbox_cmd(d, [], SEC, interactive=False, dev_repo=None, extra_ca=crt)
    mount = f"{crt.resolve()}:/usr/local/share/ca-certificates/extra-ca.crt:ro"
    assert mount in cmd
    idx = cmd.index(mount)
    assert cmd[idx - 1] == "-v"
    assert idx < cmd.index(IMAGE)

    cmd_no_ca = build_sandbox_cmd(d, [], SEC, interactive=False, dev_repo=None)
    assert not any("ca-certificates" in x for x in cmd_no_ca)


def test_container_desc_arg(tmp_path):
    d = tmp_path / "p"
    (d / "sub").mkdir(parents=True)
    (d / "sub" / "d.txt").write_text("x")
    assert container_desc_arg(d, None) is None
    assert container_desc_arg(d, str(d / "sub" / "d.txt")) == "/work/p/sub/d.txt"
    with pytest.raises(ValueError):
        container_desc_arg(d, str(tmp_path / "outside.txt"))


def _ok(*a, **k):
    return subprocess.CompletedProcess(a, 0, "", "")


def _fail(*a, **k):
    return subprocess.CompletedProcess(a, 1, "", "err")


@pytest.mark.parametrize("which, failing, expected", [
    (None, None, MSG_NO_CLI),
    ("/usr/bin/docker", ["docker", "info"], MSG_NO_DAEMON),
    ("/usr/bin/docker", ["docker", "image", "inspect"], MSG_NO_IMAGE),
    ("/usr/bin/docker", None, None),
    ("/usr/bin/docker", "timeout", MSG_NO_DAEMON),
], ids=["no_cli", "no_daemon", "no_image", "ok", "timeout_no_daemon"])
def test_check_docker(which, failing, expected):
    def run(cmd, **k):
        if failing == "timeout":
            raise subprocess.TimeoutExpired(cmd, 20)
        return _fail(cmd) if failing and cmd[:len(failing)] == failing else _ok(cmd)
    assert check_docker(run=run, which=lambda n: which) == expected


def test_entrypoint_syntax():
    entrypoint = REPO_ROOT / "docker" / "entrypoint.sh"
    r = subprocess.run(["bash", "-n", str(entrypoint)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_run_sandbox_passes_env(monkeypatch):
    import os

    captured = {}

    def fake_run(cmd, **k):
        captured.update(k)
        return subprocess.CompletedProcess(cmd, 7)

    monkeypatch.setattr("revagent.sandbox.subprocess.run", fake_run)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    # the container's exit code is returned as-is
    assert run_sandbox(["docker", "run"], env_extra={"QWEN": "sekrit", "URL": "https://h", "MODEL": "m"}) == 7
    env = captured["env"]
    assert env["QWEN"] == "sekrit"
    assert env["URL"] == "https://h"
    assert env["MODEL"] == "m"
    assert env["PATH"] == os.environ["PATH"]

import subprocess
from pathlib import Path

import pytest

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
    assert env == ["QWEN=k1", "URL=https://h", "MODEL=m/x"]
    assert cmd[-6:] == [IMAGE, "solve", "/work/revlogin", "--no-ask", "--max-steps", "5"]


def test_build_cmd_interactive_and_dev(tmp_path):
    d = tmp_path / "p"
    d.mkdir()
    repo = tmp_path / "repo"
    repo.mkdir()
    cmd = build_sandbox_cmd(d, [], SEC, interactive=True, dev_repo=repo)
    assert "-it" in cmd and "-i" not in cmd
    assert f"{repo.resolve()}:/app" in cmd
    assert cmd.index(f"{repo.resolve()}:/app") < cmd.index(IMAGE)


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


def test_check_docker_no_cli():
    assert check_docker(run=_ok, which=lambda n: None) == MSG_NO_CLI


def test_check_docker_no_daemon():
    def run(cmd, **k):
        return _fail(cmd) if cmd[:2] == ["docker", "info"] else _ok(cmd)
    assert check_docker(run=run, which=lambda n: "/usr/bin/docker") == MSG_NO_DAEMON


def test_check_docker_no_image():
    def run(cmd, **k):
        return _fail(cmd) if cmd[:3] == ["docker", "image", "inspect"] else _ok(cmd)
    assert check_docker(run=run, which=lambda n: "/usr/bin/docker") == MSG_NO_IMAGE


def test_check_docker_ok():
    assert check_docker(run=_ok, which=lambda n: "/usr/bin/docker") is None


def test_run_sandbox_returns_exit_code(monkeypatch):
    monkeypatch.setattr("revagent.sandbox.subprocess.run", lambda cmd, **k: subprocess.CompletedProcess(cmd, 7))
    assert run_sandbox(["docker", "run"]) == 7

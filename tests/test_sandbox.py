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
    # secrets by name only; PYTHONUNBUFFERED so the container's stdout streams line by line into the
    # console log; REVAGENT_IN_SANDBOX so the inner run does not open a console log of its own
    assert env == ["QWEN", "URL", "MODEL", "PYTHONUNBUFFERED=1", "REVAGENT_IN_SANDBOX=1"]
    assert "k1" not in cmd and "https://h" not in cmd and "m/x" not in cmd
    # the inner invocation is the same __main__, whose default is the sandbox: it must get --host
    assert cmd[-7:] == [IMAGE, "solve", "/work/revlogin", "--host", "--no-ask", "--max-steps", "5"]
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


class _FakePopen:
    """Stands in for the docker CLI in run_sandbox's streaming mode."""
    instances = []

    def __init__(self, cmd, **kw):
        import io
        self.cmd, self.kw = cmd, kw
        self.stdout = io.BytesIO(b"one\n[llm] retry 1/3\nbad \xff byte\n")
        self.waited = False
        _FakePopen.instances.append(self)

    def wait(self, timeout=None):
        self.waited = True
        return 5

    def kill(self):
        raise AssertionError("must not kill a container that exited on its own")


def test_run_sandbox_streams_lines_to_stdout(monkeypatch, capsys):
    _FakePopen.instances = []
    monkeypatch.setattr("revagent.sandbox.subprocess.Popen", _FakePopen)
    monkeypatch.setattr("revagent.sandbox.subprocess.run",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("stream mode must not use run()")))
    rc = run_sandbox(["docker", "run"], env_extra={"QWEN": "sekrit"}, stream=True)
    assert rc == 5
    (p,) = _FakePopen.instances
    assert p.kw["stdout"] is subprocess.PIPE and p.kw["stderr"] is subprocess.STDOUT
    assert p.kw["env"]["QWEN"] == "sekrit"
    assert not p.kw.get("start_new_session")     # same process group: Ctrl-C reaches the docker CLI
    assert p.waited and p.stdout.closed
    assert capsys.readouterr().out == "one\n[llm] retry 1/3\nbad \ufffd byte\n"


def test_run_sandbox_default_is_the_foreground_run(monkeypatch):
    monkeypatch.setattr("revagent.sandbox.subprocess.Popen",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("interactive mode must not pipe")))
    monkeypatch.setattr("revagent.sandbox.subprocess.run", lambda cmd, **k: subprocess.CompletedProcess(cmd, 3))
    assert run_sandbox(["docker", "run", "-it"], env_extra=None) == 3

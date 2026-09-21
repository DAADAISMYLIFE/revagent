import hashlib
import json
import signal
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from revagent import ghidra
from revagent.ghidra import FunctionDB, GhidraError, find_ghidra

FIX = Path(__file__).parent / "fixtures" / "functions.json"


def _fake_popen(content, calls, returncode=0):
    """Stand-in for subprocess.Popen: writes `content` to the DumpFunctions.java output
    path and returns it (plus empty combined stdout/stderr) from communicate()."""

    class FakeProc:
        def __init__(self, cmd, **kw):
            calls.append(cmd)
            self.cmd = cmd
            self.pid = 9999
            self.returncode = returncode

        def communicate(self, timeout=None):
            idx = self.cmd.index("DumpFunctions.java")
            tmp_path = Path(self.cmd[idx + 1])
            tmp_path.write_text(content, encoding="utf-8")
            return "", None

    return FakeProc


class _TimeoutThenPartialPopen:
    """First communicate() call raises TimeoutExpired; the follow-up call (made after
    the process is killed) returns some partial output. Does not write the tmp file,
    simulating a JVM that was killed mid-analysis."""

    def __init__(self, cmd, **kw):
        self.cmd = cmd
        self.pid = 4321
        self.returncode = None
        self._calls = 0

    def communicate(self, timeout=None):
        self._calls += 1
        if self._calls == 1:
            raise subprocess.TimeoutExpired(cmd=self.cmd, timeout=timeout)
        return "partial output before kill", None


def _make_binary(tmp_path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"fake-binary-bytes")
    return binary


def _expected_out(binary, cache_dir):
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()[:16]
    return cache_dir / f"{binary.name}.{digest}.functions.json"


def test_list_sorted_by_size_with_counts():
    db = FunctionDB.load(FIX)
    text = db.list_text()
    lines = text.splitlines()
    assert lines[0].startswith("4 functions")
    assert lines[1].startswith("main @0x00401136 120 strs=3 calls=3")
    assert lines[2].startswith("check @0x004011a0 60")


def test_list_limit():
    db = FunctionDB.load(FIX)
    assert len(db.list_text(limit=2).splitlines()) == 3


def test_list_text_name_filter():
    db = FunctionDB.load(FIX)
    text = db.list_text(name_filter="check")
    lines = text.splitlines()
    assert "filter='check'" in lines[0]
    assert "1 functions" in lines[0]
    assert "check" in text
    assert "main" not in text and "printf" not in text and "_start" not in text
    # case-insensitive, and a miss reports zero functions
    assert "check" in db.list_text(name_filter="CHECK")
    empty = db.list_text(name_filter="zzz_no_such_function")
    assert "0 functions" in empty.splitlines()[0]


def test_function_db_skips_unparsable_addresses():
    funcs = [
        {"name": "good", "entry": "0x00401000", "size": 10, "is_thunk": False,
         "callers": [], "callees": [], "string_refs": [], "decompiled_c": ""},
        {"name": "bad", "entry": "ram:00401000", "size": 5, "is_thunk": False,
         "callers": [], "callees": [], "string_refs": [], "decompiled_c": ""},
    ]
    db = FunctionDB(funcs)
    assert len(db.funcs) == 2
    assert db.by_name["bad"]["entry"] == "ram:00401000"
    assert db.find("0x401000")["name"] == "good"
    assert db.find("good") is not None
    assert len(db.by_addr) == 1


def test_find_by_name_and_address():
    db = FunctionDB.load(FIX)
    assert db.find("check")["entry"] == "0x004011a0"
    assert db.find("0x4011a0")["name"] == "check"
    assert db.find("4011A0")["name"] == "check"
    assert db.find("nope") is None
    assert db.find("0xdead") is None


def test_get_and_xrefs_text():
    db = FunctionDB.load(FIX)
    assert "s[i]^0x5a" in db.get_text("check")
    assert db.get_text("_start") == "[decompilation failed or empty for _start]"
    assert db.get_text("zzz").startswith("[not found]")
    x = db.xrefs_text("main")
    assert "callers: _start" in x and "callees: check, fgets, printf" in x and "Correct!" in x


def test_find_ghidra_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    with pytest.raises(GhidraError):
        find_ghidra()


def test_analyze_rejects_truncated_output(tmp_path, monkeypatch):
    monkeypatch.setattr(ghidra, "find_ghidra", lambda: (tmp_path / "fake_headless", tmp_path / "jdk"))
    calls = []
    monkeypatch.setattr(ghidra.subprocess, "Popen", _fake_popen('[{"name": "a"', calls))
    binary = _make_binary(tmp_path)
    cache_dir = tmp_path / "cache"
    with pytest.raises(GhidraError, match="not valid JSON"):
        ghidra.analyze(binary, cache_dir)
    assert not list(cache_dir.glob("*.functions.json"))
    assert not list(cache_dir.glob("*.tmp"))


def test_analyze_atomic_and_cached(tmp_path, monkeypatch):
    monkeypatch.setattr(ghidra, "find_ghidra", lambda: (tmp_path / "fake_headless", tmp_path / "jdk"))
    calls = []
    monkeypatch.setattr(ghidra.subprocess, "Popen", _fake_popen("[]", calls))
    binary = _make_binary(tmp_path)
    cache_dir = tmp_path / "cache"

    out = ghidra.analyze(binary, cache_dir)
    assert out.name.endswith(".functions.json")
    assert not list(cache_dir.glob("*.tmp"))
    assert len(calls) == 1

    out2 = ghidra.analyze(binary, cache_dir)
    assert out2 == out
    assert len(calls) == 1


def test_analyze_project_dir_has_no_dot_components(tmp_path, monkeypatch):
    # Regression: cache_dir is normally <problem_dir>/.revagent/ghidra. Ghidra's
    # ProjectLocator raises IllegalArgumentException on any path component
    # starting with '.', so the ephemeral project directory passed to
    # analyzeHeadless must live outside cache_dir rather than nested under it.
    monkeypatch.setattr(ghidra, "find_ghidra", lambda: (tmp_path / "fake_headless", tmp_path / "jdk"))
    calls = []
    monkeypatch.setattr(ghidra.subprocess, "Popen", _fake_popen("[]", calls))
    binary = _make_binary(tmp_path)
    cache_dir = tmp_path / ".revagent" / "ghidra"

    out = ghidra.analyze(binary, cache_dir)

    assert out.exists()
    project_location = Path(calls[0][1])
    assert not any(part.startswith(".") for part in project_location.parts), (
        f"project location {project_location} has a dot-prefixed component; "
        "Ghidra's ProjectLocator will reject it"
    )


def test_analyze_invalidates_corrupt_cache_hit(tmp_path, monkeypatch):
    monkeypatch.setattr(ghidra, "find_ghidra", lambda: (tmp_path / "fake_headless", tmp_path / "jdk"))
    calls = []
    monkeypatch.setattr(ghidra.subprocess, "Popen", _fake_popen("[]", calls))
    binary = _make_binary(tmp_path)
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir(parents=True)
    out_path = _expected_out(binary, cache_dir)
    out_path.write_text("{bad", encoding="utf-8")

    out = ghidra.analyze(binary, cache_dir)
    assert len(calls) == 1
    assert out == out_path
    json.loads(out.read_text(encoding="utf-8"))


def test_analyze_timeout_kills_process_group_and_leaves_no_tmp(tmp_path, monkeypatch):
    monkeypatch.setattr(ghidra, "find_ghidra", lambda: (tmp_path / "fake_headless", tmp_path / "jdk"))
    monkeypatch.setattr(ghidra.subprocess, "Popen", _TimeoutThenPartialPopen)
    killpg_calls = []
    monkeypatch.setattr(ghidra.os, "killpg", lambda pid, sig: killpg_calls.append((pid, sig)))
    binary = _make_binary(tmp_path)
    cache_dir = tmp_path / "cache"

    with pytest.raises(GhidraError, match="timed out"):
        ghidra.analyze(binary, cache_dir, timeout=1)

    assert killpg_calls == [(4321, signal.SIGKILL)]
    assert not list(cache_dir.glob("*.tmp"))
    assert not list(cache_dir.glob("*.functions.json"))


def test_analyze_timeout_guards_process_lookup_error(tmp_path, monkeypatch):
    # The JVM may already have exited between TimeoutExpired and our killpg call
    # (e.g. it crashed right as the timeout fired); os.killpg then raises
    # ProcessLookupError, which must not propagate out of analyze().
    monkeypatch.setattr(ghidra, "find_ghidra", lambda: (tmp_path / "fake_headless", tmp_path / "jdk"))
    monkeypatch.setattr(ghidra.subprocess, "Popen", _TimeoutThenPartialPopen)

    def boom(pid, sig):
        raise ProcessLookupError()

    monkeypatch.setattr(ghidra.os, "killpg", boom)
    binary = _make_binary(tmp_path)
    cache_dir = tmp_path / "cache"

    with pytest.raises(GhidraError, match="timed out"):
        ghidra.analyze(binary, cache_dir, timeout=1)
    assert not list(cache_dir.glob("*.tmp"))

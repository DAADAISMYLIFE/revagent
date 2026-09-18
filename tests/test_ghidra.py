import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from revagent import ghidra
from revagent.ghidra import FunctionDB, GhidraError, find_ghidra

FIX = Path(__file__).parent / "fixtures" / "functions.json"


def _fake_run(content, calls):
    def run(cmd, env=None, capture_output=None, text=None, timeout=None):
        calls.append(cmd)
        idx = cmd.index("DumpFunctions.java")
        tmp_path = Path(cmd[idx + 1])
        tmp_path.write_text(content, encoding="utf-8")
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    return run


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
    monkeypatch.setattr(ghidra.subprocess, "run", _fake_run('[{"name": "a"', calls))
    binary = _make_binary(tmp_path)
    cache_dir = tmp_path / "cache"
    with pytest.raises(GhidraError, match="not valid JSON"):
        ghidra.analyze(binary, cache_dir)
    assert not list(cache_dir.glob("*.functions.json"))
    assert not list(cache_dir.glob("*.tmp"))


def test_analyze_atomic_and_cached(tmp_path, monkeypatch):
    monkeypatch.setattr(ghidra, "find_ghidra", lambda: (tmp_path / "fake_headless", tmp_path / "jdk"))
    calls = []
    monkeypatch.setattr(ghidra.subprocess, "run", _fake_run("[]", calls))
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
    monkeypatch.setattr(ghidra.subprocess, "run", _fake_run("[]", calls))
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
    monkeypatch.setattr(ghidra.subprocess, "run", _fake_run("[]", calls))
    binary = _make_binary(tmp_path)
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir(parents=True)
    out_path = _expected_out(binary, cache_dir)
    out_path.write_text("{bad", encoding="utf-8")

    out = ghidra.analyze(binary, cache_dir)
    assert len(calls) == 1
    assert out == out_path
    json.loads(out.read_text(encoding="utf-8"))

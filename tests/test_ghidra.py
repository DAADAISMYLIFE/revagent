from pathlib import Path

import pytest

from revagent.ghidra import FunctionDB, GhidraError, find_ghidra

FIX = Path(__file__).parent / "fixtures" / "functions.json"


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

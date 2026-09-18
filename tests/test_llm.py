import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from revagent.llm import load_secure, parse_assistant, Secure


def test_load_secure_parses_and_strips_slash(tmp_path, monkeypatch):
    f = tmp_path / ".secure"
    f.write_text('QWEN=sk_x\nURL="https://h.example/"\n# c\nMODEL=m/n\n')
    s = load_secure(f)
    assert s == Secure(key="sk_x", url="https://h.example", model="m/n")


def test_load_secure_env_var(tmp_path, monkeypatch):
    f = tmp_path / "s"
    f.write_text("QWEN=a\nURL=https://u\nMODEL=m\n")
    monkeypatch.setenv("REVAGENT_SECURE", str(f))
    monkeypatch.chdir(tmp_path)
    assert load_secure().key == "a"


def test_load_secure_missing(tmp_path, monkeypatch):
    monkeypatch.delenv("REVAGENT_SECURE", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("revagent.llm.REPO_SECURE", tmp_path / "absent")
    with pytest.raises(FileNotFoundError):
        load_secure(tmp_path / "nope")


def _msg(content=None, reasoning=None, calls=()):
    tcs = [
        SimpleNamespace(id=i, function=SimpleNamespace(name=n, arguments=a))
        for i, n, a in calls
    ] or None
    return SimpleNamespace(content=content, reasoning_content=reasoning, tool_calls=tcs, model_extra={})


def test_parse_assistant_plain():
    content, reasoning, calls, msg = parse_assistant(_msg("hi", "think"))
    assert (content, reasoning, calls) == ("hi", "think", [])
    assert msg == {"role": "assistant", "content": "hi"}


def test_parse_assistant_tool_calls_strip_reasoning():
    content, reasoning, calls, msg = parse_assistant(
        _msg(None, "r", [("c1", "bash", '{"cmd": "ls"}'), ("c2", "notes", "{bad")])
    )
    assert content == ""
    assert calls[0].name == "bash" and calls[0].args == {"cmd": "ls"} and not calls[0].parse_error
    assert calls[1].parse_error and calls[1].args == {} and calls[1].raw_args == "{bad"
    assert "reasoning_content" not in msg
    assert msg["tool_calls"][0] == {
        "id": "c1", "type": "function", "function": {"name": "bash", "arguments": '{"cmd": "ls"}'}
    }

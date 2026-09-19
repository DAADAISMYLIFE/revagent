import os
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from openai import APIStatusError, BadRequestError

from revagent.llm import ContextOverflow, LLM, Secure, load_secure, parse_assistant


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


def test_load_secure_missing_key_raises_value_error(tmp_path):
    f = tmp_path / ".secure"
    f.write_text("QWEN=a\nURL=https://u\n")  # MODEL missing
    with pytest.raises(ValueError) as exc:
        load_secure(f)
    assert str(f) in str(exc.value)
    assert "MODEL" in str(exc.value)


def test_load_secure_missing(tmp_path, monkeypatch):
    monkeypatch.delenv("REVAGENT_SECURE", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("revagent.llm.REPO_SECURE", tmp_path / "absent")
    with pytest.raises(FileNotFoundError):
        load_secure(tmp_path / "nope")


def _msg(content=None, reasoning=None, calls=(), reasoning_attr="reasoning_content"):
    tcs = [
        SimpleNamespace(id=i, function=SimpleNamespace(name=n, arguments=a))
        for i, n, a in calls
    ] or None
    kwargs = {"content": content, "tool_calls": tcs, "model_extra": {}}
    if reasoning is not None:
        if reasoning_attr == "model_extra":
            kwargs["model_extra"] = {"reasoning": reasoning}
        else:
            kwargs[reasoning_attr] = reasoning
    return SimpleNamespace(**kwargs)


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


def test_parse_assistant_reads_reasoning_key():
    # reasoning under a `.reasoning` attribute, `reasoning_content` absent
    content, reasoning, calls, msg = parse_assistant(
        _msg("hi", "via-attr", reasoning_attr="reasoning")
    )
    assert reasoning == "via-attr"
    assert "reasoning" not in msg and "reasoning_content" not in msg

    # reasoning under model_extra["reasoning"], reasoning_content absent
    content, reasoning, calls, msg = parse_assistant(
        _msg("hi", "via-model-extra", reasoning_attr="model_extra")
    )
    assert reasoning == "via-model-extra"
    assert "reasoning" not in msg and "reasoning_content" not in msg


def _resp(content, prompt_tokens, completion_tokens):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=_msg(content))],
        usage=SimpleNamespace(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens),
    )


def _status_error(cls, status, message="boom"):
    resp = httpx.Response(status, request=httpx.Request("POST", "https://h"))
    return cls(message, response=resp, body=None)


def _llm(monkeypatch):
    monkeypatch.setattr("revagent.llm.time.sleep", lambda s: None)
    return LLM(Secure(key="k", url="https://h", model="m"))


def test_retries_on_5xx_then_succeeds(monkeypatch):
    llm = _llm(monkeypatch)
    good = _resp("pong", 10, 5)
    calls = {"n": 0}

    def fake_create(**kw):
        calls["n"] += 1
        if calls["n"] < 3:
            raise _status_error(APIStatusError, 503)
        return good

    monkeypatch.setattr(llm.client.chat.completions, "create", fake_create)
    r = llm.chat([{"role": "user", "content": "hi"}])
    assert r.content == "pong"
    assert calls["n"] == 3


def test_does_not_retry_on_401(monkeypatch):
    llm = _llm(monkeypatch)
    calls = {"n": 0}

    def fake_create(**kw):
        calls["n"] += 1
        raise _status_error(APIStatusError, 401)

    monkeypatch.setattr(llm.client.chat.completions, "create", fake_create)
    with pytest.raises(APIStatusError):
        llm.chat([{"role": "user", "content": "hi"}])
    assert calls["n"] == 1


def test_retries_on_429(monkeypatch):
    llm = _llm(monkeypatch)
    good = _resp("pong", 1, 1)
    calls = {"n": 0}

    def fake_create(**kw):
        calls["n"] += 1
        if calls["n"] < 2:
            raise _status_error(APIStatusError, 429)
        return good

    monkeypatch.setattr(llm.client.chat.completions, "create", fake_create)
    r = llm.chat([{"role": "user", "content": "hi"}])
    assert r.content == "pong"
    assert calls["n"] == 2


def test_context_overflow(monkeypatch):
    llm = _llm(monkeypatch)

    def fake_create_overflow(**kw):
        raise _status_error(
            BadRequestError, 400,
            "This model's maximum context length is 65536 tokens. However, you requested 70000 tokens",
        )

    monkeypatch.setattr(llm.client.chat.completions, "create", fake_create_overflow)
    with pytest.raises(ContextOverflow):
        llm.chat([{"role": "user", "content": "hi"}])

    def fake_create_other(**kw):
        raise _status_error(BadRequestError, 400, "invalid parameter")

    monkeypatch.setattr(llm.client.chat.completions, "create", fake_create_other)
    with pytest.raises(BadRequestError):
        llm.chat([{"role": "user", "content": "hi"}])


def test_usage_accounting(monkeypatch):
    llm = _llm(monkeypatch)
    responses = [_resp("pong", 10, 5), _resp("ok", 3, 2)]
    captured_kwargs = []

    def fake_create(**kw):
        captured_kwargs.append(kw)
        return responses.pop(0)

    monkeypatch.setattr(llm.client.chat.completions, "create", fake_create)
    r = llm.chat([{"role": "user", "content": "hi"}], tools=[{"type": "function", "function": {"name": "x"}}])
    llm.complete("say ok")

    assert llm.last_prompt_tokens == r.prompt_tokens == 10
    assert llm.total_prompt_tokens == 13
    assert llm.total_completion_tokens == 7

    kw0 = captured_kwargs[0]
    assert kw0["extra_body"] == {"reasoning_effort": "medium"}
    assert kw0["temperature"] == 0.6
    assert kw0["max_tokens"] == 8192
    assert kw0["tool_choice"] == "auto"


def test_chat_exposes_finish_reason(monkeypatch):
    llm = _llm(monkeypatch)
    r1 = _resp("cut", 10, 5)
    r1.choices[0].finish_reason = "length"
    r2 = _resp("done", 10, 5)
    responses = [r1, r2]
    monkeypatch.setattr(llm.client.chat.completions, "create", lambda **kw: responses.pop(0))
    assert llm.chat([{"role": "user", "content": "hi"}]).finish_reason == "length"
    assert llm.chat([{"role": "user", "content": "hi"}]).finish_reason == "stop"


def test_load_secure_prefers_complete_env(tmp_path, monkeypatch):
    monkeypatch.setenv("QWEN", "envkey")
    monkeypatch.setenv("URL", "https://env.example/")
    monkeypatch.setenv("MODEL", "env/model")
    monkeypatch.setattr("revagent.llm.REPO_SECURE", tmp_path / "absent")
    monkeypatch.chdir(tmp_path)  # no .secure here either
    s = load_secure()
    assert s == Secure(key="envkey", url="https://env.example", model="env/model")


def test_load_secure_partial_env_falls_back_to_file(tmp_path, monkeypatch):
    monkeypatch.setenv("QWEN", "envkey")
    monkeypatch.delenv("URL", raising=False)
    monkeypatch.delenv("MODEL", raising=False)
    f = tmp_path / ".secure"
    f.write_text("QWEN=filekey\nURL=https://file\nMODEL=m\n")
    monkeypatch.chdir(tmp_path)
    assert load_secure().key == "filekey"


def test_load_secure_explicit_file_wins_over_complete_env(tmp_path, monkeypatch):
    monkeypatch.setenv("QWEN", "envkey")
    monkeypatch.setenv("URL", "https://env.example")
    monkeypatch.setenv("MODEL", "env/model")
    f = tmp_path / ".secure"
    f.write_text("QWEN=filekey\nURL=https://file\nMODEL=file/model\n")
    s = load_secure(f)
    assert s == Secure(key="filekey", url="https://file", model="file/model")

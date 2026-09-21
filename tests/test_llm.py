import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from openai import APIConnectionError, APIError, APIStatusError, BadRequestError

from revagent.llm import ContextOverflow, LLM, Secure, collect_stream, load_secure, parse_assistant
# the same HTTP client module the SDK (and therefore llm.py's retry loop) uses: httpx2 for openai>=3
from revagent.llm import httpx


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


def test_load_secure_survives_deleted_cwd(tmp_path, monkeypatch):
    f = tmp_path / ".secure"
    f.write_text("QWEN=a\nURL=https://u\nMODEL=m\n")
    monkeypatch.setattr("revagent.llm.Path.cwd", staticmethod(lambda: (_ for _ in ()).throw(FileNotFoundError())))
    assert load_secure(f).key == "a"


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


def _llm(monkeypatch, stream=False):
    monkeypatch.setattr("revagent.llm.time.sleep", lambda s: None)
    return LLM(Secure(key="k", url="https://h", model="m"), stream=stream)


# ---- streaming ---------------------------------------------------------------------------------

def _chunk(content=None, reasoning=None, tool_calls=None, finish=None, usage=None, no_choices=False):
    delta = SimpleNamespace(content=content, reasoning_content=reasoning, tool_calls=tool_calls, model_extra={})
    choices = [] if no_choices else [SimpleNamespace(delta=delta, finish_reason=finish)]
    return SimpleNamespace(choices=choices, usage=usage)


def _tc(index, id=None, name=None, arguments=None):
    return SimpleNamespace(index=index, id=id, function=SimpleNamespace(name=name, arguments=arguments))


def test_collect_stream_assembles_reasoning_content_tool_calls_and_usage():
    chunks = [
        _chunk(reasoning="let me "), _chunk(reasoning="think"),
        _chunk(content="I will "), _chunk(content="run it."),
        _chunk(tool_calls=[_tc(0, id="c1", name="bash", arguments='{"cmd"')]),
        _chunk(tool_calls=[_tc(0, arguments=': "ls"}'), _tc(1, id="c2", name="notes", arguments="")]),
        _chunk(tool_calls=[_tc(1, arguments='{"action": "read"}')], finish="tool_calls"),
        _chunk(no_choices=True, usage=SimpleNamespace(prompt_tokens=40, completion_tokens=9)),
    ]
    r = collect_stream(iter(chunks))
    content, reasoning, calls, msg = parse_assistant(r.choices[0].message)
    assert content == "I will run it." and reasoning == "let me think"
    assert [(c.id, c.name, c.args) for c in calls] == [("c1", "bash", {"cmd": "ls"}), ("c2", "notes", {"action": "read"})]
    assert r.choices[0].finish_reason == "tool_calls"
    assert (r.usage.prompt_tokens, r.usage.completion_tokens) == (40, 9)


def test_collect_stream_length_cutoff_and_empty():
    r = collect_stream(iter([_chunk(reasoning="thinking…", finish="length")]))
    assert r.choices[0].finish_reason == "length"
    assert r.choices[0].message.content is None and r.choices[0].message.tool_calls is None
    r = collect_stream(iter([]))
    assert r.choices[0].finish_reason == "stop" and r.usage is None


def test_default_client_streams_and_asks_for_usage(monkeypatch):
    llm = LLM(Secure(key="k", url="https://h", model="m"))
    assert llm.stream is True
    captured = {}

    def fake_create(**kw):
        captured.update(kw)
        return iter([_chunk(content="ok", finish="stop"),
                     _chunk(no_choices=True, usage=SimpleNamespace(prompt_tokens=3, completion_tokens=1))])

    monkeypatch.setattr(llm.client.chat.completions, "create", fake_create)
    r = llm.chat([{"role": "user", "content": "hi"}])
    assert captured["stream"] is True and captured["stream_options"] == {"include_usage": True}
    assert r.content == "ok" and r.prompt_tokens == 3 and llm.total_completion_tokens == 1
    assert llm.complete("x") == "ok"


@pytest.mark.parametrize("drop", [
    # what openai's Stream iterator really raises when the connection dies mid-reply: the httpx
    # transport error unwrapped (not APIConnectionError) ...
    httpx.RemoteProtocolError("peer closed connection without sending complete message body"),
    httpx.ReadTimeout("timed out"),
    # ... or a bare APIError for an in-band {"error": ...} SSE event
    APIError("stream error", request=httpx.Request("POST", "https://h"), body=None),
    APIConnectionError(request=httpx.Request("POST", "https://h")),
], ids=["RemoteProtocolError", "ReadTimeout", "APIError", "APIConnectionError"])
def test_stream_dropped_mid_reply_is_retried(monkeypatch, drop):
    llm = _llm(monkeypatch, stream=True)
    calls = {"n": 0}

    def broken_then_good(**kw):
        calls["n"] += 1
        if calls["n"] == 1:
            def gen():
                yield _chunk(reasoning="partial")
                raise drop
            return gen()
        return iter([_chunk(content="done", finish="stop")])

    monkeypatch.setattr(llm.client.chat.completions, "create", broken_then_good)
    r = llm.chat([{"role": "user", "content": "hi"}])
    assert r.content == "done" and calls["n"] == 2 and llm.total_retries == 1


@pytest.mark.parametrize("status, failures, stderr_line", [
    (503, 2, None),
    (429, 1, None),
    (524, 1, "[llm] retry 1/3"),   # a 524 is the runpod proxy cutting a >100 s generation; it must be visible
])
def test_transient_status_is_retried_then_succeeds(monkeypatch, capsys, status, failures, stderr_line):
    llm = _llm(monkeypatch)
    good = _resp("pong", 10, 5)
    calls = {"n": 0}

    def fake_create(**kw):
        calls["n"] += 1
        if calls["n"] <= failures:
            raise _status_error(APIStatusError, status)
        return good

    monkeypatch.setattr(llm.client.chat.completions, "create", fake_create)
    r = llm.chat([{"role": "user", "content": "hi"}])
    assert r.content == "pong"
    assert calls["n"] == failures + 1
    assert llm.total_retries == failures
    if stderr_line:
        err = capsys.readouterr().err
        assert stderr_line in err and str(status) in err


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
    assert kw0["max_tokens"] == 16384
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


def test_chat_reasoning_effort_override(monkeypatch):
    llm = _llm(monkeypatch)
    captured = []

    def fake_create(**kw):
        captured.append(kw["extra_body"]["reasoning_effort"])
        return _resp("ok", 1, 1)

    monkeypatch.setattr(llm.client.chat.completions, "create", fake_create)
    llm.chat([{"role": "user", "content": "hi"}])
    llm.chat([{"role": "user", "content": "hi"}], reasoning_effort="low")
    llm.complete("x")
    assert captured == ["medium", "low", "medium"]


def test_client_has_no_hidden_sdk_retries(monkeypatch):
    # The OpenAI SDK retries 5xx on its own (max_retries=2 by default). Those retries are invisible to
    # the run log and would multiply with ours, so the client is created with max_retries=0.
    llm = _llm(monkeypatch)
    assert llm.client.max_retries == 0


def test_llm_complete_raises_budget_for_one_call_only(monkeypatch):
    llm = LLM.__new__(LLM)
    llm.max_tokens = 8192
    llm.total_prompt_tokens = llm.total_completion_tokens = llm.last_prompt_tokens = 0
    seen = {}

    def fake_create(**kw):
        seen["max"] = llm.max_tokens
        seen["effort"] = kw.get("reasoning_effort")
        msg = SimpleNamespace(content="hi", reasoning=None)
        return SimpleNamespace(choices=[SimpleNamespace(message=msg, finish_reason="length")], usage=None)

    monkeypatch.setattr(llm, "_create", fake_create)
    monkeypatch.setattr(llm, "_account", lambda resp: (0, 0))
    assert llm.complete("p", max_tokens=16384, reasoning_effort="low") == "hi"
    assert seen == {"max": 16384, "effort": "low"} and llm.max_tokens == 8192
    assert llm.last_finish_reason == "length"

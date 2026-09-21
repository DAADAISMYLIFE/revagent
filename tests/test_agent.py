import json
import subprocess
from pathlib import Path

import pytest

from revagent import __main__ as main_mod
from revagent.agent import Agent, load_system_prompt
from revagent.llm import ChatResponse, ContextOverflow, Secure, ToolCall


class ScriptedLLM:
    """Returns pre-baked responses in order; records the messages it was given.
    A script entry may also be an exception (instance or class), in which case
    chat() raises it instead of returning a response — used to simulate
    ContextOverflow / arbitrary server errors."""

    def __init__(self, script, prompt_tokens=100):
        self.script = list(script)
        self.seen = []
        self.max_tokens = 16384
        self.total_retries = 0
        self.max_tokens_seen = []
        self.efforts_seen = []
        self.last_prompt_tokens = 0
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.prompt_tokens = prompt_tokens
        self.completes = []

    def chat(self, messages, tools=None, reasoning_effort=None):
        self.seen.append([dict(m) for m in messages])
        self.efforts_seen.append(reasoning_effort)
        item = self.script.pop(0)
        if isinstance(item, BaseException) or (isinstance(item, type) and issubclass(item, BaseException)):
            raise item
        self.max_tokens_seen.append(self.max_tokens)
        finish_reason = "stop"
        reasoning = "thinking..."
        if isinstance(item, dict):
            finish_reason = item.get("finish_reason", "stop")
            reasoning = item.get("reasoning", "thinking...")
            item = item["calls"]
        calls = item
        tcs = [ToolCall(f"id{i}", n, a, json.dumps(a)) for i, (n, a) in enumerate(calls)]
        msg = {"role": "assistant", "content": "" if tcs else "just talking"}
        if tcs:
            msg["tool_calls"] = [{"id": t.id, "type": "function",
                                  "function": {"name": t.name, "arguments": t.raw_args}} for t in tcs]
        pt = self.prompt_tokens(len(self.seen)) if callable(self.prompt_tokens) else self.prompt_tokens
        self.last_prompt_tokens = pt
        self.total_prompt_tokens += pt
        self.total_completion_tokens += 10
        if finish_reason == "length":
            msg["content"] = ""
        return ChatResponse(msg["content"], reasoning, tcs, msg, pt, 10, finish_reason)

    def complete(self, prompt, system=None, **kw):
        self.completes.append(prompt)
        return "- summary bullet"


def make_problem(tmp_path):
    d = tmp_path / "prob"
    d.mkdir()
    (d / "chal").write_text("#!/bin/bash\nread x; [ \"$x\" = abc ] && echo Correct || echo Wrong\n")
    return d


# ---- CLI test helpers ---------------------------------------------------------------------------

_SOLVED = {"status": "solved", "flag": "DH{x}", "how_verified": "v", "reason": "",
           "steps": 1, "compactions": 0, "prompt_tokens": 1, "completion_tokens": 1, "minutes": 0.1}


def _result(**over):
    """A result dict as Agent.run returns it, with overrides."""
    return {**_SOLVED, **over}


def _write_result(d, **over):
    """Write <d>/.revagent/result.json the way a run inside the container would."""
    (d / ".revagent").mkdir(exist_ok=True)
    (d / ".revagent" / "result.json").write_text(json.dumps(_result(**over)))


def _fake_agent(run):
    """An Agent stand-in for CLI tests: run(problem_dir) returns the result dict (or raises).
    FakeAgent.calls records (problem_dir, kwargs) per construction."""
    class FakeAgent:
        calls = []

        def __init__(self, d, *a, **k):
            self.d = Path(d)
            FakeAgent.calls.append((self.d, k))

        def run(self):
            return run(self.d)
    return FakeAgent


def _patch_host(monkeypatch, run):
    """Run the CLI on the host (the tests pass --host) without a .secure or a real LLM; Agent becomes
    _fake_agent(run), and docker must never be probed. Returns the FakeAgent class."""
    monkeypatch.delenv("REVAGENT_IN_SANDBOX", raising=False)
    monkeypatch.setattr(main_mod, "load_secure", lambda *a, **k: object())
    monkeypatch.setattr(main_mod, "LLM", lambda secure: object())
    monkeypatch.setattr(main_mod, "check_docker",
                        lambda: (_ for _ in ()).throw(AssertionError("docker must not be probed with --host")))
    fake = _fake_agent(run)
    monkeypatch.setattr(main_mod, "Agent", fake)
    return fake


def _patch_sandbox(monkeypatch, run_sandbox=None, tty=False, docker=None, home=None):
    """Run the CLI in sandbox mode (the default) without docker or a .secure: check_docker returns
    `docker` (None = available), is_interactive_tty returns `tty`, run_sandbox is replaced when given
    (fakes take (cmd, env_extra)), and the Agent must never be constructed on the host. The machine's
    own REVAGENT_SANDBOX_CA / ~/.revagent/sandbox-ca.crt are hidden unless `home` (a fake HOME) is given."""
    monkeypatch.delenv("REVAGENT_SANDBOX_CA", raising=False)
    monkeypatch.delenv("REVAGENT_IN_SANDBOX", raising=False)
    if home is None:
        monkeypatch.setattr(main_mod, "_default_sandbox_ca", lambda: Path("/nonexistent/sandbox-ca.crt"))
    else:
        monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(main_mod, "check_docker", lambda: docker)
    monkeypatch.setattr(main_mod, "load_secure", lambda *a, **k: Secure("k", "https://h", "m"))
    monkeypatch.setattr(main_mod, "is_interactive_tty", lambda: tty)
    monkeypatch.setattr(main_mod, "Agent",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("Agent must not run on host")))
    if run_sandbox is not None:
        monkeypatch.setattr(main_mod, "run_sandbox",
                            lambda cmd, env_extra=None, stream=False: run_sandbox(cmd, env_extra=env_extra))


def _console_log(d):
    return (d / ".revagent" / "console.log").read_text(encoding="utf-8")


def test_solves_and_writes_result(tmp_path):
    d = make_problem(tmp_path)
    llm = ScriptedLLM([
        [("bash", {"cmd": "ls"})],
        [("notes", {"action": "add", "section": "facts", "text": "chal is a shell script"})],
        [("run_binary", {"path": "chal", "stdin": "abc\n"})],
        [("submit_flag", {"flag": "DH{abc}", "how_verified": "printed Correct"})],
    ])
    r = Agent(d, "find it", llm, max_steps=10, max_minutes=5, interactive=False).run()
    assert r["status"] == "solved" and r["flag"] == "DH{abc}" and r["steps"] == 4
    res = json.loads((d / ".revagent" / "result.json").read_text())
    assert res["flag"] == "DH{abc}"
    assert "chal is a shell script" in (d / ".revagent" / "case.md").read_text()
    lines = (d / ".revagent" / "transcript.jsonl").read_text().splitlines()
    first = json.loads(lines[0])
    assert first["role"] == "_meta" and first["event"] == "session_start"
    assert first["max_steps"] == 10 and first["max_minutes"] == 5
    assert "problem_dir" in first and "time" in first
    assert json.loads(lines[1])["role"] == "system"
    assert any(json.loads(l).get("role") == "tool" and "Correct" in json.loads(l)["content"] for l in lines)
    # system prompt and task message were sent
    first = llm.seen[0]
    assert first[0]["role"] == "system" and "submit_flag" in first[0]["content"]
    assert first[1]["role"] == "user" and "find it" in first[1]["content"] and "chal" in first[1]["content"]


def test_step_limit_gives_unsolved(tmp_path):
    d = make_problem(tmp_path)
    llm = ScriptedLLM([[("bash", {"cmd": "true"})]] * 3)
    r = Agent(d, "", llm, max_steps=3, interactive=False).run()
    assert r["status"] == "unsolved" and r["reason"] == "step limit" and r["steps"] == 3


def test_no_tool_calls_nudged_then_abort(tmp_path):
    d = make_problem(tmp_path)
    llm = ScriptedLLM([[], [], []])
    r = Agent(d, "", llm, max_steps=10, interactive=False).run()
    assert r["reason"] == "no tool calls 3x"
    nudges = [m for m in llm.seen[2] if m["role"] == "user" and "Call a tool" in m["content"]]
    assert len(nudges) == 2


def test_repeated_call_nudge(tmp_path):
    d = make_problem(tmp_path)
    same = [("bash", {"cmd": "echo same"})]
    llm = ScriptedLLM([same, same, same, [("submit_flag", {"flag": "DH{x}", "how_verified": "v"})]])
    Agent(d, "", llm, max_steps=10, interactive=False).run()
    last = llm.seen[3]
    assert any(m["role"] == "user" and "repeated the same tool call" in m["content"] for m in last)


def test_bad_tool_and_bad_args_are_reported(tmp_path):
    d = make_problem(tmp_path)
    llm = ScriptedLLM([
        [("nope", {})],
        [("bash", {"zzz": 1})],
        [("submit_flag", {"flag": "DH{x}", "how_verified": "v"})],
    ])
    Agent(d, "", llm, max_steps=10, interactive=False).run()
    tools = [m["content"] for m in llm.seen[2] if m["role"] == "tool"]
    assert tools[0].startswith("[tool error] unknown tool nope")
    assert tools[1].startswith("[tool error] bad arguments for bash")


def test_compaction_triggers_over_threshold(tmp_path):
    d = make_problem(tmp_path)
    script = [[("bash", {"cmd": f"echo {i}"})] for i in range(7)] + \
             [[("submit_flag", {"flag": "DH{x}", "how_verified": "v"})]]
    # 6th response reports a huge prompt → compaction before the 7th call
    llm = ScriptedLLM(script, prompt_tokens=lambda n: 50_000 if n == 6 else 100)
    r = Agent(d, "desc", llm, max_steps=20, interactive=False).run()
    assert r["compactions"] == 1
    # one of the two llm.complete calls is the pre-compaction critic; filter to the summarization call
    summarize_calls = [p for p in llm.completes if "Extract, as terse bullets" in p]
    assert len(summarize_calls) == 1  # middle summarized once
    seventh = llm.seen[6]
    assert seventh[2]["role"] == "user" and "[CONTEXT RESET]" in seventh[2]["content"]
    assert "- summary bullet" in seventh[2]["content"]
    # the reset message is also logged to the transcript
    lines = (d / ".revagent" / "transcript.jsonl").read_text().splitlines()
    assert any(json.loads(l).get("content", "").startswith("[CONTEXT RESET]") for l in lines)


def test_compaction_includes_work_files_created_during_run(tmp_path):
    d = make_problem(tmp_path)

    def write_table(ctx=None, **kw):
        (d / "notes_table.json").write_text("{}")
        return "wrote table"

    script = [[("bash", {"cmd": f"echo {i}"})] for i in range(7)] + \
             [[("submit_flag", {"flag": "DH{x}", "how_verified": "v"})]]
    llm = ScriptedLLM(script, prompt_tokens=lambda n: 50_000 if n == 6 else 100)
    agent = Agent(d, "desc", llm, max_steps=20, interactive=False)
    agent.handlers["bash"] = write_table
    r = agent.run()
    assert r["compactions"] == 1
    seventh = llm.seen[6]
    assert "notes_table.json" in seventh[2]["content"]
    assert "[WORK FILES]" in seventh[2]["content"]
    lines = [json.loads(l) for l in (d / ".revagent" / "transcript.jsonl").read_text().splitlines()]
    work_file_events = [m for m in lines if m.get("event") == "work_files"]
    assert len(work_file_events) == 1 and work_file_events[0]["n"] >= 1


def test_overflow_escalates_and_aborts(tmp_path):
    d = make_problem(tmp_path)
    llm = ScriptedLLM([ContextOverflow("too big")] * 3)
    r = Agent(d, "", llm, max_steps=10, interactive=False).run()
    assert r["reason"] == "context cannot be reduced"
    shrink_calls = [p for p in llm.completes if "Rewrite this case file" in p]
    assert len(shrink_calls) == 1
    assert (d / ".revagent" / "result.json").exists()


def test_exception_still_writes_result(tmp_path):
    d = make_problem(tmp_path)
    llm = ScriptedLLM([RuntimeError("boom")])
    r = Agent(d, "", llm, max_steps=10, interactive=False).run()
    assert r["status"] == "unsolved"
    assert r["reason"].startswith("error: RuntimeError")
    assert (d / ".revagent" / "result.json").exists()


def test_token_totals_are_per_run(tmp_path):
    d = make_problem(tmp_path)
    llm = ScriptedLLM([[("submit_flag", {"flag": "DH{x}", "how_verified": "v"})]], prompt_tokens=77)
    llm.total_prompt_tokens = 500
    llm.total_completion_tokens = 200
    r = Agent(d, "", llm, max_steps=10, interactive=False).run()
    assert r["prompt_tokens"] == 77
    assert r["completion_tokens"] == 10


def test_skipped_calls_get_tool_results(tmp_path):
    d = make_problem(tmp_path)
    llm = ScriptedLLM([
        [("submit_flag", {"flag": "DH{x}", "how_verified": "v"}), ("bash", {"cmd": "echo hi"})],
    ])
    Agent(d, "", llm, max_steps=10, interactive=False).run()
    lines = (d / ".revagent" / "transcript.jsonl").read_text().splitlines()
    tool_lines = [json.loads(l) for l in lines if json.loads(l).get("role") == "tool"]
    assert len(tool_lines) == 2
    assert "skipped" in tool_lines[1]["content"]


def test_solve_rejects_non_directory(tmp_path, monkeypatch):
    called = {"load_secure": False}

    def fake_load_secure(*a, **kw):
        called["load_secure"] = True
        raise AssertionError("load_secure should not be called")

    monkeypatch.setattr(main_mod, "load_secure", fake_load_secure)
    rc = main_mod.main(["solve", str(tmp_path / "nope")])
    assert rc == 2
    assert called["load_secure"] is False


def test_load_system_prompt_failure_still_writes_result(tmp_path, monkeypatch):
    d = make_problem(tmp_path)
    monkeypatch.setattr("revagent.agent.load_system_prompt",
                         lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    llm = ScriptedLLM([])
    r = Agent(d, "", llm, max_steps=10, interactive=False).run()
    assert r["status"] == "unsolved"
    assert r["reason"].startswith("error: RuntimeError")
    assert (d / ".revagent" / "result.json").exists()
    res = json.loads((d / ".revagent" / "result.json").read_text())
    assert res["status"] == "unsolved"


def test_task_message_truncates_huge_listing(tmp_path, monkeypatch):
    d = make_problem(tmp_path)
    monkeypatch.setattr("revagent.agent.run_cmd", lambda *a, **kw: "X" * 10_000)
    llm = ScriptedLLM([[("submit_flag", {"flag": "DH{x}", "how_verified": "v"})]])
    agent = Agent(d, "desc", llm, max_steps=10, interactive=False)
    msg = agent._task_message()
    assert len(msg) < 6_000
    assert "[listing truncated]" in msg


def test_bench_isolates_errors(tmp_path, monkeypatch, capsys):
    d_bad = tmp_path / "bad"
    d_bad.mkdir()
    d_good = tmp_path / "good"
    d_good.mkdir()

    def run(d):
        if d.name == "bad":
            raise RuntimeError("kaboom")
        return _result()

    _patch_host(monkeypatch, run)
    rc = main_mod.main(["bench", "--host", str(d_bad), str(d_good)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "error" in out
    assert "solved" in out


def test_truncated_thinking_retries_with_hint_at_full_budget(tmp_path):
    d = make_problem(tmp_path)
    llm = ScriptedLLM([
        {"calls": [], "finish_reason": "length"},
        [("submit_flag", {"flag": "DH{x}", "how_verified": "v"})],
    ])
    r = Agent(d, "", llm, max_steps=10, interactive=False).run()
    assert r["status"] == "solved" and r["steps"] == 1
    # 16384 is the ceiling for both (44k threshold + 16k output must stay under the 65536 model length),
    # so the retry differs from the first try only by the hint and the low effort
    assert llm.max_tokens_seen == [16384, 16384]
    # the retry alone runs at low reasoning effort; normal steps pass None (client default = medium)
    assert llm.efforts_seen == [None, "low"]
    assert llm.max_tokens == 16384
    # the retry request ends with a transient hint that is NOT persisted in the conversation
    assert llm.seen[1][-1]["role"] == "user" and "exhausted the output budget" in llm.seen[1][-1]["content"]
    assert not any(m["role"] == "user" and "exhausted the output budget" in m["content"] for m in llm.seen[0])
    lines = [json.loads(l) for l in (d / ".revagent" / "transcript.jsonl").read_text().splitlines()]
    assert any(m.get("event") == "output_truncated" for m in lines)
    # the truncated (empty) assistant message never entered the conversation
    assert not any(m.get("role") == "assistant" and m.get("content") == "" and not m.get("tool_calls") for m in lines)


def test_truncated_thinking_twice_counts_toward_abort(tmp_path):
    d = make_problem(tmp_path)
    cut = {"calls": [], "finish_reason": "length"}
    llm = ScriptedLLM([cut] * 6)
    r = Agent(d, "", llm, max_steps=10, interactive=False).run()
    assert r["reason"] == "no tool calls 3x"
    assert len(llm.seen) == 6
    nudges = [m for m in llm.seen[-1] if m["role"] == "user" and "hit the output budget" in m["content"]]
    assert len(nudges) == 2


def test_solve_sandbox_dispatches_docker(tmp_path, monkeypatch):
    d = tmp_path / "chal"
    d.mkdir()
    (d / "desc.txt").write_text("hi")
    recorded = {}
    _patch_sandbox(monkeypatch, lambda cmd, env_extra=None: recorded.update(cmd=cmd, env_extra=env_extra) or 3)
    rc = main_mod.main(["solve", str(d), "--max-steps", "7", "--desc", str(d / "desc.txt")])
    assert rc == 3
    cmd = recorded["cmd"]
    assert cmd[:2] == ["docker", "run"] and "-i" in cmd
    assert f"{d.resolve()}:/work/chal" in cmd
    tail = cmd[cmd.index("revagent-sandbox"):]
    assert tail[:3] == ["revagent-sandbox", "solve", "/work/chal"]
    assert "--max-steps" in tail and "7" in tail and "--ask" not in tail
    assert "--desc" in tail and "/work/chal/desc.txt" in tail
    assert "--sandbox" not in tail
    # the inner run (same __main__, inside the container) must stay on the host side of the container
    assert "--host" in tail and "--dev" not in tail
    # the secret key never appears in argv (visible in the host process table); it travels via env_extra
    assert "k" not in cmd
    assert recorded["env_extra"] == {"QWEN": "k", "URL": "https://h", "MODEL": "m"}


def test_solve_sandbox_dev_mounts_repo(tmp_path, monkeypatch):
    d = tmp_path / "chal"
    d.mkdir()
    recorded = {}
    _patch_sandbox(monkeypatch, lambda cmd, env_extra=None: recorded.setdefault("cmd", cmd) and 0, tty=True)
    rc = main_mod.main(["solve", "--dev", str(d)])
    assert rc == 0
    cmd = recorded["cmd"]
    assert "-i" in cmd and "-it" not in cmd      # a tty alone does not make the run interactive: --ask does
    assert any(x.endswith(":/app") for x in cmd)


def test_solve_sandbox_docker_missing(tmp_path, monkeypatch, capsys):
    d = tmp_path / "chal"
    d.mkdir()
    _patch_sandbox(monkeypatch, docker="docker not found. enable it")
    monkeypatch.setattr(main_mod, "load_secure", lambda *a, **k: (_ for _ in ()).throw(AssertionError("not reached")))
    rc = main_mod.main(["solve", str(d)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "error: docker not found. enable it (or run with --host)" in err


def test_solve_sandbox_desc_outside_dir(tmp_path, monkeypatch, capsys):
    d = tmp_path / "chal"
    d.mkdir()
    (tmp_path / "far.txt").write_text("x")
    _patch_sandbox(monkeypatch)
    rc = main_mod.main(["solve", str(d), "--desc", str(tmp_path / "far.txt")])
    assert rc == 2
    assert "inside the problem dir" in capsys.readouterr().err


@pytest.mark.parametrize("via", ["flag", "env"])
def test_solve_sandbox_ca_flag_or_env(tmp_path, monkeypatch, via):
    d = tmp_path / "chal"
    d.mkdir()
    crt = tmp_path / "corp.crt"
    crt.write_text("cert")
    recorded = {}
    _patch_sandbox(monkeypatch, lambda cmd, env_extra=None: recorded.setdefault("cmd", cmd) and 0)
    argv = ["solve", str(d)]
    if via == "flag":
        argv += ["--sandbox-ca", str(crt)]
    else:
        monkeypatch.setenv("REVAGENT_SANDBOX_CA", str(crt))
    rc = main_mod.main(argv)
    assert rc == 0
    assert any(x.endswith(":/usr/local/share/ca-certificates/extra-ca.crt:ro") for x in recorded["cmd"])


def test_solve_sandbox_ca_missing_file(tmp_path, monkeypatch, capsys):
    d = tmp_path / "chal"
    d.mkdir()
    missing = tmp_path / "nope.crt"
    _patch_sandbox(monkeypatch)
    rc = main_mod.main(["solve", str(d), "--sandbox-ca", str(missing)])
    assert rc == 2
    assert "not found" in capsys.readouterr().err


def test_bench_sandbox_runs_each_dir(tmp_path, monkeypatch, capsys):
    d1 = tmp_path / "a"
    d2 = tmp_path / "b"
    d1.mkdir()
    d2.mkdir()
    seen = []

    def fake_run(cmd, env_extra=None):
        target = cmd[cmd.index("solve") + 1]
        name = target.rsplit("/", 1)[1]
        if name == "a":
            _write_result(d1, flag="DH{a}", steps=3, minutes=1.5)
        else:
            _write_result(d2, status="unsolved", flag=None, reason="step limit", steps=3, minutes=1.5)
        seen.append(name)
        return 0 if name == "a" else 1

    _patch_sandbox(monkeypatch, fake_run)
    rc = main_mod.main(["bench", str(d1), str(d2)])
    assert seen == ["a", "b"] and rc == 1
    out = capsys.readouterr().out
    assert "| a | solved | DH{a} | 3 | 1.5 |" in out
    assert "| b | unsolved | step limit | 3 | 1.5 |" in out


@pytest.mark.parametrize("sub", ["solve", "bench"])
@pytest.mark.parametrize("mode", ["host", "sandbox"])
def test_wrong_flag_is_downgraded_via_answers_md(tmp_path, monkeypatch, capsys, sub, mode):
    suite = tmp_path / "mini"
    suite.mkdir()
    (suite / "ANSWERS.md").write_text("| challenge | flag |\n|---|---|\n| win_gui_key | DH{k3y_dr1v3n_ui} |\n")
    d = suite / "win_gui_key"
    d.mkdir()
    got = {"flag": "DH{k3y_driv3n_ui}", "steps": 5, "minutes": 2.0}

    def run(problem_dir):           # host: the (fake) Agent writes result.json and returns the result
        _write_result(problem_dir, **got)
        return _result(**got)

    def fake_run_sandbox(cmd, env_extra=None):   # sandbox: the container writes result.json, exits 0
        _write_result(d, **got)
        return 0

    if mode == "host":
        _patch_host(monkeypatch, run)
    else:
        _patch_sandbox(monkeypatch, fake_run_sandbox)
    argv = [sub, str(d)] + (["--host"] if mode == "host" else [])
    rc = main_mod.main(argv)
    assert rc == 1
    out = capsys.readouterr().out
    if sub == "bench":
        assert "| win_gui_key | wrong | got DH{k3y_driv3n_ui}, expected DH{k3y_dr1v3n_ui} | 5 | 2.0 |" in out
    else:
        res = json.loads((d / ".revagent" / "result.json").read_text())
        assert res["status"] == "wrong" and res["flag"] == "DH{k3y_driv3n_ui}"
        assert res["note"] == "got DH{k3y_driv3n_ui}, expected DH{k3y_dr1v3n_ui}"
        assert "WRONG" in out


def test_bench_sandbox_reports_container_failure_not_stale_result(tmp_path, monkeypatch, capsys):
    d1 = tmp_path / "a"
    d1.mkdir()
    _write_result(d1, flag="DH{stale}", steps=9, minutes=9.9)

    _patch_sandbox(monkeypatch, lambda cmd, env_extra=None: 125)
    rc = main_mod.main(["bench", str(d1)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "| a | error | container exited 125 | 0 | 0 |" in out
    assert "DH{stale}" not in out


def test_bench_sandbox_tolerates_bad_result_json(tmp_path, monkeypatch, capsys):
    d1 = tmp_path / "a"
    d2 = tmp_path / "b"
    d1.mkdir()
    d2.mkdir()

    def fake_run(cmd, env_extra=None):
        target = cmd[cmd.index("solve") + 1]
        name = target.rsplit("/", 1)[1]
        if name == "a":
            (d1 / ".revagent").mkdir(exist_ok=True)
            (d1 / ".revagent" / "result.json").write_text("{not json")
        else:
            _write_result(d2, flag="DH{b}", steps=2, minutes=0.5)
        return 0

    _patch_sandbox(monkeypatch, fake_run)
    rc = main_mod.main(["bench", str(d1), str(d2)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "bad result.json" in out
    assert "| b | solved | DH{b} | 2 | 0.5 |" in out


def test_sandbox_ca_flag_with_host_is_rejected(tmp_path, monkeypatch, capsys):
    d = tmp_path / "chal"
    d.mkdir()
    crt = tmp_path / "corp.crt"
    crt.write_text("cert")
    monkeypatch.setattr(main_mod, "load_secure",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("not reached")))
    rc = main_mod.main(["solve", "--host", str(d), "--sandbox-ca", str(crt)])
    assert rc == 2
    err = capsys.readouterr().err
    assert err.startswith("error: --sandbox-ca") and "--host" in err


def test_sandbox_ca_env_with_host_is_ignored(tmp_path, monkeypatch, capsys):
    d = tmp_path / "chal"
    d.mkdir()
    crt = tmp_path / "corp.crt"
    crt.write_text("cert")
    monkeypatch.setenv("REVAGENT_SANDBOX_CA", str(crt))
    _patch_host(monkeypatch, lambda problem_dir: _result())
    rc = main_mod.main(["solve", "--host", str(d)])
    assert rc == 0
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("present", [True, False])
def test_sandbox_ca_defaults_to_home_file(tmp_path, monkeypatch, present):
    d = tmp_path / "chal"
    d.mkdir()
    home = tmp_path / "home"
    (home / ".revagent").mkdir(parents=True)
    if present:
        (home / ".revagent" / "sandbox-ca.crt").write_text("cert")
    recorded = {}
    _patch_sandbox(monkeypatch, lambda cmd, env_extra=None: recorded.setdefault("cmd", cmd) and 0, home=home)
    rc = main_mod.main(["solve", str(d)])
    assert rc == 0
    mounts = [x for x in recorded["cmd"] if x.endswith(":/usr/local/share/ca-certificates/extra-ca.crt:ro")]
    if present:
        assert mounts == [f"{(home / '.revagent' / 'sandbox-ca.crt').resolve()}:"
                          f"/usr/local/share/ca-certificates/extra-ca.crt:ro"]
    else:
        assert mounts == []


def test_sandbox_ca_flag_beats_home_file(tmp_path, monkeypatch):
    d = tmp_path / "chal"
    d.mkdir()
    home = tmp_path / "home"
    (home / ".revagent").mkdir(parents=True)
    (home / ".revagent" / "sandbox-ca.crt").write_text("home cert")
    crt = tmp_path / "corp.crt"
    crt.write_text("cert")
    recorded = {}
    _patch_sandbox(monkeypatch, lambda cmd, env_extra=None: recorded.setdefault("cmd", cmd) and 0, home=home)
    assert main_mod.main(["solve", str(d), "--sandbox-ca", str(crt)]) == 0
    assert f"{crt.resolve()}:/usr/local/share/ca-certificates/extra-ca.crt:ro" in recorded["cmd"]
    assert not any("home/.revagent/sandbox-ca.crt" in x for x in recorded["cmd"])


@pytest.mark.parametrize("sub", ["solve", "bench"])
@pytest.mark.parametrize("mode", ["host", "sandbox"])
def test_missing_secure_is_a_usage_error(tmp_path, monkeypatch, capsys, sub, mode):
    # load_secure raising (no .secure anywhere / a key missing) used to escape as a traceback
    d = tmp_path / "chal"
    d.mkdir()
    if mode == "sandbox":
        _patch_sandbox(monkeypatch, lambda cmd, env_extra=None: (_ for _ in ()).throw(AssertionError("not reached")))
    else:
        _patch_host(monkeypatch, lambda problem_dir: (_ for _ in ()).throw(AssertionError("not reached")))
    monkeypatch.setattr(main_mod, "load_secure",
                        lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError("no .secure found; tried: a, b")))
    rc = main_mod.main([sub, str(d)] + (["--host"] if mode == "host" else []))
    assert rc == 2
    captured = capsys.readouterr()
    assert captured.err.strip() == "error: no .secure found; tried: a, b"
    assert "|" not in captured.out    # bench prints no table: the failure is reported once, up front


# ---- CLI defaults: sandbox unless --host, non-interactive unless --ask -------------------------------

def test_default_mode_is_sandbox(tmp_path, monkeypatch):
    d = tmp_path / "chal"
    d.mkdir()
    recorded = {}
    _patch_sandbox(monkeypatch, lambda cmd, env_extra=None: recorded.setdefault("cmd", cmd) and 0)
    assert main_mod.main(["solve", str(d)]) == 0
    cmd = recorded["cmd"]
    assert cmd[:2] == ["docker", "run"] and "-i" in cmd and "-it" not in cmd
    tail = cmd[cmd.index("revagent-sandbox"):]
    assert tail[:4] == ["revagent-sandbox", "solve", "/work/chal", "--host"]
    assert not any(x.endswith(":/app") for x in cmd)


def test_host_flag_runs_agent_on_host(tmp_path, monkeypatch):
    d = tmp_path / "chal"
    d.mkdir()
    fake = _patch_host(monkeypatch, lambda problem_dir: _result())
    monkeypatch.setattr(main_mod, "run_sandbox",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("docker must not run")))
    assert main_mod.main(["solve", "--host", str(d)]) == 0
    assert [c[0] for c in fake.calls] == [d]
    assert fake.calls[0][1]["interactive"] is False


def test_dev_flag_mounts_repo(tmp_path, monkeypatch):
    d = tmp_path / "chal"
    d.mkdir()
    recorded = {}
    _patch_sandbox(monkeypatch, lambda cmd, env_extra=None: recorded.setdefault("cmd", cmd) and 0)
    assert main_mod.main(["solve", "--dev", str(d)]) == 0
    repo = Path(main_mod.__file__).resolve().parents[1]
    assert f"{repo}:/app" in recorded["cmd"]


@pytest.mark.parametrize("sub", ["solve", "bench"])
@pytest.mark.parametrize("other", ["--dev", "--sandbox", "--sandbox-dev"])
def test_host_with_sandbox_flag_is_a_usage_error(tmp_path, monkeypatch, capsys, sub, other):
    d = tmp_path / "chal"
    d.mkdir()
    monkeypatch.setattr(main_mod, "load_secure",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("not reached")))
    monkeypatch.setattr(main_mod, "check_docker",
                        lambda: (_ for _ in ()).throw(AssertionError("not reached")))
    rc = main_mod.main([sub, "--host", other, str(d)])
    assert rc == 2
    err = capsys.readouterr().err
    assert err.startswith("error: ") and "--host" in err


@pytest.mark.parametrize("tty, flag", [(True, "-it"), (False, "-i")])
def test_ask_in_sandbox_attaches_a_tty_only_when_there_is_one(tmp_path, monkeypatch, tty, flag):
    d = tmp_path / "chal"
    d.mkdir()
    recorded = {}
    _patch_sandbox(monkeypatch, lambda cmd, env_extra=None: recorded.setdefault("cmd", cmd) and 0, tty=tty)
    assert main_mod.main(["solve", "--ask", str(d)]) == 0
    cmd = recorded["cmd"]
    assert flag in cmd and ("-it" in cmd) == tty
    tail = cmd[cmd.index("revagent-sandbox"):]
    assert "--ask" in tail and "--no-ask" not in tail


def test_ask_on_host_makes_the_agent_interactive(tmp_path, monkeypatch):
    d = tmp_path / "chal"
    d.mkdir()
    fake = _patch_host(monkeypatch, lambda problem_dir: _result())
    assert main_mod.main(["solve", "--host", "--ask", str(d)]) == 0
    assert fake.calls[0][1]["interactive"] is True


def test_legacy_flags_are_still_accepted(tmp_path, monkeypatch):
    d = tmp_path / "chal"
    d.mkdir()
    # --no-ask on the host: a no-op (non-interactive is the default)
    fake = _patch_host(monkeypatch, lambda problem_dir: _result())
    assert main_mod.main(["solve", "--host", "--no-ask", str(d)]) == 0
    assert fake.calls[0][1]["interactive"] is False
    # --sandbox: a no-op (sandbox is the default); --sandbox-dev == --dev
    recorded = []
    _patch_sandbox(monkeypatch, lambda cmd, env_extra=None: recorded.append(cmd) or 0)
    assert main_mod.main(["solve", "--sandbox", "--no-ask", str(d)]) == 0
    assert main_mod.main(["solve", "--sandbox-dev", str(d)]) == 0
    assert main_mod.main(["bench", "--sandbox", str(d)]) == 1        # no result.json written by the fake
    assert recorded[0][:2] == ["docker", "run"] and not any(x.endswith(":/app") for x in recorded[0])
    assert any(x.endswith(":/app") for x in recorded[1])
    assert recorded[2][:2] == ["docker", "run"]


def test_help_shows_new_flags_and_hides_aliases(capsys):
    with pytest.raises(SystemExit) as e:
        main_mod.main(["solve", "--help"])
    assert e.value.code == 0
    out = capsys.readouterr().out
    for flag in ("--host", "--dev", "--ask"):
        assert flag in out
    for hidden in ("--sandbox-dev", "--no-ask", "--sandbox "):
        assert hidden not in out
    # the three mode flags come first, right after the positional
    assert out.index("--host") < out.index("--dev") < out.index("--ask") < out.index("--desc")


# ---- console.log ------------------------------------------------------------------------------------

def test_host_run_appends_console_log_with_header(tmp_path, monkeypatch, capsys):
    import sys as _sys
    d = tmp_path / "chal"
    d.mkdir()

    def run(problem_dir):
        (problem_dir / ".revagent").mkdir(exist_ok=True)     # the agent creates its work dir itself
        print("[1] > bash ls")
        print("[llm] retry 1/3 after 524; waiting 2s", file=_sys.stderr, flush=True)
        return _result()

    _patch_host(monkeypatch, run)
    out_before, err_before = _sys.stdout, _sys.stderr
    assert main_mod.main(["solve", "--host", str(d), "--max-steps", "9"]) == 0
    assert _sys.stdout is out_before and _sys.stderr is err_before      # restored afterwards
    log = _console_log(d)
    first = log.splitlines()[0]
    assert first.startswith("=== run 20") and "argv:" in first and "--max-steps 9" in first and first.endswith("===")
    assert "[1] > bash ls\n" in log
    assert "[llm] retry 1/3 after 524; waiting 2s\n" in log
    captured = capsys.readouterr()
    assert "[1] > bash ls" in captured.out and "[llm] retry" in captured.err      # still printed
    # a second run appends a second header instead of truncating
    assert main_mod.main(["solve", "--host", str(d)]) == 0
    assert _console_log(d).count("=== run ") == 2


def test_console_log_creates_the_work_dir_when_missing(tmp_path, monkeypatch):
    d = tmp_path / "chal"
    d.mkdir()
    _patch_host(monkeypatch, lambda problem_dir: _result())
    assert not (d / ".revagent").exists()
    assert main_mod.main(["solve", "--host", str(d)]) == 0
    assert _console_log(d).startswith("=== run ")


def test_host_tee_is_skipped_inside_the_container(tmp_path, monkeypatch):
    d = tmp_path / "chal"
    d.mkdir()
    _patch_host(monkeypatch, lambda problem_dir: print("inner") or _result())
    monkeypatch.setenv("REVAGENT_IN_SANDBOX", "1")
    assert main_mod.main(["solve", "--host", str(d)]) == 0
    assert not (d / ".revagent" / "console.log").exists()


class _FakePopen:
    """A docker CLI stand-in for sandbox.run_sandbox's streaming path: stdout yields `lines`."""
    lines = [b"[1] > bash file chal\n", b"[llm] retry 1/3 after 524; waiting 2s\n", b"FLAG: DH{x}\n"]
    seen = []

    def __init__(self, cmd, **kw):
        _FakePopen.seen.append((cmd, kw))
        import io
        self.stdout = io.BytesIO(b"".join(self.lines))
        self.returncode = None

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def kill(self):
        pass


def test_sandbox_run_streams_container_output_into_console_log(tmp_path, monkeypatch, capsys):
    d = tmp_path / "chal"
    d.mkdir()
    _patch_sandbox(monkeypatch)            # real run_sandbox, fake docker
    _FakePopen.seen = []
    monkeypatch.setattr("revagent.sandbox.subprocess.Popen", _FakePopen)
    rc = main_mod.main(["solve", str(d)])
    assert rc == 0                          # a sandbox solve returns the container's own exit code
    (cmd, kw), = _FakePopen.seen
    assert cmd[:2] == ["docker", "run"] and "-e" in cmd and "PYTHONUNBUFFERED=1" in cmd
    assert kw["stdout"] is subprocess.PIPE and kw["stderr"] is subprocess.STDOUT
    assert not kw.get("start_new_session")           # Ctrl-C must still reach the docker CLI
    assert kw["env"]["QWEN"] == "k"
    log = _console_log(d)
    assert log.startswith("=== run ") and "argv:" in log.splitlines()[0]
    assert "[1] > bash file chal\n[llm] retry 1/3 after 524; waiting 2s\nFLAG: DH{x}\n" in log
    out = capsys.readouterr().out
    assert "[1] > bash file chal" in out and "FLAG: DH{x}" in out


def test_interactive_sandbox_run_skips_console_log(tmp_path, monkeypatch, capsys):
    d = tmp_path / "chal"
    d.mkdir()
    _patch_sandbox(monkeypatch, lambda cmd, env_extra=None: 0, tty=True)
    assert main_mod.main(["solve", "--ask", str(d)]) == 0
    assert not (d / ".revagent" / "console.log").exists()
    assert "console log" in capsys.readouterr().out.lower()


def test_bench_writes_one_console_log_per_dir(tmp_path, monkeypatch):
    d1 = tmp_path / "a"
    d2 = tmp_path / "b"
    d1.mkdir()
    d2.mkdir()
    _patch_host(monkeypatch, lambda problem_dir: print(f"working on {problem_dir.name}") or _result())
    assert main_mod.main(["bench", "--host", str(d1), str(d2)]) == 0
    la, lb = _console_log(d1), _console_log(d2)
    assert la.count("=== run ") == 1 and "working on a" in la and "working on b" not in la
    assert lb.count("=== run ") == 1 and "working on b" in lb and "working on a" not in lb
    assert "| a | solved" not in la                      # the table is printed after the runs, outside the logs


def test_system_prompt_loads_and_tells_agent_where_to_save_work_files():
    t = load_system_prompt()
    assert "submit_flag" in t
    assert "never under `/tmp`" in t
    assert "only files under the challenge directory are listed for you after a context reset" in t


def test_bench_table_shared_helper(capsys):
    rc = main_mod._print_bench_table([("a", "solved", "DH{a}", 1, 0.5)])
    assert rc == 0
    assert "| a | solved | DH{a} | 1 | 0.5 |" in capsys.readouterr().out

    rc = main_mod._print_bench_table([("a", "unsolved", "step limit", 3, 1.5)])
    assert rc == 1

    rc = main_mod._print_bench_table([("p", "runbook", ".revagent/runbook.md", 3, 0.1)])
    assert rc == 1 and "| p | runbook |" in capsys.readouterr().out


def test_critic_runs_after_idle_steps_and_before_compaction(tmp_path, monkeypatch):
    d = make_problem(tmp_path)
    # 13 identical-shape bash calls that never add Facts/obs, then a compaction, then submit
    calls = [[("bash", {"cmd": f"echo {i}"})] for i in range(13)]
    script = calls + [[("bash", {"cmd": "echo after"})], [("submit_flag", {"flag": "DH{x}", "how_verified": "ran it", "evidence": "program_accepted"})]]
    llm = ScriptedLLM(script, prompt_tokens=lambda n: 50_000 if n == 14 else 100)
    memos = []
    monkeypatch.setattr("revagent.agent.run_critic",
                        lambda l, cf, msgs, step: memos.append(step) or f"memo@{step}")
    a = Agent(d, "desc", llm, max_steps=40, interactive=False)
    r = a.run()
    assert r["status"] == "solved"
    # idle trigger fired once at step 12 (12 steps without progress), compaction trigger at step 14
    assert memos == [12, 14]
    injected = [m for s in llm.seen for m in s if m.get("role") == "user" and m["content"].startswith("[critic] ")]
    assert injected and injected[0]["content"] == "[critic] memo@12"


def test_critic_capped_per_run(tmp_path, monkeypatch):
    from revagent.critic import CRITIC_MAX
    d = make_problem(tmp_path)
    n = 12 * (CRITIC_MAX + 2)
    script = [[("bash", {"cmd": f"echo {i}"})] for i in range(n)] + [[("submit_flag", {"flag": "DH{x}", "how_verified": "ok", "evidence": "program_accepted"})]]
    llm = ScriptedLLM(script)
    memos = []
    monkeypatch.setattr("revagent.agent.run_critic", lambda l, cf, msgs, step: memos.append(step) or "m")
    Agent(d, "desc", llm, max_steps=n + 5, interactive=False).run()
    assert len(memos) == CRITIC_MAX


def test_runbook_ends_run_with_runbook_status(tmp_path):
    d = make_problem(tmp_path)
    script = [[("handoff_runbook", {"steps": ["a"], "expected_observation": "b", "flag_rule": "c"})]]
    llm = ScriptedLLM(script)
    a = Agent(d, "desc", llm, max_steps=5, interactive=False)
    a.ctx.env_blocked = True
    r = a.run()
    assert r["status"] == "runbook" and r["runbook"] == ".revagent/runbook.md" and r["flag"] is None
    assert (d / ".revagent" / "runbook.md").exists()
    assert json.loads((d / ".revagent" / "result.json").read_text())["status"] == "runbook"


def test_playbook_has_evidence_ladder_sections():
    p = load_system_prompt()
    assert "11. **Evidence ladder.**" in p
    assert "**Nested binary" in p
    assert "two_independent_readings" in p and "program_accepted" in p and "reimplementation_matches" in p
    assert "handoff_runbook" in p and "[critic]" in p
    assert "Fix the character set before classifying glyphs" in p
    assert p.index("## 1. Triage") < p.index("run it once") < p.index("## 2. Locate the check")
    for n in range(1, 11):
        assert f"\n{n}. **" in p  # existing rules keep their numbers


def test_playbook_says_assemble_flag_in_code():
    p = load_system_prompt()
    assert "Assemble the final flag IN CODE" in p


def test_playbook_covers_constructor_rewritten_data_and_gdb_dump_parsing():
    # relativity run 1: the table at 0x6020 had no relocations but an .init_array constructor rewrote it
    # before main, and the agent's gdb dump parser swallowed the `0x56...:` address prefixes as data.
    p = load_system_prompt()
    assert "**Data rewritten before main" in p and ".init_array" in p
    assert "address prefix" in p
    assert p.index("**Data rewritten before main") < p.index("**Compiler-emitted constant division")


def test_playbook_explains_gates_and_solve_check():
    p = load_system_prompt()
    assert "[blocked by G3]" in p and "[gate]" in p and "solve_check" in p
    # first choice in §3, not an afterthought (the Environment section mentions the tool earlier, so search from §3)
    assert p.index("solve_check", p.index("## 3.")) < p.index("**Compiler-emitted constant division")
    for n in range(1, 11):
        assert f"\n{n}. **" in p


def test_unreadable_case_file_mid_run_does_not_end_the_run(tmp_path):
    # I3: the per-step progress_marker read is the only case-file read on the step path. The model
    # has an unrestricted bash and .revagent is inside its cwd, so `rm -rf .revagent` is reachable;
    # it used to turn a recoverable mistake into "error: FileNotFoundError" and a lost run.
    d = make_problem(tmp_path)
    llm = ScriptedLLM([
        [("bash", {"cmd": "rm -f .revagent/case.md"})],
        [("bash", {"cmd": "echo still here"})],
        [("submit_flag", {"flag": "DH{x}", "how_verified": "v", "evidence": "program_accepted"})],
    ])
    agent = Agent(d, "desc", llm, max_steps=10, interactive=False)
    r = agent.run()
    assert r["status"] in ("solved", "unsolved")
    assert not r["reason"].startswith("error:")
    assert r["steps"] >= 2          # the run continued past the deleted case file
    events = [json.loads(l) for l in (d / ".revagent" / "transcript.jsonl").read_text().splitlines()]
    assert any(e.get("event") == "casefile_unreadable" for e in events)


def test_report_survives_an_unreadable_runbook(tmp_path, capsys):
    # M12: _report ran outside the try/finally, so an OSError there crashed solve() after
    # result.json had already been written.
    d = make_problem(tmp_path)
    agent = Agent(d, "desc", ScriptedLLM([]), max_steps=1, interactive=False)
    agent._report({"status": "runbook", "runbook": ".revagent/runbook.md", "reason": "",
                   "steps": 1, "compactions": 0, "prompt_tokens": 1, "completion_tokens": 1,
                   "minutes": 0.1})
    out = capsys.readouterr().out
    assert "could not read" in out and "runbook.md" in out


def test_tool_timeouts_are_clamped_to_the_run_budget(tmp_path, monkeypatch):
    import time as _t
    # the floor is what makes the clamped call overrun the budget (int() rounds `remaining` down, so the
    # tool would otherwise end just before the deadline); 1 s instead of 5 keeps the test fast
    monkeypatch.setattr("revagent.tools.base.MIN_TOOL_SECONDS", 1)
    d = make_problem(tmp_path)
    llm = ScriptedLLM([
        [("bash", {"cmd": "echo start; sleep 30; echo end", "timeout": 900})],
        [("bash", {"cmd": "echo never"})],
    ])
    t0 = _t.monotonic()
    r = Agent(d, "", llm, max_steps=10, max_minutes=0.01, interactive=False).run()  # 0.6 s budget
    assert _t.monotonic() - t0 < 15
    assert r["status"] == "unsolved" and r["reason"] == "time limit" and r["steps"] == 1
    assert len(llm.seen) == 1  # the time check fires before step 2's chat call
    lines = [json.loads(l) for l in (d / ".revagent" / "transcript.jsonl").read_text().splitlines()]
    tool_msgs = [m for m in lines if m.get("role") == "tool"]
    assert tool_msgs and tool_msgs[-1]["content"].startswith("[timeout after ")
    assert "end" not in tool_msgs[-1]["content"]


def test_results_jsonl_keeps_every_run(tmp_path):
    d = make_problem(tmp_path)
    for flag in ("DH{a}", "DH{b}"):
        llm = ScriptedLLM([[("submit_flag", {"flag": flag, "how_verified": "v"})]])
        Agent(d, "", llm, max_steps=3, interactive=False).run()
    latest = json.loads((d / ".revagent" / "result.json").read_text())
    assert latest["flag"] == "DH{b}"
    rows = [json.loads(l) for l in (d / ".revagent" / "results.jsonl").read_text().splitlines()]
    assert [r["flag"] for r in rows] == ["DH{a}", "DH{b}"]
    assert all("time" in r and r["status"] == "solved" for r in rows)
    assert "llm_retries" in latest and latest["llm_retries"] == 0


def _pefile_variant(i: int) -> tuple:
    body = "import pefile\npe = pefile.PE('chal')\nbase = pe.OPTIONAL_HEADER.ImageBase\n" + "x = 1\n" * 40 + f"print({i})"
    return ("bash", {"cmd": f"python3 - <<'EOF'\n{body}\nEOF"})


def test_g3_blocks_fourth_similar_script_and_lifts_on_a_run(tmp_path):
    d = make_problem(tmp_path)
    llm = ScriptedLLM([
        [_pefile_variant(0)], [_pefile_variant(1)], [_pefile_variant(2)],
        [_pefile_variant(3)],                                    # step 4: blocked
        [("run_binary", {"path": "chal", "stdin": "abc\n"})],     # step 5: lifts
        [("submit_flag", {"flag": "DH{abc}", "how_verified": "printed Correct"})],
    ])
    r = Agent(d, "", llm, max_steps=10, interactive=False).run()
    assert r["status"] == "solved"
    lines = [json.loads(l) for l in (d / ".revagent" / "transcript.jsonl").read_text().splitlines()]
    tools = [m for m in lines if m.get("role") == "tool"]
    assert tools[3]["content"].startswith("[blocked by G3]")          # the 4th script was not run
    events = [m for m in lines if m.get("role") == "_meta" and str(m.get("event", "")).startswith("gate_")]
    assert [(e["event"], e["step"]) for e in events] == [("gate_block", 4), ("gate_open", 5)]
    case = (d / ".revagent" / "case.md").read_text()
    assert "- [gate step 4] G3 blocked" in case and "- [gate step 5] G3 opened" in case
    assert r["signals"]["gate_blocks"] == 1 and r["signals"]["max_script_streak"] == 4


def test_g3_blocked_step_counts_as_no_progress_for_the_critic(tmp_path, monkeypatch):
    # a blocked call produces no [obs] line and no Facts, so idle keeps growing
    d = make_problem(tmp_path)
    llm = ScriptedLLM([[_pefile_variant(i)] for i in range(4)] + [[("bash", {"cmd": "ls"})]])
    a = Agent(d, "", llm, max_steps=5, interactive=False)
    r = a.run()
    assert r["signals"]["gate_blocks"] == 1
    assert r["status"] == "unsolved" and r["reason"] == "step limit"


def test_g4_warns_once_on_fifth_long_reasoning_step_and_lowers_effort(tmp_path):
    d = make_problem(tmp_path)
    long = "x" * 8001
    llm = ScriptedLLM([
        {"calls": [("bash", {"cmd": f"echo {i}"})], "reasoning": long} for i in range(5)
    ] + [
        {"calls": [("bash", {"cmd": "echo 5"})], "reasoning": "short"},
        [("submit_flag", {"flag": "DH{abc}", "how_verified": "v"})],
    ])
    r = Agent(d, "", llm, max_steps=10, interactive=False).run()
    assert r["status"] == "solved"
    # steps 1-5 medium (None = client default); the 5th long step sets the override, so steps 6, 7 are low
    assert llm.efforts_seen == [None, None, None, None, None, "low", "low"]
    warns = [m for m in llm.seen[-1] if m["role"] == "user" and m["content"].startswith("[gate]")]
    assert len(warns) == 1 and "5" in warns[0]["content"]
    lines = [json.loads(l) for l in (d / ".revagent" / "transcript.jsonl").read_text().splitlines()]
    assert [m["step"] for m in lines if m.get("event") == "gate_warn"] == [5]
    assert r["signals"]["long_reasoning_steps"] == 5
    assert "- [gate step 5] G4" in (d / ".revagent" / "case.md").read_text()


def test_signals_record_first_facts_step(tmp_path):
    d = make_problem(tmp_path)
    llm = ScriptedLLM([
        [("bash", {"cmd": "ls"})],
        [("notes", {"action": "add", "section": "facts", "text": "chal is a script"})],
        [("submit_flag", {"flag": "DH{abc}", "how_verified": "v"})],
    ])
    r = Agent(d, "", llm, max_steps=5, interactive=False).run()
    assert r["signals"] == {"gate_blocks": 0, "max_script_streak": 0, "long_reasoning_steps": 0,
                            "first_facts_step": 2}
    llm2 = ScriptedLLM([[("submit_flag", {"flag": "DH{abc}", "how_verified": "v"})]])
    (tmp_path / "b").mkdir()
    r2 = Agent(make_problem(tmp_path / "b"), "", llm2, max_steps=5, interactive=False).run()
    assert r2["signals"]["first_facts_step"] is None

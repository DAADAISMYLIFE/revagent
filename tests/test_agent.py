import json
from pathlib import Path

from revagent.agent import Agent, load_system_prompt
from revagent.llm import ChatResponse, ContextOverflow, ToolCall


class ScriptedLLM:
    """Returns pre-baked responses in order; records the messages it was given.
    A script entry may also be an exception (instance or class), in which case
    chat() raises it instead of returning a response — used to simulate
    ContextOverflow / arbitrary server errors."""

    def __init__(self, script, prompt_tokens=100):
        self.script = list(script)
        self.seen = []
        self.max_tokens = 8192
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
        if isinstance(item, dict):
            finish_reason = item.get("finish_reason", "stop")
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
        return ChatResponse(msg["content"], "thinking...", tcs, msg, pt, 10, finish_reason)

    def complete(self, prompt, system=None, **kw):
        self.completes.append(prompt)
        return "- summary bullet"


def make_problem(tmp_path):
    d = tmp_path / "prob"
    d.mkdir()
    (d / "chal").write_text("#!/bin/bash\nread x; [ \"$x\" = abc ] && echo Correct || echo Wrong\n")
    return d


def test_solves_and_writes_result(tmp_path):
    d = make_problem(tmp_path)
    llm = ScriptedLLM([
        [("bash", {"cmd": "ls"})],
        [("notes", {"action": "add", "section": "facts", "text": "chal is a shell script"})],
        [("run_binary", {"path": "chal", "stdin": "abc\n"})],
        [("submit_flag", {"flag": "DH{abc}", "how_verified": "printed Correct"})],
    ])
    r = Agent(d, "find it", llm, max_steps=10, interactive=False).run()
    assert r["status"] == "solved" and r["flag"] == "DH{abc}" and r["steps"] == 4
    res = json.loads((d / ".revagent" / "result.json").read_text())
    assert res["flag"] == "DH{abc}"
    assert "chal is a shell script" in (d / ".revagent" / "case.md").read_text()
    lines = (d / ".revagent" / "transcript.jsonl").read_text().splitlines()
    first = json.loads(lines[0])
    assert first["role"] == "_meta" and first["event"] == "session_start"
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


def test_reset_message_logged(tmp_path):
    d = make_problem(tmp_path)
    script = [[("bash", {"cmd": f"echo {i}"})] for i in range(7)] + \
             [[("submit_flag", {"flag": "DH{x}", "how_verified": "v"})]]
    llm = ScriptedLLM(script, prompt_tokens=lambda n: 50_000 if n == 6 else 100)
    Agent(d, "desc", llm, max_steps=20, interactive=False).run()
    lines = (d / ".revagent" / "transcript.jsonl").read_text().splitlines()
    assert any(json.loads(l).get("content", "").startswith("[CONTEXT RESET]") for l in lines)


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
    from revagent import __main__ as main_mod

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


def test_session_start_logged_first(tmp_path):
    d = make_problem(tmp_path)
    llm = ScriptedLLM([[("submit_flag", {"flag": "DH{x}", "how_verified": "v"})]])
    Agent(d, "desc", llm, max_steps=10, max_minutes=5, interactive=False).run()
    lines = (d / ".revagent" / "transcript.jsonl").read_text().splitlines()
    first = json.loads(lines[0])
    assert first["role"] == "_meta" and first["event"] == "session_start"
    assert first["max_steps"] == 10 and first["max_minutes"] == 5
    assert "problem_dir" in first and "time" in first


def test_task_message_truncates_huge_listing(tmp_path, monkeypatch):
    d = make_problem(tmp_path)
    monkeypatch.setattr("revagent.agent.run_cmd", lambda *a, **kw: "X" * 10_000)
    llm = ScriptedLLM([[("submit_flag", {"flag": "DH{x}", "how_verified": "v"})]])
    agent = Agent(d, "desc", llm, max_steps=10, interactive=False)
    msg = agent._task_message()
    assert len(msg) < 6_000
    assert "[listing truncated]" in msg


def test_bench_isolates_errors(tmp_path, monkeypatch, capsys):
    from revagent import __main__ as main_mod

    d_bad = tmp_path / "bad"
    d_bad.mkdir()
    d_good = tmp_path / "good"
    d_good.mkdir()

    class FakeAgent:
        def __init__(self, d, desc, llm, **kw):
            self.d = Path(d)

        def run(self):
            if self.d.name == "bad":
                raise RuntimeError("kaboom")
            return {"status": "solved", "flag": "DH{x}", "how_verified": "v", "reason": "",
                    "steps": 1, "compactions": 0, "prompt_tokens": 1, "completion_tokens": 1, "minutes": 0.1}

    monkeypatch.setattr(main_mod, "load_secure", lambda *a, **kw: object())
    monkeypatch.setattr(main_mod, "LLM", lambda secure: object())
    monkeypatch.setattr(main_mod, "Agent", FakeAgent)

    rc = main_mod.main(["bench", str(d_bad), str(d_good)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "error" in out
    assert "solved" in out


def test_truncated_thinking_retries_with_bigger_budget(tmp_path):
    d = make_problem(tmp_path)
    llm = ScriptedLLM([
        {"calls": [], "finish_reason": "length"},
        [("submit_flag", {"flag": "DH{x}", "how_verified": "v"})],
    ])
    r = Agent(d, "", llm, max_steps=10, interactive=False).run()
    assert r["status"] == "solved" and r["steps"] == 1
    assert llm.max_tokens_seen == [8192, 16384]
    # the retry alone runs at low reasoning effort; normal steps pass None (client default = medium)
    assert llm.efforts_seen == [None, "low"]
    assert llm.max_tokens == 8192
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
    from revagent import __main__ as main_mod
    from revagent.llm import Secure

    d = tmp_path / "chal"
    d.mkdir()
    (d / "desc.txt").write_text("hi")
    recorded = {}
    monkeypatch.setattr(main_mod, "check_docker", lambda: None)
    monkeypatch.setattr(main_mod, "load_secure", lambda *a, **k: Secure("k", "https://h", "m"))
    monkeypatch.setattr(main_mod, "is_interactive_tty", lambda: False)
    monkeypatch.setattr(main_mod, "run_sandbox",
                        lambda cmd, env_extra=None: recorded.update(cmd=cmd, env_extra=env_extra) or 3)
    monkeypatch.setattr(main_mod, "Agent", lambda *a, **k: (_ for _ in ()).throw(AssertionError("Agent must not run on host")))
    rc = main_mod.main(["solve", "--sandbox", str(d), "--max-steps", "7", "--no-ask", "--desc", str(d / "desc.txt")])
    assert rc == 3
    cmd = recorded["cmd"]
    assert cmd[:2] == ["docker", "run"] and "-i" in cmd
    assert f"{d.resolve()}:/work/chal" in cmd
    tail = cmd[cmd.index("revagent-sandbox"):]
    assert tail[:3] == ["revagent-sandbox", "solve", "/work/chal"]
    assert "--max-steps" in tail and "7" in tail and "--no-ask" in tail
    assert "--desc" in tail and "/work/chal/desc.txt" in tail
    assert "--sandbox" not in tail
    # the secret key never appears in argv (visible in the host process table); it travels via env_extra
    assert "k" not in cmd
    assert recorded["env_extra"] == {"QWEN": "k", "URL": "https://h", "MODEL": "m"}


def test_solve_sandbox_dev_mounts_repo(tmp_path, monkeypatch):
    from revagent import __main__ as main_mod
    from revagent.llm import Secure

    d = tmp_path / "chal"
    d.mkdir()
    recorded = {}
    monkeypatch.setattr(main_mod, "check_docker", lambda: None)
    monkeypatch.setattr(main_mod, "load_secure", lambda *a, **k: Secure("k", "https://h", "m"))
    monkeypatch.setattr(main_mod, "is_interactive_tty", lambda: True)
    monkeypatch.setattr(main_mod, "run_sandbox",
                        lambda cmd, env_extra=None: recorded.setdefault("cmd", cmd) and 0)
    rc = main_mod.main(["solve", "--sandbox-dev", str(d)])
    assert rc == 0
    cmd = recorded["cmd"]
    assert "-it" in cmd
    assert any(x.endswith(":/app") for x in cmd)


def test_solve_sandbox_docker_missing(tmp_path, monkeypatch, capsys):
    from revagent import __main__ as main_mod

    d = tmp_path / "chal"
    d.mkdir()
    monkeypatch.setattr(main_mod, "check_docker", lambda: "docker not found. enable it")
    monkeypatch.setattr(main_mod, "load_secure", lambda *a, **k: (_ for _ in ()).throw(AssertionError("not reached")))
    rc = main_mod.main(["solve", "--sandbox", str(d)])
    assert rc == 2
    assert "docker not found" in capsys.readouterr().err


def test_solve_sandbox_desc_outside_dir(tmp_path, monkeypatch, capsys):
    from revagent import __main__ as main_mod
    from revagent.llm import Secure

    d = tmp_path / "chal"
    d.mkdir()
    (tmp_path / "far.txt").write_text("x")
    monkeypatch.setattr(main_mod, "check_docker", lambda: None)
    monkeypatch.setattr(main_mod, "load_secure", lambda *a, **k: Secure("k", "https://h", "m"))
    rc = main_mod.main(["solve", "--sandbox", str(d), "--desc", str(tmp_path / "far.txt")])
    assert rc == 2
    assert "inside the problem dir" in capsys.readouterr().err


def test_solve_sandbox_ca_flag(tmp_path, monkeypatch):
    from revagent import __main__ as main_mod
    from revagent.llm import Secure

    d = tmp_path / "chal"
    d.mkdir()
    crt = tmp_path / "corp.crt"
    crt.write_text("cert")
    recorded = {}
    monkeypatch.setattr(main_mod, "check_docker", lambda: None)
    monkeypatch.setattr(main_mod, "load_secure", lambda *a, **k: Secure("k", "https://h", "m"))
    monkeypatch.setattr(main_mod, "is_interactive_tty", lambda: False)
    monkeypatch.setattr(main_mod, "run_sandbox", lambda cmd, env_extra=None: recorded.setdefault("cmd", cmd) and 0)
    rc = main_mod.main(["solve", "--sandbox", str(d), "--sandbox-ca", str(crt)])
    assert rc == 0
    assert any(x.endswith(":/usr/local/share/ca-certificates/extra-ca.crt:ro") for x in recorded["cmd"])


def test_solve_sandbox_ca_env(tmp_path, monkeypatch):
    from revagent import __main__ as main_mod
    from revagent.llm import Secure

    d = tmp_path / "chal"
    d.mkdir()
    crt = tmp_path / "corp.crt"
    crt.write_text("cert")
    recorded = {}
    monkeypatch.setattr(main_mod, "check_docker", lambda: None)
    monkeypatch.setattr(main_mod, "load_secure", lambda *a, **k: Secure("k", "https://h", "m"))
    monkeypatch.setattr(main_mod, "is_interactive_tty", lambda: False)
    monkeypatch.setattr(main_mod, "run_sandbox", lambda cmd, env_extra=None: recorded.setdefault("cmd", cmd) and 0)
    monkeypatch.setenv("REVAGENT_SANDBOX_CA", str(crt))
    rc = main_mod.main(["solve", "--sandbox", str(d)])
    assert rc == 0
    assert any(x.endswith(":/usr/local/share/ca-certificates/extra-ca.crt:ro") for x in recorded["cmd"])


def test_solve_sandbox_ca_missing_file(tmp_path, monkeypatch, capsys):
    from revagent import __main__ as main_mod
    from revagent.llm import Secure

    d = tmp_path / "chal"
    d.mkdir()
    missing = tmp_path / "nope.crt"
    monkeypatch.setattr(main_mod, "check_docker", lambda: None)
    monkeypatch.setattr(main_mod, "load_secure", lambda *a, **k: Secure("k", "https://h", "m"))
    rc = main_mod.main(["solve", "--sandbox", str(d), "--sandbox-ca", str(missing)])
    assert rc == 2
    assert "not found" in capsys.readouterr().err


def test_bench_sandbox_runs_each_dir(tmp_path, monkeypatch, capsys):
    import json
    from revagent import __main__ as main_mod
    from revagent.llm import Secure

    d1 = tmp_path / "a"
    d2 = tmp_path / "b"
    d1.mkdir()
    d2.mkdir()
    seen = []

    def fake_run(cmd, env_extra=None):
        target = cmd[cmd.index("solve") + 1]
        name = target.rsplit("/", 1)[1]
        d = d1 if name == "a" else d2
        (d / ".revagent").mkdir(exist_ok=True)
        (d / ".revagent" / "result.json").write_text(json.dumps(
            {"status": "solved" if name == "a" else "unsolved", "flag": "DH{a}" if name == "a" else None,
             "reason": "" if name == "a" else "step limit", "steps": 3, "minutes": 1.5}))
        seen.append(name)
        return 0 if name == "a" else 1

    monkeypatch.setattr(main_mod, "check_docker", lambda: None)
    monkeypatch.setattr(main_mod, "load_secure", lambda *a, **k: Secure("k", "https://h", "m"))
    monkeypatch.setattr(main_mod, "run_sandbox", fake_run)
    rc = main_mod.main(["bench", "--sandbox", str(d1), str(d2)])
    assert seen == ["a", "b"] and rc == 1
    out = capsys.readouterr().out
    assert "| a | solved | DH{a} | 3 | 1.5 |" in out
    assert "| b | unsolved | step limit | 3 | 1.5 |" in out


def test_bench_sandbox_reports_container_failure_not_stale_result(tmp_path, monkeypatch, capsys):
    import json
    from revagent import __main__ as main_mod
    from revagent.llm import Secure

    d1 = tmp_path / "a"
    d1.mkdir()
    (d1 / ".revagent").mkdir()
    (d1 / ".revagent" / "result.json").write_text(json.dumps(
        {"status": "solved", "flag": "DH{stale}", "reason": "", "steps": 9, "minutes": 9.9}))

    monkeypatch.setattr(main_mod, "check_docker", lambda: None)
    monkeypatch.setattr(main_mod, "load_secure", lambda *a, **k: Secure("k", "https://h", "m"))
    monkeypatch.setattr(main_mod, "run_sandbox", lambda cmd, env_extra=None: 125)
    rc = main_mod.main(["bench", "--sandbox", str(d1)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "| a | error | container exited 125 | 0 | 0 |" in out
    assert "DH{stale}" not in out


def test_bench_sandbox_tolerates_bad_result_json(tmp_path, monkeypatch, capsys):
    import json
    from revagent import __main__ as main_mod
    from revagent.llm import Secure

    d1 = tmp_path / "a"
    d2 = tmp_path / "b"
    d1.mkdir()
    d2.mkdir()

    def fake_run(cmd, env_extra=None):
        target = cmd[cmd.index("solve") + 1]
        name = target.rsplit("/", 1)[1]
        d = d1 if name == "a" else d2
        (d / ".revagent").mkdir(exist_ok=True)
        if name == "a":
            (d / ".revagent" / "result.json").write_text("{not json")
        else:
            (d / ".revagent" / "result.json").write_text(json.dumps(
                {"status": "solved", "flag": "DH{b}", "reason": "", "steps": 2, "minutes": 0.5}))
        return 0

    monkeypatch.setattr(main_mod, "check_docker", lambda: None)
    monkeypatch.setattr(main_mod, "load_secure", lambda *a, **k: Secure("k", "https://h", "m"))
    monkeypatch.setattr(main_mod, "run_sandbox", fake_run)
    rc = main_mod.main(["bench", "--sandbox", str(d1), str(d2)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "bad result.json" in out
    assert "| b | solved | DH{b} | 2 | 0.5 |" in out


def test_sandbox_ca_flag_without_sandbox_is_rejected(tmp_path, monkeypatch, capsys):
    from revagent import __main__ as main_mod

    d = tmp_path / "chal"
    d.mkdir()
    crt = tmp_path / "corp.crt"
    crt.write_text("cert")
    monkeypatch.setattr(main_mod, "load_secure",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("not reached")))
    rc = main_mod.main(["solve", str(d), "--sandbox-ca", str(crt)])
    assert rc == 2
    assert "error: --sandbox-ca requires --sandbox" in capsys.readouterr().err


def test_sandbox_ca_env_without_sandbox_is_ignored(tmp_path, monkeypatch, capsys):
    from revagent import __main__ as main_mod

    d = tmp_path / "chal"
    d.mkdir()
    crt = tmp_path / "corp.crt"
    crt.write_text("cert")
    monkeypatch.setenv("REVAGENT_SANDBOX_CA", str(crt))

    class FakeAgent:
        def __init__(self, *a, **kw):
            pass

        def run(self):
            return {"status": "solved", "flag": "DH{x}", "how_verified": "v", "reason": "",
                    "steps": 1, "compactions": 0, "prompt_tokens": 1, "completion_tokens": 1, "minutes": 0.1}

    monkeypatch.setattr(main_mod, "load_secure", lambda *a, **k: object())
    monkeypatch.setattr(main_mod, "LLM", lambda secure: object())
    monkeypatch.setattr(main_mod, "Agent", FakeAgent)
    rc = main_mod.main(["solve", str(d)])
    assert rc == 0
    assert capsys.readouterr().err == ""


def test_system_prompt_loads_and_tells_agent_where_to_save_work_files():
    t = load_system_prompt()
    assert "submit_flag" in t
    assert "never under `/tmp`" in t
    assert "only files under the challenge directory are listed for you after a context reset" in t


def test_bench_table_shared_helper(capsys):
    from revagent import __main__ as main_mod

    rc = main_mod._print_bench_table([("a", "solved", "DH{a}", 1, 0.5)])
    assert rc == 0
    assert "| a | solved | DH{a} | 1 | 0.5 |" in capsys.readouterr().out

    rc = main_mod._print_bench_table([("a", "unsolved", "step limit", 3, 1.5)])
    assert rc == 1


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


def test_bench_table_exit_code_with_runbook(capsys):
    from revagent.__main__ import _print_bench_table
    rc = _print_bench_table([("p", "runbook", ".revagent/runbook.md", 3, 0.1)])
    assert rc == 1 and "| p | runbook |" in capsys.readouterr().out

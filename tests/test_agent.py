import json
from pathlib import Path

from revagent.agent import Agent
from revagent.llm import ChatResponse, ContextOverflow, ToolCall


class ScriptedLLM:
    """Returns pre-baked responses in order; records the messages it was given.
    A script entry may also be an exception (instance or class), in which case
    chat() raises it instead of returning a response — used to simulate
    ContextOverflow / arbitrary server errors."""

    def __init__(self, script, prompt_tokens=100):
        self.script = list(script)
        self.seen = []
        self.last_prompt_tokens = 0
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.prompt_tokens = prompt_tokens
        self.completes = []

    def chat(self, messages, tools=None):
        self.seen.append([dict(m) for m in messages])
        item = self.script.pop(0)
        if isinstance(item, BaseException) or (isinstance(item, type) and issubclass(item, BaseException)):
            raise item
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
        return ChatResponse(msg["content"], "thinking...", tcs, msg, pt, 10)

    def complete(self, prompt, system=None):
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
    assert len(llm.completes) == 1  # middle summarized once
    seventh = llm.seen[6]
    assert seventh[2]["role"] == "user" and "[CONTEXT RESET]" in seventh[2]["content"]
    assert "- summary bullet" in seventh[2]["content"]


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

import json
from pathlib import Path

from revagent.agent import Agent
from revagent.llm import ChatResponse, ToolCall


class ScriptedLLM:
    """Returns pre-baked responses in order; records the messages it was given."""

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
        calls = self.script.pop(0)
        tcs = [ToolCall(f"id{i}", n, a, json.dumps(a)) for i, (n, a) in enumerate(calls)]
        msg = {"role": "assistant", "content": "" if tcs else "just talking"}
        if tcs:
            msg["tool_calls"] = [{"id": t.id, "type": "function",
                                  "function": {"name": t.name, "arguments": t.raw_args}} for t in tcs]
        pt = self.prompt_tokens(len(self.seen)) if callable(self.prompt_tokens) else self.prompt_tokens
        self.last_prompt_tokens = pt
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
    assert json.loads(lines[0])["role"] == "system"
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

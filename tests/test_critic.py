from pathlib import Path

from revagent.casefile import CaseFile
from revagent.critic import (CRITIC_IDLE_STEPS, CRITIC_MAX, CRITIC_MAX_TOKENS, CRITIC_PROMPT, progress_marker,
                             render_recent, run_critic)


class FakeLLM:
    def __init__(self, reply="1. obs contradicts plan\n2. repeated 3x\n3. run_gui with clicks\n4. none", raise_=False):
        self.reply, self.raise_, self.kw, self.prompts = reply, raise_, None, []
        self.last_finish_reason = "stop"

    def complete(self, prompt, system=None, **kw):
        self.prompts.append(prompt)
        self.kw = kw
        if self.raise_:
            raise RuntimeError("down")
        return self.reply


def test_constants():
    assert CRITIC_IDLE_STEPS == 12 and CRITIC_MAX == 8 and CRITIC_MAX_TOKENS == 4096


def test_progress_marker_counts_facts_and_obs(tmp_path):
    cf = CaseFile(tmp_path / "c.md", "p", "d")
    assert progress_marker(cf.read()) == (0, 0)
    cf.add("facts", "a"); cf.add("facts", "b"); cf.add("log", "[obs step 1] x"); cf.add("log", "not obs")
    assert progress_marker(cf.read()) == (2, 1)


def test_render_recent_takes_last_n_tool_exchanges():
    msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
    for i in range(20):
        msgs.append({"role": "assistant", "content": "", "tool_calls": [{"id": f"i{i}", "type": "function",
                     "function": {"name": "bash", "arguments": '{"cmd": "echo %d"}' % i}}]})
        msgs.append({"role": "tool", "tool_call_id": f"i{i}", "content": "out %d" % i})
    text = render_recent(msgs, n=3)
    assert "echo 19" in text and "out 19" in text and "echo 16" not in text
    assert len(text) < 3 * 600


def test_run_critic_appends_memo_and_uses_low_effort(tmp_path):
    cf = CaseFile(tmp_path / "c.md", "p", "d")
    llm = FakeLLM()
    memo = run_critic(llm, cf, [], step=15)
    assert memo and memo.startswith("1. obs contradicts plan")
    assert llm.kw == {"max_tokens": CRITIC_MAX_TOKENS, "reasoning_effort": "low"}
    assert "- [critic step 15] 1. obs contradicts plan" in cf.read()
    assert "# Case: p" in llm.prompts[0]


def test_run_critic_failure_returns_none_and_logs(tmp_path):
    cf = CaseFile(tmp_path / "c.md", "p", "d")
    assert run_critic(FakeLLM(raise_=True), cf, [], step=3) is None
    assert "- [critic step 3] (failed: RuntimeError)" in cf.read()
    cf2 = CaseFile(tmp_path / "c2.md", "p", "d")
    assert run_critic(FakeLLM(reply="   "), cf2, [], step=4) is None


def test_run_critic_keeps_answer_4_despite_blank_line_separators(tmp_path):
    # the model separates its four numbered answers with blank lines; the clamp must strip
    # those before taking the first 6 lines, or answer 4 (the environment question) is lost.
    cf = CaseFile(tmp_path / "c.md", "p", "d")
    llm = FakeLLM(reply="1. a\n\n2. b\n\n3. c\n\n4. none")
    memo = run_critic(llm, cf, [], step=1)
    assert memo == "1. a\n2. b\n3. c\n4. none"
    assert "4. none" in memo
    assert "" not in memo.splitlines()


def test_run_critic_clamps_to_first_6_nonempty_lines(tmp_path):
    cf = CaseFile(tmp_path / "c.md", "p", "d")
    reply = "\n\n".join(f"line{i}" for i in range(1, 11))  # 10 non-empty lines, blank-line separated
    llm = FakeLLM(reply=reply)
    memo = run_critic(llm, cf, [], step=2)
    assert memo.splitlines() == [f"line{i}" for i in range(1, 7)]


def test_critic_prompt_allows_handoff_runbook_on_env_question():
    assert "handoff_runbook is allowed" in CRITIC_PROMPT


def test_run_critic_writes_one_ledger_bullet_per_memo_line(tmp_path):
    # I2: a multi-line memo written as one bullet leaves continuation lines that _is_ledger_line
    # does not match, so prune_log detaches answers 2-4 from the memo. One bullet per line makes
    # the memo prune-safe by construction.
    cf = CaseFile(tmp_path / "c.md", "p", "d")
    llm = FakeLLM(reply="1. line one\n2. line two\n3. line three\n4. none")
    memo = run_critic(llm, cf, [], step=7)
    assert memo == "1. line one\n2. line two\n3. line three\n4. none"
    bullets = [l for l in cf.read().splitlines() if l.startswith("- [critic step 7] ")]
    assert bullets == [
        "- [critic step 7] 1. line one",
        "- [critic step 7] 2. line two",
        "- [critic step 7] 3. line three",
        "- [critic step 7] 4. none",
    ]
    assert not any(l.startswith("  ") and l.strip() for l in cf.read().splitlines())


def test_run_critic_memo_is_sanitized_so_a_header_line_is_not_a_boundary(tmp_path):
    # I2: question 1 asks the critic to quote the case file, so a bare "## Facts" line is reachable.
    cf = CaseFile(tmp_path / "c.md", "p", "d")
    cf.add("facts", "before the critic ran")
    llm = FakeLLM(reply="1. quoting the case file:\n## Facts\n3. rerun it\n4. none")
    run_critic(llm, cf, [], step=9)
    text = cf.read()
    assert len([l for l in text.splitlines() if l.strip() == "## Facts"]) == 1
    assert "- [critic step 9] ### Facts" in text
    cf.add("facts", "after the critic ran")
    lines = cf.read().splitlines()
    facts = lines.index("## Facts")
    log = lines.index("## Log")
    assert facts < lines.index("- after the critic ran") < log


def test_prune_log_keeps_every_critic_bullet_once(tmp_path):
    from revagent.context import prune_log
    cf = CaseFile(tmp_path / "c.md", "p", "d")
    for n in range(1, 6):
        cf.add("log", f"### compaction {n}\n## (a) FACTS\n- fact {n}\n## (b) FAILED\n- fail {n}\n"
                      f"## (c) UNFINISHED\n- todo {n}\n## (d) ARTIFACTS\n- art {n}", bullet=False)
        run_critic(FakeLLM(), cf, [], step=n)
    prune_log(cf, keep=3)
    text = cf.read()
    for n in range(1, 6):
        for answer in ("1. obs contradicts plan", "2. repeated 3x", "3. run_gui with clicks", "4. none"):
            assert text.count(f"- [critic step {n}] {answer}") == 1


def test_run_critic_survives_an_unreadable_case_file(tmp_path):
    # I3: casefile.read() is on the critic path; an OSError there must degrade to None, not escape.
    cf = CaseFile(tmp_path / "c.md", "p", "d")
    real_read, fired = cf.read, []

    def raise_once():
        if not fired:
            fired.append(True)
            raise OSError("gone")
        return real_read()

    cf.read = raise_once
    assert run_critic(FakeLLM(), cf, [], step=5) is None
    assert "- [critic step 5] (failed: OSError)" in real_read()


def test_run_critic_ledger_write_failure_is_swallowed(tmp_path):
    # ... and when even the fallback ledger write fails, run_critic still returns quietly.
    cf = CaseFile(tmp_path / "c.md", "p", "d")
    cf.read = lambda: (_ for _ in ()).throw(OSError("gone"))
    assert run_critic(FakeLLM(), cf, [], step=6) is None

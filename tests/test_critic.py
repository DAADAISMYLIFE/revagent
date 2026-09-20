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

from revagent.casefile import CaseFile
from revagent.context import compact, serialize, shrink_casefile, split_messages, KEEP_RECENT, RESET_TEXT


class FakeLLM:
    def __init__(self, reply="- fact: x\n- failed: y\n- todo: z"):
        self.reply = reply
        self.prompts = []

    def complete(self, prompt, system=None):
        self.prompts.append(prompt)
        return self.reply


def exchange(i, big=False):
    body = ("R" * 5000) if big else f"result {i}"
    return [
        {"role": "assistant", "content": f"step {i}", "tool_calls": [
            {"id": f"c{i}", "type": "function", "function": {"name": "bash", "arguments": '{"cmd": "x"}'}}]},
        {"role": "tool", "tool_call_id": f"c{i}", "content": body},
    ]


def build(n):
    msgs = [{"role": "system", "content": "SYS"}, {"role": "user", "content": "TASK"}]
    for i in range(n):
        msgs += exchange(i)
    return msgs


def test_split_keeps_head_and_last_4_exchanges():
    head, middle, tail = split_messages(build(10))
    assert [m["content"] for m in head] == ["SYS", "TASK"]
    assert tail[0]["content"] == f"step {10 - KEEP_RECENT}"
    assert len(tail) == 2 * KEEP_RECENT
    assert middle[0]["content"] == "step 0" and middle[-1]["content"] == "result 5"


def test_split_with_few_exchanges_has_empty_middle():
    head, middle, tail = split_messages(build(2))
    assert middle == [] and len(tail) == 4


def test_serialize_caps_each_message_and_total():
    middle = []
    for i in range(80):
        middle += exchange(i, big=True)
    s = serialize(middle)
    assert "<assistant>" in s and "<tool>" in s and "[call bash]" in s
    assert len(s) <= 90_000 + 100
    assert "[… middle omitted …]" in s


def test_compact_summarizes_middle_into_log_and_resets(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    cf.add("facts", "main at 0x401136")
    llm = FakeLLM()
    new = compact(build(10), llm, cf, n=1)
    assert "step 0" in llm.prompts[0] and "result 5" in llm.prompts[0]
    log = cf.read().split("## Log")[1]
    assert "### compaction 1" in log and "- fact: x" in log
    assert new[0]["content"] == "SYS" and new[1]["content"] == "TASK"
    assert new[2]["role"] == "user" and new[2]["content"].startswith(RESET_TEXT)
    assert "main at 0x401136" in new[2]["content"] and "- fact: x" in new[2]["content"]
    assert new[3]["content"] == "step 6"
    assert len(new) == 3 + 2 * KEEP_RECENT


def test_compact_without_middle_skips_summary(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    llm = FakeLLM()
    new = compact(build(2), llm, cf, n=1)
    assert llm.prompts == []
    assert new[2]["role"] == "user"


def test_shrink_casefile_rewrites(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    cf.add("facts", "a" * 3000)
    llm = FakeLLM(reply="# Case: p\n\n## Facts\n- short\n\n## Hypotheses\n\n## Todo\n\n## Log\n")
    shrink_casefile(cf, llm)
    assert cf.read().count("a" * 100) == 0 and "- short" in cf.read()
    assert "a" * 3000 in llm.prompts[0]


def test_compact_sanitizes_header_lines(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    llm = FakeLLM(reply="## Facts\n- a\n## Todo\n- b")
    compact(build(10), llm, cf, n=1)
    text = cf.read()
    lines = text.split("\n")
    assert lines.count("## Facts") == 1 and lines.count("## Todo") == 1
    log = text.split("## Log")[1]
    assert "### Facts" in log and "### Todo" in log
    cf.add("facts", "later")
    facts_section = cf.read().split("## Facts")[1].split("## Hypotheses")[0]
    assert "- later" in facts_section


def test_shrink_casefile_returns_bool(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    cf.add("facts", "x")
    before = cf.read()
    llm = FakeLLM(reply="# Case: p\n\n## Facts\n- short\n\n## Hypotheses\n\n## Todo\n\n## Log\n")
    assert shrink_casefile(cf, llm) is True
    assert cf.read() != before

    cf2 = CaseFile(tmp_path / "case2.md", "p", "d")
    before2 = cf2.read()
    llm2 = FakeLLM(reply="garbage")
    assert shrink_casefile(cf2, llm2) is False
    assert cf2.read() == before2

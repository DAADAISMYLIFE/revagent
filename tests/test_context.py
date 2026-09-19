import os
import time

from revagent.casefile import CaseFile
from revagent.context import (compact, format_work_files, list_work_files, serialize,
                              shrink_casefile, split_messages, KEEP_RECENT, RESET_TEXT)


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


def test_shrink_casefile_llm_exception_returns_false(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    cf.add("facts", "x")
    before = cf.read()

    class BoomLLM:
        def complete(self, prompt, system=None):
            raise RuntimeError("server down")

    assert shrink_casefile(cf, BoomLLM()) is False
    assert cf.read() == before
    assert not (tmp_path / "case.md.bak").exists()


def test_shrink_casefile_missing_header_rejected(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    cf.add("facts", "x")
    before = cf.read()
    # missing "## Log"
    llm = FakeLLM(reply="# Case: p\n\n## Facts\n- short\n\n## Hypotheses\n\n## Todo\n- t")
    assert shrink_casefile(cf, llm) is False
    assert cf.read() == before
    assert not (tmp_path / "case.md.bak").exists()


def test_shrink_casefile_rejects_reply_that_looks_cut_off(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    cf.add("facts", "x")
    before = cf.read()
    # has all headers but the reply is truncated mid-sentence, not on a bullet/heading line
    llm = FakeLLM(reply="# Case: p\n\n## Facts\n- short\n\n## Hypotheses\n\n## Todo\n\n## Log\nthe function does")
    assert shrink_casefile(cf, llm) is False
    assert cf.read() == before


def test_shrink_casefile_backs_up_before_overwrite(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    cf.add("facts", "original fact, verbatim")
    before = cf.read()
    llm = FakeLLM(reply="# Case: p\n\n## Facts\n- short\n\n## Hypotheses\n\n## Todo\n\n## Log\n")
    assert shrink_casefile(cf, llm) is True
    backup = tmp_path / "case.md.bak"
    assert backup.exists()
    assert backup.read_text(encoding="utf-8") == before
    assert "original fact, verbatim" in backup.read_text(encoding="utf-8")


def test_shrink_casefile_caps_huge_input(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    cf.add("facts", "a" * 61_000)
    llm = FakeLLM(reply="# Case: p\n\n## Facts\n- short\n\n## Hypotheses\n\n## Todo\n\n## Log\n")
    shrink_casefile(cf, llm)
    assert llm.prompts[0].count("a") <= 60_000 + 100
    assert "truncated" in llm.prompts[0]


def test_compact_excludes_reset_banner_from_next_middle(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    llm = FakeLLM()
    msgs = compact(build(10), llm, cf, n=1)
    assert RESET_TEXT in msgs[2]["content"]

    # Grow the conversation again so the earlier reset banner (msgs[2]) would fall
    # inside "middle" on the next compaction if it weren't filtered out.
    for i in range(10, 20):
        msgs = msgs + exchange(i)
    compact(msgs, llm, cf, n=2)

    assert RESET_TEXT not in llm.prompts[1]


def test_list_work_files_skips_excluded_dirs_and_files(tmp_path):
    since = time.time_ns()
    (tmp_path / "notes_table.json").write_text("{}")
    (tmp_path / "case.md").write_text("case")
    (tmp_path / "case.md.bak").write_text("case bak")
    (tmp_path / "transcript.jsonl").write_text("{}")
    (tmp_path / "result.json").write_text("{}")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("x")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "foo.pyc").write_text("x")
    (tmp_path / ".revagent" / "out").mkdir(parents=True)
    (tmp_path / ".revagent" / "out" / "001.txt").write_text("x")
    (tmp_path / ".revagent" / "ghidra").mkdir(parents=True)
    (tmp_path / ".revagent" / "ghidra" / "cache.json").write_text("x")

    files = list_work_files(tmp_path, since)
    paths = [p for p, _ in files]
    assert "notes_table.json" in paths
    assert not any(p.startswith(".git") for p in paths)
    assert not any(p.startswith("__pycache__") for p in paths)
    assert not any(p.startswith(".revagent/out") for p in paths)
    assert not any(p.startswith(".revagent/ghidra") for p in paths)
    assert "case.md" not in paths
    assert "case.md.bak" not in paths
    assert "transcript.jsonl" not in paths
    assert "result.json" not in paths


def test_list_work_files_honours_since_ns(tmp_path):
    (tmp_path / "old.json").write_text("{}")
    since = time.time_ns()
    time.sleep(0.01)
    (tmp_path / "new.json").write_text("{}")
    files = list_work_files(tmp_path, since)
    paths = [p for p, _ in files]
    assert "new.json" in paths
    assert "old.json" not in paths


def test_list_work_files_respects_limit(tmp_path):
    since = time.time_ns()
    for i in range(5):
        (tmp_path / f"f{i}.json").write_text("{}")
    files = list_work_files(tmp_path, since, limit=2)
    assert len(files) == 2
    assert [p for p, _ in files] == sorted(p for p, _ in files)


def test_list_work_files_returns_relative_posix_path_and_size(tmp_path):
    since = time.time_ns()
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "f.json").write_text("12345")
    files = list_work_files(tmp_path, since)
    assert files == [("sub/f.json", 5)]


def test_format_work_files_empty():
    assert format_work_files([]) == ""


def test_format_work_files_block():
    s = format_work_files([("notes_table.json", 1234), ("sub/x.txt", 9)])
    assert s.startswith("[WORK FILES]")
    assert "- notes_table.json (1234 bytes)" in s
    assert "- sub/x.txt (9 bytes)" in s


def test_compact_appends_work_files_block_after_casefile(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    llm = FakeLLM()
    block = format_work_files([("notes_table.json", 1234)])
    new = compact(build(10), llm, cf, n=1, work_files_block=block)
    content = new[2]["content"]
    assert content.startswith(RESET_TEXT)
    case_idx = content.index(cf.read().strip()[:20])
    wf_idx = content.index("[WORK FILES]")
    assert case_idx < wf_idx


def test_compact_without_work_files_block_omits_section(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    llm = FakeLLM()
    new = compact(build(10), llm, cf, n=1)
    assert "[WORK FILES]" not in new[2]["content"]

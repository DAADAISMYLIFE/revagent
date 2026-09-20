import os
import time

from revagent.casefile import CaseFile
from revagent.context import (compact, extract_unfinished, format_work_files, list_work_files,
                              prune_log, serialize, shrink_casefile, split_messages, KEEP_RECENT,
                              RESET_TEXT, SUMMARY_PROMPT)


class FakeLLM:
    def __init__(self, reply="- fact: x\n- failed: y\n- todo: z"):
        self.reply = reply
        self.prompts = []

    def complete(self, prompt, system=None, **kw):
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
        def complete(self, prompt, system=None, **kw):
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


def test_list_work_files_skips_screens_subtree(tmp_path):
    since = time.time_ns()
    (tmp_path / ".revagent" / "screens").mkdir(parents=True)
    (tmp_path / ".revagent" / "screens" / "001.png").write_bytes(b"\x89PNG")
    files = list_work_files(tmp_path, since)
    paths = [p for p, _ in files]
    assert not any(p.startswith(".revagent/screens") for p in paths)


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


def test_summary_prompt_asks_for_artifacts(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    llm = FakeLLM()
    compact(build(10), llm, cf, n=1)
    assert "(d) ARTIFACTS" in llm.prompts[0]
    assert "Do not invent anything absent from the log." in llm.prompts[0]


def test_summary_prompt_constant_has_artifacts_heading():
    assert "(d) ARTIFACTS" in SUMMARY_PROMPT


def test_extract_unfinished_returns_c_section():
    summary = ("(a) FACTS\n- fact one\n(b) FAILED\n- fail one\n"
               "(c) UNFINISHED\n- todo one\n- todo two\n(d) ARTIFACTS\n- art one")
    out = extract_unfinished(summary)
    assert "- todo one" in out and "- todo two" in out
    assert "fact one" not in out and "art one" not in out


def test_extract_unfinished_to_end_when_no_d():
    summary = "(a) FACTS\n- fact one\n(c) UNFINISHED\n- todo one"
    out = extract_unfinished(summary)
    assert "- todo one" in out


def test_extract_unfinished_empty_when_missing():
    assert extract_unfinished("(a) FACTS\n- fact one\n(b) FAILED\n- fail one") == ""


def test_compact_fills_todo_from_summary_c_section(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    reply = ("(a) FACTS\n- addr 0x401000\n(b) FAILED\n- brute force\n"
             "(c) UNFINISHED\n- try z3 on the byte constraints\n(d) ARTIFACTS\n- table.json: opcode map")
    llm = FakeLLM(reply=reply)
    compact(build(10), llm, cf, n=1)
    todo = cf.read().split("## Todo")[1].split("## Log")[0]
    assert "try z3 on the byte constraints" in todo
    assert "addr 0x401000" not in todo


def test_compact_leaves_todo_unchanged_without_c_section(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    cf.add("todo", "existing todo")
    llm = FakeLLM(reply="(a) FACTS\n- addr 0x401000")
    compact(build(10), llm, cf, n=1)
    todo = cf.read().split("## Todo")[1].split("## Log")[0]
    assert "existing todo" in todo


def test_extract_unfinished_ignores_mid_sentence_c_mention_before_real_heading():
    summary = ('(a) FACTS\n- strings: "Copyright (c) 1998 Foo"\n(b) FAILED\n- fail one\n'
               "(c) UNFINISHED\n- real todo one\n- real todo two\n(d) ARTIFACTS\n- art one")
    out = extract_unfinished(summary)
    assert "real todo one" in out and "real todo two" in out
    assert "Copyright" not in out and "fail one" not in out and "art one" not in out


def test_extract_unfinished_mid_line_d_does_not_truncate_section():
    summary = ("(c) UNFINISHED\n- add (d)ata parsing support\n- another real todo\n"
               "(d) ARTIFACTS\n- art one")
    out = extract_unfinished(summary)
    assert "add (d)ata parsing support" in out
    assert "another real todo" in out
    assert "art one" not in out


def test_extract_unfinished_excludes_heading_line_itself():
    summary = "(c) UNFINISHED\n- todo one"
    out = extract_unfinished(summary)
    assert "(c) UNFINISHED" not in out
    assert out == "- todo one"


def test_format_work_files_caps_block_length(tmp_path):
    files = [(f"very/long/relative/path/to/some/deeply/nested/directory/structure/for/"
              f"testing/purposes/file_number_{i:04d}.json", 1234) for i in range(40)]
    s = format_work_files(files)
    assert len(s) <= 4000
    assert "more files)" in s


def _add_log_block(cf, n):
    text = (f"### compaction {n}\n"
            "(a) FACTS\n- fact\n"
            "(b) FAILED\n- fail\n"
            "(c) UNFINISHED\n- todo\n"
            "(d) ARTIFACTS\n- art")
    cf.add("log", text, bullet=False)


def test_prune_log_reduces_older_blocks_keeps_recent(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    cf.add("log", "pre-existing log note", bullet=True)
    for i in range(1, 6):
        _add_log_block(cf, i)

    n = prune_log(cf, keep=3)
    assert n == 2

    log = cf.read().split("## Log")[1]
    assert "pre-existing log note" in log
    assert log.index("pre-existing log note") < log.index("### compaction 1")

    parts = log.split("### compaction ")
    # parts[0] is the preamble before the first block; parts[1..5] are blocks "1"…"5"
    for i in (1, 2):
        block = parts[i]
        assert "(a)" in block and "(d)" in block
        assert "(b)" not in block and "(c)" not in block
    for i in (3, 4, 5):
        block = parts[i]
        assert "(b)" in block and "(c)" in block

    after_first_prune = cf.read()
    n2 = prune_log(cf, keep=3)
    assert n2 == 0
    assert cf.read() == after_first_prune


def test_compact_prunes_log_to_at_most_keep_unreduced_blocks(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    reply = ("(a) FACTS\n- fact\n(b) FAILED\n- fail\n(c) UNFINISHED\n- todo\n(d) ARTIFACTS\n- art")
    llm = FakeLLM(reply=reply)
    msgs = build(10)
    for n in range(1, 6):
        msgs = compact(msgs, llm, cf, n=n)
        for i in range(10 * n, 10 * n + 10):
            msgs = msgs + exchange(i)

    log = cf.read().split("## Log")[1]
    assert log.count("### compaction") == 5
    assert log.count("(b)") <= 3
    assert log.count("(c)") <= 3


def test_list_work_files_skips_non_regular_files(tmp_path):
    since = time.time_ns()
    (tmp_path / "real.json").write_text("{}")
    fifo_path = tmp_path / "a_fifo"
    os.mkfifo(fifo_path)
    files = list_work_files(tmp_path, since)
    paths = [p for p, _ in files]
    assert "real.json" in paths
    assert "a_fifo" not in paths


def test_shrink_casefile_uses_big_budget_and_rejects_length_cutoff(tmp_path):
    from revagent.context import SHRINK_MAX_TOKENS
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    cf.add("facts", "x")
    before = cf.read()

    class RecordingLLM:
        def __init__(self, finish):
            self.kw = None
            self.last_finish_reason = finish
        def complete(self, prompt, system=None, **kw):
            self.kw = kw
            return "# Case: p\n\n## Facts\n- short\n\n## Hypotheses\n\n## Todo\n\n## Log\n- ok\n"

    llm = RecordingLLM("length")
    assert shrink_casefile(cf, llm) is False and cf.read() == before
    assert llm.kw["max_tokens"] >= 16384 == SHRINK_MAX_TOKENS and llm.kw["reasoning_effort"] == "low"
    assert shrink_casefile(cf, RecordingLLM("stop")) is True


def test_llm_complete_raises_budget_for_one_call_only(monkeypatch):
    from types import SimpleNamespace
    from revagent.llm import LLM
    llm = LLM.__new__(LLM)
    llm.max_tokens = 8192
    llm.tokens_in = llm.tokens_out = 0
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


def test_prune_log_keeps_obs_and_critic_bullets(tmp_path):
    from revagent.context import prune_log
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    for n in range(1, 6):
        cf.add("log", f"### compaction {n}\n## (a) FACTS\n- fact {n}\n## (b) FAILED\n- fail {n}\n"
                      f"## (c) UNFINISHED\n- todo {n}\n## (d) ARTIFACTS\n- art {n}", bullet=False)
        cf.add("log", f"[obs step {n}] run_gui x.exe: windows: W")
        cf.add("log", f"[critic step {n}] try clicking")
    reduced = prune_log(cf, keep=3)
    assert reduced == 2
    text = cf.read()
    for n in range(1, 6):
        assert f"- [obs step {n}] run_gui x.exe: windows: W" in text
        assert f"- [critic step {n}] try clicking" in text
    assert "- fail 1" not in text and "- todo 1" not in text and "- fact 1" in text


def test_shrink_prompt_mentions_obs_lines():
    from revagent.context import SHRINK_PROMPT
    assert "[obs" in SHRINK_PROMPT and "[critic" in SHRINK_PROMPT

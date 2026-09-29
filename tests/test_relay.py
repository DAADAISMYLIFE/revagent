"""Relay runs: short sessions that carry only the case file, with a Fact audit between sessions."""
import json
from pathlib import Path

from revagent import __main__ as main_mod
from revagent import relay
from revagent.agent import Agent
from revagent.casefile import CaseFile
from revagent.relay import (audit, evidence_for, fact_bullets, parse_verdicts, quote_found, run_relay,
                            session_evidence)
from revagent.tools import notes
from tests.conftest import FakeLLM, make_ctx
from tests.test_agent import ScriptedLLM, _patch_host, _patch_sandbox, _result, _write_result, make_problem


def _case(tmp_path, facts=(), log=()):
    cf = CaseFile(tmp_path / ".revagent" / "case.md", "t", "d")
    for f in facts:
        cf.add("facts", f)
    for l in log:
        cf.add("log", l)
    return cf


EVIDENCE = ["$ objdump -d chal | grep cmp\n  401136: 3c 55    cmp al,0x55\n  401138: 75 0a    jne 401144",
            "run_binary chal stdin='AAAA'\nexit 1\nstdout: Wrong",
            "emulate check_len: strlen compared with 8 (rdi=8 -> returns 1, rdi=4 -> returns 0)"]


# ---- pieces -------------------------------------------------------------------------------------

def test_parse_verdicts_reads_quotes_and_ignores_noise():
    v = parse_verdicts('Sure.\nF1 SUPPORTED "cmp al,0x55"\n- F2: contradicted `stdout: Wrong`\nF3 UNSUPPORTED\n'
                       'F1 CONTRADICTED "x"\nF4 SUPPORTED "key = 0x1337" (from "trace-2")\nF5 SUPPORTED "a "b" c"')
    assert v[1] == ("SUPPORTED", ["cmp al,0x55"])
    assert v[2] == ("CONTRADICTED", ["stdout: Wrong"])
    assert v[3] == ("UNSUPPORTED", [])
    assert v[4][1][0] == "key = 0x1337"                     # the first quoted span, not the greedy one
    assert 'a "b" c' in v[5][1]                             # a quote holding quotes survives as a candidate


def test_evidence_for_prefers_lines_with_the_facts_constants():
    lines = [l for d in EVIDENCE for l in d.splitlines()]
    ev = evidence_for("each byte is compared with 0x55 at 401136", lines)
    assert ev[0].startswith("401136: 3c 55")


def test_quote_found_ignores_whitespace_case_and_escaped_quotes_but_not_inventions():
    corpus = relay._norm("\n".join(EVIDENCE))
    fact = "check compares with 0x55"
    assert quote_found('read x; [ \\"$x\\" = abc ]', "uses read then compares with abc", relay._norm('read x; [ "$x" = abc ]'), [])
    assert quote_found("CMP  al,0x55", fact, corpus, [])
    assert not quote_found("cmp al,0x66", fact, corpus, [])
    assert not quote_found("stdout: Wrong", fact, corpus, [])   # in the evidence, but not about this Fact


def test_quote_fuzzy_fallback_is_for_support_only():
    lines = ["401136: 3c 55 cmp al,0x55 ; key_check loop"]
    fact = "key_check compares al with 0x55 at 401136"
    para = "key_check: cmp al with 0x55 at 401136"
    assert quote_found(para, fact, relay._norm(lines[0]), lines, fuzzy=True)
    assert not quote_found(para, fact, relay._norm(lines[0]), lines, fuzzy=False)


def test_fact_bullets_flattens_multiline_bullets(tmp_path):
    cf = _case(tmp_path, ["key is 0x55\nused at 401136", "second"])
    assert fact_bullets(cf.read()) == ["key is 0x55 used at 401136", "second"]


def test_session_evidence_skips_outputs_that_are_the_case_file(tmp_path):
    t = tmp_path / "transcript.jsonl"
    call = lambda i, name, args: {"id": i, "function": {"name": name, "arguments": args}}
    rows = [{"role": "assistant", "tool_calls": [call("a", "notes", '{"action": "read"}'),
                                                 call("b", "bash", '{"cmd": "cat .revagent/case.md"}'),
                                                 call("c", "bash", '{"cmd": "objdump -d chal"}')]},
            {"role": "tool", "tool_call_id": "a", "content": "## Facts\n- key is 0x55"},
            {"role": "tool", "tool_call_id": "b", "content": "## Facts\n- key is 0x55"},
            {"role": "tool", "tool_call_id": "c", "content": "cmp al,0x55"}]
    t.write_text("".join(json.dumps(r) + "\n" for r in rows))
    assert session_evidence(t, 0) == ["cmp al,0x55"]


def test_session_evidence_reads_tool_outputs_after_the_offset(tmp_path):
    t = tmp_path / "transcript.jsonl"
    t.write_text(json.dumps({"role": "tool", "content": "old"}) + "\n")
    off = t.stat().st_size
    with open(t, "a") as f:
        for m in ({"role": "tool", "content": "new"}, {"role": "assistant", "content": "thinking"},
                  {"role": "user", "content": "[start observation] trace"}, {"role": "user", "content": "nudge"}):
            f.write(json.dumps(m) + "\n")
    assert session_evidence(t, off) == ["new", "[start observation] trace"]


def test_retract_prefers_exact_hits_over_whitespace_collapsed_ones(ctx):
    ctx.casefile.add("facts", "key is 0x10")
    ctx.casefile.add("facts", "table at 0x4000; key is\n0x10 xor input")
    assert notes._retract(ctx, "key is 0x10", "r").startswith("retracted")
    assert "table at 0x4000" in ctx.casefile.read().split("## Hypotheses")[0]


def test_retract_matches_a_flattened_multiline_bullet_and_labels_the_audit(ctx):
    ctx.casefile.add("facts", "key is 0x55\nused at 401136")
    assert notes._retract(ctx, "key is 0x55 used at 401136", "r", where="audit 2").startswith("retracted")
    body = ctx.casefile.read()
    assert "- [retracted audit 2] key is 0x55 used at 401136 — because r" in body
    assert "0x55" not in body.split("## Facts")[1].split("## Hypotheses")[0]


# ---- the audit ----------------------------------------------------------------------------------

def test_audit_keeps_supported_and_demotes_unsupported_and_fake_quotes(tmp_path):
    cf = _case(tmp_path, ["check compares each byte with 0x55 (cmp at 401136)",
                          "the flag is DH{guessed_in_head}",
                          "program prints Correct on success"])
    llm = FakeLLM('F1 SUPPORTED "cmp al,0x55"\nF2 UNSUPPORTED\nF3 SUPPORTED "stdout: Correct"')
    rec = audit(llm, cf, EVIDENCE, earlier=set(), after_session=1)
    assert rec["facts"] == 3 and rec["error"] is None
    # unverified is not refuted: both leave Facts but survive as Hypotheses (relativity run 9 lost a correct one)
    assert rec["retracted"] == []
    assert rec["demoted"] == ["the flag is DH{guessed_in_head}", "program prints Correct on success"]
    body = cf.read()
    assert fact_bullets(body) == ["check compares each byte with 0x55 (cmp at 401136)"]
    hyp = body[body.index("## Hypotheses"):body.index("## Todo")]
    assert "[unverified after session 1] the flag is DH{guessed_in_head}" in hyp
    assert "[unverified after session 1] program prints Correct on success" in hyp
    assert "no tool output supports it; kept as a Hypothesis" in body
    assert "its quoted support is not in the tool outputs" in body
    assert "- [audit 1] 3 Facts checked, 0 retracted, 2 moved to Hypotheses, 1 kept" in body
    assert "F1: check compares" in llm.prompts[0] and "| 401136: 3c 55" in llm.prompts[0]
    assert llm.kw == {"max_tokens": relay.AUDIT_MAX_TOKENS, "reasoning_effort": "low"}


def test_audit_only_retracts_earlier_facts_on_a_found_contradiction(tmp_path):
    old1, old2, old3 = "binary is packed with UPX", "check_len wants strlen 4", "main loops 3 times at 401136"
    cf = _case(tmp_path, [old1, old2, old3])
    earlier = {relay._norm(f) for f in (old1, old2, old3)}
    llm = FakeLLM('F1 UNSUPPORTED\nF2 CONTRADICTED "strlen compared with 8"\n'
                  'F3 CONTRADICTED "stdout: Wrong"')          # F3: a real line, but not about that Fact
    rec = audit(llm, cf, EVIDENCE, earlier, after_session=2)
    assert rec["retracted"] == [old2]
    assert fact_bullets(cf.read()) == [old1, old3]
    assert "(earlier)" in llm.prompts[0]


def test_audit_treats_a_reworded_earlier_fact_as_earlier(tmp_path):
    cf = _case(tmp_path, ["VM dispatch loop at 0x401136 reads opcode from table_402000"])
    earlier = {relay._norm("dispatch loop at 0x401136 reads the opcode from table_402000")}
    rec = audit(FakeLLM("F1 UNSUPPORTED"), cf, EVIDENCE, earlier, 2)
    assert rec["retracted"] == []


def test_audit_does_not_let_a_fact_quote_itself(tmp_path):
    fact = "the flag check xors input with 0x37 then compares to table_401200"
    cf = _case(tmp_path, [fact])
    llm = FakeLLM(f'F1 SUPPORTED "{fact}"')
    rec = audit(llm, cf, [f"## Facts\n- {fact}"], set(), 1)   # e.g. a `cat` of a copy of the notes
    assert "| - the flag check" not in llm.prompts[0]
    assert rec["retracted"] == [] and rec["demoted"] == [fact]


def test_audit_ignores_grep_hits_in_the_notes_and_pieces_of_multiline_facts(tmp_path):
    fact = "the flag check xors input with 0x37 then compares to table_401200"
    multi = "decoder at 0x401500 walks table_402000\nand writes each result into buffer_403000"
    cf = _case(tmp_path, [fact, multi])
    llm = FakeLLM(f'F1 SUPPORTED "{fact}"\nF2 SUPPORTED "and writes each result into buffer_403000"')
    ev = [f"./.revagent/case.md:7:- {fact}", "notes_copy.txt:9:  and writes each result into buffer_403000"]
    rec = audit(llm, cf, ev, set(), 1)
    assert len(rec["demoted"]) == 2 and rec["retracted"] == []


def test_audit_keeps_a_fact_copied_from_the_obs_ledger(tmp_path):
    fact = "run_binary chal stdin=AAAA: stdout Wrong exit 1"
    cf = _case(tmp_path, [fact], [f"[obs step 3] {fact}"])
    rec = audit(FakeLLM(f'F1 SUPPORTED "[obs step 3] {fact}"'), cf, [], set(), 1)
    assert rec["retracted"] == []


def test_audit_keeps_a_supported_fact_without_distinctive_tokens(tmp_path):
    cf = _case(tmp_path, ["key is 42"])
    rec = audit(FakeLLM('F1 SUPPORTED "mov edi, 42 ; key is 42"'), cf, ["mov edi, 42 ; key is 42"], set(), 1)
    assert rec["retracted"] == []


def test_is_earlier_needs_enough_tokens_for_a_rewording():
    assert not relay.is_earlier("input length is 0x37", {relay._norm("key is 0x37")})
    assert relay.is_earlier("dispatch loop at 0x401136 reads opcode table_402000",
                            {relay._norm("dispatch loop at 0x401136 reads the opcode from table_402000")})


def test_fuzzy_support_needs_one_line_not_the_whole_pack():
    fact = "key_check compares al with 0x55 at 401136"
    spread = ["key_check prologue", "cmp al,0x55", "401136: 3c 55"]
    assert not quote_found("key_check compares 0x55 401136", fact, "", spread, fuzzy=True)


def test_audit_that_fails_retracts_nothing_but_leaves_a_ledger_line(tmp_path):
    for llm in (FakeLLM(raise_=True), FakeLLM("I think they look fine."), FakeLLM("F1 UNSUPPORTED", finish="length")):
        d = tmp_path / str(id(llm))
        cf = _case(d, ["unverified claim"])
        rec = audit(llm, cf, EVIDENCE, set(), 1)
        assert rec["retracted"] == [] and rec["error"]
        assert fact_bullets(cf.read()) == ["unverified claim"]
        assert "- [audit 1] 1 Facts checked, 0 retracted, 0 moved to Hypotheses, 1 kept (audit failed:" in cf.read()


def test_audit_without_facts_makes_no_call(tmp_path):
    cf = _case(tmp_path)
    llm = FakeLLM()
    assert audit(llm, cf, EVIDENCE, set(), 1)["facts"] == 0
    assert llm.prompts == []


def test_audit_caps_retractions(tmp_path):
    facts = [f"claim number {i} about 0x{i:02x}" for i in range(relay.AUDIT_MAX_RETRACT + 3)]
    cf = _case(tmp_path, facts)
    llm = FakeLLM("\n".join(f"F{i + 1} UNSUPPORTED" for i in range(len(facts))))
    rec = audit(llm, cf, EVIDENCE, set(), 1)
    assert len(rec["demoted"]) == relay.AUDIT_MAX_RETRACT and rec["skipped_over_cap"] == 3


def test_audit_sees_the_observation_ledger(tmp_path):
    cf = _case(tmp_path, ["running with AAAA prints Wrong"], ["[obs step 3] run_binary chal: stdout Wrong exit 1"])
    llm = FakeLLM('F1 SUPPORTED "[obs step 3] run_binary chal: stdout Wrong"')
    assert audit(llm, cf, [], set(), 1)["retracted"] == []
    assert "OBSERVATION LEDGER:\n- [obs step 3]" in llm.prompts[0]


# ---- the relay loop -----------------------------------------------------------------------------

class _FakeAgent:
    """Records construction and relay_note; each run() pops the next result and may touch the case file."""
    made = []

    def __init__(self, d, desc, llm, **kw):
        self.d, self.kw = Path(d), kw
        self.casefile = CaseFile(self.d / ".revagent" / "case.md", "t", desc)
        self.relay_note = None
        _FakeAgent.made.append(self)

    def run(self):
        r, action = _FakeAgent.script.pop(0)
        if action:
            action(self)
        (self.d / ".revagent" / "result.json").write_text(json.dumps(r))
        return r


class _Tokens:
    total_prompt_tokens = total_completion_tokens = total_retries = 0


def _relay(tmp_path, script, sessions=3, llm=None, **kw):
    _FakeAgent.made, _FakeAgent.script = [], list(script)
    return run_relay(tmp_path, "desc", llm or _Tokens(), sessions, agent_cls=_FakeAgent, **kw)


def test_relay_splits_budget_carries_notes_and_audits_between_sessions(tmp_path, monkeypatch):
    audits = []
    monkeypatch.setattr(relay, "audit", lambda llm, cf, ev, earlier, k, *rest: audits.append((k, set(earlier))) or
                        {"after_session": k, "facts": 1, "retracted": ["x"], "error": None})
    add = lambda a: a.casefile.add("facts", "found the check at 0x401136")
    out = _relay(tmp_path, [(_result(status="unsolved", flag=None, reason="step limit", steps=10), add),
                            (_result(status="unsolved", flag=None, reason="step limit", steps=10), None),
                            (_result(steps=4), None)], sessions=3, max_steps=30, max_minutes=60)
    made = _FakeAgent.made
    assert [a.kw["max_steps"] for a in made] == [10, 10, 10]
    assert made[0].kw["max_minutes"] == 20
    assert made[0].relay_note.startswith("[RELAY] This is session 1 of 3")
    assert "found the check at 0x401136" not in made[0].relay_note
    assert made[1].relay_note.startswith("[RELAY] This is session 2 of 3")
    assert "Nothing from the earlier sessions' conversation is carried over" in made[1].relay_note
    assert "- found the check at 0x401136" in made[1].relay_note
    assert [k for k, _ in audits] == [1, 2]                          # between sessions, never after the last
    assert audits[0][1] == set()                                    # nothing inherited from before the relay
    assert audits[1][1] == {"found the check at 0x401136"}          # kept by audit 1: "earlier" from then on
    assert out["status"] == "solved" and out["steps"] == 24
    assert [s["status"] for s in out["relay"]["sessions"]] == ["unsolved", "unsolved", "solved"]
    assert len(out["relay"]["audits"]) == 2
    on_disk = json.loads((tmp_path / ".revagent" / "result.json").read_text())
    assert on_disk["relay"]["planned"] == 3 and on_disk["steps"] == 24
    assert json.loads((tmp_path / ".revagent" / "results.jsonl").read_text().splitlines()[-1])["relay"]


def test_relay_stops_early_on_solved_runbook_or_a_dead_server(tmp_path, monkeypatch):
    monkeypatch.setattr(relay, "audit", lambda *a: (_ for _ in ()).throw(AssertionError("no audit expected")))
    for first in (_result(), _result(status="runbook", flag=None),
                  _result(status="unsolved", flag=None, reason="error: APIConnectionError", steps=1,
                          signals={"tool_calls": {}})):
        out = _relay(tmp_path, [(first, None), (_result(), None)], sessions=2)
        assert len(_FakeAgent.made) == 1 and out["status"] == first["status"]


def test_relay_stops_when_the_real_agent_meets_a_dead_server(tmp_path, monkeypatch):
    monkeypatch.setattr(relay, "audit", lambda *a: (_ for _ in ()).throw(AssertionError("no audit expected")))
    d = make_problem(tmp_path)
    llm = ScriptedLLM([RuntimeError("connection refused"), RuntimeError("connection refused")])
    out = run_relay(d, "", llm, 3, max_steps=9, max_minutes=10)
    assert len(out["relay"]["sessions"]) == 1 and out["reason"].startswith("error:")


def test_relay_numbers_new_out_files_after_the_old_ones(tmp_path):
    out = tmp_path / ".revagent" / "out"
    out.mkdir(parents=True)
    (out / "007.txt").write_text("x")
    (out / "trace-12.ops.txt").write_text("x")

    class WithCtx(_FakeAgent):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.ctx = type("C", (), {"out_counter": 0})()

    _FakeAgent.made, _FakeAgent.script = [], [(_result(), None)]
    run_relay(tmp_path, "", _Tokens(), 2, agent_cls=WithCtx)
    assert _FakeAgent.made[0].ctx.out_counter == 12


def test_relay_with_no_time_left_still_reports_session_one(tmp_path):
    out = _relay(tmp_path, [(_result(status="unsolved", flag=None, reason="time limit", steps=0), None)],
                 sessions=2, max_minutes=0)
    assert out["status"] == "unsolved" and len(_FakeAgent.made) == 1


def test_relay_treats_inherited_facts_as_earlier(tmp_path, monkeypatch):
    _case(tmp_path, ["fact from an older run"])
    seen = []
    monkeypatch.setattr(relay, "audit", lambda llm, cf, ev, earlier, k, *rest: seen.append(set(earlier)) or
                        {"after_session": k, "facts": 1, "retracted": [], "error": None})
    _relay(tmp_path, [(_result(status="unsolved", flag=None, steps=3), None), (_result(), None)], sessions=2)
    assert seen == [{"fact from an older run"}]


def test_relay_end_to_end_with_the_real_agent(tmp_path):
    """Two real sessions: session 1 reads the script and writes a Fact, the audit keeps it on a quote from the
    bash output, session 2 starts from an empty conversation that carries the case file."""
    d = make_problem(tmp_path)

    class LLM(ScriptedLLM):
        def complete(self, prompt, system=None, **kw):
            self.completes.append(prompt)
            if prompt.startswith(relay.AUDIT_PROMPT):
                return 'F1 SUPPORTED "[ \\"$x\\" = abc ] && echo Correct"'
            return "- summary bullet"

    llm = LLM([[("bash", {"cmd": "cat chal"})],
               [("notes", {"action": "add", "text": "chal prints Correct when stdin equals abc ([ \"$x\" = abc ])"})],
               [("bash", {"cmd": "true"})], [("bash", {"cmd": "true"})]])
    out = run_relay(d, "", llm, 2, max_steps=4, max_minutes=10)
    assert [s["steps"] for s in out["relay"]["sessions"]] == [2, 2]
    hist = [json.loads(l) for l in (d / ".revagent" / "results.jsonl").read_text().splitlines()]
    assert [h.get("relay_session") for h in hist] == [1, 2, None] and "relay" in hist[-1]
    assert out["relay"]["audits"][0]["retracted"] == [] and out["relay"]["audits"][0]["facts"] == 1
    second = llm.seen[2]                                    # the first chat() of session 2
    assert [m["role"] for m in second] == ["system", "user", "user"]
    assert second[2]["content"].startswith("[RELAY] This is session 2 of 2")
    assert "chal prints Correct when stdin equals abc" in second[2]["content"]
    assert "[audit 1] 1 Facts checked, 0 retracted, 0 moved to Hypotheses, 1 kept" in second[2]["content"]
    assert json.loads((d / ".revagent" / "result.json").read_text())["relay"]["planned"] == 2


def test_agent_without_relay_note_is_unchanged(tmp_path):
    d = make_problem(tmp_path)
    llm = ScriptedLLM([[("bash", {"cmd": "true"})]])
    Agent(d, "", llm, max_steps=1, interactive=False).run()
    assert [m["role"] for m in llm.seen[0]] == ["system", "user"]


# ---- CLI ----------------------------------------------------------------------------------------

def test_bench_host_relay_calls_run_relay(tmp_path, monkeypatch, capsys):
    d = tmp_path / "a"
    d.mkdir()
    fake = _patch_host(monkeypatch, lambda p: _result())
    got = []
    monkeypatch.setattr(main_mod, "run_relay", lambda d_, desc, llm, n, **kw: got.append((d_.name, n, kw)) or
                        _result(steps=7))
    assert main_mod.main(["bench", str(d), "--host", "--relay", "3", "--max-steps", "90"]) == 0
    assert got == [("a", 3, {"max_steps": 90, "max_minutes": 120, "interactive": False, "show_thinking": False})]
    assert fake.calls == []
    assert "| a | solved | DH{x} | 7 |" in capsys.readouterr().out


def test_bench_sandbox_passes_relay_through(tmp_path, monkeypatch):
    d = tmp_path / "a"
    d.mkdir()
    cmds = []

    def fake_run(cmd, env_extra=None):
        cmds.append(cmd)
        _write_result(d)
        return 0

    _patch_sandbox(monkeypatch, fake_run)
    assert main_mod.main(["bench", str(d), "--relay", "4"]) == 0
    tail = cmds[0][cmds[0].index("solve"):]
    assert tail[tail.index("--relay") + 1] == "4" and "--host" in tail


def test_relay_off_by_default_and_negative_rejected(tmp_path, monkeypatch, capsys):
    d = tmp_path / "a"
    d.mkdir()
    cmds = []
    _patch_sandbox(monkeypatch, lambda cmd, env_extra=None: cmds.append(cmd) or _write_result(d) or 0)
    main_mod.main(["bench", str(d)])
    assert "--relay" not in cmds[0]
    assert main_mod.main(["bench", str(d), "--relay", "-1"]) == 2
    assert "--relay" in capsys.readouterr().err


def test_a_contradiction_must_come_after_the_fact_was_written(tmp_path):
    """relativity run 9: audit 1 retracted a correct Fact on the output of the buggy parser the model had already
    replaced (step 7) before writing the Fact (step 15)."""
    fact = "rela.tivity has 300 PC32 entries whose addends point into rodata 0x6798"
    cf = _case(tmp_path, [fact])
    docs = ["total 0 | pc32: 0 | addends in rodata: 0",            # buggy script, seen before the Fact
            "total 400 | pc32: 300 | first: ('0x778', '0x6798')"]  # fixed script, the Fact's source
    adds = [(2, fact)]                                             # written after both outputs
    llm = FakeLLM('F1 CONTRADICTED "addends in rodata: 0"')
    assert audit(llm, cf, docs, {relay._norm(fact)}, 1, adds)["retracted"] == []
    later = docs + ["recheck: addends in rodata: 0 (parsed properly this time)"]
    cf2 = _case(tmp_path / "b", [fact])
    assert audit(FakeLLM('F1 CONTRADICTED "addends in rodata: 0 (parsed properly"'), cf2, later,
                 {relay._norm(fact)}, 1, adds)["retracted"] == [fact]


def test_session_record_notes_when_each_fact_was_written(tmp_path):
    t = tmp_path / "transcript.jsonl"
    call = lambda i, name, args: {"id": i, "function": {"name": name, "arguments": json.dumps(args)}}
    rows = [{"role": "assistant", "tool_calls": [call("a", "bash", {"cmd": "x"})]},
            {"role": "tool", "tool_call_id": "a", "content": "out1"},
            {"role": "assistant", "tool_calls": [call("b", "notes", {"action": "add", "text": "key is 0x55"}),
                                                 call("c", "notes", {"action": "add", "section": "todo", "text": "t"})]},
            {"role": "tool", "tool_call_id": "b", "content": "added to facts"}]
    t.write_text("".join(json.dumps(r) + "\n" for r in rows))
    docs, adds = relay.session_record(t, 0)
    assert docs == ["out1"] and adds == [(1, "key is 0x55")]
    assert relay.written_after("key is 0x55", adds) == 1 and relay.written_after("other", adds) == 0

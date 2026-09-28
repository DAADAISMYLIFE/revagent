"""Relay: one challenge as several short sessions. Each session is a fresh Agent (empty conversation) on the same
challenge directory; the only thing carried from one session to the next is the case file (notes). Between two
sessions a short audit checks every Fact against the observation record (the [obs ...] ledger and the tool
outputs of the session that just ended) and retracts the Facts that an observation contradicts, plus the new
Facts that no tool output supports. Live runs kept wrong Facts for a whole run and handed them to the next one
(damnida run 3, ROVM run 6); a session boundary is the natural place to drop them before they are inherited."""
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from .agent import Agent
from .casefile import section_span
from .tools.notes import _bullets, _retract

AUDIT_MAX_TOKENS = 8192          # thinking counts toward it; the answer itself is one short line per Fact
AUDIT_EFFORT = "low"
AUDIT_MAX_RETRACT = 8            # a runaway audit must not wipe a whole case file in one go
EVIDENCE_LINES_PER_FACT = 6
EVIDENCE_LINE_CHARS = 300
OBS_LEDGER_LINES = 40
MIN_QUOTE_CHARS = 6

RELAY_NOTE = ("[RELAY] This is session {k} of {n} on this challenge. It ends after {steps} steps or {minutes} "
              "minutes; the next session starts with an empty conversation and gets only the case file (notes), so "
              "write every conclusion, artifact path and next step to notes as you go. Between sessions an audit "
              "checks each Fact against the tool outputs and moves contradicted or unsupported ones to the Log as "
              "[retracted].")
RELAY_CARRY = ("Nothing from the earlier sessions' conversation is carried over. The case file below is everything "
               "they left; files they wrote are still on disk. Continue from the Todo section, and re-verify with a "
               "tool before building on anything that was retracted.\n\n")

AUDIT_PROMPT = (
    "You audit the Facts of a reverse-engineering case file between two work sessions. A Fact must rest on tool "
    "output. For each Fact below you get the evidence lines found for it in the tool outputs of the session that "
    "just ended; the observation ledger follows. Answer exactly one line per Fact and nothing else:\n"
    "F<n> SUPPORTED \"<quote>\"\n"
    "F<n> CONTRADICTED \"<quote>\"\n"
    "F<n> UNSUPPORTED\n"
    "The quote is copied character for character from the evidence text below (part of one line). A Fact derived "
    "from numbers in the evidence is SUPPORTED by the line holding those numbers. Observation (program output, "
    "traces, emulation, debugger values) outranks decompiler/disassembly output: a Fact that follows the "
    "decompiler where an observation disagrees is CONTRADICTED. Facts marked (earlier) survived a previous audit: "
    "answer SUPPORTED or CONTRADICTED for them, missing evidence this session is not a reason to drop them.\n\n"
)

_TOKEN = re.compile(r"0x[0-9a-f]+|[a-z_][a-z0-9_]{3,}|\d{3,}")
_STOP = frozenset("""this that with from into when then each byte bytes input value values function check string
    flag returns return called address true false after before which where there their must only also every
    same than they them does done used uses using have been will would should could about length size data
    first last next number""".split())
_VERDICT = re.compile(r"^\W*F(\d+)\W+(SUPPORTED|CONTRADICTED|UNSUPPORTED)\b(.*)$", re.I)
_QUOTES = (re.compile(r'"(.+?)"'), re.compile(r'"(.+)"'), re.compile(r"`(.+?)`"), re.compile(r"'(.+)'"))
EARLIER_JACCARD = 0.8            # a reworded earlier Fact (shrink_casefile, a re-add) still counts as earlier


def _norm(s: str) -> str:
    return " ".join(s.lower().split())


def _tokens(s: str) -> set[str]:
    return {t for t in _TOKEN.findall(s.lower()) if t not in _STOP}


def fact_bullets(text: str) -> list[str]:
    """The Facts section's bullets, each flattened to one line without the leading '- '."""
    lines = text.split("\n")
    span = section_span(lines, "facts")
    if span is None:
        return []
    return [" ".join(" ".join(lines[a:b]).split())[2:] for a, b in _bullets(lines, *span)]


def obs_ledger(text: str) -> list[str]:
    return [l for l in text.split("\n") if l.startswith("- [obs ")]


def _reads_case_file(name: str, args: str) -> bool:
    """A tool call whose output is the case file itself (`notes`, or a shell reading case.md): its text would let
    every Fact quote itself as its own evidence."""
    return name == "notes" or "case.md" in (args or "")


def session_evidence(transcript: Path, offset: int) -> list[str]:
    """Tool outputs (and the harness's [start observation]) logged to transcript.jsonl after byte `offset`,
    except the outputs of calls that read the case file."""
    docs, calls = [], {}
    try:
        with open(transcript, "rb") as f:
            f.seek(offset)
            raw = f.read().decode("utf-8", errors="replace")
    except OSError:
        return docs
    for line in raw.splitlines():
        try:
            m = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(m, dict):
            continue
        if m.get("role") == "assistant":
            # tool messages follow the assistant message that made the calls; ids are only unique within it
            calls = {tc.get("id"): tc.get("function") or {} for tc in m.get("tool_calls") or []}
            continue
        content = m.get("content")
        if not isinstance(content, str) or not content:
            continue
        if m.get("role") == "tool":
            fn = calls.get(m.get("tool_call_id"), {})
            if not _reads_case_file(fn.get("name", ""), fn.get("arguments", "")):
                docs.append(content)
        elif m.get("role") == "user" and content.startswith("[start observation]"):
            docs.append(content)
    return docs


def evidence_for(fact: str, lines: list[str], limit: int = EVIDENCE_LINES_PER_FACT) -> list[str]:
    """The evidence lines sharing the most distinctive tokens with `fact`; hex constants and long numbers weigh
    three times a word. Deterministic retrieval, so the audit call sees a small, targeted pack per Fact."""
    want = _tokens(fact)
    if not want:
        return []
    scored = []
    for i, line in enumerate(lines):
        hit = want & _tokens(line)
        score = sum(3 if (t.startswith("0x") or t.isdigit()) else 1 for t in hit)
        if score >= 2:
            scored.append((-score, i, line))
    scored.sort()
    seen, out = set(), []
    for _, _, line in scored:
        cut = line.strip()[:EVIDENCE_LINE_CHARS]
        if cut not in seen:
            seen.add(cut)
            out.append(cut)
        if len(out) >= limit:
            break
    return out


def parse_verdicts(reply: str) -> dict[int, tuple[str, list[str]]]:
    """{fact number: (VERDICT, quote candidates)}; the first line for a number wins. Candidates are the first
    quoted span, the widest one (a quote may itself contain quotes), backtick and single-quote spans, and the bare
    rest of the line; the audit accepts the verdict when any of them checks out."""
    out: dict[int, tuple[str, list[str]]] = {}
    for line in (reply or "").splitlines():
        m = _VERDICT.match(line.strip())
        if not m:
            continue
        n, verdict, rest = int(m.group(1)), m.group(2).upper(), m.group(3)
        cands = []
        for rx in _QUOTES:
            q = rx.search(rest)
            if q and q.group(1).strip() and q.group(1).strip() not in cands:
                cands.append(q.group(1).strip())
        bare = rest.strip(" :-—")
        if bare and not cands:
            cands.append(bare)
        out.setdefault(n, (verdict, cands))
    return out


def quote_found(quote: str, fact: str, corpus_norm: str, local_lines: list[str], fuzzy: bool = True) -> bool:
    """The quote is about the Fact (shares a distinctive token with it) and appears in the evidence, whitespace
    and case ignored. With `fuzzy` (SUPPORTED only, never a contradiction), a lightly paraphrased quote also
    passes when at least 80% of its (3 or more) distinctive tokens appear in one evidence line shown for that
    Fact."""
    q = _norm(quote.replace('\\"', '"').strip("\"'`"))   # a reply may JSON-escape the quotes inside a quote
    toks, fact_toks = _tokens(q), _tokens(fact)
    if fact_toks and not toks & fact_toks:      # a Fact without distinctive tokens ("key is 42") skips this
        return False
    if len(q) >= MIN_QUOTE_CHARS and q in corpus_norm:
        return True
    if not fuzzy or len(toks) < 3:
        return False
    # one evidence line must carry the paraphrase, not the Fact's tokens spread over the whole pack
    return any(len(toks & _tokens(l)) >= 0.8 * len(toks) for l in local_lines)


_GREP_PREFIX = re.compile(r"^\S+?:\d+[:-]")


def _is_notes_copy(line: str, own: list[str]) -> bool:
    """A line that is the notes rather than evidence: a hit inside the case file or transcript (a `grep -r .`
    from the challenge dir), any line holding a whole Fact, or a case-file bullet/continuation line that is a
    piece of a (multi-line) Fact. Ledger lines ('- [obs ...') are observations and always stay."""
    if line.startswith("- [obs "):
        return False
    if "case.md" in line or "transcript.jsonl" in line:
        return True
    body = _GREP_PREFIX.sub("", line)
    n = _norm(body)
    if any(len(o) >= 20 and o in n for o in own):   # a short Fact ("key is 42") can be a real output line
        return True
    if body.startswith(("- ", "  ")) and len(n) >= 20:
        frag = n[2:] if n.startswith("- ") else n
        return any(frag in o for o in own)
    return False


def is_earlier(fact: str, earlier: set[str]) -> bool:
    """`fact` survived a previous audit (or predates the relay): the same text, or a rewording whose distinctive
    tokens (3 or more on both sides) overlap one of those Facts by EARLIER_JACCARD."""
    if _norm(fact) in earlier:
        return True
    t = _tokens(fact)
    if len(t) < 3:                              # too few tokens to tell a rewording from a different claim
        return False
    return any(len(t & u) >= EARLIER_JACCARD * len(t | u) for u in (_tokens(e) for e in earlier) if len(u) >= 3)


class _AuditCtx:
    """What notes._retract needs: the case file and a step label."""
    def __init__(self, casefile):
        self.casefile = casefile
        self.step = 0


def audit(llm, casefile, evidence_docs: list[str], earlier: set[str], after_session: int) -> dict:
    """One audit between sessions. Retracts (via notes' retract, so the Log keeps '[retracted ...]' lines):
    a Fact whose CONTRADICTED quote is found in the evidence, and a Fact new since the last audit that has no
    SUPPORTED quote found in the evidence. Facts in `earlier` are only ever retracted on a contradiction. A failed
    or unparseable audit call retracts nothing. Leaves one '[audit K]' ledger line. Returns a summary dict;
    never raises."""
    rec = {"after_session": after_session, "facts": 0, "retracted": [], "skipped_over_cap": 0, "error": None}
    try:
        _audit(llm, casefile, evidence_docs, earlier, after_session, rec)
    except Exception as e:   # the audit is advisory bookkeeping: it must never end the relay
        rec["error"] = f"{type(e).__name__}: {e}"[:200]
    try:
        kept = len(fact_bullets(casefile.read()))
        casefile.add("log", f"[audit {after_session}] {rec['facts']} Facts checked, {len(rec['retracted'])} "
                            f"retracted, {kept} kept" + (f" (audit failed: {rec['error']})" if rec["error"] else ""))
    except Exception:
        pass
    return rec


def _audit(llm, casefile, evidence_docs, earlier, after_session, rec) -> None:
    text = casefile.read()
    facts = fact_bullets(text)
    rec["facts"] = len(facts)
    if not facts:
        return
    ledger = obs_ledger(text)
    own = [_norm(f) for f in facts]
    lines = [l for d in ledger + evidence_docs for l in d.splitlines() if l.strip() and not _is_notes_copy(l, own)]
    corpus_norm = _norm("\n".join(lines))
    old = [is_earlier(f, earlier) for f in facts]
    packs, blocks = [], []
    for i, f in enumerate(facts, 1):
        ev = evidence_for(f, lines)
        packs.append(ev)
        body = "\n".join(f"    | {l}" for l in ev) or "    | (no matching line)"
        blocks.append(f"F{i}{' (earlier)' if old[i - 1] else ''}: {f}\n  evidence:\n{body}")
    prompt = (AUDIT_PROMPT + "FACTS:\n" + "\n".join(blocks)
              + "\n\nOBSERVATION LEDGER:\n" + ("\n".join(ledger[-OBS_LEDGER_LINES:]) or "(empty)"))
    reply = llm.complete(prompt, max_tokens=AUDIT_MAX_TOKENS, reasoning_effort=AUDIT_EFFORT)
    if getattr(llm, "last_finish_reason", None) == "length":
        rec["error"] = "reply cut off by the token budget"
        return
    verdicts = parse_verdicts(reply)
    if not verdicts:
        rec["error"] = "no verdict lines in the reply"
        return
    drop = []
    for i, f in enumerate(facts, 1):
        verdict, cands = verdicts.get(i, (None, []))
        if verdict is None:
            continue                                    # no answer for this Fact: keep it
        fuzzy = verdict == "SUPPORTED"
        found = next((q for q in cands if quote_found(q, f, corpus_norm, packs[i - 1], fuzzy)), None)
        if verdict == "CONTRADICTED" and found:
            drop.append((f, f"audit after session {after_session}: contradicted by \"{found[:150]}\""))
        elif not old[i - 1] and not (verdict == "SUPPORTED" and found):
            why = ("its quoted support is not in the tool outputs" if verdict == "SUPPORTED"
                   else "no tool output supports it")
            drop.append((f, f"audit after session {after_session}: {why}"))
    ctx = _AuditCtx(casefile)
    for f, reason in drop[:AUDIT_MAX_RETRACT]:
        if _retract(ctx, f, reason, where=f"audit {after_session}").startswith("retracted"):
            rec["retracted"].append(f[:200])
    rec["skipped_over_cap"] = max(0, len(drop) - AUDIT_MAX_RETRACT)


def _seed_out_counter(agent, work: Path) -> None:
    """A new Agent numbers out/NNN.txt and out/trace-N.* from 1 again, which would overwrite files an earlier
    session wrote and the case file names. Start after the highest id already there."""
    out = work / "out"
    ids = [int(m.group(1)) for f in out.iterdir() if (m := re.match(r"(?:trace-)?(\d+)\.", f.name))] \
        if out.is_dir() else []
    ctx = getattr(agent, "ctx", None)
    if ctx is not None and ids:
        ctx.out_counter = max(ctx.out_counter, max(ids))


def _dead_server(r: dict) -> bool:
    """The session ended on an error before any tool ran (the LLM server is down): later sessions would only
    wait through the same retries."""
    calls = sum(((r.get("signals") or {}).get("tool_calls") or {}).values())
    return r.get("steps", 0) == 0 or (str(r.get("reason", "")).startswith("error:") and calls == 0)


def _sum_counts(dicts: list[dict]) -> dict:
    out: dict = {}
    for d in dicts:
        for k, v in (d or {}).items():
            out[k] = out.get(k, 0) + v
    return out


def run_relay(problem_dir: Path, description: str, llm, sessions: int, max_steps: int = 300,
              max_minutes: float = 120, interactive: bool = False, show_thinking: bool = False,
              agent_cls=Agent) -> dict:
    """Run `sessions` short sessions on one challenge, auditing the Facts between them. The total step and
    minute budgets are split evenly; a session never gets more minutes than the relay has left. Stops early on
    solved or runbook, or when a session ended on an error before any tool ran (the server is down). Writes the aggregate result.json
    (plus a `relay` record) and returns it."""
    problem_dir = Path(problem_dir).resolve()
    work = problem_dir / ".revagent"
    work.mkdir(exist_ok=True)
    transcript = work / "transcript.jsonl"
    steps_per = max(1, max_steps // sessions)
    minutes_per = max_minutes / sessions
    start = time.monotonic()
    tok0 = (llm.total_prompt_tokens, llm.total_completion_tokens, getattr(llm, "total_retries", 0))
    earlier: set[str] | None = None
    results, audits, r = [], [], None
    for k in range(1, sessions + 1):
        left = max_minutes - (time.monotonic() - start) / 60
        if k > 1 and left <= 0:          # session 1 always runs, so there is always a result to report
            break
        minutes = max(0, min(minutes_per, left))
        note = RELAY_NOTE.format(k=k, n=sessions, steps=steps_per, minutes=round(minutes, 1))
        offset = transcript.stat().st_size if transcript.exists() else 0
        agent = agent_cls(problem_dir, description, llm, max_steps=steps_per, max_minutes=minutes,
                          interactive=interactive, show_thinking=show_thinking)
        agent.relay_session = k
        _seed_out_counter(agent, work)
        if earlier is None:
            # Facts inherited from a run before this relay are treated like audited ones: retracted only on a
            # contradiction, since their evidence lives in a transcript this relay did not produce
            earlier = {_norm(f) for f in fact_bullets(agent.casefile.read())}
        agent.relay_note = note if k == 1 else note + "\n" + RELAY_CARRY + agent.casefile.read()
        print(f"\n=== relay session {k}/{sessions} ({steps_per} steps, {minutes:.1f} min) ===", flush=True)
        r = agent.run()
        results.append(r)
        if r["status"] in ("solved", "runbook") or _dead_server(r) or k == sessions:
            break
        rec = audit(llm, agent.casefile, session_evidence(transcript, offset), earlier, k)
        audits.append(rec)
        print(f"=== audit after session {k}: {rec['facts']} Facts, {len(rec['retracted'])} retracted"
              + (f" (failed: {rec['error']})" if rec["error"] else "") + " ===", flush=True)
        earlier = {_norm(f) for f in fact_bullets(agent.casefile.read())}
    calls = _sum_counts([(x.get("signals") or {}).get("tool_calls") for x in results])
    n_calls = sum(calls.values())
    total = {
        **{key: v for key, v in r.items() if key != "relay_session"},
        "steps": sum(x.get("steps", 0) for x in results),
        "compactions": sum(x.get("compactions", 0) for x in results),
        "prompt_tokens": llm.total_prompt_tokens - tok0[0],
        "completion_tokens": llm.total_completion_tokens - tok0[1],
        "llm_retries": getattr(llm, "total_retries", 0) - tok0[2],
        "minutes": round((time.monotonic() - start) / 60, 1),
        "signals": {**(r.get("signals") or {}), "tool_calls": calls,
                    "bash_share": round(calls.get("bash", 0) / n_calls, 2) if n_calls else None,
                    "notes_calls": calls.get("notes", 0)},
        "relay": {
            "planned": sessions,
            "sessions": [{"status": x["status"], "reason": x.get("reason", ""), "steps": x.get("steps", 0),
                          "minutes": x.get("minutes", 0)} for x in results],
            "audits": audits,
        },
    }
    (work / "result.json").write_text(json.dumps(total, indent=2, ensure_ascii=False))
    with open(work / "results.jsonl", "a", encoding="utf-8") as hist:
        hist.write(json.dumps({"time": datetime.now(timezone.utc).isoformat(), **total}, ensure_ascii=False) + "\n")
    print(f"relay: {len(results)} session(s), {len(audits)} audit(s), "
          f"{sum(len(a['retracted']) for a in audits)} Fact(s) retracted, status {total['status']}", flush=True)
    return total

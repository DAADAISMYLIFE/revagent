"""Critic: a separate, cheap LLM call that reviews the case file and the last few tool exchanges and
answers four fixed questions. It runs before every compaction and after CRITIC_IDLE_STEPS steps without
new Facts/observations. Its memo is advice injected as a user message, not an instruction the loop enforces."""
from .casefile import section_span
from .context import sanitize_summary

CRITIC_IDLE_STEPS = 12
CRITIC_MAX = 8
CRITIC_MAX_TOKENS = 4096
CRITIC_MAX_LINES = 6
RECENT_ARG_CHARS = 200
RECENT_RESULT_CHARS = 300

CRITIC_PROMPT = (
    "You are reviewing an autonomous reverse-engineering session that may be stuck. Below is its case file "
    "(notes) and its most recent tool calls. Answer these four questions, one short line each, no preamble:\n"
    "1. Which observation ([obs ...] lines, run outputs, screenshots) contradicts the current plan (first Todo item)? "
    "Quote it, or say 'none'.\n"
    "2. Is the same approach being repeated? Name it and how many times.\n"
    "3. The single cheapest, most decisive next experiment, written as a concrete tool call "
    "(e.g. run_gui with actions [...], run_binary with stdin ..., bash ...).\n"
    "4. Is there tool evidence that this environment cannot execute the target ('[cannot run here]', "
    "no window ever appeared, crash on start)? Quote it or say 'none'. If there is, say explicitly: "
    "'the sandbox cannot run this program; handoff_runbook is allowed'.\n"
    "Prefer observation over decompilation. If a byte stream is being displayed, ask what it decodes to.\n\n"
)


def progress_marker(casefile_text: str) -> tuple[int, int]:
    """(number of Facts bullets, number of '- [obs' lines). Used to detect steps without progress."""
    lines = casefile_text.split("\n")
    n_facts = 0
    span = section_span(lines, "facts")
    if span is not None:
        start, end = span
        n_facts = sum(1 for line in lines[start + 1:end] if line.startswith("- "))
    n_obs = sum(1 for l in lines if l.startswith("- [obs "))
    return n_facts, n_obs


def render_recent(messages: list[dict], n: int = CRITIC_IDLE_STEPS) -> str:
    """The last n (assistant tool call, tool result) pairs as compact text."""
    pairs: list[str] = []
    results = {m.get("tool_call_id"): m.get("content", "") for m in messages if m.get("role") == "tool"}
    for m in messages:
        if m.get("role") != "assistant":
            continue
        for tc in m.get("tool_calls") or []:
            fn = tc.get("function", {})
            args = (fn.get("arguments") or "")[:RECENT_ARG_CHARS]
            res = (results.get(tc.get("id")) or "")[:RECENT_RESULT_CHARS]
            pairs.append(f"> {fn.get('name')} {args}\n< {res}")
    return "\n".join(pairs[-n:])


def run_critic(llm, casefile, messages: list[dict], step: int) -> str | None:
    """One critic call. Writes one '- [critic step N] <line>' ledger bullet per memo line and
    returns the memo, or None.

    The memo is model text going into the case file, so it gets the same `sanitize_summary` guard
    as a compaction summary: a line that exactly matches a canonical header ("## Facts" — question
    1 asks the critic to quote the case file) would otherwise split the Log section. One bullet per
    line, rather than one bullet with indented continuations, is what makes the memo survive
    `prune_log`: `_is_ledger_line` then holds for every line of it by construction.

    Reading the case file and rendering the recent calls happen inside the try, so a case file the
    model deleted degrades to None + a "(failed: ...)" ledger line instead of ending the run."""
    try:
        prompt = (CRITIC_PROMPT + "CASE FILE:\n" + casefile.read()
                  + "\n\nRECENT TOOL CALLS:\n" + render_recent(messages))
        memo = llm.complete(prompt, max_tokens=CRITIC_MAX_TOKENS, reasoning_effort="low")
    except Exception as e:
        try:
            casefile.add("log", f"[critic step {step}] (failed: {type(e).__name__})")
        except Exception:
            pass
        return None
    memo = (memo or "").strip()
    nonempty = [l for l in memo.splitlines() if l.strip()]
    memo = sanitize_summary("\n".join(nonempty[:CRITIC_MAX_LINES]))
    if not memo.strip():
        return None
    for line in memo.splitlines():
        if not line.strip():
            continue
        try:
            casefile.add("log", f"[critic step {step}] {line}")
        except Exception:
            pass
    return memo

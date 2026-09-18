"""Context compaction: summarize the middle of the conversation into the case file and rebuild."""

THRESHOLD = 44_000
KEEP_RECENT = 4
PER_MSG_CAP = 1_500
TOTAL_CAP = 90_000

RESET_TEXT = ("[CONTEXT RESET] Your context was compacted. The case file below is everything that "
              "survived. Read it, then continue from the Todo section. Keep writing conclusions to notes.")

SUMMARY_PROMPT = (
    "Below is a log of an autonomous reverse-engineering session (assistant tool calls and tool outputs). "
    "Extract, as terse bullets under three headings:\n"
    "(a) FACTS confirmed by tool output: addresses, constants (hex), function roles, check logic, file layout\n"
    "(b) FAILED attempts and why they failed\n"
    "(c) UNFINISHED work / concrete next steps\n"
    "Do not invent anything absent from the log. No preamble.\n\nLOG:\n"
)

SHRINK_PROMPT = (
    "Rewrite this case file to about half its length. Keep EVERY concrete fact (addresses, constants, "
    "algorithms, verified inputs) and every open todo; drop repetition and narrative. Keep the exact "
    "markdown structure: '# Case: ...' then sections '## Facts', '## Hypotheses', '## Todo', '## Log'. "
    "Output only the rewritten file.\n\n"
)


def split_messages(messages: list[dict]) -> tuple[list, list, list]:
    """head = [system, task]; tail = last KEEP_RECENT assistant-tool-call exchanges; middle = the rest."""
    idxs = [i for i, m in enumerate(messages) if m.get("role") == "assistant" and m.get("tool_calls")]
    if len(idxs) > KEEP_RECENT:
        tail_start = idxs[-KEEP_RECENT]
    elif idxs:
        tail_start = idxs[0]
    else:
        tail_start = len(messages)
    tail_start = max(tail_start, 2)
    return messages[:2], messages[2:tail_start], messages[tail_start:]


def serialize(middle: list[dict]) -> str:
    parts = []
    for m in middle:
        role = m.get("role", "?")
        body = m.get("content") or ""
        for tc in m.get("tool_calls") or []:
            fn = tc["function"]
            body += f"\n[call {fn['name']}] {fn['arguments'][:500]}"
        if len(body) > PER_MSG_CAP:
            body = body[:PER_MSG_CAP] + " …"
        parts.append(f"<{role}>\n{body}")
    s = "\n\n".join(parts)
    if len(s) > TOTAL_CAP:
        half = TOTAL_CAP // 2
        s = s[:half] + "\n\n[… middle omitted …]\n\n" + s[-half:]
    return s


def compact(messages: list[dict], llm, casefile, n: int) -> list[dict]:
    head, middle, tail = split_messages(messages)
    if middle:
        summary = llm.complete(SUMMARY_PROMPT + serialize(middle))
        casefile.add("log", f"### compaction {n}\n{summary.strip()}", bullet=False)
    reset = {"role": "user", "content": RESET_TEXT + "\n\n" + casefile.read()}
    return head + [reset] + tail


def shrink_casefile(casefile, llm) -> None:
    text = casefile.read()
    new = llm.complete(SHRINK_PROMPT + text).strip()
    if new.startswith("# Case:") and "## Facts" in new and "## Todo" in new:
        casefile.write(new + "\n")

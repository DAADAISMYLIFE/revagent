SCHEMA = {
    "type": "function",
    "function": {
        "name": "notes",
        "description": (
            "Your case file: the ONLY memory that survives context resets. Write conclusions, not raw "
            "output. Sections: facts (confirmed by tool output: addresses, constants, function roles, "
            "check logic), hypotheses (unverified), todo (next steps), log (history). `retract` removes a Fact or "
            "Hypothesis that an observation contradicted: pass a unique piece of its text and the reason; the "
            "bullet moves to the log as '[retracted]' and is not restored after a context reset."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["read", "add", "retract"]},
                "section": {"type": "string", "enum": ["facts", "hypotheses", "todo", "log"],
                            "description": "for add (default facts)"},
                "text": {"type": "string", "description": "for add: one bullet (may be multi-line); for retract: a unique piece of the bullet to remove"},
                "reason": {"type": "string", "description": "for retract: the observation that contradicts it"},
            },
            "required": ["action"],
        },
    },
}


def run(ctx, action: str, section: str = "facts", text: str = "", reason: str = "") -> str:
    if action == "read":
        return ctx.casefile.read()
    if action == "add":
        if not text.strip():
            return "[tool error] text is empty"
        try:
            ctx.casefile.add(section, text)
        except ValueError as e:
            return f"[tool error] {e}"
        return f"added to {section}"
    if action == "retract":
        return _retract(ctx, text, reason)
    return f"[tool error] unknown action {action!r}; use read, add or retract"


def _bullets(lines: list[str], start: int, end: int) -> list[tuple[int, int]]:
    """(first, last+1) line spans of the bullets between a section header and the next header."""
    spans, cur = [], None
    for k in range(start + 1, end):
        if lines[k].startswith("#"):
            if cur is not None:
                spans.append((cur, k))
            cur = None
        elif lines[k].startswith("- "):
            if cur is not None:
                spans.append((cur, k))
            cur = k
        elif cur is not None and not lines[k].strip():
            spans.append((cur, k))
            cur = None
    if cur is not None:
        spans.append((cur, end))
    return spans


def _retract(ctx, text: str, reason: str, where: str | None = None) -> str:
    """Observation beats Fact: remove one Facts/Hypotheses bullet and log why. Live runs kept a wrong Fact
    for a whole run and passed it on to the next one because nothing could remove it. The needle matches
    with whitespace collapsed, so a multi-line bullet can be named by its flattened text. `where` labels
    the ledger line (default `step N`; the relay audit passes `audit K`)."""
    from ..casefile import section_span
    needle = (text or "").strip()
    if not needle:
        return "[tool error] text is empty: pass a unique piece of the bullet to retract"
    if not (reason or "").strip():
        return "[tool error] reason is empty: name the observation that contradicts it"
    lines = ctx.casefile.read().split("\n")
    flat = " ".join(needle.split())
    hits, loose = [], []
    for sec in ("facts", "hypotheses"):
        span = section_span(lines, sec)
        if span is None:
            continue
        for a, b in _bullets(lines, *span):
            body = "\n".join(lines[a:b])
            if needle in body:
                hits.append((a, b))
            elif flat in " ".join(body.split()):
                loose.append((a, b))
    collapsed = not hits
    hits = hits or loose
    if not hits:
        return f"[tool error] no Facts/Hypotheses bullet contains {needle[:80]!r}"
    if len(hits) > 1:
        return f"[tool error] {len(hits)} bullets contain {needle[:80]!r}; pass a longer, unique piece"
    a, b = hits[0]
    gone = " ".join(" ".join(lines[a:b]).split())[2:]
    if section_span(lines, "log") is None:
        return "[tool error] the case file has no '## Log' section; nothing was retracted"
    del lines[a:b]
    # earlier compaction summaries in the Log may repeat the Fact as confirmed; drop those copies too
    log = section_span(lines, "log")
    if log is not None:
        s0, e0 = log
        keep = [l for l in lines[s0 + 1:e0]
                if l.startswith("- [") or (flat not in " ".join(l.split()) if collapsed else needle not in l)]
        lines[s0 + 1:e0] = keep
    ctx.casefile.write("\n".join(lines))
    ctx.casefile.add("log", f"[retracted {where or f'step {ctx.step}'}] {gone[:300]} — because {' '.join(reason.split())[:200]}")
    return "retracted; moved to the log"

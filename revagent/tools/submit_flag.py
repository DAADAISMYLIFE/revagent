import re

FLAG_RE = re.compile(r"^[A-Za-z0-9_]+\{.+\}$")  # PREFIX{...}; the prefix comes from the challenge description (Dreamhack: DH)
EVIDENCE_KINDS = ("program_accepted", "two_independent_readings", "reimplementation_matches")
SAME_FLAG_LIMIT = 3
# Tools a reading can come from. A two_independent_readings submission must name one of these per
# reading, the first two must differ, and each must have been called this run (ctx.tools_used).
READING_TOOLS = ("run_gui", "run_binary", "emulate", "decompile", "bash", "summarize")
SHORT_BODY_MAX = 2
SHORT_BODY_PHRASE = "description states"
_CIRCLED = "①②③④⑤⑥⑦⑧⑨"
# Format check only (spec §3.4): splits on separators a human would use to list steps, e.g. prose
# like "step 2)" counts as a separator too — this is not a semantic check of what the methods are.
_METHOD_SPLIT = re.compile(r"(?:\n|[①②③④⑤]|(?<!\d)\d\)\s)")

SCHEMA = {
    "type": "function",
    "function": {
        "name": "submit_flag",
        "description": (
            "Submit the final flag and end the session. Format is PREFIX{...} with the prefix the description "
            "states (Dreamhack default DH{...}). State HOW it was verified with `evidence`: "
            "program_accepted = run_binary/run_gui showed the success message for your input; "
            "reimplementation_matches = your faithful Python model of the check accepts it and you matched "
            "intermediate values; two_independent_readings = the flag is DISPLAYED by the program (drawn, printed, "
            "dumped) and you read it by TWO DIFFERENT METHODS that agree (e.g. screenshot diff read + coordinate log "
            "rebuilt; or screen read + decoded from the file). For two_independent_readings, how_verified must "
            "describe both methods, one per line. Reading the same glyph table twice is one method."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "flag": {"type": "string"},
                "how_verified": {"type": "string", "description": "what you ran and what it showed; for two_independent_readings: method ① on one line, method ② on the next; for two_independent_readings, name the tool of each reading (① run_gui: ... ② bash: ...)"},
                "evidence": {"type": "string", "enum": list(EVIDENCE_KINDS)},
            },
            "required": ["flag", "how_verified", "evidence"],
        },
    },
}


def method_parts(how_verified: str) -> list[str]:
    return [p.strip() for p in _METHOD_SPLIT.split(how_verified or "") if p and p.strip()]


def count_methods(how_verified: str) -> int:
    return len(method_parts(how_verified))


def reading_tool(part: str) -> str | None:
    """The READING_TOOLS name mentioned earliest in one method part, or None."""
    hits = [(part.find(t), t) for t in READING_TOOLS if t in part]
    return min(hits)[1] if hits else None


def _label(i: int) -> str:
    return _CIRCLED[i] if i < len(_CIRCLED) else str(i + 1)


def _check_readings(ctx, how_verified: str) -> str | None:
    """The two_independent_readings rule; returns the [rejected] text or None when it passes."""
    parts = method_parts(how_verified)
    if len(parts) < 2:
        return ("[rejected] second independent reading required: how_verified describes one method. A displayed flag "
                "is accepted only when two DIFFERENT methods agree (e.g. ① read the captures after real input, "
                "② rebuild the text from logged coordinates / decoded bytes / a different alphabet check). "
                "Build the second method, then resubmit with both on separate lines.")
    tools = [reading_tool(p) for p in parts]
    if any(t is None for t in tools):
        return ("[rejected] each reading must say which tool produced it (run_gui / run_binary / emulate / decompile "
                "/ bash / summarize): ① <tool>: ... ② <tool>: ...")
    if tools[0] == tools[1]:
        return (f"[rejected] both readings come from the same tool ({tools[0]}); a second reading must come from a "
                "DIFFERENT source — e.g. a run_gui capture AND bytes decoded from the file with bash, or emulate "
                "on the draw routine.")
    for i, t in enumerate(tools):
        if ctx.tools_used.get(t, 0) < 1:
            return f"[rejected] reading {_label(i)} names {t} but this run never called it; read it for real first."
    return None


def run(ctx, flag: str, how_verified: str = "", evidence: str = "program_accepted") -> str:
    flag = flag.strip()
    if not FLAG_RE.match(flag):
        return (f"[rejected] {flag!r} does not look like PREFIX{{...}}. Use the prefix the description "
                f"states (Dreamhack default DH). If the description says the flag is PREFIX{{<correct input>}}, "
                f"wrap the verified input; otherwise find the real flag string.")
    if evidence not in EVIDENCE_KINDS:
        return f"[rejected] evidence must be one of {', '.join(EVIDENCE_KINDS)}."
    if not how_verified.strip():
        return "[rejected] how_verified is empty. Verify first (run_binary or re-implemented check), then resubmit."
    body = flag[flag.index("{") + 1:-1]
    if len(body) <= SHORT_BODY_MAX and SHORT_BODY_PHRASE not in how_verified:
        return ("[rejected] a flag body of 1-2 characters is almost never the whole flag: keep reading (the "
                "stream/screen usually continues). If the description really states the flag is that short, "
                "write 'description states ...' in how_verified.")
    if evidence == "two_independent_readings":
        rejection = _check_readings(ctx, how_verified)
        if rejection:
            attempts = ctx.flag_attempts.get(flag, 0)
            if attempts >= SAME_FLAG_LIMIT:
                return "[rejected] same flag 3× — change approach"
            ctx.flag_attempts[flag] = attempts + 1
            return rejection
    ctx.flag = flag
    ctx.how_verified = how_verified.strip()
    return "[accepted] flag recorded; the session will end now."

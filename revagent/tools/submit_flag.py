import re

FLAG_RE = re.compile(r"^[A-Za-z0-9_]+\{.+\}$")  # PREFIX{...}; the prefix comes from the challenge description (Dreamhack: DH)
EVIDENCE_KINDS = ("program_accepted", "two_independent_readings", "reimplementation_matches")
SAME_FLAG_LIMIT = 3
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
                "how_verified": {"type": "string", "description": "what you ran and what it showed; for two_independent_readings: method ① on one line, method ② on the next"},
                "evidence": {"type": "string", "enum": list(EVIDENCE_KINDS)},
            },
            "required": ["flag", "how_verified", "evidence"],
        },
    },
}


def count_methods(how_verified: str) -> int:
    parts = [p.strip() for p in _METHOD_SPLIT.split(how_verified or "") if p and p.strip()]
    return len(parts)


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
    attempts = ctx.flag_attempts.get(flag, 0)
    if attempts >= SAME_FLAG_LIMIT:
        return "[rejected] same flag 3× — change approach"
    if evidence == "two_independent_readings" and count_methods(how_verified) < 2:
        ctx.flag_attempts[flag] = attempts + 1
        return ("[rejected] second independent reading required: how_verified describes one method. A displayed flag "
                "is accepted only when two DIFFERENT methods agree (e.g. ① read the captures after real input, "
                "② rebuild the text from logged coordinates / decoded bytes / a different alphabet check). "
                "Build the second method, then resubmit with both on separate lines.")
    ctx.flag = flag
    ctx.how_verified = how_verified.strip()
    return "[accepted] flag recorded; the session will end now."

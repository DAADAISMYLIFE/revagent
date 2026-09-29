import re
import subprocess

from . import run_binary

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
_METHOD_SPLIT = re.compile(r"(?:\n|[①②③④⑤⑥⑦⑧⑨]|(?<!\d)\d\)\s)")
REPLAY_TIMEOUT = 20

SCHEMA = {
    "type": "function",
    "function": {
        "name": "submit_flag",
        "description": (
            "Submit the final flag and end the session. Format is PREFIX{...} with the prefix the description "
            "states (Dreamhack default DH{...}). State HOW it was verified with `evidence`: "
            "program_accepted = run_binary/run_gui showed the success message for your input; "
            "reimplementation_matches = your Python model of the check accepts it AND reproduces at least one "
            "intermediate value observed from the real program (run_binary, gdb, emulate, trace_run), not only "
            "matching constants; two_independent_readings = the flag is DISPLAYED by the program (drawn, printed, "
            "dumped) and you read it by TWO DIFFERENT METHODS that agree (e.g. screenshot diff read + coordinate log "
            "rebuilt; or screen read + decoded from the file). For two_independent_readings, how_verified must "
            "describe both methods, one per line. Reading the same glyph table twice is one method. "
            "For program_accepted the harness replays your input on a PLAIN run of the program (no debugger, no "
            "LD_PRELOAD, no patched memory) and rejects the flag if that run answers exactly as it does for a wrong "
            "input; pass the accepted stdin as `input` when it is not the flag body (e.g. a password that makes "
            "the program print the flag)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "flag": {"type": "string"},
                "how_verified": {"type": "string", "description": "what you ran and what it showed; for two_independent_readings: method ① on one line, method ② on the next; for two_independent_readings, name the tool of each reading (① run_gui: ... ② bash: ...); the first tool named in a reading is the one that counts"},
                "evidence": {"type": "string", "enum": list(EVIDENCE_KINDS)},
                "input": {"type": "string", "description": "program_accepted: the exact stdin the program accepted (default: the flag body plus a newline)"},
                "args": {"type": "array", "items": {"type": "string"}, "description": "program_accepted: argv of that run (default [])"},
                "binary": {"type": "string", "description": "program_accepted: the program that accepted it (default: the only executable in the challenge dir)"},
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
    """The READING_TOOLS name mentioned earliest in one method part (case-insensitive), or None."""
    low = part.lower()
    hits = [(low.find(t), t) for t in READING_TOOLS if t in low]
    return min(hits)[1] if hits else None


def _label(i: int) -> str:
    return _CIRCLED[i] if i < len(_CIRCLED) else str(i + 1)


def _short_body(flag: str, how_verified: str) -> str | None:
    """A displayed flag of 1-2 characters is nearly always a partial reading; the hatch is the model
    saying the description states it is that short."""
    body = flag[flag.index("{") + 1:-1]
    if len(body) <= SHORT_BODY_MAX and SHORT_BODY_PHRASE not in how_verified.lower():
        return ("[rejected] a flag body of 1-2 characters is almost never the whole flag: keep reading (the "
                "stream/screen usually continues). If the description really states the flag is that short, "
                "write 'description states ...' in how_verified.")
    return None


def _check_readings(ctx, how_verified: str) -> str | None:
    """The two_independent_readings rule; returns the [rejected] text or None when it passes.
    The splitter can cut a reading at a parenthesised digit ("pixel (0) is"), so fragments that name
    no tool are dropped and the rule is applied to the tool-named parts that remain."""
    parts = method_parts(how_verified)
    if len(parts) < 2:
        return ("[rejected] second independent reading required: how_verified describes one method. A displayed flag "
                "is accepted only when two DIFFERENT methods agree (e.g. ① read the captures after real input, "
                "② rebuild the text from logged coordinates / decoded bytes / a different alphabet check). "
                "Build the second method, then resubmit with both on separate lines.")
    tools = [t for t in (reading_tool(p) for p in parts) if t]
    if len(tools) < 2:
        return ("[rejected] each reading must say which tool produced it (run_gui / run_binary / emulate / decompile "
                "/ bash / summarize): ① <tool>: ... ② <tool>: ... (the first tool named in a reading is the one that counts)")
    if tools[0] == tools[1]:
        return (f"[rejected] both readings come from the same tool ({tools[0]}); a second reading must come from a "
                "DIFFERENT source — e.g. a run_gui capture AND bytes decoded from the file with bash, or emulate "
                "on the draw routine. (the first tool named in a reading is the one that counts)")
    for i, t in enumerate(tools):
        if ctx.tools_used.get(t, 0) < 1:
            return f"[rejected] reading {_label(i)} names {t} but this run never called it; read it for real first."
    return None


def _target(ctx, binary: str) -> str | None:
    """The program a program_accepted claim is replayed on: `binary`, else the only executable (ELF, PE, #! script)
    at the top of the challenge dir, else the one decompile analyzed. None when it cannot be told."""
    if binary:
        return binary
    found = []
    for q in sorted(ctx.problem_dir.iterdir()):
        if not q.is_file() or q.name.startswith(".") or q.name == "desc.txt":
            continue
        try:
            with q.open("rb") as f:
                head = f.read(4)
        except OSError:
            continue
        if head == b"\x7fELF" or head[:2] == b"MZ" or head[:2] == b"#!":
            found.append(q.name)
    if len(found) == 1:
        return found[0]
    rel = ctx.current_binary_rel
    return rel if rel and (ctx.problem_dir / rel).is_file() else None


def _masked(out: str, *texts: str) -> str:
    """Run output with the fed input masked (a program that echoes its input must not look accepted)."""
    for t in texts:
        t = t.strip()
        if t:
            out = out.replace(t, "<INPUT>")
    return out.strip()


def replay(ctx, flag: str, input_text: str | None, args: list[str] | None, binary: str) -> tuple[str | None, str]:
    """Replay a program_accepted claim on a plain run. Returns (rejection text or None, note for how_verified).
    Undecidable cases (no target, GUI, cannot run here, a tool error) pass with an empty note: the replay only
    ever blocks on a clear negative: the plain run answers the claimed input exactly as it answers a wrong one,
    and does not print the flag."""
    target = _target(ctx, binary)
    if target is None:
        return None, ""
    try:
        kind = subprocess.run(["file", "-b", str(ctx.problem_dir / target)], capture_output=True, text=True,
                              timeout=10).stdout
    except Exception:
        kind = ""
    if "(GUI)" in kind:
        return None, ""                               # run_gui territory: no stdin to replay
    body = flag[flag.index("{") + 1:-1]
    given = input_text is not None and input_text != ""
    text = input_text if given else body + "\n"
    wrong = "".join("B" if ch == "A" else "A" for ch in text.rstrip("\n")) + "\n"
    got = run_binary._run(ctx, target, args, text, REPLAY_TIMEOUT)
    if got.startswith(("[cannot run here]", "[tool error]", "[timeout")):
        return None, ""
    if flag in got:
        return None, f"replay: a plain run of {target} with this input prints the flag"
    base = run_binary._run(ctx, target, args, wrong, REPLAY_TIMEOUT)
    if base.startswith(("[cannot run here]", "[tool error]", "[timeout")):
        return None, ""
    if _masked(got, text, body) != _masked(base, wrong):
        return None, f"replay: a plain run of {target} answers this input differently from a wrong one"
    shown = _masked(got, text, body)[:300]
    hint = "" if given else (" If the program accepted some other stdin (a password that prints the flag), "
                             "pass it as `input`.")
    return (f"[rejected] replay failed: a plain run of {target} (no debugger, no LD_PRELOAD, no patched memory) "
            f"answers your input exactly as it answers a wrong input of the same length:\n{shown}\n"
            "A success seen only under gdb, with memory patched, or with a preloaded library is not the program "
            "accepting the input: anti-debug and environment checks change what it computes. Find the input that "
            "a plain run_binary accepts." + hint), ""


def run(ctx, flag: str, how_verified: str = "", evidence: str = "program_accepted", input: str | None = None,
        args: list[str] | None = None, binary: str = "") -> str:
    flag = flag.strip()
    if not FLAG_RE.match(flag):
        return (f"[rejected] {flag!r} does not look like PREFIX{{...}}. Use the prefix the description "
                f"states (Dreamhack default DH). If the description says the flag is PREFIX{{<correct input>}}, "
                f"wrap the verified input; otherwise find the real flag string.")
    if evidence not in EVIDENCE_KINDS:
        return f"[rejected] evidence must be one of {', '.join(EVIDENCE_KINDS)}."
    if not how_verified.strip():
        return "[rejected] how_verified is empty. Verify first (run_binary or re-implemented check), then resubmit."
    if evidence == "two_independent_readings":
        rejection = _short_body(flag, how_verified) or _check_readings(ctx, how_verified)
        if rejection:
            attempts = ctx.flag_attempts.get(flag, 0)
            if attempts >= SAME_FLAG_LIMIT:
                return "[rejected] same flag 3× — change approach"
            ctx.flag_attempts[flag] = attempts + 1
            return rejection
    note = ""
    if evidence == "program_accepted":
        try:
            rejection, note = replay(ctx, flag, input, args, binary)
        except Exception:                  # a replay bug must never block a verified flag
            rejection, note = None, ""
        if rejection:
            attempts = ctx.flag_attempts.get(flag, 0)
            ctx.flag_attempts[flag] = attempts + 1
            ctx.observe(f"submit_flag replay rejected {flag[:40]}")
            return rejection if attempts < SAME_FLAG_LIMIT else "[rejected] same flag 3× — change approach"
    ctx.flag = flag
    ctx.how_verified = how_verified.strip() + (f" [{note}]" if note else "")
    return "[accepted] flag recorded; the session will end now."

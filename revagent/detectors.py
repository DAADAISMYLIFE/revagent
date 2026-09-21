"""Content-free signals computed from a step's tool calls and reasoning.

Everything here is a pure function of transcript-observable data (tool names, script text, reasoning
length). Nothing may reference a challenge. Thresholds were set by replaying every transcript on hand
(spec 2026-09-21-transition-rules-design.md §8): zero false positives in the solved runs."""
import re

PREFIX_CHARS = 200          # two scripts are "the same artifact" when their first 200 normalized chars match ...
JACCARD_MIN = 0.6           # ... or their line sets overlap by more than 0.6 (Jaccard)
STREAK_LIMIT = 4            # G3 blocks the 4th consecutive similar script
RELEASE_AFTER = 3           # ... and gives up after 3 consecutively blocked steps
COOLDOWN_STEPS = 10         # ... then stays quiet for 10 steps
LONG_REASONING_CHARS = 8000  # a "long thinking" step
LONG_REASONING_LIMIT = 5     # G4 warns on the 5th one (solved runs never exceeded 4)

_HEREDOC = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?[^\n]*\n(.*?)\n\1(?:\n|$)", re.S)
_PY_C_DQ = re.compile(r"python3?\s+-c\s+\"((?:[^\"\\]|\\.)*)\"", re.S)
_PY_C_SQ = re.compile(r"python3?\s+-c\s+'((?:[^'\\]|\\.)*)'", re.S)


def script_body(cmd: str) -> str | None:
    """The script text inside a bash command: a heredoc body (`python3 - <<'EOF' ... EOF`,
    `cat > f.py <<'EOF' ... EOF`) or the string after `python3 -c`. None for plain commands."""
    if not cmd:
        return None
    m = _HEREDOC.search(cmd)
    if m:
        return m.group(2)
    m = _PY_C_DQ.search(cmd) or _PY_C_SQ.search(cmd)
    if m:
        return m.group(1)
    return None


def normalize(text: str) -> str:
    lines = [" ".join(line.split()) for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def similar(a: str, b: str) -> bool:
    """True when b looks like a re-edit of a: same first PREFIX_CHARS after normalization, or a
    line-set Jaccard above JACCARD_MIN."""
    na, nb = normalize(a), normalize(b)
    if not na or not nb:
        return False
    if na[:PREFIX_CHARS] == nb[:PREFIX_CHARS] and len(na) >= PREFIX_CHARS // 2:
        return True
    la, lb = set(na.splitlines()), set(nb.splitlines())
    union = la | lb
    return bool(union) and len(la & lb) / len(union) > JACCARD_MIN

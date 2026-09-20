from pathlib import Path
from typing import Callable

LIMIT = 12_000
FOOTER_MARKER = "\n[env] "
# The only footer truncate() carries past the cut: the exact opening of ToolContext.env_note().
# Anchoring on this prefix (and on FOOTER_MAX) is what keeps challenge-controlled output that
# happens to contain a "\n[env] " line from becoming an unbounded "footer" and disabling the cap.
ENV_NOTE_PREFIX = "[env] this environment could not start the program"
FOOTER_MAX = 512


def truncate(text: str, out_dir: Path, next_id: Callable[[], int]) -> str:
    """Cap tool output at LIMIT chars. Longer output is saved whole to out_dir/NNN.txt
    and the returned text ends with a pointer the model can page through with sed/grep.

    A trailing env_note() footer (tacked on by run_binary/run_gui to flag that handoff_runbook has
    opened up) is preserved past the cut: it is the whole reason this task exists, so it must never
    be the part silently dropped by truncation. Only a tail that starts with ENV_NOTE_PREFIX and is
    at most FOOTER_MAX chars counts as that footer — anything else (a binary printing "[env] ...",
    `bash env | ...`) is ordinary body text and gets capped like the rest. The body is capped to
    LIMIT and the footer is re-appended unchanged; when there is no footer, behaviour is
    byte-identical to a plain cap."""
    if len(text) <= LIMIT:
        return text
    body, footer = text, ""
    idx = text.rfind(FOOTER_MARKER)
    if idx != -1 and len(text) - idx <= FOOTER_MAX and text.startswith(ENV_NOTE_PREFIX, idx + 1):
        body, footer = text[:idx], text[idx:]
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{next_id():03d}.txt"
    path.write_text(text, encoding="utf-8", errors="replace")
    rel = f".revagent/out/{path.name}"
    return (
        body[:LIMIT]
        + f"\n[truncated: {len(text)} chars total. full output: {rel} "
        + f"— page it with bash: sed -n 'A,Bp' {rel}  or  grep -n PATTERN {rel}]"
        + footer
    )

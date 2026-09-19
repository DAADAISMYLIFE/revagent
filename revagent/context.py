"""Context compaction: summarize the middle of the conversation into the case file and rebuild."""

import os
from pathlib import Path

from .casefile import SECTIONS

THRESHOLD = 44_000
KEEP_RECENT = 4
PER_MSG_CAP = 1_500
TOTAL_CAP = 90_000
SHRINK_INPUT_CAP = 60_000

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


EXCLUDED_DIR_NAMES = {".git", "__pycache__"}
EXCLUDED_SUBTREES = {Path(".revagent/out"), Path(".revagent/ghidra")}
EXCLUDED_FILE_NAMES = {"case.md", "case.md.bak", "transcript.jsonl", "result.json"}


def list_work_files(problem_dir: Path, since_ns: int, limit: int = 40) -> list[tuple[str, int]]:
    """Walk problem_dir for files modified at or after since_ns, skipping VCS/cache/output dirs
    and the case file bookkeeping. Returns (relative posix path, size_bytes) sorted by path."""
    problem_dir = Path(problem_dir)
    found: list[tuple[str, int]] = []
    for root, dirnames, filenames in os.walk(problem_dir):
        rel_root = Path(root).relative_to(problem_dir)
        dirnames[:] = [
            d for d in dirnames
            if d not in EXCLUDED_DIR_NAMES and (rel_root / d) not in EXCLUDED_SUBTREES
        ]
        for name in filenames:
            if name in EXCLUDED_FILE_NAMES:
                continue
            full = Path(root) / name
            try:
                st = full.stat()
            except OSError:
                continue
            if st.st_mtime_ns < since_ns:
                continue
            rel = (rel_root / name).as_posix()
            found.append((rel, st.st_size))
    found.sort(key=lambda t: t[0])
    return found[:limit]


def format_work_files(files: list[tuple[str, int]]) -> str:
    if not files:
        return ""
    lines = ["[WORK FILES] These files were created or modified during this run and still exist "
             "under the challenge dir. Read/load them instead of re-deriving their contents:"]
    lines += [f"- {path} ({size} bytes)" for path, size in files]
    return "\n".join(lines)


def _is_reset_banner(m: dict) -> bool:
    return m.get("role") == "user" and (m.get("content") or "").startswith(RESET_TEXT)


def split_messages(messages: list[dict]) -> tuple[list, list, list]:
    """head = [system, task]; tail = last KEEP_RECENT assistant-tool-call exchanges; middle = the rest,
    excluding any earlier [CONTEXT RESET] banner (already folded into the case file; re-summarizing
    it would just re-feed stale context back into the log)."""
    idxs = [i for i, m in enumerate(messages) if m.get("role") == "assistant" and m.get("tool_calls")]
    if len(idxs) > KEEP_RECENT:
        tail_start = idxs[-KEEP_RECENT]
    elif idxs:
        tail_start = idxs[0]
    else:
        tail_start = len(messages)
    tail_start = max(tail_start, 2)
    middle = [m for m in messages[2:tail_start] if not _is_reset_banner(m)]
    return messages[:2], middle, messages[tail_start:]


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


def sanitize_summary(text: str) -> str:
    """Demote any line that exactly matches a canonical section header (## Facts, etc.)
    to a level-3 heading, so it doesn't get mistaken for a real section boundary."""
    headers = set(SECTIONS.values())
    lines = text.split("\n")
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped in headers:
            indent = line[:len(line) - len(line.lstrip())]
            lines[i] = indent + "### " + stripped[3:]
    return "\n".join(lines)


def compact(messages: list[dict], llm, casefile, n: int, work_files_block: str = "") -> list[dict]:
    head, middle, tail = split_messages(messages)
    if middle:
        summary = llm.complete(SUMMARY_PROMPT + serialize(middle))
        summary = sanitize_summary(summary.strip())
        casefile.add("log", f"### compaction {n}\n{summary}", bullet=False)
    content = RESET_TEXT + "\n\n" + casefile.read()
    if work_files_block:
        content += "\n\n" + work_files_block
    reset = {"role": "user", "content": content}
    return head + [reset] + tail


def shrink_casefile(casefile, llm) -> bool:
    text = casefile.read()
    input_text = text
    if len(input_text) > SHRINK_INPUT_CAP:
        input_text = input_text[:SHRINK_INPUT_CAP] + "\n[… truncated …]"
    try:
        new = llm.complete(SHRINK_PROMPT + input_text).strip()
    except Exception:
        return False
    required_headers = ("## Facts", "## Hypotheses", "## Todo", "## Log")
    if not (new.startswith("# Case:") and all(h in new for h in required_headers)):
        return False
    non_empty_lines = [l for l in new.splitlines() if l.strip()]
    if non_empty_lines and not non_empty_lines[-1].strip().startswith(("-", "#")):
        return False  # looks like the reply was cut off mid-line
    backup = casefile.path.with_name(casefile.path.name + ".bak")
    backup.write_text(text, encoding="utf-8")
    casefile.write(new + "\n")
    return True

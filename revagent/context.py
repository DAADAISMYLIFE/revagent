"""Context compaction: summarize the middle of the conversation into the case file and rebuild."""

import os
import stat
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
    "Extract, as terse bullets under four headings:\n"
    "(a) FACTS confirmed by tool output: addresses, constants (hex), function roles, check logic, file layout\n"
    "(b) FAILED attempts and why they failed\n"
    "(c) UNFINISHED work / concrete next steps\n"
    "(d) ARTIFACTS: every file the assistant created or wrote (scripts, JSON/pickle tables, dumps) with its "
    "path and what it contains\n"
    "Do not invent anything absent from the log. No preamble.\n\nLOG:\n"
)

SHRINK_PROMPT = (
    "Rewrite this case file to about half its length. Keep EVERY concrete fact (addresses, constants, "
    "algorithms, verified inputs) and every open todo; drop repetition and narrative. Keep the exact "
    "markdown structure: '# Case: ...' then sections '## Facts', '## Hypotheses', '## Todo', '## Log'. "
    "Output only the rewritten file.\n\n"
)


EXCLUDED_DIR_NAMES = {".git", "__pycache__"}
EXCLUDED_SUBTREES = {Path(".revagent/out"), Path(".revagent/ghidra"), Path(".revagent/screens")}
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
            if not stat.S_ISREG(st.st_mode):
                continue
            if st.st_mtime_ns < since_ns:
                continue
            rel = (rel_root / name).as_posix()
            found.append((rel, st.st_size))
    found.sort(key=lambda t: t[0])
    return found[:limit]


WORK_FILES_BLOCK_CAP = 4_000
_WORK_FILES_TAIL_RESERVE = 80  # room for a trailing "- … (N more files)" line


def format_work_files(files: list[tuple[str, int]]) -> str:
    if not files:
        return ""
    header = ("[WORK FILES] These files were created or modified during this run and still exist "
              "under the challenge dir. Read/load them instead of re-deriving their contents:")
    lines = [header]
    budget = WORK_FILES_BLOCK_CAP - _WORK_FILES_TAIL_RESERVE
    shown = 0
    for path, size in files:
        line = f"- {path} ({size} bytes)"
        prospective = len("\n".join(lines)) + 1 + len(line)
        if prospective > budget:
            break
        lines.append(line)
        shown += 1
    remaining = len(files) - shown
    if remaining > 0:
        lines.append(f"- … ({remaining} more files)")
    result = "\n".join(lines)
    return result[:WORK_FILES_BLOCK_CAP]


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


def _is_heading(line: str, tag: str) -> bool:
    """True if `line`, once bullet/heading punctuation is stripped, starts with `tag`
    (e.g. "(c)"). Guards against a fact bullet merely mentioning "(c)" mid-sentence
    (e.g. a "Copyright (c) 1998" string dumped from the binary)."""
    return line.strip().lstrip("#*- ").startswith(tag)


def extract_unfinished(summary: str) -> str:
    """Return the body under the "(c)" heading line (the line itself is a heading-shaped line
    starting with "(c)", not just any line mentioning it) up to the next heading-shaped "(d)"
    line found after it, or the end. Excludes the heading line itself; stripped; "" if no
    "(c)" heading or no body remains."""
    lines = summary.split("\n")
    start = next((i for i, line in enumerate(lines) if _is_heading(line, "(c)")), None)
    if start is None:
        return ""
    end = next((i for i in range(start + 1, len(lines)) if _is_heading(lines[i], "(d)")), len(lines))
    return "\n".join(lines[start + 1:end]).strip()


def _reduce_log_block(block: list[str]) -> tuple[list[str], bool]:
    """`block[0]` is the "### compaction N" heading line; `block[1:]` is the (a)/(b)/(c)/(d)
    summary body. Returns (new_block, changed): changed is False (block returned as-is) if the
    block has no heading-shaped (b) or (c) part left to drop (already reduced, or never had one)."""
    heading, rest = block[0], block[1:]
    tags = ("(a)", "(b)", "(c)", "(d)")
    part_starts = []
    for i, line in enumerate(rest):
        for tag in tags:
            if _is_heading(line, tag):
                part_starts.append((tag, i))
                break
    if not any(tag in ("(b)", "(c)") for tag, _ in part_starts):
        return block, False
    parts = {}
    for idx, (tag, pstart) in enumerate(part_starts):
        pend = part_starts[idx + 1][1] if idx + 1 < len(part_starts) else len(rest)
        parts[tag] = rest[pstart:pend]
    new_rest = parts.get("(a)", []) + parts.get("(d)", [])
    return [heading, *new_rest], True


def prune_log(casefile, keep: int = 3) -> int:
    """Reduce older "### compaction N" blocks in the case file's Log section to just their
    (a) FACTS and (d) ARTIFACTS parts (dropping (b) FAILED and (c) UNFINISHED), keeping the
    last `keep` blocks verbatim. The case file is re-sent whole on every reset, so an unbounded
    Log makes resets progressively more expensive; this keeps old compactions' facts/artifacts
    without their now-stale failed-attempt/todo narrative. Text before the first block, and
    blocks already reduced (no (b)/(c) part left), are left untouched. Returns the number of
    blocks reduced."""
    text = casefile.read()
    header = SECTIONS["log"]
    lines = text.split("\n")
    try:
        start = lines.index(header)
    except ValueError:
        return 0
    valid_headers = set(SECTIONS.values())
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].strip() in valid_headers),
        len(lines),
    )
    body = lines[start + 1:end]

    block_starts = [i for i, line in enumerate(body) if line.startswith("### ")]
    if not block_starts:
        return 0

    preamble = body[:block_starts[0]]
    blocks = []
    for idx, bstart in enumerate(block_starts):
        bend = block_starts[idx + 1] if idx + 1 < len(block_starts) else len(body)
        blocks.append(body[bstart:bend])

    n_older = max(0, len(blocks) - keep)
    reduced_count = 0
    new_blocks = []
    for i, block in enumerate(blocks):
        if i < n_older:
            new_block, changed = _reduce_log_block(block)
            if changed:
                reduced_count += 1
            new_blocks.append(new_block)
        else:
            new_blocks.append(block)

    if reduced_count == 0:
        return 0

    new_body = preamble + [line for block in new_blocks for line in block]
    casefile.replace_section("log", "\n".join(new_body))
    return reduced_count


def compact(messages: list[dict], llm, casefile, n: int, work_files_block: str = "") -> list[dict]:
    head, middle, tail = split_messages(messages)
    if middle:
        summary = llm.complete(SUMMARY_PROMPT + serialize(middle))
        summary = sanitize_summary(summary.strip())
        casefile.add("log", f"### compaction {n}\n{summary}", bullet=False)
        todo = extract_unfinished(summary)
        if todo:
            casefile.replace_section("todo", todo)
        prune_log(casefile)
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

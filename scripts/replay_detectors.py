#!/usr/bin/env python3
"""Replay the gates over past transcripts: for every session, at which steps would G3 have blocked
and would G4 have warned. Uses the SAME Gate class as the live loop, so the table is exactly what the
agent would have done. A session reported `solved` whose flag differs from `<suite>/ANSWERS.md` (the same
cross-check bench applies) is shown as `wrong`. Exit 1 when a solved session shows any firing (the
zero-false-positive rule of docs/superpowers/specs/2026-09-21-transition-rules-design.md §2.3 / §8).
A session that ran WITH the gates (its transcript carries `gate_*` _meta events) is marked `(gated)`:
its blocks are interventions, not calibration errors, so it is counted in the columns but exempt from
the rule, which is for un-gated historical sessions only.

usage: python scripts/replay_detectors.py quiz/*/.revagent/transcript.jsonl bench/mini/*/.revagent/transcript.jsonl
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from revagent.__main__ import check_answer  # noqa: E402
from revagent.detectors import LONG_REASONING_CHARS, LONG_REASONING_LIMIT  # noqa: E402
from revagent.gate import Gate  # noqa: E402


def _sessions(lines: list[dict]) -> list[list[dict]]:
    out, cur = [], None
    for d in lines:
        if d.get("event") == "session_start":
            if cur:
                out.append(cur)
            cur = [d]
        elif cur is not None:
            cur.append(d)
    if cur:
        out.append(cur)
    return out


def replay_session(lines: list[dict]) -> dict:
    gate = Gate()
    step = 0
    blocks, released, long_steps, g4_step = [], [], 0, None
    status, flag, gated = "incomplete", None, False
    for d in lines:
        if d.get("role") == "_meta" and str(d.get("event") or "").startswith("gate_"):
            gated = True
        if d.get("role") == "_reasoning":
            step = d["step"]
            if len(d.get("content") or "") > LONG_REASONING_CHARS:
                long_steps += 1
                if long_steps == LONG_REASONING_LIMIT:
                    g4_step = step
        elif d.get("role") == "assistant" and d.get("tool_calls"):
            calls = [(tc["function"]["name"], tc["function"]["arguments"]) for tc in d["tool_calls"]]
            verdicts, events = gate.check(step, calls)
            for ev in events:
                if ev["event"] == "gate_block" and step not in blocks:
                    blocks.append(step)
                elif ev["event"] == "gate_released":
                    released.append(step)
        elif d.get("event") == "end":
            status = d.get("status", "?")
            flag = d.get("flag")
    return {"steps": step, "status": status, "flag": flag, "g3_blocks": blocks, "g3_released": released,
            "long_reasoning_steps": long_steps, "g4_step": g4_step, "max_streak": gate.max_streak,
            "gated": gated}


def _challenge_dir(path) -> Path:
    """The challenge directory of a transcript: `<dir>/.revagent/transcript.jsonl` or an archived
    `<dir>/transcript.jsonl`. Its name is the ANSWERS.md row, its parent holds ANSWERS.md."""
    parent = Path(path).resolve().parent
    return parent.parent if parent.name == ".revagent" else parent


def replay_file(path) -> list[dict]:
    """One row per session. A `solved` session whose flag contradicts `<challenge_dir>/../ANSWERS.md`
    gets status `wrong` (and `note`), exactly as bench reports it."""
    lines = [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]
    challenge_dir = _challenge_dir(path)
    rows = []
    for s in _sessions(lines):
        r = replay_session(s)
        r["status"], r["note"] = check_answer(challenge_dir, r["status"], r["flag"])
        rows.append(r)
    return rows


def main(argv=None) -> int:
    paths = argv if argv is not None else sys.argv[1:]
    if not paths:
        print(__doc__)
        return 2
    print("| transcript | session | status | steps | G3 blocks at | released at | max streak | long-thinking steps | G4 at |")
    print("|---|---|---|---|---|---|---|---|---|")
    false_positives = 0
    for p in paths:
        for i, r in enumerate(replay_file(p), 1):
            fired = bool(r["g3_blocks"] or r["g4_step"] is not None)
            fp = r["status"] == "solved" and fired and not r["gated"]
            false_positives += bool(fp)
            name = _challenge_dir(p).name
            suffix = " (gated)" if r["gated"] else (" FALSE POSITIVE" if fp else "")
            print(f"| {name} | {i} | {r['status']}{suffix} | {r['steps']} | "
                  f"{r['g3_blocks'] or '-'} | {r['g3_released'] or '-'} | {r['max_streak']} | "
                  f"{r['long_reasoning_steps']} | {r['g4_step'] or '-'} |")
    if false_positives:
        print(f"\n{false_positives} solved session(s) would have fired: raise a threshold before shipping.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

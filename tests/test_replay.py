import json
import subprocess
import sys
from pathlib import Path

from revagent.detectors import LONG_REASONING_CHARS, LONG_REASONING_LIMIT
from scripts.replay_detectors import replay_file, replay_session

FIX = Path(__file__).parent / "fixtures" / "transcripts"


def test_basic_pefile_loop_blocks_at_step_9_and_releases():
    rows = replay_file(FIX / "pefile_loop.jsonl")
    assert len(rows) == 1
    r = rows[0]
    # steps 6..11 are six re-edits of the same pefile script (Jaccard 0.67..0.90; step 12 diverges at 0.44);
    # the streak reaches 4 at step 9 -> block; 10, 11 blocked; release at 11 with cooldown to 21
    assert r["g3_blocks"] == [9, 10, 11]
    assert r["g3_released"] == [11]
    assert r["max_streak"] >= 4


def test_multipoint_extractor_variants_never_block():
    rows = replay_file(FIX / "extractor_variants.jsonl")
    assert rows[0]["g3_blocks"] == [] and rows[0]["g4_step"] is None


def test_cli_exits_nonzero_when_a_solved_session_would_have_fired(tmp_path):
    lines = [{"role": "_meta", "event": "session_start"}]
    body = "import pefile\npe = pefile.PE('c')\n" + "y = 2\n" * 50
    for step in range(1, 6):
        lines.append({"role": "_reasoning", "step": step, "content": "t"})
        lines.append({"role": "assistant", "content": "", "tool_calls": [{"id": f"c{step}", "type": "function",
                      "function": {"name": "bash", "arguments": json.dumps({"cmd": f"python3 - <<'EOF'\n{body}print({step})\nEOF"})}}]})
    lines.append({"role": "_meta", "event": "end", "status": "solved"})
    p = tmp_path / "t.jsonl"
    p.write_text("\n".join(json.dumps(l) for l in lines) + "\n")
    proc = subprocess.run([sys.executable, "scripts/replay_detectors.py", str(p)], capture_output=True, text=True,
                          cwd=Path(__file__).resolve().parents[1])
    assert proc.returncode == 1
    assert "solved" in proc.stdout and "FALSE POSITIVE" in proc.stdout


def test_solved_with_wrong_flag_counts_as_wrong_not_false_positive(tmp_path):
    # the same cross-check bench applies: <challenge_dir>/../ANSWERS.md says DH{y}, the run reported DH{x}
    suite = tmp_path / "suite"
    work = suite / "chal" / ".revagent"
    work.mkdir(parents=True)
    (suite / "ANSWERS.md").write_text("| challenge | flag |\n|---|---|\n| chal | DH{y} |\n", encoding="utf-8")
    lines = [{"role": "_meta", "event": "session_start"}]
    for step in range(1, LONG_REASONING_LIMIT + 1):  # G4 fires on the LIMIT-th long-thinking step
        lines.append({"role": "_reasoning", "step": step, "content": "t" * (LONG_REASONING_CHARS + 1)})
        lines.append({"role": "assistant", "content": "", "tool_calls": [{"id": f"c{step}", "type": "function",
                      "function": {"name": "bash", "arguments": json.dumps({"cmd": f"echo {step}"})}}]})
    lines.append({"role": "_meta", "event": "end", "status": "solved", "flag": "DH{x}"})
    p = work / "transcript.jsonl"
    p.write_text("\n".join(json.dumps(l) for l in lines) + "\n")
    rows = replay_file(p)
    assert rows[0]["status"] == "wrong" and rows[0]["g4_step"] == LONG_REASONING_LIMIT
    proc = subprocess.run([sys.executable, "scripts/replay_detectors.py", str(p)], capture_output=True, text=True,
                          cwd=Path(__file__).resolve().parents[1])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "| chal | 1 | wrong |" in proc.stdout and "FALSE POSITIVE" not in proc.stdout


def test_gated_solved_session_is_exempt_from_the_false_positive_rule(tmp_path):
    # a live run WITH the gates: its blocks are interventions, not calibration errors
    lines = [{"role": "_meta", "event": "session_start"}]
    body = "import pefile\npe = pefile.PE('c')\n" + "y = 2\n" * 50
    for step in range(1, 6):
        lines.append({"role": "_reasoning", "step": step, "content": "t"})
        lines.append({"role": "assistant", "content": "", "tool_calls": [{"id": f"c{step}", "type": "function",
                      "function": {"name": "bash", "arguments": json.dumps({"cmd": f"python3 - <<'EOF'\n{body}print({step})\nEOF"})}}]})
        if step == 4:
            lines.append({"role": "_meta", "event": "gate_block", "gate": "G3", "step": step, "streak": 4})
    lines.append({"role": "_meta", "event": "end", "status": "solved"})
    p = tmp_path / "t.jsonl"
    p.write_text("\n".join(json.dumps(l) for l in lines) + "\n")
    rows = replay_file(p)
    assert rows[0]["gated"] and rows[0]["g3_blocks"]           # the G3 columns are still counted
    proc = subprocess.run([sys.executable, "scripts/replay_detectors.py", str(p)], capture_output=True, text=True,
                          cwd=Path(__file__).resolve().parents[1])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "| solved (gated) |" in proc.stdout and "FALSE POSITIVE" not in proc.stdout
    assert f"| {rows[0]['g3_blocks']} |" in proc.stdout

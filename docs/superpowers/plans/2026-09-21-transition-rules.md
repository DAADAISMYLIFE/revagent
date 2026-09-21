# Transition Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two replay-calibrated, content-free gates to the agent loop (G3: block the 4th consecutive re-edit of the same script; G4: warn once at the 5th long-reasoning step and drop reasoning effort to `low`), a `solve_check` tool that inverts a byte-wise transform with z3, and a replay script that recomputes both gates over past transcripts.

**Architecture:** `revagent/detectors.py` holds pure helpers (script-body extraction, similarity, thresholds). `revagent/gate.py` holds a small stateful `Gate` whose `check(step, calls)` returns per-call verdicts plus events; the agent feeds it the tool calls of every step before executing them, and the replay script feeds it the same calls from a transcript, so both use one implementation. `revagent/tools/solve_check.py` runs the model's `transform()` on z3 bit-vectors wrapped in a Python-int-semantics `Sym` class. Nothing in these modules mentions a challenge.

**Tech Stack:** Python 3.12, z3-solver (already in the sandbox image and the host venv: `~/.revagent-venv/bin/python -c "import z3"` → 4.13), pytest. Tests: `~/.revagent-venv/bin/python -m pytest -q -p no:cacheprovider`.

**Spec:** `docs/superpowers/specs/2026-09-21-transition-rules-design.md`

## Global Constraints

- Content-free: no module under `revagent/` may reference a challenge name, a binary's property, or a challenge-specific string. Test fixtures may contain real challenge data.
- Gates never raise into the loop: any exception inside `Gate.check` is logged as `_meta gate_error` and the step is fully allowed.
- Thresholds (verbatim from the spec §8): D3 similarity = first 200 normalized chars equal OR line-set Jaccard > 0.6; G3 blocks at streak 4; auto-release after 3 consecutively blocked steps; cooldown 10 steps. D4 = reasoning > 8,000 chars; G4 fires on the 5th such step.
- Every model-visible string outside the new gate/tool texts stays byte-identical (schemas, tool outputs, playbook rules other than the additions in Task 7).
- Blocked calls are not executed; the same step's other calls run normally.
- Branch: `feat/transition-rules` (already exists, spec committed at 1e593d5). Commit after every task with the trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Suite must stay green after every task (284 tests at the start).

---

### Task 1: Detector helpers (`script_body`, `similar`, thresholds)

**Files:**
- Create: `revagent/detectors.py`
- Test: `tests/test_detectors.py`

**Interfaces:**
- Produces: `script_body(cmd: str) -> str | None`, `normalize(text: str) -> str`, `similar(a: str, b: str) -> bool`, constants `PREFIX_CHARS = 200`, `JACCARD_MIN = 0.6`, `LONG_REASONING_CHARS = 8000`, `LONG_REASONING_LIMIT = 5`, `STREAK_LIMIT = 4`, `RELEASE_AFTER = 3`, `COOLDOWN_STEPS = 10`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_detectors.py
from revagent.detectors import (JACCARD_MIN, LONG_REASONING_CHARS, LONG_REASONING_LIMIT, PREFIX_CHARS,
                                normalize, script_body, similar)


def test_script_body_extracts_heredoc_body():
    cmd = "cd /work/x && python3 - <<'EOF'\nimport pefile\npe = pefile.PE('a.exe')\nprint(pe)\nEOF"
    assert script_body(cmd) == "import pefile\npe = pefile.PE('a.exe')\nprint(pe)"


def test_script_body_extracts_python_c_string():
    assert script_body('cd /w && python3 -c "import json\\nprint(1)"') == "import json\\nprint(1)"
    assert script_body("python3 -c 'print(2)'") == "print(2)"


def test_script_body_extracts_cat_heredoc_to_file():
    cmd = "cat > /tmp/emu.py <<'EOF'\nfrom unicorn import Uc\nmu = Uc()\nEOF\npython3 /tmp/emu.py"
    assert script_body(cmd) == "from unicorn import Uc\nmu = Uc()"


def test_script_body_none_for_plain_commands():
    assert script_body("ls -la && file chall") is None
    assert script_body("objdump -d -M intel chall | head") is None
    assert script_body("") is None


def test_normalize_collapses_whitespace_and_blank_lines():
    assert normalize("a  =  1\n\n\n  b=2  \n") == "a = 1\nb=2"


def test_similar_by_prefix():
    base = "x = 1\n" * 60          # 360 chars, identical first 200
    assert similar(base + "print('a')", base + "print('zzz')")


def test_similar_by_jaccard_of_lines():
    a = "\n".join(f"line{i}" for i in range(10))
    b = "\n".join(f"line{i}" for i in range(2, 10)) + "\nnew1\nnew2"   # 8 shared / 12 union = 0.67
    assert similar(a, b)
    c = "\n".join(f"other{i}" for i in range(10))
    assert not similar(a, c)


def test_similar_thresholds_are_the_spec_values():
    assert (PREFIX_CHARS, JACCARD_MIN, LONG_REASONING_CHARS, LONG_REASONING_LIMIT) == (200, 0.6, 8000, 5)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `~/.revagent-venv/bin/python -m pytest -q -p no:cacheprovider tests/test_detectors.py`
Expected: ImportError / ModuleNotFoundError for `revagent.detectors`.

- [ ] **Step 3: Implement `revagent/detectors.py`**

```python
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `~/.revagent-venv/bin/python -m pytest -q -p no:cacheprovider tests/test_detectors.py`
Expected: 8 passed. If `test_similar_by_prefix` fails on the `len(na) >= PREFIX_CHARS // 2` guard, the base string is 360 chars so it passes; the guard exists so two 30-char scripts are not "similar by prefix".

- [ ] **Step 5: Commit**

```bash
git add revagent/detectors.py tests/test_detectors.py
git commit -m "detectors: script_body, similar, replay-calibrated thresholds

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: The `Gate` (G3 state machine) as one implementation for loop and replay

**Files:**
- Create: `revagent/gate.py`
- Test: `tests/test_gate.py`

**Interfaces:**
- Consumes: `revagent.detectors.script_body`, `similar`, `STREAK_LIMIT`, `RELEASE_AFTER`, `COOLDOWN_STEPS`.
- Produces:
  - `Verdict` dataclass: `index: int`, `allowed: bool`, `text: str` (the `[blocked by G3] ...` result when not allowed, else `""`).
  - `class Gate` with `check(step: int, calls: list[tuple[str, str]]) -> tuple[list[Verdict], list[dict]]` where `calls` is `[(tool_name, raw_args_json)]` and the second element is a list of event dicts (`{"event": "gate_block"|"gate_open"|"gate_released", "step": N, "gate": "G3", ...}`) for the caller to log.
  - Attributes read by the agent for `result.json`: `blocks` (int), `max_streak` (int).
  - `G3_TEXT` constant.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_gate.py
import json

from revagent.gate import G3_TEXT, Gate


def _bash(script: str) -> tuple[str, str]:
    return ("bash", json.dumps({"cmd": f"cd /w && python3 - <<'EOF'\n{script}\nEOF"}))


def _variants(n: int) -> list[tuple[str, str]]:
    base = "import pefile\npe = pefile.PE('chall.exe')\nbase = pe.OPTIONAL_HEADER.ImageBase\n" + "x = 1\n" * 40
    return [_bash(base + f"print({i})") for i in range(n)]


def test_fourth_similar_script_is_blocked_and_earlier_ones_allowed():
    g = Gate()
    v = _variants(4)
    for step in range(1, 4):
        verdicts, events = g.check(step, [v[step - 1]])
        assert verdicts[0].allowed and events == []
    verdicts, events = g.check(4, [v[3]])
    assert not verdicts[0].allowed
    assert verdicts[0].text.startswith("[blocked by G3]") and verdicts[0].text == G3_TEXT
    assert events == [{"event": "gate_block", "gate": "G3", "step": 4, "streak": 4}]
    assert g.blocks == 1 and g.max_streak == 4


def test_dissimilar_script_or_other_tool_resets_the_streak():
    g = Gate()
    v = _variants(3)
    for step, call in enumerate(v, 1):
        g.check(step, [call])
    assert g.streak == 3
    g.check(4, [("notes", json.dumps({"action": "add", "text": "x"}))])
    assert g.streak == 0
    g.check(5, [v[0]])
    g.check(6, [_bash("completely = 'different'\nprint(completely)")])
    assert g.streak == 1  # the different script starts a new streak of its own


def test_block_opens_when_the_model_changes_approach():
    g = Gate()
    v = _variants(5)
    for step, call in enumerate(v[:4], 1):
        g.check(step, [call])
    verdicts, events = g.check(5, [("run_binary", json.dumps({"path": "chall", "stdin": "abc"}))])
    assert verdicts[0].allowed
    assert events == [{"event": "gate_open", "gate": "G3", "step": 5}]
    assert g.streak == 0


def test_three_consecutive_blocked_steps_release_the_gate_with_cooldown():
    g = Gate()
    v = _variants(9)
    for step, call in enumerate(v[:4], 1):
        g.check(step, [call])                       # step 4 blocked (streak 4)
    g.check(5, [v[4]])                              # blocked
    verdicts, events = g.check(6, [v[5]])           # third consecutive block -> released
    assert not verdicts[0].allowed
    assert {"event": "gate_released", "gate": "G3", "step": 6, "cooldown_until": 16} in events
    verdicts, _ = g.check(7, [v[6]])                # in cooldown: allowed even though similar
    assert verdicts[0].allowed
    assert g.streak == 0 and g.blocks == 3


def test_only_the_similar_call_in_a_step_is_blocked():
    g = Gate()
    v = _variants(4)
    for step, call in enumerate(v[:3], 1):
        g.check(step, [call])
    verdicts, _ = g.check(4, [("notes", json.dumps({"action": "read"})), v[3]])
    assert verdicts[0].allowed and not verdicts[1].allowed


def test_plain_bash_does_not_count_and_bad_json_is_ignored():
    g = Gate()
    v = _variants(3)
    for step, call in enumerate(v, 1):
        g.check(step, [call])
    g.check(4, [("bash", json.dumps({"cmd": "ls -la"}))])
    assert g.streak == 0
    verdicts, events = g.check(5, [("bash", "{not json")])
    assert verdicts[0].allowed and events == []


def test_gate_never_raises(monkeypatch):
    import revagent.gate as gate_mod
    monkeypatch.setattr(gate_mod, "script_body", lambda cmd: (_ for _ in ()).throw(RuntimeError("boom")))
    g = Gate()
    verdicts, events = g.check(1, [_bash("x = 1")])
    assert verdicts[0].allowed
    assert events == [{"event": "gate_error", "gate": "G3", "step": 1, "error": "RuntimeError: boom"}]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `~/.revagent-venv/bin/python -m pytest -q -p no:cacheprovider tests/test_gate.py`
Expected: ModuleNotFoundError for `revagent.gate`.

- [ ] **Step 3: Implement `revagent/gate.py`**

```python
"""G3: block the Nth consecutive re-edit of the same script and demand a change of representation.

One implementation serves the live loop (agent._run_tools feeds each step's tool calls) and the
replay script (feeds the same calls from a transcript), so what the replay says would have fired is
exactly what the loop does. The gate blocks; it never advises a direction (a wrong advice costs a
run, a wrong block costs at most RELEASE_AFTER steps)."""
import json
from dataclasses import dataclass

from .detectors import COOLDOWN_STEPS, RELEASE_AFTER, STREAK_LIMIT, script_body, similar

G3_TEXT = (
    f"[blocked by G3] This is the {STREAK_LIMIT}th consecutive edit of the same script and it was not run. "
    "Change the approach instead of patching it again: (1) run the real program on your current candidate "
    "(run_binary / run_gui) and compare its output with your model's; (2) write the forward transform as a "
    "plain Python transform(x) and let solve_check invert it; or (3) write to notes why this approach fails "
    "and pick a different hypothesis. A script that differs from this one, any other tool, or notes lifts the block."
)


@dataclass
class Verdict:
    index: int
    allowed: bool
    text: str = ""


class Gate:
    def __init__(self):
        self.streak = 0            # consecutive similar script bodies (the current one included)
        self.last_body = None
        self.blocking = False      # a block happened in the previous step and was not lifted yet
        self.blocked_steps = 0     # consecutive steps with at least one block
        self.cooldown_until = 0    # step number until which G3 stays quiet after a release
        self.blocks = 0            # total blocked calls this run
        self.max_streak = 0

    def check(self, step: int, calls: list[tuple[str, str]]) -> tuple[list[Verdict], list[dict]]:
        try:
            return self._check(step, calls)
        except Exception as e:  # a detector bug must never touch the run
            return ([Verdict(i, True) for i in range(len(calls))],
                    [{"event": "gate_error", "gate": "G3", "step": step, "error": f"{type(e).__name__}: {e}"[:200]}])

    def _check(self, step: int, calls: list[tuple[str, str]]) -> tuple[list[Verdict], list[dict]]:
        verdicts, events = [], []
        blocked_here = False
        for i, (name, raw) in enumerate(calls):
            body = self._body(name, raw)
            if body is None:
                # plain bash, another tool, notes: the model changed what it is doing
                if self.blocking:
                    events.append({"event": "gate_open", "gate": "G3", "step": step})
                self._reset()
                verdicts.append(Verdict(i, True))
                continue
            if self.last_body is not None and similar(self.last_body, body):
                self.streak += 1
            else:
                if self.blocking:
                    events.append({"event": "gate_open", "gate": "G3", "step": step})
                self.blocking = False
                self.blocked_steps = 0
                self.streak = 1
            self.last_body = body
            self.max_streak = max(self.max_streak, self.streak)
            if self.streak >= STREAK_LIMIT and step > self.cooldown_until:
                self.blocks += 1
                blocked_here = True
                verdicts.append(Verdict(i, False, G3_TEXT))
                events.append({"event": "gate_block", "gate": "G3", "step": step, "streak": self.streak})
            else:
                verdicts.append(Verdict(i, True))
        if blocked_here:
            self.blocking = True
            self.blocked_steps += 1
            if self.blocked_steps >= RELEASE_AFTER:
                self.cooldown_until = step + COOLDOWN_STEPS
                events.append({"event": "gate_released", "gate": "G3", "step": step,
                               "cooldown_until": self.cooldown_until})
                self._reset()
        return verdicts, events

    def _reset(self) -> None:
        self.streak = 0
        self.last_body = None
        self.blocking = False
        self.blocked_steps = 0

    @staticmethod
    def _body(name: str, raw: str) -> str | None:
        if name != "bash":
            return None
        try:
            args = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(args, dict):
            return None
        return script_body(str(args.get("cmd", "")))
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `~/.revagent-venv/bin/python -m pytest -q -p no:cacheprovider tests/test_gate.py tests/test_detectors.py`
Expected: 15 passed. Walk through `test_three_consecutive_blocked_steps_release_the_gate_with_cooldown` by hand if it fails: steps 4, 5, 6 each block (streak 4, 5, 6), `blocked_steps` reaches 3 at step 6 → release, `cooldown_until = 16`, reset; step 7 starts a new streak of 1 → allowed.

- [ ] **Step 5: Commit**

```bash
git add revagent/gate.py tests/test_gate.py
git commit -m "gate: G3 same-script re-edit block with auto-release and cooldown

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Wire G3 and G4 into the agent loop

**Files:**
- Modify: `revagent/agent.py` (imports at lines 8–15; `__init__` after line 60; `_run_tools` lines 103–118; `run()` at lines 187–198 for the effort override, after line 205 for G4, result dict lines 268–280)
- Modify: `tests/test_agent.py` (`ScriptedLLM.chat`, lines 31–54: let a script item carry `"reasoning": <str>`)
- Test: `tests/test_agent.py`

**Interfaces:**
- Consumes: `Gate`, `Verdict` from `revagent.gate`; `LONG_REASONING_CHARS`, `LONG_REASONING_LIMIT` from `revagent.detectors`.
- Produces: `Agent.gate` (a `Gate`), `Agent.long_reasoning` (int), `Agent.effort_override` (str | None), `G4_TEXT` constant, `result["signals"] = {"gate_blocks": int, "max_script_streak": int, "long_reasoning_steps": int, "first_facts_step": int | None}`, transcript `_meta` events `gate_block` / `gate_open` / `gate_released` / `gate_error` / `gate_warn`, case-file ledger lines `- [gate step N] ...`.

- [ ] **Step 1: Extend the test driver so a scripted step can carry long reasoning**

In `tests/test_agent.py`, inside `ScriptedLLM.chat`, the dict form of a script item currently reads `finish_reason` and `calls`. Add `reasoning`:

```python
        finish_reason = "stop"
        reasoning = "thinking..."
        if isinstance(item, dict):
            finish_reason = item.get("finish_reason", "stop")
            reasoning = item.get("reasoning", "thinking...")
            item = item["calls"]
```
and return `ChatResponse(msg["content"], reasoning, tcs, msg, pt, 10, finish_reason)` instead of the literal `"thinking..."`.

- [ ] **Step 2: Write the failing agent tests** (append to `tests/test_agent.py`)

```python
def _pefile_variant(i: int) -> tuple:
    body = "import pefile\npe = pefile.PE('chal')\nbase = pe.OPTIONAL_HEADER.ImageBase\n" + "x = 1\n" * 40 + f"print({i})"
    return ("bash", {"cmd": f"python3 - <<'EOF'\n{body}\nEOF"})


def test_g3_blocks_fourth_similar_script_and_lifts_on_a_run(tmp_path):
    d = make_problem(tmp_path)
    llm = ScriptedLLM([
        [_pefile_variant(0)], [_pefile_variant(1)], [_pefile_variant(2)],
        [_pefile_variant(3)],                                    # step 4: blocked
        [("run_binary", {"path": "chal", "stdin": "abc\n"})],     # step 5: lifts
        [("submit_flag", {"flag": "DH{abc}", "how_verified": "printed Correct"})],
    ])
    r = Agent(d, "", llm, max_steps=10, interactive=False).run()
    assert r["status"] == "solved"
    lines = [json.loads(l) for l in (d / ".revagent" / "transcript.jsonl").read_text().splitlines()]
    tools = [m for m in lines if m.get("role") == "tool"]
    assert tools[3]["content"].startswith("[blocked by G3]")          # the 4th script was not run
    assert "print(3)" not in (d / ".revagent" / "console.log").read_text() if (d / ".revagent" / "console.log").exists() else True
    events = [m for m in lines if m.get("role") == "_meta" and str(m.get("event", "")).startswith("gate_")]
    assert [(e["event"], e["step"]) for e in events] == [("gate_block", 4), ("gate_open", 5)]
    case = (d / ".revagent" / "case.md").read_text()
    assert "- [gate step 4] G3 blocked" in case and "- [gate step 5] G3 opened" in case
    assert r["signals"]["gate_blocks"] == 1 and r["signals"]["max_script_streak"] == 4


def test_g3_blocked_step_counts_as_no_progress_for_the_critic(tmp_path, monkeypatch):
    # a blocked call produces no [obs] line and no Facts, so idle keeps growing
    d = make_problem(tmp_path)
    llm = ScriptedLLM([[_pefile_variant(i)] for i in range(4)] + [[("bash", {"cmd": "ls"})]])
    a = Agent(d, "", llm, max_steps=5, interactive=False)
    r = a.run()
    assert r["signals"]["gate_blocks"] == 1
    assert r["status"] == "unsolved" and r["reason"] == "step limit"


def test_g4_warns_once_on_fifth_long_reasoning_step_and_lowers_effort(tmp_path):
    d = make_problem(tmp_path)
    long = "x" * 8001
    llm = ScriptedLLM([
        {"calls": [("bash", {"cmd": f"echo {i}"})], "reasoning": long} for i in range(5)
    ] + [
        {"calls": [("bash", {"cmd": "echo 5"})], "reasoning": "short"},
        [("submit_flag", {"flag": "DH{abc}", "how_verified": "v"})],
    ])
    r = Agent(d, "", llm, max_steps=10, interactive=False).run()
    assert r["status"] == "solved"
    # steps 1-5 medium (None = client default); the 5th long step sets the override, so steps 6, 7 are low
    assert llm.efforts_seen == [None, None, None, None, None, "low", "low"]
    warns = [m for m in llm.seen[-1] if m["role"] == "user" and m["content"].startswith("[gate]")]
    assert len(warns) == 1 and "5" in warns[0]["content"]
    lines = [json.loads(l) for l in (d / ".revagent" / "transcript.jsonl").read_text().splitlines()]
    assert [m["step"] for m in lines if m.get("event") == "gate_warn"] == [5]
    assert r["signals"]["long_reasoning_steps"] == 5
    assert "- [gate step 5] G4" in (d / ".revagent" / "case.md").read_text()


def test_signals_record_first_facts_step(tmp_path):
    d = make_problem(tmp_path)
    llm = ScriptedLLM([
        [("bash", {"cmd": "ls"})],
        [("notes", {"action": "add", "section": "facts", "text": "chal is a script"})],
        [("submit_flag", {"flag": "DH{abc}", "how_verified": "v"})],
    ])
    r = Agent(d, "", llm, max_steps=5, interactive=False).run()
    assert r["signals"] == {"gate_blocks": 0, "max_script_streak": 0, "long_reasoning_steps": 0,
                            "first_facts_step": 2}
    llm2 = ScriptedLLM([[("submit_flag", {"flag": "DH{abc}", "how_verified": "v"})]])
    r2 = Agent(make_problem(tmp_path / "b"), "", llm2, max_steps=5, interactive=False).run()
    assert r2["signals"]["first_facts_step"] is None
```

Note for `make_problem(tmp_path / "b")`: `make_problem` does `d = tmp_path / "prob"; d.mkdir()`; pass `tmp_path / "b"` after `(tmp_path / "b").mkdir()` — add that line before the call.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `~/.revagent-venv/bin/python -m pytest -q -p no:cacheprovider tests/test_agent.py -k "g3 or g4 or signals"`
Expected: 4 failed (KeyError `signals`, missing gate events).

- [ ] **Step 4: Implement in `revagent/agent.py`**

Imports (add after line 10):
```python
from .detectors import LONG_REASONING_CHARS, LONG_REASONING_LIMIT
from .gate import Gate
```
Constant (after `TRUNCATED_NUDGE`):
```python
G4_TEXT = (f"[gate] This is the {LONG_REASONING_LIMIT}th step whose thinking exceeded {LONG_REASONING_CHARS} characters. "
           "No solved run has ever needed that many. Stop tracing in your head: put the derivation into a script "
           "(python3), save its output to a file, and reason from the printed result. Thinking effort is now lowered "
           "for the rest of this run.")
```
In `__init__` (after `self.critic_calls = 0`):
```python
        self.gate = Gate()
        self.long_reasoning = 0
        self.effort_override: str | None = None
        self.first_facts_step: int | None = None
```
Replace `_run_tools` with:
```python
    def _run_tools(self, step: int, calls: list[ToolCall]) -> None:
        """Execute one assistant turn's tool calls in order; once a call has set the flag or a
        runbook, the remaining calls are answered with a skip error instead of being run. G3 may
        replace a call's result with a [blocked by G3] text without running it."""
        verdicts, events = self.gate.check(step, [(c.name, c.raw_args) for c in calls])
        for ev in events:
            self._log({"role": "_meta", **ev})
            self._ledger(step, ev)
        flag_just_set = False
        for call, verdict in zip(calls, verdicts):
            if flag_just_set:
                result = "[tool error] skipped: session ended"
                self._append({"role": "tool", "tool_call_id": call.id, "content": result})
                continue
            self._print(f"[{step}] > {call.name} {call.raw_args[:160]}")
            result = verdict.text if not verdict.allowed else self._execute(call)
            self._append({"role": "tool", "tool_call_id": call.id, "content": result})
            head = "\n".join(result.splitlines()[:3])
            self._print(f"[{step}] < {head[:300]}")
            if self.ctx.flag or self.ctx.runbook_path:
                flag_just_set = True

    def _ledger(self, step: int, ev: dict) -> None:
        """One `- [gate step N] ...` bullet per gate event, in the case file's Log: survives compaction
        like the [obs]/[critic] lines (context.prune_log keeps bullets starting with `- [`... see
        _is_ledger_line — extend it in this task)."""
        text = {"gate_block": f"G3 blocked a repeated script (streak {ev.get('streak')})",
                "gate_open": "G3 opened: approach changed",
                "gate_released": f"G3 released after {RELEASE_AFTER} blocked steps; quiet until step {ev.get('cooldown_until')}",
                "gate_error": f"gate error: {ev.get('error')}",
                "gate_warn": f"G4 warned: long-thinking step #{ev.get('count')}; effort lowered to low"}.get(ev["event"], ev["event"])
        try:
            self.casefile.add("log", f"[gate step {step}] {text}")
        except Exception:
            pass
```
(import `RELEASE_AFTER` from `.detectors` too.)

In `run()`, the two `self.llm.chat(...)` calls: pass the override. Line 187 becomes
```python
                        resp = self.llm.chat(self.messages, self.schemas, reasoning_effort=self.effort_override)
```
(the retry call at 196–198 already passes `reasoning_effort=TRUNCATED_RETRY_EFFORT`; leave it).

After line 205 (`self._log({"role": "_reasoning", ...})`) add the G4 check:
```python
                    if len(resp.reasoning or "") > LONG_REASONING_CHARS:
                        self.long_reasoning += 1
                        if self.long_reasoning == LONG_REASONING_LIMIT:
                            self.effort_override = "low"
                            ev = {"event": "gate_warn", "gate": "G4", "step": step, "count": self.long_reasoning}
                            self._log({"role": "_meta", **ev})
                            self._ledger(step, ev)
                            self._append({"role": "user", "content": G4_TEXT})
                            self._print(f"[{step}] -- G4: {self.long_reasoning} long-thinking steps; effort -> low --")
```
(The warning is appended AFTER the assistant message of this step, so the model sees it on its next turn; `efforts_seen` in the test therefore shows `low` from step 6.)

Where the progress marker is computed (line 238, `marker = progress_marker(...)`), record the first Facts:
```python
                    if self.first_facts_step is None and marker[0] > 0:
                        self.first_facts_step = step
```
(put it right after the `try/except OSError` block that sets `marker`).

Result dict: add
```python
                "signals": {
                    "gate_blocks": self.gate.blocks,
                    "max_script_streak": self.gate.max_streak,
                    "long_reasoning_steps": self.long_reasoning,
                    "first_facts_step": self.first_facts_step,
                },
```

`context.py`: `_is_ledger_line` currently returns True for `- [obs ` and `- [critic `; add `- [gate ` so gate bullets survive `prune_log` and `shrink` (also add `[gate` to the `SHRINK_PROMPT` sentence "Lines starting with '- [obs' or '- [critic' are the observation ledger" → "'- [obs', '- [critic' or '- [gate'"). Add one assertion to `tests/test_context.py::test_prune_log_keeps_obs_and_critic_bullets`: a `- [gate step 3] G3 blocked ...` line inside an old block survives with count 1.

- [ ] **Step 5: Run the whole suite**

Run: `~/.revagent-venv/bin/python -m pytest -q -p no:cacheprovider`
Expected: all green (284 + 4 new). If `test_solves_and_writes_result` or other result-shape tests fail on the new `signals` key, they compare specific keys only — check and, if a test asserts the exact key set, add `signals`.

- [ ] **Step 6: Commit**

```bash
git add revagent/agent.py revagent/context.py tests/test_agent.py tests/test_context.py
git commit -m "agent: G3 block in _run_tools, G4 long-reasoning warning + effort override, signals in result.json

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: `solve_check` tool — z3 inversion of a byte-wise `transform`

**Files:**
- Create: `revagent/tools/solve_check.py`
- Create: `tests/fixtures/transforms/xor_transform.py`, `tests/fixtures/transforms/block_cipher_transform.py`
- Modify: `tests/test_tools.py::test_registry_has_all_tools` (add `"solve_check"` to the expected name set)
- Test: `tests/test_tools.py`

**Interfaces:**
- Consumes: `resolve_inside`, `PathError` from `revagent.tools.base`; `ctx.clamp_timeout`.
- Produces: tool `solve_check(file, target, length, charset="", timeout=60)`; module-level `Sym` and `Table` classes (exposed to the user script as `Table`); `symbolic_solve(source: str, target: bytes, length: int, charset: str, timeout_s: int) -> tuple[str, bytes | None]` returning `("sat", solution)`, `("unsat", None)`, `("timeout", None)` or `("error", None)` with the error text in the first element after a colon (see implementation).

- [ ] **Step 1: Create the fixtures**

`tests/fixtures/transforms/xor_transform.py`:
```python
KEY = [0x13, 0x37, 0x42, 0x99]


def transform(x):
    return [(x[i] ^ KEY[i % len(KEY)]) & 0xff for i in range(len(x))]
```

`tests/fixtures/transforms/block_cipher_transform.py` — a 16-round, 8-byte block transform with an S-box, key and table lookups (the shape that stumped the agent on a bronze challenge; the constants are test data, the tool knows nothing about them). Generate the S-box as the AES S-box so the file is self-contained:
```python
# 8-byte block: 16 rounds x 8 steps of acc = rol3(SBOX[acc ^ KEY[i]] + p[(i+1)&7]); p[(i+1)&7] = acc
KEY = list(b"I_am_KEY")


def _aes_sbox():
    p = q = 1
    sbox = [0] * 256
    while True:
        p = p ^ ((p << 1) & 0xff) ^ (0x1b if p & 0x80 else 0)
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff
        if q & 0x80:
            q ^= 0x09
        x = q ^ (q << 1) ^ (q << 2) ^ (q << 3) ^ (q << 4)
        sbox[p] = (x ^ 0x63) & 0xff
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


SBOX = Table(_aes_sbox())   # Table is injected by solve_check; on the host it is a plain list wrapper


def rol3(v):
    return ((v << 3) | (v >> 5)) & 0xff


def transform(x):
    out = []
    for b in range(0, len(x), 8):
        p = list(x[b:b + 8])
        acc = p[0]
        for _ in range(16):
            for i in range(8):
                v = (SBOX[acc ^ KEY[i]] + p[(i + 1) & 7]) & 0xff
                acc = rol3(v)
                p[(i + 1) & 7] = acc
        out.extend(p)
    return out
```
Expected plaintext for the test target: the test computes `target = transform(list(b"Reverse__your__brain_;)\x00"))` with a plain-list `Table` and then asks the tool to invert it, so no external file is needed.

- [ ] **Step 2: Write the failing tests** (append to `tests/test_tools.py`)

```python
from pathlib import Path as _P
FIX = _P(__file__).parent / "fixtures" / "transforms"


def _copy_fixture(tmp_path, name):
    (tmp_path / name).write_text((FIX / name).read_text(encoding="utf-8"), encoding="utf-8")


def test_solve_check_inverts_xor(tmp_path):
    from revagent.tools import solve_check
    _copy_fixture(tmp_path, "xor_transform.py")
    plain = b"DH{x0r}"
    target = bytes(c ^ [0x13, 0x37, 0x42, 0x99][i % 4] for i, c in enumerate(plain))
    out = solve_check.run(ctx_for(tmp_path), file="xor_transform.py", target=target.hex(), length=len(plain))
    assert out.startswith("[sat]") and "DH{x0r}" in out and target.hex() in out


def test_solve_check_inverts_a_sequential_block_cipher(tmp_path):
    from revagent.tools import solve_check
    _copy_fixture(tmp_path, "block_cipher_transform.py")
    ns = {"Table": solve_check.Table}
    exec((FIX / "block_cipher_transform.py").read_text(encoding="utf-8"), ns)
    plain = list(b"Reverse__your__brain_;)\x00")
    target = bytes(ns["transform"](plain))
    out = solve_check.run(ctx_for(tmp_path), file="block_cipher_transform.py", target=target.hex(), length=24,
                          charset="[ -~\\x00]")
    assert out.startswith("[sat]") and "Reverse__your__brain_;)" in out


def test_solve_check_reports_unsat(tmp_path):
    from revagent.tools import solve_check
    (tmp_path / "t.py").write_text("def transform(x):\n    return [x[0] & 0, x[1]]\n")
    out = solve_check.run(ctx_for(tmp_path), file="t.py", target="0102", length=2)
    assert out.startswith("[unsat]")


def test_solve_check_names_the_line_that_cannot_be_symbolic(tmp_path):
    from revagent.tools import solve_check
    (tmp_path / "t.py").write_text("def transform(x):\n    y = x[0] + 1\n    n = int(y)\n    return [n]\n")
    out = solve_check.run(ctx_for(tmp_path), file="t.py", target="05", length=1)
    assert out.startswith("[error]") and "line 3" in out and "int(" in out


def test_solve_check_rejects_bad_inputs_and_escapes(tmp_path):
    from revagent.tools import solve_check
    (tmp_path / "t.py").write_text("def transform(x):\n    return x\n")
    assert solve_check.run(ctx_for(tmp_path), file="../t.py", target="00", length=1).startswith("[tool error] path escapes")
    assert solve_check.run(ctx_for(tmp_path), file="nope.py", target="00", length=1).startswith("[tool error] no such file")
    assert solve_check.run(ctx_for(tmp_path), file="t.py", target="zz", length=1).startswith("[tool error] target")
    assert solve_check.run(ctx_for(tmp_path), file="t.py", target="0000", length=1).startswith("[tool error] length")
    (tmp_path / "u.py").write_text("x = 1\n")
    assert "transform" in solve_check.run(ctx_for(tmp_path), file="u.py", target="00", length=1)


def test_solve_check_timeout_is_clamped_to_run_deadline(tmp_path, monkeypatch):
    from revagent.tools import solve_check
    (tmp_path / "t.py").write_text("def transform(x):\n    return x\n")
    seen = {}
    monkeypatch.setattr(solve_check, "symbolic_solve",
                        lambda src, target, length, charset, timeout_s: seen.update(t=timeout_s) or ("sat", b"\x00"))
    monkeypatch.setattr("revagent.tools.base.time.monotonic", lambda: 50.0)
    ctx = ctx_for(tmp_path)
    ctx.deadline = 50.0 + 20
    solve_check.run(ctx, file="t.py", target="00", length=1, timeout=600)
    assert seen["t"] == 20
```
Update `test_registry_has_all_tools`: the expected set gains `"solve_check"`.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `~/.revagent-venv/bin/python -m pytest -q -p no:cacheprovider tests/test_tools.py -k "solve_check or registry"`
Expected: 7 failed (no module `revagent.tools.solve_check`; registry set mismatch).

- [ ] **Step 4: Implement `revagent/tools/solve_check.py`**

```python
"""Invert a byte-wise transform with z3. The model writes the FORWARD transform as ordinary Python
(what it can do); the solver finds the input (what it repeatedly could not do by hand).

The user script defines transform(x) over a list of 8-bit values using integer arithmetic
(+ - * ^ & | << >> % and constant-table lookups). We run it with x = symbolic values wrapped in Sym,
which keeps Python-int semantics (logical >>, wrap-around only when the script masks) on top of
64-bit z3 bit-vectors, then ask z3 for x such that transform(x) == target."""
import re
import traceback

from .base import PathError, resolve_inside

WIDTH = 64
DEFAULT_TIMEOUT = 60

SCHEMA = {
    "type": "function",
    "function": {
        "name": "solve_check",
        "description": (
            "Invert a byte-wise check with z3 instead of by hand. Write the FORWARD transform as plain Python in a "
            "file: `def transform(x): ...` takes a list of `length` byte values (ints 0-255) and returns the list "
            "the program compares against its target, using only + - * ^ & | << >> % and indexing into constant "
            "tables (wrap tables as Table([...]) — Table is provided). The tool runs transform on symbolic bytes and "
            "returns an input whose transform equals `target`. Works for byte-wise / sequential / stateful checks "
            "(XOR, add, S-box, rotations, per-block rounds); useless for hashes and standard ciphers. Data-dependent "
            "branches, int() casts and loops whose bounds depend on x are not symbolic: the tool names the line."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "file": {"type": "string", "description": "python file (relative to the challenge dir) defining transform(x)"},
                "target": {"type": "string", "description": "expected output as hex, e.g. '7e7d9a8b...'"},
                "length": {"type": "integer", "description": "number of input bytes (len(x))"},
                "charset": {"type": "string", "description": "optional regex character class each input byte must match, e.g. '[ -~]' for printable"},
                "timeout": {"type": "integer", "description": "solver seconds (default 60)"},
            },
            "required": ["file", "target", "length"],
        },
    },
}


class NotSymbolic(Exception):
    pass


class Sym:
    """A z3 bit-vector with Python-int semantics for the operators a byte-wise check uses."""
    __slots__ = ("v",)

    def __init__(self, v):
        self.v = v

    @staticmethod
    def _raw(o):
        return o.v if isinstance(o, Sym) else o

    def _bin(self, other, f):
        import z3
        a, b = self.v, Sym._raw(other)
        if isinstance(b, bool):
            b = int(b)
        if not isinstance(b, (int, z3.BitVecRef)):
            raise NotSymbolic(f"unsupported operand {type(other).__name__}")
        return Sym(f(a, b))

    def __add__(self, o): return self._bin(o, lambda a, b: a + b)
    def __radd__(self, o): return self._bin(o, lambda a, b: b + a)
    def __sub__(self, o): return self._bin(o, lambda a, b: a - b)
    def __rsub__(self, o): return self._bin(o, lambda a, b: b - a)
    def __mul__(self, o): return self._bin(o, lambda a, b: a * b)
    def __rmul__(self, o): return self._bin(o, lambda a, b: b * a)
    def __xor__(self, o): return self._bin(o, lambda a, b: a ^ b)
    def __rxor__(self, o): return self._bin(o, lambda a, b: b ^ a)
    def __and__(self, o): return self._bin(o, lambda a, b: a & b)
    def __rand__(self, o): return self._bin(o, lambda a, b: b & a)
    def __or__(self, o): return self._bin(o, lambda a, b: a | b)
    def __ror__(self, o): return self._bin(o, lambda a, b: b | a)
    def __lshift__(self, o): return self._bin(o, lambda a, b: a << b)
    def __rshift__(self, o):
        import z3
        return self._bin(o, lambda a, b: z3.LShR(a, b))       # Python >> on non-negative ints is logical
    def __mod__(self, o):
        import z3
        return self._bin(o, lambda a, b: z3.URem(a, b))
    def __neg__(self): return Sym(-self.v)
    def __invert__(self): return Sym(~self.v)
    def __eq__(self, o): return Sym(self.v == Sym._raw(o))
    def __ne__(self, o): return Sym(self.v != Sym._raw(o))
    def __hash__(self): return id(self)
    def __int__(self): raise NotSymbolic("int() on a symbolic value")
    def __index__(self): raise NotSymbolic("a symbolic value used as an index/range bound (wrap the table in Table)")
    def __bool__(self): raise NotSymbolic("a symbolic value used in a branch (if/while/and/or)")
    def __lt__(self, o): raise NotSymbolic("comparison used as a value; only == against constants is supported")
    __le__ = __gt__ = __ge__ = __lt__


class Table:
    """A constant lookup table. Indexed by a plain int it is a list; indexed by a Sym it becomes a z3
    Array select (the index is reduced mod the table size), so S-boxes and key schedules work symbolically."""

    def __init__(self, values):
        self.values = [int(v) & 0xff for v in values]
        self._arr = None

    def __len__(self):
        return len(self.values)

    def __iter__(self):
        return iter(self.values)

    def __getitem__(self, idx):
        if isinstance(idx, Sym):
            import z3
            if self._arr is None:
                self._arr = z3.Array(f"table_{id(self)}", z3.BitVecSort(WIDTH), z3.BitVecSort(WIDTH))
                self._cons = [self._arr[z3.BitVecVal(i, WIDTH)] == z3.BitVecVal(v, WIDTH) for i, v in enumerate(self.values)]
            n = len(self.values)
            return Sym(self._arr[z3.URem(idx.v, n)])
        return self.values[idx]

    def constraints(self):
        return list(getattr(self, "_cons", []) or [])


def _allowed_bytes(charset: str) -> list[int] | None:
    if not charset:
        return None
    rx = re.compile(f"^{charset}$")
    return [c for c in range(256) if rx.match(chr(c))]


def symbolic_solve(source: str, target: bytes, length: int, charset: str, timeout_s: int):
    """Returns ("sat", bytes) | ("unsat", None) | ("timeout", None) | ("error: <text>", None)."""
    import z3
    ns = {"Table": Table, "__name__": "transform_module"}
    try:
        exec(compile(source, "transform.py", "exec"), ns)
    except Exception as e:
        return f"error: the file failed to import: {type(e).__name__}: {e}", None
    fn = ns.get("transform")
    if not callable(fn):
        return "error: the file must define transform(x)", None
    xs = [z3.BitVec(f"x{i}", WIDTH) for i in range(length)]
    try:
        out = fn([Sym(v) for v in xs])
        out = list(out)
    except NotSymbolic as e:
        tb = traceback.extract_tb(e.__traceback__)
        user = [f for f in tb if f.filename == "transform.py"]
        where = f"line {user[-1].lineno}: `{user[-1].line}`" if user else "unknown line"
        return f"error: not symbolic at {where} — {e}. Rewrite that line with arithmetic (masks, Table lookups) only.", None
    except Exception as e:
        tb = traceback.extract_tb(e.__traceback__)
        user = [f for f in tb if f.filename == "transform.py"]
        where = f"line {user[-1].lineno}: `{user[-1].line}`" if user else "unknown line"
        return f"error: transform raised {type(e).__name__}: {e} at {where}", None
    if len(out) != len(target):
        return f"error: transform returned {len(out)} values but target has {len(target)} bytes", None
    s = z3.Solver()
    s.set("timeout", int(timeout_s * 1000))
    for x in xs:
        s.add(z3.ULE(x, 255))
    allowed = _allowed_bytes(charset)
    if allowed is not None:
        for x in xs:
            s.add(z3.Or([x == c for c in allowed]))
    tables = [v for v in ns.values() if isinstance(v, Table)]
    for t in tables:
        for c in t.constraints():
            s.add(c)
    for o, tb_ in zip(out, target):
        ov = Sym._raw(o)
        if isinstance(ov, int):
            if (ov & 0xff) != tb_:
                return "unsat", None
            continue
        s.add((ov & 0xff) == tb_)
    r = s.check()
    if r == z3.sat:
        m = s.model()
        return "sat", bytes(m.eval(x, model_completion=True).as_long() & 0xff for x in xs)
    if r == z3.unsat:
        return "unsat", None
    return "timeout", None


def run(ctx, file: str, target: str, length: int, charset: str = "", timeout: int = DEFAULT_TIMEOUT) -> str:
    try:
        p = resolve_inside(ctx, file)
    except PathError as e:
        return str(e)
    try:
        tgt = bytes.fromhex(target.replace(" ", ""))
    except ValueError:
        return f"[tool error] target must be hex (got {target[:40]!r})"
    if not (1 <= int(length) <= 4096):
        return f"[tool error] length must be 1..4096 (got {length})"
    if len(tgt) != int(length):
        return f"[tool error] length {length} does not match target ({len(tgt)} bytes); pass the input length and make transform return exactly len(target) values"
    try:
        _allowed_bytes(charset)
    except re.error as e:
        return f"[tool error] charset is not a valid character class: {e}"
    timeout_s = ctx.clamp_timeout(max(1, min(int(timeout), 900)))
    source = p.read_text(encoding="utf-8", errors="replace")
    status, sol = symbolic_solve(source, tgt, int(length), charset, timeout_s)
    if status == "sat":
        printable = "".join(chr(c) if 32 <= c < 127 else "." for c in sol)
        return (f"[sat] input ({len(sol)} bytes)\nhex: {sol.hex()}\ntext: {printable}\n"
                f"Verify it on the real program before submit_flag (run_binary / run_gui).")
    if status == "unsat":
        return ("[unsat] no input of that length maps to the target under this transform. Either the transform is "
                "not faithful (compare it against the real program on a known input) or the length/charset is wrong.")
    if status == "timeout":
        return f"[timeout] z3 gave up after {timeout_s}s; simplify the transform or split the input into independent blocks."
    return f"[error] {status[len('error: '):]}"
```

The `Sym.__eq__` returning a `Sym` breaks `zip`/`list` membership only if the script compares symbols; that is the intended failure (`__bool__` raises with a clear message).

- [ ] **Step 5: Run the tests**

Run: `~/.revagent-venv/bin/python -m pytest -q -p no:cacheprovider tests/test_tools.py -k "solve_check or registry" --durations=3`
Expected: 7 passed. The block-cipher case must solve in well under 60 s (384 Array selects, 24 unknown bytes); if it takes longer than ~20 s locally, replace the per-table `Array` with `z3.Function` over `BitVecSort(8)` and `Extract(7, 0, idx)` — but try the Array version first.

- [ ] **Step 6: Commit**

```bash
git add revagent/tools/solve_check.py tests/fixtures/transforms tests/test_tools.py
git commit -m "solve_check: invert a byte-wise transform with z3 (Sym/Table symbolic execution)

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: Replay script over transcripts + fixture regression test

**Files:**
- Create: `scripts/replay_detectors.py`
- Delete: `scripts/replay_detectors_prototype.py` (the measurement prototype; its logic is superseded by importing `Gate`)
- Create: `tests/fixtures/transcripts/pefile_loop.jsonl`, `tests/fixtures/transcripts/extractor_variants.jsonl`
- Test: `tests/test_replay.py`

**Interfaces:**
- Consumes: `Gate` (revagent.gate), `LONG_REASONING_CHARS`, `LONG_REASONING_LIMIT` (revagent.detectors).
- Produces: `replay_session(lines: list[dict]) -> dict` with keys `steps`, `status`, `g3_blocks` (list of step numbers), `g3_released` (list), `long_reasoning_steps` (int), `g4_step` (int | None), `max_streak` (int); `replay_file(path) -> list[dict]` (one per session); CLI `python scripts/replay_detectors.py PATH...` printing one table row per session and exiting 1 if any session whose end status is `solved` has a G3 block or a G4 warning (the spec's zero-false-positive rule).

- [ ] **Step 1: Build the fixture excerpts**

Run once (read-only on quiz data; writes two small files):
```bash
~/.revagent-venv/bin/python - <<'EOF'
import json
from pathlib import Path
def excerpt(src, dst, lo, hi):
    L=[json.loads(l) for l in open(src, encoding='utf-8')]
    s=[i for i,d in enumerate(L) if d.get('event')=='session_start'][-1]
    out=[L[s]]; step=0
    for d in L[s+1:]:
        if d.get('role')=='_reasoning': step=d['step']; out.append({"role":"_reasoning","step":step,"content":"x"*len(d.get('content') or '')}); continue
        if d.get('role')=='assistant' and lo<=step<=hi: out.append({"role":"assistant","content":"","tool_calls":d.get('tool_calls')}); continue
        if d.get('role')=='tool' and lo<=step<=hi: out.append({"role":"tool","tool_call_id":d['tool_call_id'],"content":(d.get('content') or '')[:80]}); continue
        if d.get('event')=='end': out.append({"role":"_meta","event":"end","status":d.get('status')})
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    Path(dst).write_text("\n".join(json.dumps(o, ensure_ascii=False) for o in out)+"\n", encoding='utf-8')
    print(dst, len(out))
excerpt('/mnt/c/Users/강순우/Documents/vs/rev/quiz/basic/.revagent/transcript.jsonl', 'tests/fixtures/transcripts/pefile_loop.jsonl', 1, 16)
excerpt('/mnt/c/Users/강순우/Documents/vs/rev/quiz/multipoint/.revagent/transcript.jsonl', 'tests/fixtures/transcripts/extractor_variants.jsonl', 28, 36)
EOF
```
Keep only assistant tool calls and truncated tool results, so no challenge output beyond script text lands in the repo. Then check with `grep -c '"tool_calls"'` that each file has the expected number of steps (16 and 9).

- [ ] **Step 2: Write the failing tests**

```python
# tests/test_replay.py
import json
import subprocess
import sys
from pathlib import Path

from scripts.replay_detectors import replay_file, replay_session

FIX = Path(__file__).parent / "fixtures" / "transcripts"


def test_basic_pefile_loop_blocks_at_step_9_and_releases():
    rows = replay_file(FIX / "pefile_loop.jsonl")
    assert len(rows) == 1
    r = rows[0]
    # steps 6..12 are seven re-edits of the same pefile script (the 16th step is the raw-offset read);
    # the streak reaches 4 at step 9 -> block; 10, 11 blocked; release at 11 with cooldown to 21
    assert r["g3_blocks"][:3] == [9, 10, 11]
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
```
Add an empty `scripts/__init__.py` so `from scripts.replay_detectors import ...` works from the repo root (pytest's rootdir is the repo; `tests/` is already a package).

- [ ] **Step 3: Run the tests to verify they fail**

Run: `~/.revagent-venv/bin/python -m pytest -q -p no:cacheprovider tests/test_replay.py`
Expected: ImportError for `scripts.replay_detectors`.

- [ ] **Step 4: Implement `scripts/replay_detectors.py`**

```python
#!/usr/bin/env python3
"""Replay the gates over past transcripts: for every session, at which steps would G3 have blocked
and would G4 have warned. Uses the SAME Gate class as the live loop, so the table is exactly what the
agent would have done. Exit 1 when a solved session shows any firing (the zero-false-positive rule of
docs/superpowers/specs/2026-09-21-transition-rules-design.md §2.3 / §8).

usage: python scripts/replay_detectors.py quiz/*/.revagent/transcript.jsonl bench/mini/*/.revagent/transcript.jsonl
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
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
    status = "incomplete"
    for d in lines:
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
    return {"steps": step, "status": status, "g3_blocks": blocks, "g3_released": released,
            "long_reasoning_steps": long_steps, "g4_step": g4_step, "max_streak": gate.max_streak}


def replay_file(path) -> list[dict]:
    lines = [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]
    return [replay_session(s) for s in _sessions(lines)]


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
            fp = r["status"] == "solved" and (r["g3_blocks"] or r["g4_step"] is not None)
            false_positives += bool(fp)
            name = Path(p).resolve().parents[1].name
            print(f"| {name} | {i} | {r['status']}{' FALSE POSITIVE' if fp else ''} | {r['steps']} | "
                  f"{r['g3_blocks'] or '-'} | {r['g3_released'] or '-'} | {r['max_streak']} | "
                  f"{r['long_reasoning_steps']} | {r['g4_step'] or '-'} |")
    if false_positives:
        print(f"\n{false_positives} solved session(s) would have fired: raise a threshold before shipping.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 5: Run the tests, then the real replay**

Run: `~/.revagent-venv/bin/python -m pytest -q -p no:cacheprovider tests/test_replay.py`
Expected: 3 passed. If `test_basic_pefile_loop_blocks_at_step_9_and_releases` disagrees on the exact steps, print `replay_file(...)` and check the excerpt: the spec's measurement found the basic pefile re-edits at steps 6→11 with Jaccard 0.67–0.90; adjust the asserted steps to what the shared `Gate` computes (the fixture pins the implementation, not the prototype's numbers), but the block must start at streak 4 and the release must follow three blocked steps.

Then run the full replay over everything on hand and paste the table into the spec's §8 under a new heading "구현 후 리플레이 (실제 Gate 코드)":
```bash
~/.revagent-venv/bin/python scripts/replay_detectors.py /mnt/c/Users/강순우/Documents/vs/rev/quiz/*/.revagent/transcript.jsonl /mnt/c/Users/강순우/Documents/vs/rev/quiz/captain-hook.archive-pre-ladder/transcript.jsonl bench/mini/*/.revagent/transcript.jsonl
```
Expected: exit 0 (no solved session fires). If a solved session fires, stop and report — do not tune constants silently; the spec says to raise the threshold and record it.

- [ ] **Step 6: Commit**

```bash
git rm -q scripts/replay_detectors_prototype.py
git add scripts/__init__.py scripts/replay_detectors.py tests/test_replay.py tests/fixtures/transcripts docs/superpowers/specs/2026-09-21-transition-rules-design.md
git commit -m "replay: recompute G3/G4 over transcripts with the live Gate; fixture regression

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: Playbook and README

**Files:**
- Modify: `revagent/prompts/system.md` (Environment section; rule 4; §3 "Constraint / byte-wise" and "Sequential / stateful" bullets)
- Modify: `README.md` (실행 옵션 표 아래 한 단락, 동작 원리 불릿 하나)
- Test: `tests/test_agent.py::test_playbook_*` (add one test)

- [ ] **Step 1: Write the failing test** (append to `tests/test_agent.py`)

```python
def test_playbook_explains_gates_and_solve_check():
    p = load_system_prompt()
    assert "[blocked by G3]" in p and "[gate]" in p and "solve_check" in p
    assert p.index("solve_check") < p.index("**Compiler-emitted constant division")   # first choice in §3, not an afterthought
    for n in range(1, 11):
        assert f"\n{n}. **" in p
```

- [ ] **Step 2: Run it to verify it fails**

Run: `~/.revagent-venv/bin/python -m pytest -q -p no:cacheprovider tests/test_agent.py -k gates_and_solve_check`
Expected: FAIL (strings absent).

- [ ] **Step 3: Edit `revagent/prompts/system.md`** (exact insertions; everything else byte-identical)

Rule 4 — append one sentence:
```
4. **Change hypothesis after 3 failures.** If the same approach fails three times, write the failure to `notes` and pick a different one. The loop enforces the script case: the 4th consecutive edit of the same script is refused with `[blocked by G3]` until you run the program, hand the transform to `solve_check`, or note the failure.
```
Rule 7 — append one sentence at the end:
```
 After the 5th step whose thinking runs past 8,000 characters you get a `[gate]` warning and thinking effort is lowered for the rest of the run: by then, the derivation belongs in a script, not in your head.
```
Environment — add a bullet after the `decompile` bullet:
```
- `solve_check` inverts a byte-wise check for you: put the FORWARD transform in a file as `def transform(x)` over a list of byte values (arithmetic, masks, `Table([...])` lookups only) and pass the target hex and the input length; it returns an input, `[unsat]`, or the line that is not symbolic. Use it before trying to invert anything by hand.
- Messages that start with `[blocked by G3]` or `[gate]` come from the loop, not from a tool failure: they say what to do next.
```
§3 "Constraint / byte-wise" bullet — replace "then invert it or solve with z3 (`from z3 import *`, one BitVec(8) per input byte)." with:
```
then hand it to `solve_check` (write `transform(x)` = the forward check, target = the compared bytes) — or, if the transform needs branches, model it yourself with z3 (`from z3 import *`, one BitVec(8) per input byte). Do not invert by hand.
```
§3 "Sequential / stateful" bullet — after "either translate every step 1:1 into z3 (...)" insert "— `solve_check` does this for you when the steps are arithmetic and table lookups —".

- [ ] **Step 4: README** (`README.md`, 반말 유지)

Under the 실행 옵션 table add:
```
루프가 막는 것 두 가지. 같은 스크립트를 4번째 고치면 그 호출은 실행 안 되고 `[blocked by G3]`가 돌아온다(프로그램을 돌리거나, `solve_check`에 넘기거나, 노트에 실패를 적으면 풀림). 8천 자 넘게 생각하는 스텝이 5번째 나오면 `[gate]` 경고 한 번 주고 남은 실행은 생각 예산을 낮춘다. 둘 다 과거 transcript 전부에 리플레이해서 푼 실행에선 한 번도 안 울리는 값으로 잡았다: `python scripts/replay_detectors.py 문제폴더/.revagent/transcript.jsonl`.
```
동작 원리 bullets: add `- 도구 열 개:` (was 아홉) with `solve_check` in the list, and one bullet: "- `solve_check`: 모델이 forward 변환만 파이썬으로 쓰면 z3가 입력을 찾아 준다. 바이트 단위 체크용." Also `result.json`의 `signals` 언급 one line in the 산출물 table row for result.json: "마지막 실행 결과 (+ `signals`: 게이트 발동, 긴 생각 횟수, 첫 Facts 스텝)".

- [ ] **Step 5: Run the suite**

Run: `~/.revagent-venv/bin/python -m pytest -q -p no:cacheprovider`
Expected: all green, including the existing playbook pins (`test_playbook_has_evidence_ladder_sections` checks rule numbering 1–10 and the `run it once` ordering; the new sentences do not move them).

- [ ] **Step 6: Commit**

```bash
git add revagent/prompts/system.md README.md tests/test_agent.py
git commit -m "playbook + README: G3/G4 gates and solve_check

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: Live validation and record

**Files:**
- Modify: `README.md` (bench table rows), `docs/superpowers/specs/2026-09-21-transition-rules-design.md` (§8 live results)

- [ ] **Step 1: Rebuild the sandbox image** (the container runs the image's code)

```bash
bash scripts/sandbox-build.sh
```
Expected: `EXIT=0`, smoke passes (includes `revagent ok` which imports the new modules).

- [ ] **Step 2: basic** — fresh case file, 15 minutes

```bash
cd /mnt/c/Users/강순우/Documents/vs/rev/quiz
mv basic/.revagent/case.md basic/.revagent/case.md.run1 2>/dev/null
~/.revagent-venv/bin/revagent solve basic --max-minutes 15
python3 -c "import json; print(json.load(open('basic/.revagent/result.json'))['signals'])"
grep -n "gate step" basic/.revagent/case.md
```
Expected: either `solved` with `DH{Reverse__your__brain_;)}` (ANSWERS.md will confirm), or at least `signals.gate_blocks >= 1` with a `[gate step N] G3 blocked` line during a script loop and a `solve_check` call in the transcript. Record steps, minutes, gate events.

- [ ] **Step 3: relativity regression** — same case file as run 4 (already on disk), 30 minutes

```bash
~/.revagent-venv/bin/revagent solve relativity --max-minutes 30
python3 -c "import json; print(json.load(open('relativity/.revagent/result.json'))['signals'])"
```
Expected: `solved` and `signals.gate_blocks == 0` (no false positive on a run that used to solve). If G3 fired, run the replay on this transcript, paste the steps into the spec §8 and raise `STREAK_LIMIT` per the spec's rule — do not merge with a false positive.

- [ ] **Step 4: Replay both new transcripts** and append the rows to the spec §8

```bash
cd /mnt/c/Users/강순우/Documents/vs/rev/revagent
~/.revagent-venv/bin/python scripts/replay_detectors.py ../quiz/basic/.revagent/transcript.jsonl ../quiz/relativity/.revagent/transcript.jsonl
```

- [ ] **Step 5: Bench rows + commit + push + PR**

Add one row per run to the README bench table (steps, minutes, gate events, outcome), then:
```bash
git add README.md docs/superpowers/specs/2026-09-21-transition-rules-design.md
git commit -m "bench: basic and relativity under the gates; spec §8 live results

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
git push -u origin feat/transition-rules
gh pr create --base main --head feat/transition-rules --title "Transition rules: G3 same-script block, G4 long-reasoning budget, solve_check" --body "..."
```
Do not merge; the owner reviews the bench rows first.

---

## Self-review

- Spec coverage: §3.1 detectors → Task 1 (D3 helpers) and Task 3 (D4 counter, metrics); §3.2 gate table → Task 2 (G3) and Task 3 (G4, events, ledger, auto-release/cooldown in Gate); §3.3 solve_check → Task 4; §3.4 replay + fixtures + zero-FP rule → Task 5; §3.5 playbook → Task 6; §5 error handling → Task 2 (`gate_error`), Task 4 (`[tool error]`, `[error]`, `[timeout]`); §6 tests → Tasks 1–6; live validation → Task 7. §2.7 metrics (`first_facts_step`, scripting streak) → `first_facts_step` in Task 3; the scripting-streak metric is not implemented (it needs the "bash runs the binary" heuristic and is a metric only) — recorded here as a deliberate omission, to add if the replay ever needs it.
- Types: `Gate.check(step, calls: list[tuple[str, str]]) -> (list[Verdict], list[dict])` is used identically in Task 3 and Task 5; `Verdict.text` is what the agent appends; `symbolic_solve(source, target, length, charset, timeout_s)` matches its test monkeypatch signature in Task 4.
- Placeholders: none; every step carries its code or exact command.

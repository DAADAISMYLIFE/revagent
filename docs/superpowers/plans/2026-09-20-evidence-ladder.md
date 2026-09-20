# Evidence Ladder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the agent trust and remember observations, notice when it is stuck, verify output-type flags by two independent methods, and hand a runbook to a human only when the sandbox provably cannot run the target.

**Architecture:** The single ReAct loop stays. Four additions: (1) tools write an observation ledger line into the case file by themselves (`ToolContext.observe`); (2) a critic call (`revagent/critic.py`) runs before each compaction and after 12 idle steps, injecting a short `[critic]` memo; (3) `submit_flag` takes an `evidence` enum and refuses a single-method reading for displayed flags; (4) a new `handoff_runbook` tool, gated on tool-set `ctx.env_blocked`, ends the run with a third status `runbook`. The playbook is rewritten around an evidence ladder and a nested-binary rule.

**Tech Stack:** Python 3.12, pytest, existing `revagent` package (agent.py loop, casefile.py, context.py, tools/*). Tests run with `~/.revagent-venv/bin/python -m pytest -q`.

**Spec:** `docs/superpowers/specs/2026-09-20-evidence-ladder-design.md`

## Global Constraints

- Branch: continue on `feat/pe-stage`. Commit trailer on every commit: `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Test command: `~/.revagent-venv/bin/python -m pytest -q` (host has Python 3.14 without pip; the venv exists). The suite must stay green and warning-free (currently 184 passed).
- Observation ledger line format, exactly: `- [obs step N] <one line>` appended to the case file `## Log` section. `N` = `ctx.step` (int, 0 before the first step).
- Critic constants: `CRITIC_IDLE_STEPS = 12`, `CRITIC_MAX = 8`, `CRITIC_MAX_TOKENS = 4096`, critic calls use `reasoning_effort="low"`. Critic memo is injected as a user message starting with `[critic] ` and logged as `- [critic step N] <memo>` in the Log section. Critic failures never abort the loop.
- `submit_flag` `evidence` enum values, exactly: `program_accepted`, `two_independent_readings`, `reimplementation_matches`. Rejection text for a single-method reading starts with `[rejected] second independent reading required`. Same flag submitted a 4th time returns `[rejected] same flag 3× — change approach`.
- Runbook: tool name `handoff_runbook`, file `.revagent/runbook.md` with first line `UNVERIFIED — the agent could not execute the program in its environment`, run status string `runbook`, CLI exit code 3 for `solve`, bench table shows `runbook`. Gate: `ctx.env_blocked` is set only by tools (`[cannot run here]` returned, or 2 start failures), never by the model.
- `[obs …]` and `[critic …]` bullets survive `prune_log` and the shrink prompt says to keep them.
- Playbook rule numbering: existing rules 1–10 keep their numbers; the evidence ladder is rule 11. Do not delete existing rules.
- Nothing in this plan changes `run_gui`/`run_binary` behaviour except adding the ledger line and the `env_blocked` bookkeeping.
- No credentials in code, tests or commits; never read `.secure`, `*.key`, `prism.*`.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `revagent/tools/base.py` | `ToolContext` dataclass | add `step`, `env_blocked`, `start_failures`, `runbook_path`, `flag_attempts`, `observe()` |
| `revagent/tools/run_binary.py` | run ELF/PE | call `ctx.observe(...)`, set `env_blocked` |
| `revagent/tools/run_gui.py` | run GUI PE | call `ctx.observe(...)`, set `env_blocked` |
| `revagent/context.py` | compaction/prune/shrink | keep `[obs`/`[critic` bullets in `_reduce_log_block`; shrink prompt sentence |
| `revagent/critic.py` (new) | critic prompt, trigger bookkeeping, one LLM call | new module |
| `revagent/agent.py` | loop | set `ctx.step`, count Facts/obs lines, critic triggers, `runbook` status, report |
| `revagent/tools/submit_flag.py` | flag gate | `evidence` enum, two-method check, same-flag spam guard |
| `revagent/tools/handoff_runbook.py` (new) | runbook terminal tool | gate on `env_blocked`, write `runbook.md` |
| `revagent/__main__.py` | CLI | exit code 3 for runbook, bench table accepts `runbook` |
| `revagent/prompts/system.md` | playbook | triage observe-first, rule 11, rule 8 rewrite, rule 2 addendum, nested-binary class, critic/runbook notes |
| `bench/mini/src/win_gui_nodll.c`, `bench/mini/win_gui_nodll/desc.txt`, `bench/mini/build_win.sh`, `bench/mini/ANSWERS.md`, `.gitignore`, `scripts/sandbox-build.sh` | mini bench for the runbook path | new PE that imports a missing DLL |
| `tests/test_tools.py`, `tests/test_context.py`, `tests/test_agent.py`, `tests/test_critic.py` (new) | tests | per task |
| `README.md` | docs | tool list, statuses, bench rows |

---

### Task 1: Observation ledger in ToolContext, run_binary and run_gui

**Files:**
- Modify: `revagent/tools/base.py`
- Modify: `revagent/tools/run_binary.py:33-64`
- Modify: `revagent/tools/run_gui.py:225-316` (the `run` function; the final `return` is at line ~308)
- Modify: `revagent/agent.py` (set `self.ctx.step = step` at the top of each loop iteration, right after `steps = step`)
- Test: `tests/test_tools.py`

**Interfaces:**
- Consumes: `CaseFile.add(section, text, bullet=True)` (existing).
- Produces: `ToolContext.step: int = 0`, `ToolContext.env_blocked: bool = False`, `ToolContext.start_failures: int = 0`, `ToolContext.runbook_path: Path | None = None`, `ToolContext.flag_attempts: dict[str, int]` (default empty), `ToolContext.observe(line: str) -> None`, `ToolContext.note_start_failure() -> None` (increments `start_failures`; sets `env_blocked = True` when it reaches 2). Later tasks (critic, runbook, submit_flag) rely on these exact names.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_tools.py`:

```python
def test_observe_appends_ledger_line_to_log(tmp_path):
    c = ctx_for(tmp_path)
    c.step = 7
    c.observe("run_binary chal: exit 0, stdout 'Wrong'")
    log = c.casefile.read().split("## Log")[1]
    assert "- [obs step 7] run_binary chal: exit 0, stdout 'Wrong'" in log
    facts = c.casefile.read().split("## Facts")[1].split("## Hypotheses")[0]
    assert "[obs" not in facts


def test_observe_flattens_newlines_and_survives_write_errors(tmp_path, monkeypatch):
    c = ctx_for(tmp_path)
    c.observe("line one\nline two")
    assert "- [obs step 0] line one line two" in c.casefile.read()
    monkeypatch.setattr(c.casefile, "add", lambda *a, **k: (_ for _ in ()).throw(OSError("locked")))
    c.observe("still fine")  # must not raise


def test_note_start_failure_sets_env_blocked_on_second(tmp_path):
    c = ctx_for(tmp_path)
    c.note_start_failure()
    assert c.env_blocked is False and c.start_failures == 1
    c.note_start_failure()
    assert c.env_blocked is True


def test_run_binary_observes_and_flags_cannot_run(tmp_path, monkeypatch):
    (tmp_path / "w.exe").write_bytes(b"MZ" + b"\0" * 60)
    monkeypatch.setattr("revagent.tools.run_binary.shutil.which", lambda n: None)
    monkeypatch.setattr("revagent.tools.run_binary.subprocess.run",
                        lambda *a, **k: subprocess.CompletedProcess(a[0], 0, "PE32+ executable (GUI) x86-64", ""))
    c = ctx_for(tmp_path)
    c.step = 3
    out = run_binary.run(c, path="w.exe")
    assert out.startswith("[cannot run here]")
    assert c.env_blocked is True
    assert "- [obs step 3] run_binary w.exe: [cannot run here]" in c.casefile.read()


def test_run_binary_observes_exit_and_first_line(tmp_path):
    (tmp_path / "chal").write_text("#!/bin/bash\necho Wrong; exit 1\n")
    c = ctx_for(tmp_path)
    c.step = 4
    run_binary.run(c, path="chal", stdin="x\n")
    text = c.casefile.read()
    assert "- [obs step 4] run_binary chal: exit 1, stdout 'Wrong'" in text
    assert c.env_blocked is False


def test_run_gui_observes_windows_and_change_counts(tmp_path, monkeypatch):
    calls = []
    c = _gui_fixture(tmp_path, monkeypatch, calls)
    c.step = 9
    run_gui.run(c, path="g.exe", actions=["click", "key RButton", "wait 1"])
    text = c.casefile.read()
    line = next(l for l in text.splitlines() if l.startswith("- [obs step 9] run_gui g.exe"))
    assert "windows: CaptainHook" in line and "inputs: 2" in line and "captures: 001-003" in line


def test_run_gui_no_window_twice_sets_env_blocked(tmp_path, monkeypatch):
    import subprocess as sp
    calls = []
    c = _gui_fixture(tmp_path, monkeypatch, calls)
    real_run = run_gui.subprocess.run

    def no_windows(cmd, **kw):
        if cmd[0] == "xdotool" and cmd[1] == "search" and cmd[-2] == "getwindowname":
            return sp.CompletedProcess(cmd, 0, "", "")
        return real_run(cmd, **kw)

    monkeypatch.setattr("revagent.tools.run_gui.subprocess.run", no_windows)
    run_gui.run(c, path="g.exe")
    assert c.env_blocked is False
    run_gui.run(c, path="g.exe")
    assert c.env_blocked is True
```

`subprocess` is already imported at the top of `tests/test_tools.py`; if not, add `import subprocess`. `run_binary` and `run_gui` modules are already imported there (`from revagent.tools import ... run_binary, run_gui`); check the import line and extend it if needed.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `~/.revagent-venv/bin/python -m pytest -q tests/test_tools.py -k "observe or start_failure or env_blocked or observes" -v`
Expected: FAIL with `AttributeError: 'ToolContext' object has no attribute 'step'` / `observe`.

- [ ] **Step 3: Implement `ToolContext` additions**

Replace `revagent/tools/base.py` with:

```python
from dataclasses import dataclass, field
from pathlib import Path

from ..casefile import CaseFile

START_FAILURES_TO_BLOCK = 2


@dataclass
class ToolContext:
    problem_dir: Path
    work_dir: Path
    casefile: CaseFile
    llm: object  # revagent.llm.LLM; typed loosely so tools can be tested without a server
    interactive: bool = True
    out_counter: int = 0
    flag: str | None = None
    how_verified: str = ""
    function_dbs: dict = field(default_factory=dict)
    current_binary: str | None = None
    step: int = 0                      # current loop step; the agent updates it before each tool call
    env_blocked: bool = False          # set by tools only: the sandbox cannot execute the target
    start_failures: int = 0
    runbook_path: Path | None = None   # set by handoff_runbook; ends the run with status "runbook"
    flag_attempts: dict = field(default_factory=dict)

    @property
    def out_dir(self) -> Path:
        return self.work_dir / "out"

    def next_out_id(self) -> int:
        self.out_counter += 1
        return self.out_counter

    def observe(self, line: str) -> None:
        """Observation ledger: one line per execution, written to the case file by the tool itself so
        it survives even when the model never calls `notes`. Never raises."""
        flat = " ".join(str(line).split())
        try:
            self.casefile.add("log", f"[obs step {self.step}] {flat}")
        except Exception:
            pass

    def note_start_failure(self) -> None:
        self.start_failures += 1
        if self.start_failures >= START_FAILURES_TO_BLOCK:
            self.env_blocked = True
```

- [ ] **Step 4: Add ledger calls to `run_binary`**

In `revagent/tools/run_binary.py`, wrap the body of `run` so every return passes through one helper. Replace the function with:

```python
def run(ctx, path: str, args: list[str] | None = None, stdin: str = "", timeout: int = 10) -> str:
    out = _run(ctx, path, args, stdin, timeout)
    _observe(ctx, path, out)
    return out


def _observe(ctx, path: str, out: str) -> None:
    if out.startswith("[cannot run here]"):
        ctx.env_blocked = True
        ctx.observe(f"run_binary {path}: [cannot run here]")
        return
    if out.startswith("[tool error]"):
        return
    first = out.splitlines()[0] if out else ""
    m = re.match(r"\[exit (-?\d+)\]", first)
    code = m.group(1) if m else "?"
    body = "\n".join(out.splitlines()[1:]).strip()
    stdout_first = body.splitlines()[0][:80] if body else ""
    if code not in ("0", "?") and not body:
        ctx.note_start_failure()
    ctx.observe(f"run_binary {path}: exit {code}, stdout {stdout_first!r}")
```

Rename the existing `run` to `_run` (keep its body unchanged) and add `import re` at the top. Confirm the `[exit N]` prefix is what `run_cmd` returns by reading `revagent/tools/bash.py` (`run_cmd`); if the prefix differs, match that exact format in the regex.

- [ ] **Step 5: Add ledger calls to `run_gui`**

In `revagent/tools/run_gui.py`, inside `run`, before the final `return`, compute counts from the data already in hand and observe. Just above the `return ((reset_note + "\n") if reset_note else "") + (...)` statement, insert:

```python
    n_inputs = sum(1 for s in action_specs if (_parse_action(s) or ("wait", []))[0] != "wait")
    n_changed = sum(1 for l in info["actions"].splitlines() if "changed:" in l and "changed: nothing" not in l)
    n_unchanged = sum(1 for l in info["actions"].splitlines() if "changed: nothing" in l)
    n_undelivered = info["actions"].count("NOT DELIVERED")
    last_png = _last_capture_name(screens)
    ctx.observe(f"run_gui {path}{' ' + ' '.join(args) if args else ''}: windows: {info.get('windows', '?')}; "
                f"{info.get('state', '?')}; inputs: {n_inputs} (changed {n_changed}, unchanged {n_unchanged}, "
                f"undelivered {n_undelivered}); captures: {first_png_name}-{last_png}")
    if info.get("windows") in ("(none)", "(timeout)"):
        ctx.note_start_failure()
```

To make `first_png_name` and `_last_capture_name` exist: right after `png = _next_screenshot_path(screens)` add `first_png_name = png.stem`, and add a module-level helper:

```python
def _last_capture_name(screens: Path) -> str:
    existing = sorted(int(f.stem) for f in screens.glob("*.png") if f.stem.isdigit())
    return f"{existing[-1]:03d}" if existing else "?"
```

Also handle the early returns (`[cannot run here]`, `[tool error]`, no display): for the `[cannot run here]` return add `ctx.env_blocked = True; ctx.observe(f"run_gui {path}: [cannot run here]")` before returning. `[tool error]` returns record nothing.

- [ ] **Step 6: Set `ctx.step` in the loop**

In `revagent/agent.py`, in `run()`, directly after `steps = step` inside the `for step in range(...)` loop, add:

```python
                    self.ctx.step = step
```

- [ ] **Step 7: Run the tests**

Run: `~/.revagent-venv/bin/python -m pytest -q`
Expected: all pass, no warnings. (If `test_run_gui_observes_windows_and_change_counts` fails on `captures: 001-003`, check that the `key RButton` action in the fixture is treated as delivered — the fixture's fake xdotool returns exit 0 with empty stderr, so it captures; the three captures are 001 first look, 002 click, 003 key.)

- [ ] **Step 8: Commit**

```bash
git add revagent/tools/base.py revagent/tools/run_binary.py revagent/tools/run_gui.py revagent/agent.py tests/test_tools.py
git commit -m "observation ledger: run_binary/run_gui write [obs step N] lines; env_blocked bookkeeping

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: Ledger lines survive prune_log and shrink

**Files:**
- Modify: `revagent/context.py` (`_reduce_log_block`, `SHRINK_PROMPT`)
- Test: `tests/test_context.py`

**Interfaces:**
- Consumes: `prune_log(casefile, keep=3)`, `shrink_casefile(casefile, llm)`, `SHRINK_PROMPT` (existing).
- Produces: no new names. Behaviour: bullets starting with `- [obs` or `- [critic` inside a reduced compaction block are kept (appended after the (a)/(d) parts, in original order).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_context.py`:

```python
def test_prune_log_keeps_obs_and_critic_bullets(tmp_path):
    from revagent.context import prune_log
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    for n in range(1, 6):
        cf.add("log", f"### compaction {n}\n## (a) FACTS\n- fact {n}\n## (b) FAILED\n- fail {n}\n"
                      f"## (c) UNFINISHED\n- todo {n}\n## (d) ARTIFACTS\n- art {n}", bullet=False)
        cf.add("log", f"[obs step {n}] run_gui x.exe: windows: W")
        cf.add("log", f"[critic step {n}] try clicking")
    reduced = prune_log(cf, keep=3)
    assert reduced == 2
    text = cf.read()
    for n in range(1, 6):
        assert f"- [obs step {n}] run_gui x.exe: windows: W" in text
        assert f"- [critic step {n}] try clicking" in text
    assert "- fail 1" not in text and "- todo 1" not in text and "- fact 1" in text


def test_shrink_prompt_mentions_obs_lines():
    from revagent.context import SHRINK_PROMPT
    assert "[obs" in SHRINK_PROMPT and "[critic" in SHRINK_PROMPT
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `~/.revagent-venv/bin/python -m pytest -q tests/test_context.py -k "obs_and_critic or shrink_prompt_mentions" -v`
Expected: FAIL (obs lines from reduced blocks are dropped; prompt lacks the words).

- [ ] **Step 3: Implement**

In `revagent/context.py`, find `_reduce_log_block` (it returns `[heading, *new_rest], True`). Before computing `new_rest`, collect ledger bullets from the whole block body and append them:

```python
    ledger = [l for l in rest if l.startswith("- [obs ") or l.startswith("- [critic ")]
    new_rest = parts.get("(a)", []) + parts.get("(d)", []) + ledger
```

(`rest` is the block body without its heading — use whatever local name the function already uses for that list; read the function first.) If `_reduce_log_block` returns `changed=False` for blocks with no (b)/(c) parts, leave that behaviour.

Change `SHRINK_PROMPT` to:

```python
SHRINK_PROMPT = (
    "Rewrite this case file to about half its length. Keep EVERY concrete fact (addresses, constants, "
    "algorithms, verified inputs) and every open todo; drop repetition and narrative. Keep the exact "
    "markdown structure: '# Case: ...' then sections '## Facts', '## Hypotheses', '## Todo', '## Log'. "
    "Lines starting with '- [obs' or '- [critic' are the observation ledger: never delete them, only merge "
    "exact duplicates. Output only the rewritten file.\n\n"
)
```

- [ ] **Step 4: Run the tests**

Run: `~/.revagent-venv/bin/python -m pytest -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add revagent/context.py tests/test_context.py
git commit -m "context: keep [obs]/[critic] ledger bullets through prune_log and shrink

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Critic module and loop integration

**Files:**
- Create: `revagent/critic.py`
- Modify: `revagent/agent.py` (loop bookkeeping, injection before compaction and on idle)
- Test: `tests/test_critic.py` (new), `tests/test_agent.py`

**Interfaces:**
- Consumes: `LLM.complete(prompt, system=None, max_tokens=None, reasoning_effort=None)`; `ScriptedLLM.complete(prompt, system=None, **kw)` in tests returns `"- summary bullet"`; `CaseFile.read()/add()`; `ToolContext.step`.
- Produces:
  - `revagent/critic.py`: `CRITIC_IDLE_STEPS = 12`, `CRITIC_MAX = 8`, `CRITIC_MAX_TOKENS = 4096`, `CRITIC_PROMPT: str`, `progress_marker(casefile_text: str) -> tuple[int, int]` (count of Facts bullets, count of `- [obs` lines), `render_recent(messages: list[dict], n: int = 12) -> str`, `run_critic(llm, casefile, messages, step: int) -> str | None` (returns memo text or `None` on failure/empty; on success appends `- [critic step N] <memo>` to the Log).
  - `agent.py`: `Agent.critic_calls: int` counter; a user message `{"role": "user", "content": "[critic] " + memo}` appended after a critic run.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_critic.py`:

```python
from pathlib import Path

from revagent.casefile import CaseFile
from revagent.critic import (CRITIC_IDLE_STEPS, CRITIC_MAX, CRITIC_MAX_TOKENS, progress_marker, render_recent,
                             run_critic)


class FakeLLM:
    def __init__(self, reply="1. obs contradicts plan\n2. repeated 3x\n3. run_gui with clicks\n4. none", raise_=False):
        self.reply, self.raise_, self.kw, self.prompts = reply, raise_, None, []
        self.last_finish_reason = "stop"

    def complete(self, prompt, system=None, **kw):
        self.prompts.append(prompt)
        self.kw = kw
        if self.raise_:
            raise RuntimeError("down")
        return self.reply


def test_constants():
    assert CRITIC_IDLE_STEPS == 12 and CRITIC_MAX == 8 and CRITIC_MAX_TOKENS == 4096


def test_progress_marker_counts_facts_and_obs(tmp_path):
    cf = CaseFile(tmp_path / "c.md", "p", "d")
    assert progress_marker(cf.read()) == (0, 0)
    cf.add("facts", "a"); cf.add("facts", "b"); cf.add("log", "[obs step 1] x"); cf.add("log", "not obs")
    assert progress_marker(cf.read()) == (2, 1)


def test_render_recent_takes_last_n_tool_exchanges():
    msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
    for i in range(20):
        msgs.append({"role": "assistant", "content": "", "tool_calls": [{"id": f"i{i}", "type": "function",
                     "function": {"name": "bash", "arguments": '{"cmd": "echo %d"}' % i}}]})
        msgs.append({"role": "tool", "tool_call_id": f"i{i}", "content": "out %d" % i})
    text = render_recent(msgs, n=3)
    assert "echo 19" in text and "out 19" in text and "echo 16" not in text
    assert len(text) < 3 * 600


def test_run_critic_appends_memo_and_uses_low_effort(tmp_path):
    cf = CaseFile(tmp_path / "c.md", "p", "d")
    llm = FakeLLM()
    memo = run_critic(llm, cf, [], step=15)
    assert memo and memo.startswith("1. obs contradicts plan")
    assert llm.kw == {"max_tokens": CRITIC_MAX_TOKENS, "reasoning_effort": "low"}
    assert "- [critic step 15] 1. obs contradicts plan" in cf.read()
    assert "# Case: p" in llm.prompts[0]


def test_run_critic_failure_returns_none_and_logs(tmp_path):
    cf = CaseFile(tmp_path / "c.md", "p", "d")
    assert run_critic(FakeLLM(raise_=True), cf, [], step=3) is None
    assert "- [critic step 3] (failed: RuntimeError)" in cf.read()
    cf2 = CaseFile(tmp_path / "c2.md", "p", "d")
    assert run_critic(FakeLLM(reply="   "), cf2, [], step=4) is None
```

Append to `tests/test_agent.py`:

```python
def test_critic_runs_after_idle_steps_and_before_compaction(tmp_path, monkeypatch):
    d = make_problem(tmp_path)
    # 13 identical-shape bash calls that never add Facts/obs, then a compaction, then submit
    calls = [[("bash", {"cmd": f"echo {i}"})] for i in range(13)]
    script = calls + [[("bash", {"cmd": "echo after"})], [("submit_flag", {"flag": "DH{x}", "how_verified": "ran it",
                                                                            "evidence": "program_accepted"})]]
    llm = ScriptedLLM(script, prompt_tokens=lambda n: 50_000 if n == 14 else 100)
    memos = []
    monkeypatch.setattr("revagent.agent.run_critic",
                        lambda l, cf, msgs, step: memos.append(step) or f"memo@{step}")
    a = Agent(d, "desc", llm, max_steps=40, interactive=False)
    r = a.run()
    assert r["status"] == "solved"
    # idle trigger fired once at step 12 (12 steps without progress), compaction trigger at step 14
    assert memos == [12, 14]
    injected = [m for s in llm.seen for m in s if m.get("role") == "user" and m["content"].startswith("[critic] ")]
    assert injected and injected[0]["content"] == "[critic] memo@12"


def test_critic_capped_per_run(tmp_path, monkeypatch):
    from revagent.critic import CRITIC_MAX
    d = make_problem(tmp_path)
    n = 12 * (CRITIC_MAX + 2)
    script = [[("bash", {"cmd": f"echo {i}"})] for i in range(n)] + [[("submit_flag", {"flag": "DH{x}", "how_verified": "ok", "evidence": "program_accepted"})]]
    llm = ScriptedLLM(script)
    memos = []
    monkeypatch.setattr("revagent.agent.run_critic", lambda l, cf, msgs, step: memos.append(step) or "m")
    Agent(d, "desc", llm, max_steps=n + 5, interactive=False).run()
    assert len(memos) == CRITIC_MAX
```

Note: `submit_flag` gains an `evidence` parameter in Task 4; until then the extra key would make `_execute` return `[tool error] bad arguments`. To keep Task 3 green on its own, in these two tests pass `submit_flag` **without** `evidence` and change them to include it in Task 4's Step 5.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `~/.revagent-venv/bin/python -m pytest -q tests/test_critic.py tests/test_agent.py -k "critic" -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'revagent.critic'`.

- [ ] **Step 3: Implement `revagent/critic.py`**

```python
"""Critic: a separate, cheap LLM call that reviews the case file and the last few tool exchanges and
answers four fixed questions. It runs before every compaction and after CRITIC_IDLE_STEPS steps without
new Facts/observations. Its memo is advice injected as a user message, not an instruction the loop enforces."""
from .casefile import SECTIONS

CRITIC_IDLE_STEPS = 12
CRITIC_MAX = 8
CRITIC_MAX_TOKENS = 4096
RECENT_ARG_CHARS = 200
RECENT_RESULT_CHARS = 300

CRITIC_PROMPT = (
    "You are reviewing an autonomous reverse-engineering session that may be stuck. Below is its case file "
    "(notes) and its most recent tool calls. Answer these four questions, one short line each, no preamble:\n"
    "1. Which observation ([obs ...] lines, run outputs, screenshots) contradicts the current plan (first Todo item)? "
    "Quote it, or say 'none'.\n"
    "2. Is the same approach being repeated? Name it and how many times.\n"
    "3. The single cheapest, most decisive next experiment, written as a concrete tool call "
    "(e.g. run_gui with actions [...], run_binary with stdin ..., bash ...).\n"
    "4. Is there tool evidence that this environment cannot execute the target ('[cannot run here]', "
    "no window ever appeared, crash on start)? Quote it or say 'none'.\n"
    "Prefer observation over decompilation. If a byte stream is being displayed, ask what it decodes to.\n\n"
)


def progress_marker(casefile_text: str) -> tuple[int, int]:
    """(number of Facts bullets, number of '- [obs' lines). Used to detect steps without progress."""
    lines = casefile_text.split("\n")
    try:
        f0 = lines.index(SECTIONS["facts"])
    except ValueError:
        f0 = None
    n_facts = 0
    if f0 is not None:
        headers = set(SECTIONS.values())
        for line in lines[f0 + 1:]:
            if line.strip() in headers:
                break
            if line.startswith("- "):
                n_facts += 1
    n_obs = sum(1 for l in lines if l.startswith("- [obs "))
    return n_facts, n_obs


def render_recent(messages: list[dict], n: int = CRITIC_IDLE_STEPS) -> str:
    """The last n (assistant tool call, tool result) pairs as compact text."""
    pairs: list[str] = []
    results = {m.get("tool_call_id"): m.get("content", "") for m in messages if m.get("role") == "tool"}
    for m in messages:
        if m.get("role") != "assistant":
            continue
        for tc in m.get("tool_calls") or []:
            fn = tc.get("function", {})
            args = (fn.get("arguments") or "")[:RECENT_ARG_CHARS]
            res = (results.get(tc.get("id")) or "")[:RECENT_RESULT_CHARS]
            pairs.append(f"> {fn.get('name')} {args}\n< {res}")
    return "\n".join(pairs[-n:])


def run_critic(llm, casefile, messages: list[dict], step: int) -> str | None:
    """One critic call. Appends '- [critic step N] memo' to the Log and returns the memo, or None."""
    prompt = CRITIC_PROMPT + "CASE FILE:\n" + casefile.read() + "\n\nRECENT TOOL CALLS:\n" + render_recent(messages)
    try:
        memo = llm.complete(prompt, max_tokens=CRITIC_MAX_TOKENS, reasoning_effort="low")
    except Exception as e:
        try:
            casefile.add("log", f"[critic step {step}] (failed: {type(e).__name__})")
        except Exception:
            pass
        return None
    memo = (memo or "").strip()
    memo = "\n".join(memo.splitlines()[:6])
    if not memo:
        return None
    try:
        casefile.add("log", f"[critic step {step}] {memo}")
    except Exception:
        pass
    return memo
```

- [ ] **Step 4: Integrate into the loop**

In `revagent/agent.py`:

1. Import: `from .critic import CRITIC_IDLE_STEPS, CRITIC_MAX, progress_marker, run_critic`.
2. In `__init__`: `self.critic_calls = 0`.
3. Add a method:

```python
    def _critic(self, step: int, cause: str) -> None:
        if self.critic_calls >= CRITIC_MAX:
            return
        self.critic_calls += 1
        self._log({"role": "_meta", "event": "critic", "step": step, "cause": cause, "n": self.critic_calls})
        memo = run_critic(self.llm, self.casefile, self.messages, step)
        if memo:
            self._append({"role": "user", "content": "[critic] " + memo})
            self._print(f"[{step}] -- critic ({cause}) --\n{memo[:600]}")
```

4. In `run()`, before the `for` loop: `last_marker = progress_marker(self.casefile.read()); idle = 0`.
5. After the tool-execution block of each step (right after the `recent.append(...)`/repeat-check lines and before the `THRESHOLD` check), add:

```python
                    marker = progress_marker(self.casefile.read())
                    if marker != last_marker:
                        last_marker, idle = marker, 0
                    else:
                        idle += 1
                    if idle >= CRITIC_IDLE_STEPS:
                        self._critic(step, "idle")
                        idle = 0
```

6. In both compaction sites (the `except ContextOverflow` branch and the threshold branch), call `self._critic(step, "compaction")` immediately before `compactions += 1`. In the overflow branch the critic call happens while the context is already too large for `chat`, but `complete` sends only the case file + recent calls, so it fits.

Note: `compact()` keeps the last 4 tool exchanges and the reset message; the injected `[critic]` user message may be dropped by compaction — that is fine because the memo is also in the Log, which the reset message re-sends.

- [ ] **Step 5: Run the tests**

Run: `~/.revagent-venv/bin/python -m pytest -q`
Expected: all pass. If `test_critic_runs_after_idle_steps_and_before_compaction` reports memos `[12, 14, ...]` with an extra idle firing, check that `idle` is reset to 0 after the idle-triggered call and that the compaction-triggered call does not also count as idle progress.

- [ ] **Step 6: Commit**

```bash
git add revagent/critic.py revagent/agent.py tests/test_critic.py tests/test_agent.py
git commit -m "critic: review call before compaction and after 12 idle steps, memo injected as [critic]

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: submit_flag evidence enum, two-method rule, same-flag guard

**Files:**
- Modify: `revagent/tools/submit_flag.py`
- Modify: `tests/test_agent.py` (add `"evidence": "program_accepted"` to the two critic tests' submit calls; any other `submit_flag` calls in tests keep working because `evidence` defaults to `program_accepted`)
- Test: `tests/test_tools.py`

**Interfaces:**
- Consumes: `ToolContext.flag_attempts: dict[str, int]` (Task 1).
- Produces: `EVIDENCE_KINDS = ("program_accepted", "two_independent_readings", "reimplementation_matches")`, `count_methods(how_verified: str) -> int`, `run(ctx, flag, how_verified="", evidence="program_accepted")`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_tools.py`:

```python
def test_submit_flag_two_readings_requires_two_methods(tmp_path):
    from revagent.tools import submit_flag
    c = ctx_for(tmp_path)
    out = submit_flag.run(c, flag="DH{abc}", how_verified="read it from the screenshot with pillow",
                          evidence="two_independent_readings")
    assert out.startswith("[rejected] second independent reading required") and c.flag is None
    out = submit_flag.run(c, flag="DH{abc}", evidence="two_independent_readings",
                          how_verified="① rasterised the click-diff PNGs and read 16 glyphs\n"
                                       "② gate constants form a 0..15 permutation, so the alphabet is hex; log coordinates rebuilt the same string")
    assert out.startswith("[accepted]") and c.flag == "DH{abc}"


def test_submit_flag_evidence_enum_and_default(tmp_path):
    from revagent.tools import submit_flag
    c = ctx_for(tmp_path)
    assert submit_flag.run(c, flag="DH{a}", how_verified="x", evidence="vibes").startswith("[rejected] evidence must be one of")
    assert submit_flag.run(c, flag="DH{a}", how_verified="run_binary printed Correct").startswith("[accepted]")
    assert submit_flag.SCHEMA["function"]["parameters"]["properties"]["evidence"]["enum"] == list(submit_flag.EVIDENCE_KINDS)


def test_submit_flag_same_flag_spam_guard(tmp_path):
    from revagent.tools import submit_flag
    c = ctx_for(tmp_path)
    for _ in range(3):
        out = submit_flag.run(c, flag="DH{zzz}", how_verified="one method only", evidence="two_independent_readings")
        assert out.startswith("[rejected] second independent reading required")
    out = submit_flag.run(c, flag="DH{zzz}", how_verified="one method only", evidence="two_independent_readings")
    assert out == "[rejected] same flag 3× — change approach"


def test_count_methods():
    from revagent.tools.submit_flag import count_methods
    assert count_methods("only one sentence here") == 1
    assert count_methods("① a\n② b") == 2
    assert count_methods("1) screen diff read 2) log rebuild") == 2
    assert count_methods("first line\nsecond line") == 2
    assert count_methods("") == 0
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `~/.revagent-venv/bin/python -m pytest -q tests/test_tools.py -k "submit_flag or count_methods" -v`
Expected: FAIL (`unexpected keyword argument 'evidence'`, missing `EVIDENCE_KINDS`).

- [ ] **Step 3: Implement**

Replace `revagent/tools/submit_flag.py` with:

```python
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
```

- [ ] **Step 4: Update the two critic tests in `tests/test_agent.py`**

Add `"evidence": "program_accepted"` to the `submit_flag` argument dicts in `test_critic_runs_after_idle_steps_and_before_compaction` and `test_critic_capped_per_run` (they were written without it in Task 3).

- [ ] **Step 5: Run the tests**

Run: `~/.revagent-venv/bin/python -m pytest -q`
Expected: all pass. Existing tests that call `submit_flag` without `evidence` still pass because of the default.

- [ ] **Step 6: Commit**

```bash
git add revagent/tools/submit_flag.py tests/test_tools.py tests/test_agent.py
git commit -m "submit_flag: evidence kind; displayed flags need two independent readings; same-flag guard

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: handoff_runbook tool and the `runbook` run status

**Files:**
- Create: `revagent/tools/handoff_runbook.py`
- Modify: `revagent/agent.py` (status after tool execution, `_report`)
- Modify: `revagent/__main__.py` (`solve` exit code, `_print_bench_table`)
- Test: `tests/test_tools.py`, `tests/test_agent.py`

**Interfaces:**
- Consumes: `ToolContext.env_blocked`, `ToolContext.runbook_path`, `ToolContext.work_dir` (Task 1).
- Produces: tool `handoff_runbook(steps: list[str], expected_observation: str, flag_rule: str) -> str`; file `<work_dir>/runbook.md`; `Agent.run()` result `status == "runbook"` with `result["runbook"] = ".revagent/runbook.md"`; `revagent solve` returns exit code 3 for runbook; bench table prints `runbook` in the status column and the exit code is 1 unless every row is `solved`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_tools.py`:

```python
def test_handoff_runbook_rejected_when_env_can_run(tmp_path):
    from revagent.tools import handoff_runbook
    c = ctx_for(tmp_path)
    out = handoff_runbook.run(c, steps=["run it", "click 16 times"], expected_observation="16 hex glyphs",
                              flag_rule="DH{<the 16 glyphs>}")
    assert out.startswith("[rejected] the sandbox can run this program")
    assert c.runbook_path is None and not (c.work_dir / "runbook.md").exists()


def test_handoff_runbook_writes_file_when_env_blocked(tmp_path):
    from revagent.tools import handoff_runbook
    c = ctx_for(tmp_path)
    c.env_blocked = True
    out = handoff_runbook.run(c, steps=["Run CaptainHook.exe on Windows", "Left-click the window 16 times"],
                              expected_observation="one 7-segment hex glyph per click",
                              flag_rule="DH{<glyphs in order, O is 0>}")
    assert out.startswith("[accepted] runbook written")
    text = (c.work_dir / "runbook.md").read_text(encoding="utf-8")
    assert text.splitlines()[0] == "UNVERIFIED — the agent could not execute the program in its environment"
    assert "1. Run CaptainHook.exe on Windows" in text and "2. Left-click the window 16 times" in text
    assert "## Expected observation" in text and "## Flag rule" in text
    assert c.runbook_path == c.work_dir / "runbook.md"


def test_handoff_runbook_needs_steps(tmp_path):
    from revagent.tools import handoff_runbook
    c = ctx_for(tmp_path)
    c.env_blocked = True
    assert handoff_runbook.run(c, steps=[], expected_observation="x", flag_rule="y").startswith("[rejected] steps is empty")
```

Also extend the existing `test_registry_has_all_tools` expected-names set with `"handoff_runbook"`.

Append to `tests/test_agent.py`:

```python
def test_runbook_ends_run_with_runbook_status(tmp_path):
    d = make_problem(tmp_path)
    script = [[("handoff_runbook", {"steps": ["a"], "expected_observation": "b", "flag_rule": "c"})]]
    llm = ScriptedLLM(script)
    a = Agent(d, "desc", llm, max_steps=5, interactive=False)
    a.ctx.env_blocked = True
    r = a.run()
    assert r["status"] == "runbook" and r["runbook"] == ".revagent/runbook.md" and r["flag"] is None
    assert (d / ".revagent" / "runbook.md").exists()
    assert json.loads((d / ".revagent" / "result.json").read_text())["status"] == "runbook"


def test_bench_table_exit_code_with_runbook(capsys):
    from revagent.__main__ import _print_bench_table
    rc = _print_bench_table([("p", "runbook", ".revagent/runbook.md", 3, 0.1)])
    assert rc == 1 and "| p | runbook |" in capsys.readouterr().out
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `~/.revagent-venv/bin/python -m pytest -q tests/test_tools.py tests/test_agent.py -k "runbook" -v`
Expected: FAIL (`ImportError: cannot import name 'handoff_runbook'`).

- [ ] **Step 3: Implement the tool**

Create `revagent/tools/handoff_runbook.py`:

```python
"""Last resort: hand a human a procedure when the sandbox provably cannot execute the target.
The gate is ctx.env_blocked, which only run_binary/run_gui set ([cannot run here], repeated start failures)."""
from pathlib import Path

RUNBOOK_HEADER = "UNVERIFIED — the agent could not execute the program in its environment"

SCHEMA = {
    "type": "function",
    "function": {
        "name": "handoff_runbook",
        "description": (
            "LAST RESORT, allowed only when run_binary/run_gui reported that this environment cannot execute the "
            "program ([cannot run here], no window ever appears, crash on start). Ends the session with a runbook "
            "a human runs on a real machine: numbered steps, what they will observe, and how to turn the "
            "observation into the flag. Put everything static analysis already established (input format, which "
            "event advances the program, the character set, the length) into the steps. If the sandbox CAN run "
            "the program, this tool is rejected: continue by observation instead."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "steps": {"type": "array", "items": {"type": "string"}, "description": "numbered procedure for a human, one action per entry"},
                "expected_observation": {"type": "string", "description": "what the human will see at each step"},
                "flag_rule": {"type": "string", "description": "how to turn the observation into PREFIX{...}"},
            },
            "required": ["steps", "expected_observation", "flag_rule"],
        },
    },
}


def run(ctx, steps: list[str], expected_observation: str, flag_rule: str) -> str:
    if not ctx.env_blocked:
        return ("[rejected] the sandbox can run this program (no [cannot run here] / start failure was recorded; "
                "see the [obs ...] lines in notes). Continue by observation: run it, drive it with input, read the "
                "captures. A runbook is only for programs this environment cannot execute.")
    steps = [str(s).strip() for s in (steps or []) if str(s).strip()]
    if not steps:
        return "[rejected] steps is empty. Give the human a numbered procedure."
    body = [RUNBOOK_HEADER, "", f"# Runbook: {ctx.problem_dir.name}", "", "## Steps"]
    body += [f"{i}. {s}" for i, s in enumerate(steps, 1)]
    body += ["", "## Expected observation", expected_observation.strip() or "(none given)", "",
             "## Flag rule", flag_rule.strip() or "(none given)", ""]
    path = Path(ctx.work_dir) / "runbook.md"
    path.write_text("\n".join(body), encoding="utf-8")
    ctx.runbook_path = path
    return f"[accepted] runbook written to .revagent/runbook.md; the session will end now."
```

- [ ] **Step 4: Loop and CLI integration**

In `revagent/agent.py`:

1. In the tool-execution `for call in resp.tool_calls:` loop, treat a written runbook like a submitted flag: change `if self.ctx.flag:` (inside the loop, the one setting `flag_just_set`) to `if self.ctx.flag or self.ctx.runbook_path:` and the skip message to `"[tool error] skipped: session ended"`.
2. After the loop, where `if self.ctx.flag: status = "solved"; break` is, add before it:

```python
                    if self.ctx.runbook_path:
                        status = "runbook"
                        break
```

3. In the `result` dict add `"runbook": ".revagent/runbook.md" if self.ctx.runbook_path else None,`.
4. In `_report`, add a branch:

```python
        elif result["status"] == "runbook":
            self._print(f"\n\033[1mRUNBOOK: {result['runbook']}\033[0m (the sandbox could not execute the program)\n")
            self._print((self.work_dir / "runbook.md").read_text(encoding="utf-8"))
```

In `revagent/__main__.py`:

1. `solve`: replace `return 0 if r["status"] == "solved" else 1` with `return {"solved": 0, "runbook": 3}.get(r["status"], 1)`.
2. `_print_bench_table` already prints the status string; keep `return 0 if all(r[1] == "solved" ...)`. In the bench row builders, use `r.get("flag") or r.get("runbook") or r.get("reason", "")` for the third column (both the sandbox and host branches).

- [ ] **Step 5: Run the tests**

Run: `~/.revagent-venv/bin/python -m pytest -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add revagent/tools/handoff_runbook.py revagent/agent.py revagent/__main__.py tests/test_tools.py tests/test_agent.py
git commit -m "handoff_runbook: human procedure when the sandbox cannot run the target; runbook run status

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: Playbook rewrite (evidence ladder, nested binary, verification, runbook, critic)

**Files:**
- Modify: `revagent/prompts/system.md`
- Test: `tests/test_agent.py`

**Interfaces:**
- Consumes: `load_system_prompt()` (existing).
- Produces: prompt text only. Later validation (Task 7/8) depends on these exact phrases: `Evidence ladder`, `Nested binary`, `two_independent_readings`, `handoff_runbook`, `[critic]`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_agent.py`:

```python
def test_playbook_has_evidence_ladder_sections():
    p = load_system_prompt()
    assert "11. **Evidence ladder.**" in p
    assert "**Nested binary" in p
    assert "two_independent_readings" in p and "program_accepted" in p and "reimplementation_matches" in p
    assert "handoff_runbook" in p and "[critic]" in p
    assert "Fix the character set before classifying glyphs" in p
    assert p.index("## 1. Triage") < p.index("run it once") < p.index("## 2. Locate the check")
    for n in range(1, 11):
        assert f"\n{n}. **" in p  # existing rules keep their numbers
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `~/.revagent-venv/bin/python -m pytest -q tests/test_agent.py -k playbook -v`
Expected: FAIL.

- [ ] **Step 3: Edit `revagent/prompts/system.md`**

Make these edits (keep everything else):

(a) Rule 2 — replace its text with:

```
2. **No unverified submission.** `submit_flag` needs `evidence`: `program_accepted` (run_binary/run_gui showed the success message for your input), `reimplementation_matches` (your faithful Python model accepts it and you matched intermediate values against the real program), or `two_independent_readings` (the program DISPLAYS the flag and you read it by two DIFFERENT methods that agree — e.g. captures after real input + text rebuilt from logged coordinates or decoded bytes). Reading the same glyph table twice is one method. A string that merely looks like a flag inside the binary is not verified. Flag format is whatever the description states (Dreamhack default `DH{...}`).
```

(b) Rule 8 — replace its text with:

```
8. **Flags drawn as graphics:** first READ them from the screen: `run_gui` captures, then the `NNN.diff.png` after each input (static noise cancels out), rasterised with pillow into an ASCII grid. Fix the character set before classifying glyphs: count the distinct draw routines, read the range of the gate/index constants, use the description's hint (16 draw functions ⇒ hex `0-9A-F`; 10 ⇒ decimal; 36/62 ⇒ alphanumeric). A glyph read as a character outside that set is a misread — write the alternatives and settle it by a second method. Only when the screen cannot be read extract the primitives (segment endpoints, bitmap pixels) from a log or the code and rasterise them. Seven-segment fonts: `b` and `d` may be lowercase shapes, `D` may be a triangle, `A` has no bottom bar.
```

(c) After rule 10 add:

```
11. **Evidence ladder.** Observation (program output, screen captures, debugger values) > trace/log (proxy DLL, strace, hooks) > decompiler/disassembly > your reasoning. When two levels disagree, the higher one wins. When an observation looks wrong ("wine renders black", "clicks do nothing"), suspect YOUR changes to the environment first (a replaced DLL, a leftover process, a patched binary) and observe again from a clean state before blaming the tool. Observation does not replace static analysis, it aims it: first establish WHAT you are looking at (a character set, a byte stream, a state machine, a menu), then pick the cheapest way to get all of it (decrypt from the file, dump from memory, log, emulate) instead of observing thousands of steps. `[critic]` messages are a second opinion on exactly this: if one proposes an experiment, run it before arguing with it.
```

(d) In `## 1. Triage`, append this sentence to the paragraph:

```
If the binary can run here, run it once during triage (`run_binary` with a plausible input, or `run_gui` for a GUI PE) and write what it does — prompts, output, windows, what advances it — to notes before reading any code.
```

(e) In `## 3. Classify the check and act`, add a bullet after the **Packed** bullet:

```
- **Nested binary / emitted byte stream:** if the program prints, draws or dumps a stream of bytes (hex digits, base64, a bitmap, one character per event), decode it to a file and identify it (`file`, magic `MZ`/`ELF`/`UPX!`/`PK`, size hints such as an End constant). If it is a PE/ELF, this is a second-stage challenge: locate the encrypted source in the outer file (search for the PRNG/XOR routine that produces the stream), decrypt it in one go instead of observing the whole stream, then apply this same procedure (triage → run → classify) to the inner binary.
```

(f) In `## 5. Dynamic vs static — and when the binary will not run`, append a paragraph:

```
**When this environment truly cannot execute the program** (`run_binary`/`run_gui` said `[cannot run here]`, or the program never shows a window / crashes on start twice), finish the static analysis (input format, which event advances it, character set, length, where the data comes from) and call `handoff_runbook` with a numbered procedure a human runs on a real machine. It is rejected while the sandbox can run the program: then observe instead.
```

- [ ] **Step 4: Run the test**

Run: `~/.revagent-venv/bin/python -m pytest -q`
Expected: all pass. Check with `grep -n "^[0-9]*\. \*\*" revagent/prompts/system.md` that rules 1–11 appear once each in order.

- [ ] **Step 5: Commit**

```bash
git add revagent/prompts/system.md tests/test_agent.py
git commit -m "playbook: evidence ladder, observe during triage, nested-binary class, verification kinds, runbook

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: Mini bench for the runbook path and README

**Files:**
- Create: `bench/mini/src/win_gui_nodll.c`, `bench/mini/win_gui_nodll/desc.txt`
- Modify: `bench/mini/build_win.sh`, `bench/mini/ANSWERS.md`, `.gitignore`, `scripts/sandbox-build.sh`, `README.md`

**Interfaces:**
- Consumes: mingw cross compiler inside the sandbox image (`x86_64-w64-mingw32-gcc`), `run_gui` `[cannot run here]`/no-window behaviour (Task 1), `handoff_runbook` (Task 5).
- Produces: `bench/mini/win_gui_nodll/win_gui_nodll.exe` (built in the image, git-ignored), expected run status `runbook`.

- [ ] **Step 1: Add the source**

`bench/mini/src/win_gui_nodll.c`:

```c
#include <windows.h>
/* Imports a DLL that does not exist, so the loader fails before WinMain: wine shows no window.
   Expected agent outcome: handoff_runbook (status "runbook"). The flag is never displayed here. */
__declspec(dllimport) int __stdcall NoSuchExport(int);
static const wchar_t *FLAG = L"DH{runb00k_p4th}";
int WINAPI wWinMain(HINSTANCE hi, HINSTANCE hp, PWSTR cmd, int show) {
    (void)FLAG;
    return NoSuchExport(1);
}
```

Build it against an import library for a fake DLL so the import is real. In `bench/mini/build_win.sh` append before the final `echo`:

```bash
cat > "$HERE/win_gui_nodll/nosuch.def" <<'EOF'
LIBRARY nosuchdll_zz.dll
EXPORTS
NoSuchExport@4
EOF
x86_64-w64-mingw32-dlltool -d "$HERE/win_gui_nodll/nosuch.def" -l "$HERE/win_gui_nodll/libnosuch.a"
x86_64-w64-mingw32-gcc -O1 -s -municode -mwindows -o "$HERE/win_gui_nodll/win_gui_nodll.exe" "$HERE/src/win_gui_nodll.c" -L"$HERE/win_gui_nodll" -lnosuch
rm -f "$HERE/win_gui_nodll/nosuch.def" "$HERE/win_gui_nodll/libnosuch.a"
```

and change the final echo to `echo "built win_console.exe, win_gui.exe, win_gui_key.exe and win_gui_nodll.exe"`.

`bench/mini/win_gui_nodll/desc.txt`: `Run the program and read the flag DH{...} from its window.`

`bench/mini/ANSWERS.md`: add `| win_gui_nodll | (expected status: runbook — the exe cannot start; no flag is displayed) |`.

`.gitignore`: add `bench/mini/win_gui_nodll/win_gui_nodll.exe`.

- [ ] **Step 2: Smoke in `scripts/sandbox-build.sh`**

After the existing `run_gui actions ok` block add:

```python
d = Path("/app/bench/mini/win_gui_nodll")
ctx = ToolContext(problem_dir=d, work_dir=w, casefile=CaseFile(w/"case.md","g","d"), llm=None, interactive=False)
out = run_gui.run(ctx, path="win_gui_nodll.exe", wait_seconds=4)
out = run_gui.run(ctx, path="win_gui_nodll.exe", wait_seconds=4)
assert ctx.env_blocked, "two window-less launches should set env_blocked"
print("env_blocked ok")
```

- [ ] **Step 3: Build and smoke**

Run (from a shell that can use docker; in this session that is the wsl.exe wrapper with a script file):

```bash
bash scripts/sandbox-build.sh
```

Expected: the smoke prints `run_gui ok`, `run_gui actions ok`, `env_blocked ok`, and the host tree gets `bench/mini/win_gui_nodll/win_gui_nodll.exe`.

- [ ] **Step 4: README**

In `README.md`:
- Architecture paragraph: tool count becomes nine, add `handoff_runbook`; mention the observation ledger (`[obs step N]` lines written by run tools), the critic (before compaction and after 12 idle steps), and `submit_flag` evidence kinds.
- Statuses: document `solved` / `unsolved` / `runbook` (exit codes 0 / 1 / 3).
- Bench table: add a row `| bench/mini/win_gui_nodll (mingw PE, missing DLL import) | runbook-path test | pending |` (filled in Task 8).

- [ ] **Step 5: Commit**

```bash
git add bench/mini/src/win_gui_nodll.c bench/mini/win_gui_nodll/desc.txt bench/mini/build_win.sh bench/mini/ANSWERS.md .gitignore scripts/sandbox-build.sh README.md
git commit -m "bench: win_gui_nodll (runbook path); README for ledger, critic, evidence kinds, runbook status

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 8 (controller-run validation, no implementer): sandbox benches and the captain-hook rerun

**Files:** `README.md` (results only)

- [ ] **Step 1:** Run `revagent solve --sandbox-dev bench/mini/win_gui_key --no-ask --max-steps 40 --max-minutes 30` (fresh `.revagent`). Expected: `solved`, ≤ 20 steps.
- [ ] **Step 2:** Run the same for `bench/mini/win_gui_nodll` with `--max-steps 60`. Expected: status `runbook`, `.revagent/runbook.md` exists with numbered steps. If the agent instead loops without calling `handoff_runbook`, read the transcript for whether `env_blocked` was set (two `[obs …] run_gui … windows: (none)` lines) and whether the `[critic]` memo mentioned the environment; fix wording, not gates.
- [ ] **Step 3:** Run `quiz/captain-hook` with a fresh case file (move the old one aside), `--max-steps 300 --max-minutes 120`, alone. Success criteria (spec §6): either a submission with `two_independent_readings` whose two methods are genuinely different, or an honest `unsolved`. Any submission that skips the two-method rule is a failure of Task 4/6 wording.
- [ ] **Step 4:** Record the three results in the README bench table and commit:

```bash
git add README.md
git commit -m "README: evidence-ladder bench results

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

"""The ReAct loop."""
import json
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from .casefile import CaseFile
from .context import THRESHOLD, compact, format_work_files, list_work_files, shrink_casefile
from .critic import CRITIC_IDLE_STEPS, CRITIC_MAX, progress_marker, run_critic
from .detectors import LONG_REASONING_CHARS, LONG_REASONING_LIMIT, RELEASE_AFTER
from .gate import Gate
from .llm import ContextOverflow, ToolCall
from .tools import load_tools
from .tools.base import ToolContext
from .tools.bash import run_cmd
from .truncate import truncate

TRUNCATED_RETRY_EFFORT = "low"  # the retry step only; normal steps keep the client default (medium)
TRUNCATED_RETRY_HINT = ("[system] Your previous attempt at this step exhausted the output budget while thinking and "
                        "produced nothing. Do not repeat that: decide in a few sentences, then call a tool. If a "
                        "computation is long, put it in a Python script and let the tool run it. Save intermediate "
                        "results (tables, mappings) to a file and to notes so they survive context resets.")
TRUNCATED_NUDGE = ("Your previous reply hit the output budget while thinking, so nothing was produced. "
                   "Do not trace long code by hand in your head: decide in a few sentences, write the key facts to "
                   "notes, then call a tool (write a script for any parsing).")
G4_TEXT = (f"[gate] This is the {LONG_REASONING_LIMIT}th step whose thinking exceeded {LONG_REASONING_CHARS} characters. "
           "No solved run has ever needed that many. Stop tracing in your head: put the derivation into a script "
           "(python3), save its output to a file, and reason from the printed result.")

TASK_TEMPLATE = """# Challenge
Directory: {dir}

## Description
{desc}

## Files (ls -la)
{listing}

## Rules
- Flag format: PREFIX{{...}} using the prefix stated in the description (Dreamhack default DH{{...}}). Verify before submit_flag.
- Write conclusions to notes as you go; your context will be reset when it grows.
- Start with triage, then locate and classify the check. Go."""


def load_system_prompt() -> str:
    return (Path(__file__).parent / "prompts" / "system.md").read_text(encoding="utf-8")


class Agent:
    def __init__(self, problem_dir: Path, description: str, llm, max_steps: int = 300,
                 max_minutes: int = 120, interactive: bool = True, show_thinking: bool = False):
        self.problem_dir = Path(problem_dir).resolve()
        self.description = description or ""
        self.llm = llm
        self.max_steps = max_steps
        self.max_minutes = max_minutes
        self.show_thinking = show_thinking
        self.work_dir = self.problem_dir / ".revagent"
        self.work_dir.mkdir(exist_ok=True)
        self.run_start_ns = time.time_ns()
        self.casefile = CaseFile(self.work_dir / "case.md", self.problem_dir.name, self.description)
        self.ctx = ToolContext(problem_dir=self.problem_dir, work_dir=self.work_dir,
                               casefile=self.casefile, llm=llm, interactive=interactive)
        self.schemas, self.handlers = load_tools()
        self.transcript = open(self.work_dir / "transcript.jsonl", "a", encoding="utf-8")
        self.messages: list[dict] = []
        self.critic_calls = 0
        self.gate = Gate()
        self.long_reasoning = 0
        self.first_facts_step: int | None = None
        self.compactions = 0
        self.over_streak = 0
        self.recent: deque = deque(maxlen=3)

    # ---- bookkeeping -------------------------------------------------------
    def _log(self, obj: dict) -> None:
        self.transcript.write(json.dumps(obj, ensure_ascii=False) + "\n")
        self.transcript.flush()

    def _append(self, msg: dict) -> None:
        self.messages.append(msg)
        self._log(msg)

    def _task_message(self) -> str:
        listing = run_cmd("ls -la", cwd=self.problem_dir, timeout=10)
        if len(listing) > 4_000:
            listing = listing[:4_000] + "\n[listing truncated]"
        return TASK_TEMPLATE.format(dir=self.problem_dir, desc=self.description.strip() or "(none)",
                                    listing=listing)

    def _print(self, text: str) -> None:
        print(text, flush=True)

    # ---- tools -------------------------------------------------------------
    def _execute(self, call: ToolCall) -> str:
        handler = self.handlers.get(call.name)
        if handler is None:
            result = f"[tool error] unknown tool {call.name}; available: {', '.join(sorted(self.handlers))}"
        elif call.parse_error:
            result = f"[tool error] arguments were not valid JSON: {call.raw_args[:300]}"
        else:
            ran = True
            try:
                result = str(handler(self.ctx, **call.args))
            except TypeError as e:
                ran = False   # the handler was never entered
                result = f"[tool error] bad arguments for {call.name}: {e}"
            except Exception as e:  # tool bugs must not kill the session
                result = f"[tool error] {type(e).__name__}: {e}"
            if ran:
                self.ctx.tools_used[call.name] = self.ctx.tools_used.get(call.name, 0) + 1
        return truncate(result, self.ctx.out_dir, self.ctx.next_out_id)

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
        like the [obs]/[critic] lines (context._is_ledger_line keeps `- [gate ` bullets through
        prune_log and shrink)."""
        text = {"gate_block": f"G3 blocked a repeated script (streak {ev.get('streak')})",
                "gate_open": "G3 opened: approach changed",
                "gate_released": f"G3 released after {RELEASE_AFTER} blocked steps; quiet until step {ev.get('cooldown_until')}",
                "gate_error": f"gate error: {ev.get('error')}",
                "gate_warn": f"G4 warned: long-thinking step #{ev.get('count')}"}.get(ev["event"], ev["event"])
        try:
            self.casefile.add("log", f"[gate step {step}] {text}")
        except Exception:
            pass

    def _g4_warn(self, step: int) -> None:
        """The LONG_REASONING_LIMITth long-thinking step: tell the model once. Called after the step's
        tool results (or after the no-tool nudge). Warning only: an effort downgrade here was tried
        live (2026-09-22, ROVM/damnida) and reasoning got longer after it, so it was removed."""
        ev = {"event": "gate_warn", "gate": "G4", "step": step, "count": self.long_reasoning}
        self._log({"role": "_meta", **ev})
        self._ledger(step, ev)
        self._append({"role": "user", "content": G4_TEXT})
        self._print(f"[{step}] -- G4: {self.long_reasoning} long-thinking steps; warned --")

    def _critic(self, step: int, cause: str) -> None:
        if self.critic_calls >= CRITIC_MAX:
            return
        self.critic_calls += 1
        self._log({"role": "_meta", "event": "critic", "step": step, "cause": cause, "n": self.critic_calls})
        memo = run_critic(self.llm, self.casefile, self.messages, step)
        if memo:
            self._append({"role": "user", "content": "[critic] " + memo})
            self._print(f"[{step}] -- critic ({cause}) --\n{memo[:600]}")

    def _compact(self, cause: str, compactions: int) -> list[dict]:
        self._log({"role": "_meta", "event": "compaction", "n": compactions, "cause": cause})
        files = list_work_files(self.problem_dir, self.run_start_ns)
        self._log({"role": "_meta", "event": "work_files", "n": len(files)})
        messages = compact(self.messages, self.llm, self.casefile, compactions, format_work_files(files))
        self._log(messages[2])
        return messages

    def _reduce_context(self, step: int, cause: str) -> bool:
        """Over-threshold / overflow handling shared by both call sites. Returns False when the
        context cannot be reduced (third consecutive over-size step); otherwise critic, compact."""
        self.over_streak += 1
        if self.over_streak >= 3:
            return False
        if self.over_streak == 2:
            shrunk = shrink_casefile(self.casefile, self.llm)
            self._log({"role": "_meta", "event": "shrink_casefile", "accepted": shrunk})
        self._critic(step, "compaction")
        self.compactions += 1
        self.messages = self._compact(cause, self.compactions)
        self.recent.clear()
        return True

    # ---- main loop ---------------------------------------------------------
    def run(self) -> dict:
        start = time.monotonic()
        self.ctx.deadline = start + self.max_minutes * 60
        self._log({
            "role": "_meta", "event": "session_start",
            "time": datetime.now(timezone.utc).isoformat(),
            "problem_dir": str(self.problem_dir),
            "max_steps": self.max_steps,
            "max_minutes": self.max_minutes,
        })
        start_prompt_tokens = self.llm.total_prompt_tokens
        start_completion_tokens = self.llm.total_completion_tokens
        start_retries = getattr(self.llm, "total_retries", 0)
        no_tool_streak = 0
        self.recent.clear()
        self.compactions = 0
        self.over_streak = 0
        status, reason, steps = "unsolved", "", 0
        last_marker = progress_marker(self.casefile.read())
        idle = 0

        try:
            try:
                self._append({"role": "system", "content": load_system_prompt()})
                self._append({"role": "user", "content": self._task_message()})
                for step in range(1, self.max_steps + 1):
                    steps = step
                    self.ctx.step = step
                    if time.monotonic() > self.ctx.deadline:
                        reason = "time limit"
                        steps = step - 1
                        break
                    try:
                        resp = self.llm.chat(self.messages, self.schemas)
                        if resp.finish_reason == "length" and not resp.tool_calls:
                            # The model spent the whole output budget thinking. Retry once with a
                            # hint and low effort (same max_tokens: 44k threshold + 16k output is the
                            # 65536 ceiling already) before treating it as a no-tool turn.
                            self._log({"role": "_meta", "event": "output_truncated", "step": step,
                                       "retry_max_tokens": self.llm.max_tokens})
                            self._print(f"[{step}] -- output truncated mid-thinking; retrying with a hint at low effort --")
                            self._log({"role": "_meta", "event": "retry_hint", "content": TRUNCATED_RETRY_HINT})
                            resp = self.llm.chat(
                                self.messages + [{"role": "user", "content": TRUNCATED_RETRY_HINT}], self.schemas,
                                reasoning_effort=TRUNCATED_RETRY_EFFORT)
                    except ContextOverflow:
                        steps = step - 1
                        if not self._reduce_context(step, "overflow"):
                            reason = "context cannot be reduced"
                            break
                        continue
                    self._log({"role": "_reasoning", "step": step, "content": resp.reasoning})
                    self._append(resp.message)
                    g4_due = False
                    if len(resp.reasoning or "") > LONG_REASONING_CHARS:
                        self.long_reasoning += 1
                        g4_due = self.long_reasoning == LONG_REASONING_LIMIT
                    if self.show_thinking and resp.reasoning:
                        self._print(f"\033[2m{resp.reasoning[:2000]}\033[0m")
                    if resp.content:
                        self._print(f"[{step}] {resp.content[:600]}")

                    if not resp.tool_calls:
                        no_tool_streak += 1
                        if no_tool_streak >= 3:
                            reason = "no tool calls 3x"
                            break
                        nudge = TRUNCATED_NUDGE if resp.finish_reason == "length" else \
                            "Call a tool, or finish with submit_flag. Do not just narrate."
                        self._append({"role": "user", "content": nudge})
                        if g4_due:
                            self._g4_warn(step)
                        continue
                    no_tool_streak = 0

                    self._run_tools(step, resp.tool_calls)
                    if g4_due:
                        # after the tool results: a user message must never sit between an
                        # assistant tool_calls message and its tool messages
                        self._g4_warn(step)
                    self._print(f"[{step}] tokens: prompt={resp.prompt_tokens} completion={resp.completion_tokens}")
                    if self.ctx.runbook_path:
                        status = "runbook"
                        break
                    if self.ctx.flag:
                        status = "solved"
                        break

                    self.recent.append(tuple((c.name, c.raw_args) for c in resp.tool_calls))
                    if len(self.recent) == 3 and len(set(self.recent)) == 1:
                        self._append({"role": "user", "content": "You have repeated the same tool call 3 times. Read your notes and choose a different approach."})
                        self.recent.clear()

                    try:
                        marker = progress_marker(self.casefile.read())
                    except OSError as e:
                        # the model has an unrestricted bash and .revagent sits inside its cwd, so
                        # it can delete its own case file. That is a tool-level mistake to recover
                        # from, not a reason to lose the run: count the step as "no progress".
                        marker = last_marker
                        self._log({"role": "_meta", "event": "casefile_unreadable",
                                   "step": step, "error": f"{type(e).__name__}: {e}"[:200]})
                    if self.first_facts_step is None and marker[0] > 0:
                        self.first_facts_step = step
                    if marker != last_marker:
                        last_marker, idle = marker, 0
                    else:
                        idle += 1
                    if idle >= CRITIC_IDLE_STEPS:
                        self._critic(step, "idle")
                        idle = 0

                    if self.llm.last_prompt_tokens > THRESHOLD:
                        if not self._reduce_context(step, "threshold"):
                            reason = "context cannot be reduced"
                            break
                        self._print(f"[{step}] -- context compacted ({self.compactions}) --")
                    else:
                        self.over_streak = 0
                else:
                    reason = "step limit"
            except Exception as e:  # never lose the run: still write result.json and report
                status = "unsolved"
                reason = f"error: {type(e).__name__}: {e}"[:500]
                self._log({"role": "_meta", "event": "error", "error": reason})

            result = {
                "status": status,
                "flag": self.ctx.flag,
                "how_verified": self.ctx.how_verified,
                "runbook": ".revagent/runbook.md" if self.ctx.runbook_path else None,
                "reason": reason,
                "steps": steps,
                "compactions": self.compactions,
                "prompt_tokens": self.llm.total_prompt_tokens - start_prompt_tokens,
                "completion_tokens": self.llm.total_completion_tokens - start_completion_tokens,
                "llm_retries": getattr(self.llm, "total_retries", 0) - start_retries,
                "minutes": round((time.monotonic() - start) / 60, 1),
                "signals": {
                    "gate_blocks": self.gate.blocks,
                    "max_script_streak": self.gate.max_streak,
                    "long_reasoning_steps": self.long_reasoning,
                    "first_facts_step": self.first_facts_step,
                },
            }
            self._finish(result)
        finally:
            self.transcript.close()
        self._report(result)
        return result

    def _finish(self, result: dict) -> None:
        (self.work_dir / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False))
        # result.json is "latest run" and gets overwritten by the next run, including a run that died
        # at step 1 because the server was down (ROVM: 44 steps of results were lost that way).
        # results.jsonl keeps one line per run, forever.
        with open(self.work_dir / "results.jsonl", "a", encoding="utf-8") as hist:
            hist.write(json.dumps({"time": datetime.now(timezone.utc).isoformat(), **result},
                                  ensure_ascii=False) + "\n")
        self._log({"role": "_meta", "event": "end", **result})

    def _report(self, result: dict) -> None:
        if result["status"] == "solved":
            self._print(f"\n\033[1mFLAG: {result['flag']}\033[0m\nverified: {result['how_verified']}")
        elif result["status"] == "runbook":
            self._print(f"\n\033[1mRUNBOOK: {result['runbook']}\033[0m (the sandbox could not execute the program)\n")
            try:
                self._print((self.work_dir / "runbook.md").read_text(encoding="utf-8"))
            except OSError as e:  # result.json is already on disk; do not crash solve() over the echo
                self._print(f"(could not read runbook.md: {type(e).__name__}: {e})")
        else:
            self._print(f"\n\033[1mUNSOLVED\033[0m ({result['reason']}). Case file:\n")
            self._print(self.casefile.read())
        self._print(f"steps={result['steps']} compactions={result['compactions']} "
                    f"tokens={result['prompt_tokens']}+{result['completion_tokens']} minutes={result['minutes']}")

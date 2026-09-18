"""The ReAct loop."""
import json
import time
from collections import deque
from pathlib import Path

from .casefile import CaseFile
from .context import THRESHOLD, compact, shrink_casefile
from .llm import ContextOverflow, ToolCall
from .tools import load_tools
from .tools.base import ToolContext
from .tools.bash import run_cmd
from .truncate import truncate

TASK_TEMPLATE = """# Challenge
Directory: {dir}

## Description
{desc}

## Files (ls -la)
{listing}

## Rules
- Flag format: DH{{...}}. Verify before submit_flag.
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
        self.casefile = CaseFile(self.work_dir / "case.md", self.problem_dir.name, self.description)
        self.ctx = ToolContext(problem_dir=self.problem_dir, work_dir=self.work_dir,
                               casefile=self.casefile, llm=llm, interactive=interactive)
        self.schemas, self.handlers = load_tools()
        self.transcript = open(self.work_dir / "transcript.jsonl", "a", encoding="utf-8")
        self.messages: list[dict] = []

    # ---- bookkeeping -------------------------------------------------------
    def _log(self, obj: dict) -> None:
        self.transcript.write(json.dumps(obj, ensure_ascii=False) + "\n")
        self.transcript.flush()

    def _append(self, msg: dict) -> None:
        self.messages.append(msg)
        self._log(msg)

    def _task_message(self) -> str:
        listing = run_cmd("ls -la", cwd=self.problem_dir, timeout=10)
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
            try:
                result = str(handler(self.ctx, **call.args))
            except TypeError as e:
                result = f"[tool error] bad arguments for {call.name}: {e}"
            except Exception as e:  # tool bugs must not kill the session
                result = f"[tool error] {type(e).__name__}: {e}"
        return truncate(result, self.ctx.out_dir, self.ctx.next_out_id)

    def _compact(self, cause: str, compactions: int) -> list[dict]:
        self._log({"role": "_meta", "event": "compaction", "n": compactions, "cause": cause})
        messages = compact(self.messages, self.llm, self.casefile, compactions)
        self._log(messages[2])
        return messages

    # ---- main loop ---------------------------------------------------------
    def run(self) -> dict:
        start = time.time()
        start_prompt_tokens = self.llm.total_prompt_tokens
        start_completion_tokens = self.llm.total_completion_tokens
        self._append({"role": "system", "content": load_system_prompt()})
        self._append({"role": "user", "content": self._task_message()})
        no_tool_streak = 0
        recent = deque(maxlen=3)
        compactions = 0
        over_streak = 0
        status, reason, steps = "unsolved", "", 0

        try:
            try:
                for step in range(1, self.max_steps + 1):
                    steps = step
                    if time.time() - start > self.max_minutes * 60:
                        reason = "time limit"
                        steps = step - 1
                        break
                    try:
                        resp = self.llm.chat(self.messages, self.schemas)
                    except ContextOverflow:
                        over_streak += 1
                        if over_streak >= 3:
                            reason = "context cannot be reduced"
                            steps = step - 1
                            break
                        if over_streak == 2:
                            shrunk = shrink_casefile(self.casefile, self.llm)
                            self._log({"role": "_meta", "event": "shrink_casefile", "accepted": shrunk})
                        compactions += 1
                        self.messages = self._compact("overflow", compactions)
                        recent.clear()
                        steps = step - 1
                        continue
                    self._log({"role": "_reasoning", "step": step, "content": resp.reasoning})
                    self._append(resp.message)
                    if self.show_thinking and resp.reasoning:
                        self._print(f"\033[2m{resp.reasoning[:2000]}\033[0m")
                    if resp.content:
                        self._print(f"[{step}] {resp.content[:600]}")

                    if not resp.tool_calls:
                        no_tool_streak += 1
                        if no_tool_streak >= 3:
                            reason = "no tool calls 3x"
                            break
                        self._append({"role": "user", "content": "Call a tool, or finish with submit_flag. Do not just narrate."})
                        continue
                    no_tool_streak = 0

                    flag_just_set = False
                    for call in resp.tool_calls:
                        if flag_just_set:
                            result = "[tool error] skipped: flag submitted"
                            self._append({"role": "tool", "tool_call_id": call.id, "content": result})
                            continue
                        self._print(f"[{step}] > {call.name} {call.raw_args[:160]}")
                        result = self._execute(call)
                        self._append({"role": "tool", "tool_call_id": call.id, "content": result})
                        head = "\n".join(result.splitlines()[:3])
                        self._print(f"[{step}] < {head[:300]}")
                        if self.ctx.flag:
                            flag_just_set = True
                    self._print(f"[{step}] tokens: prompt={resp.prompt_tokens} completion={resp.completion_tokens}")
                    if self.ctx.flag:
                        status = "solved"
                        break

                    recent.append(tuple((c.name, c.raw_args) for c in resp.tool_calls))
                    if len(recent) == 3 and len(set(recent)) == 1:
                        self._append({"role": "user", "content": "You have repeated the same tool call 3 times. Read your notes and choose a different approach."})
                        recent.clear()

                    if self.llm.last_prompt_tokens > THRESHOLD:
                        over_streak += 1
                        if over_streak >= 3:
                            reason = "context cannot be reduced"
                            break
                        if over_streak == 2:
                            shrunk = shrink_casefile(self.casefile, self.llm)
                            self._log({"role": "_meta", "event": "shrink_casefile", "accepted": shrunk})
                        compactions += 1
                        self.messages = self._compact("threshold", compactions)
                        recent.clear()
                        self._print(f"[{step}] -- context compacted ({compactions}) --")
                    else:
                        over_streak = 0
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
                "reason": reason,
                "steps": steps,
                "compactions": compactions,
                "prompt_tokens": self.llm.total_prompt_tokens - start_prompt_tokens,
                "completion_tokens": self.llm.total_completion_tokens - start_completion_tokens,
                "minutes": round((time.time() - start) / 60, 1),
            }
            (self.work_dir / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False))
            self._log({"role": "_meta", "event": "end", **result})
        finally:
            self.transcript.close()
        self._report(result)
        return result

    def _report(self, result: dict) -> None:
        if result["status"] == "solved":
            self._print(f"\n\033[1mFLAG: {result['flag']}\033[0m\nverified: {result['how_verified']}")
        else:
            self._print(f"\n\033[1mUNSOLVED\033[0m ({result['reason']}). Case file:\n")
            self._print(self.casefile.read())
        self._print(f"steps={result['steps']} compactions={result['compactions']} "
                    f"tokens={result['prompt_tokens']}+{result['completion_tokens']} minutes={result['minutes']}")

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
        if step <= self.cooldown_until:
            # released: G3 stays quiet and tracks nothing until the cooldown ends
            return [Verdict(i, True) for i in range(len(calls))], []
        bodies = [self._body(name, raw) for name, raw in calls]
        events = []
        if calls and all(body is None for body in bodies):
            # plain bash, another tool, notes, and no script at all: the model changed what it is doing
            if self.blocking:
                events.append({"event": "gate_open", "gate": "G3", "step": step})
            self._reset()
            return [Verdict(i, True) for i in range(len(calls))], events
        verdicts = []
        blocked_here = False
        for i, body in enumerate(bodies):
            if body is None:
                # a non-script call next to a re-edit in the same step is neutral: it neither
                # counts nor lifts anything
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
            if self.streak >= STREAK_LIMIT:
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

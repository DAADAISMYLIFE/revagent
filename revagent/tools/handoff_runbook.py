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
    body = [RUNBOOK_HEADER]
    blocked = list(getattr(ctx, "env_blocked_paths", []) or [])
    if blocked:  # env_blocked is global for the run; name what actually failed to start
        body.append("Blocked target(s): " + ", ".join(blocked))
    body += ["", f"# Runbook: {ctx.problem_dir.name}", "", "## Steps"]
    body += [f"{i}. {s}" for i, s in enumerate(steps, 1)]
    body += ["", "## Expected observation", expected_observation.strip() or "(none given)", "",
             "## Flag rule", flag_rule.strip() or "(none given)", ""]
    path = Path(ctx.work_dir) / "runbook.md"
    path.write_text("\n".join(body), encoding="utf-8")
    ctx.runbook_path = path
    return "[accepted] runbook written to .revagent/runbook.md; the session will end now."

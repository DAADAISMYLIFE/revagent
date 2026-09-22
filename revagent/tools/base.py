import time
from dataclasses import dataclass, field
from pathlib import Path

from ..casefile import CaseFile
from ..truncate import ENV_NOTE_PREFIX

START_FAILURES_TO_BLOCK = 2
MIN_TOOL_SECONDS = 5        # a tool called at the very end of the budget still gets this long
BLOCKED_PATHS_CHARS = 200   # env_note() must stay well under truncate()'s FOOTER_MAX


class PathError(Exception):
    """Raised by resolve_inside(); str(e) is the exact `[tool error] ...` text the tool returns."""


def resolve_inside(ctx, rel: str, must_exist: bool = True) -> Path:
    """Resolve a model-supplied path relative to the challenge directory, refusing anything that
    escapes it (absolute paths, `..`, symlinks out). With must_exist, the target must be a file."""
    problem_dir = ctx.problem_dir.resolve()
    p = (ctx.problem_dir / rel).resolve()
    if not p.is_relative_to(problem_dir):
        raise PathError(f"[tool error] path escapes the challenge directory: {rel}")
    if must_exist and not p.is_file():
        raise PathError(f"[tool error] no such file: {rel}")
    return p


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
    current_binary_rel: str | None = None   # the binary= path as the model wrote it (quoted back in decompile's emulate hint)
    step: int = 0                      # current loop step; the agent updates it before each tool call
    env_blocked: bool = False          # set by tools only: the sandbox cannot execute the target
    start_failures: int = 0
    env_blocked_paths: list[str] = field(default_factory=list)   # targets that could not be started
    runbook_path: Path | None = None   # set by handoff_runbook; ends the run with status "runbook"
    flag_attempts: dict = field(default_factory=dict)
    deadline: float | None = None      # time.monotonic() at which the run's wall-clock budget ends
    emulate_images: dict = field(default_factory=dict)   # (path, mtime_ns, size) -> revagent.emulate.Image (cle+unicorn image cache per run)
    trace_bases: dict = field(default_factory=dict)     # (path, mtime_ns, size) -> qemu guest base of its PIE image (from a previous trace_run; lets range= become -dfilter)
    tools_used: dict = field(default_factory=dict)       # tool name -> calls whose handler actually ran (not unknown tools, bad JSON, bad arguments or G3-blocked calls); submit_flag checks readings against it

    def clamp_timeout(self, seconds: int) -> int:
        """Cap a tool timeout to the time left in the run. agent.py checks max_minutes only between
        steps, so without this one 900 s bash call started at minute 119 ends the run at minute 134
        (damnida run 1 was killed by an outer wrapper for exactly that). The deadline cut is floored at
        MIN_TOOL_SECONDS so a tool called at the very end still runs; a request shorter than the floor
        (`timeout=2`) is returned unchanged — the floor never raises what the model asked for."""
        if self.deadline is None:
            return seconds
        remaining = int(self.deadline - time.monotonic())
        return min(seconds, max(MIN_TOOL_SECONDS, remaining))

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

    def block_env(self, path: str | None = None) -> None:
        """Open the runbook gate immediately ([cannot run here]) and record what was blocked."""
        self.env_blocked = True
        self.record_blocked_path(path)

    def observe_cannot_run(self, tool: str, path: str) -> None:
        """A run tool answered [cannot run here]: open the gate and write the ledger line for it."""
        self.block_env(path)
        self.observe(f"{tool} {path}: [cannot run here]")

    def note_start_failure(self, path: str | None = None) -> None:
        self.start_failures += 1
        if self.start_failures >= START_FAILURES_TO_BLOCK:
            self.env_blocked = True
            self.record_blocked_path(path)

    def record_blocked_path(self, path: str | None) -> None:
        """env_blocked is one global flag for the whole run (spec §3.5), so the least it can do is
        name the target it was set for: the runbook header and env_note() then show whether the
        hand-off is about the program the model is actually stuck on or some inner stage."""
        if path and path not in self.env_blocked_paths:
            self.env_blocked_paths.append(path)

    def env_note(self) -> str:
        """Appended to a run tool's returned text once env_blocked is set, so the agent is told
        directly (not just via the [obs ...] ledger line) that handoff_runbook has opened up.
        Starts with ENV_NOTE_PREFIX, which is what truncate() anchors on to carry it past the cut."""
        if not self.env_blocked:
            return ""
        targets = ""
        if self.env_blocked_paths:
            targets = ": " + ", ".join(self.env_blocked_paths)[:BLOCKED_PATHS_CHARS]
        return (f"\n{ENV_NOTE_PREFIX} (2 attempts){targets}. If static analysis "
                "cannot finish the job, handoff_runbook is now allowed: put everything you learned (input "
                "format, what advances the program, character set, length) into its steps.")

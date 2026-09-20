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

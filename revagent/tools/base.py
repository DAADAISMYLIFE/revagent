from dataclasses import dataclass, field
from pathlib import Path

from ..casefile import CaseFile


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

    @property
    def out_dir(self) -> Path:
        return self.work_dir / "out"

    def next_out_id(self) -> int:
        self.out_counter += 1
        return self.out_counter

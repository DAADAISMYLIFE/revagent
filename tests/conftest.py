"""Shared test helpers: a ToolContext builder and a recording fake LLM.

Import them with `from tests.conftest import make_ctx, FakeLLM` (tests/ is a package) or use the
`ctx` fixture.
"""
import pytest

from revagent.casefile import CaseFile
from revagent.tools.base import ToolContext


def make_ctx(tmp_path, interactive=True, llm=None):
    """A ToolContext rooted at tmp_path with its CaseFile under tmp_path/.revagent."""
    work = tmp_path / ".revagent"
    cf = CaseFile(work / "case.md", "t", "d")
    return ToolContext(problem_dir=tmp_path, work_dir=work, casefile=cf, llm=llm, interactive=interactive)


@pytest.fixture
def ctx(tmp_path):
    return make_ctx(tmp_path)


class FakeLLM:
    """Records every complete() call and returns `reply`; raise_ makes it fail instead.

    raise_ may be True (raises RuntimeError("down")) or an exception instance/class.
    finish is what .last_finish_reason reports ("length" simulates a cut-off reply).
    """

    def __init__(self, reply="SUMMARY", raise_=False, finish="stop"):
        self.reply = reply
        self.raise_ = raise_
        self.prompts = []
        self.systems = []
        self.kwargs = []
        self.kw = None            # kwargs of the most recent call
        self.last_finish_reason = finish

    def complete(self, prompt, system=None, **kw):
        self.prompts.append(prompt)
        self.systems.append(system)
        self.kwargs.append(kw)
        self.kw = kw
        if self.raise_:
            raise RuntimeError("down") if self.raise_ is True else self.raise_
        return self.reply

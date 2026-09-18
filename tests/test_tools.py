import os
import stat
from pathlib import Path

from revagent.casefile import CaseFile
from revagent.tools import load_tools
from revagent.tools.base import ToolContext
from revagent.tools import bash, run_binary, notes, ask_user, submit_flag


def ctx_for(tmp_path, interactive=True):
    work = tmp_path / ".revagent"
    cf = CaseFile(work / "case.md", "t", "d")
    return ToolContext(problem_dir=tmp_path, work_dir=work, casefile=cf, llm=None, interactive=interactive)


def test_registry_has_all_tools():
    schemas, handlers = load_tools()
    names = {s["function"]["name"] for s in schemas}
    assert names == {"bash", "run_binary", "notes", "decompile", "summarize", "ask_user", "submit_flag"}
    assert set(handlers) == names
    for s in schemas:
        assert s["type"] == "function" and "parameters" in s["function"]


def test_bash_runs_in_problem_dir(tmp_path):
    (tmp_path / "a.txt").write_text("hi")
    out = bash.run(ctx_for(tmp_path), cmd="cat a.txt; echo err 1>&2")
    assert out.startswith("[exit 0]")
    assert "hi" in out and "err" in out


def test_bash_timeout_kills(tmp_path):
    out = bash.run(ctx_for(tmp_path), cmd="echo start; sleep 5; echo end", timeout=1)
    assert out.startswith("[timeout after 1s]")
    assert "start" in out and "end" not in out


def test_bash_stdin_is_closed(tmp_path):
    out = bash.run(ctx_for(tmp_path), cmd="cat", timeout=3)
    assert out.startswith("[exit 0]")


def test_run_binary_with_stdin(tmp_path):
    script = tmp_path / "prog.sh"
    script.write_text("#!/bin/bash\nread x; if [ \"$x\" = secret ]; then echo Correct; else echo Wrong; fi\n")
    out = run_binary.run(ctx_for(tmp_path), path="prog.sh", stdin="secret\n")
    assert "Correct" in out
    out = run_binary.run(ctx_for(tmp_path), path="prog.sh", args=[], stdin="nope\n")
    assert "Wrong" in out


def test_run_binary_makes_executable(tmp_path):
    script = tmp_path / "p.sh"
    script.write_text("#!/bin/bash\necho ran\n")
    script.chmod(0o644)
    out = run_binary.run(ctx_for(tmp_path), path="p.sh")
    assert "ran" in out


def test_run_binary_missing(tmp_path):
    assert run_binary.run(ctx_for(tmp_path), path="nope").startswith("[tool error]")


def test_run_binary_refuses_pe(tmp_path, monkeypatch):
    (tmp_path / "x.exe").write_bytes(b"MZ" + b"\0" * 100)
    out = run_binary.run(ctx_for(tmp_path), path="x.exe")
    assert out.startswith("[cannot run here]")


def test_run_binary_rejects_escape(tmp_path):
    c = ctx_for(tmp_path)
    assert run_binary.run(c, path="../outside").startswith("[tool error] path escapes")
    assert run_binary.run(c, path="/bin/true").startswith("[tool error] path escapes")


def test_run_binary_survives_missing_file_cmd(tmp_path, monkeypatch):
    script = tmp_path / "p.sh"
    script.write_text("#!/bin/bash\necho ran\n")
    script.chmod(0o755)
    (tmp_path / "x.exe").write_bytes(b"MZ" + b"\0" * 100)

    def boom(*a, **kw):
        raise FileNotFoundError("no file(1)")

    monkeypatch.setattr("revagent.tools.run_binary.subprocess.run", boom)
    c = ctx_for(tmp_path)
    assert "ran" in run_binary.run(c, path="p.sh")
    assert run_binary.run(c, path="x.exe").startswith("[cannot run here]")


def test_notes_read_add(tmp_path):
    c = ctx_for(tmp_path)
    assert notes.run(c, action="add", section="facts", text="f1") == "added to facts"
    assert "- f1" in notes.run(c, action="read")
    assert notes.run(c, action="add", section="facts", text="  ").startswith("[tool error]")
    assert notes.run(c, action="zap").startswith("[tool error]")


def test_ask_user_non_interactive(tmp_path):
    out = ask_user.run(ctx_for(tmp_path, interactive=False), question="host?")
    assert out.startswith("[user unavailable]")


def test_ask_user_reads_stdin(tmp_path, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda: "  1.2.3.4:31337 ")
    assert ask_user.run(ctx_for(tmp_path), question="host?") == "1.2.3.4:31337"


def test_submit_flag_format(tmp_path):
    c = ctx_for(tmp_path)
    assert submit_flag.run(c, flag="flag{x}", how_verified="ran it").startswith("[rejected]")
    assert c.flag is None
    assert submit_flag.run(c, flag="DH{x}", how_verified="").startswith("[rejected]")
    assert submit_flag.run(c, flag=" DH{x} ", how_verified="run_binary printed Correct").startswith("[accepted]")
    assert c.flag == "DH{x}" and c.how_verified == "run_binary printed Correct"


from revagent.tools import decompile, summarize
import revagent.tools.decompile as decompile_mod


class FakeLLM:
    def __init__(self):
        self.prompts = []

    def complete(self, prompt, system=None):
        self.prompts.append(prompt)
        return "SUMMARY"


def test_decompile_needs_binary_first(tmp_path):
    assert decompile.run(ctx_for(tmp_path), action="list").startswith("[decompile unavailable]")


def test_decompile_uses_cached_db(tmp_path, monkeypatch):
    fix = Path(__file__).parent / "fixtures" / "functions.json"
    (tmp_path / "prog").write_bytes(b"\x7fELF")
    monkeypatch.setattr(decompile_mod, "analyze", lambda binary, cache_dir: fix)
    c = ctx_for(tmp_path)
    out = decompile.run(c, action="list", binary="prog")
    assert out.startswith("4 functions")
    assert "s[i]^0x5a" in decompile.run(c, action="get", target="check")
    assert "callers: _start" in decompile.run(c, action="xrefs", target="main")
    assert decompile.run(c, action="bogus").startswith("[tool error]")
    assert decompile.run(c, action="get", target="nope", binary="missing").startswith("[decompile unavailable]")


def test_summarize_caps_and_calls_llm(tmp_path):
    c = ctx_for(tmp_path)
    c.llm = FakeLLM()
    big = tmp_path / "big.txt"
    big.write_text("A" * 50_000)
    out = summarize.run(c, file="big.txt", question="what?")
    assert out.startswith("SUMMARY")
    assert "only the first 40000" in out
    assert "what?" in c.llm.prompts[0] and c.llm.prompts[0].count("A") <= 40_000 + 100
    assert summarize.run(c, file="nope.txt", question="q").startswith("[tool error]")

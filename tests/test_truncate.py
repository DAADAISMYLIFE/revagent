from pathlib import Path
from revagent.truncate import truncate, ENV_NOTE_PREFIX, LIMIT


def test_short_text_untouched(tmp_path):
    ids = iter([1])
    assert truncate("hello", tmp_path, lambda: next(ids)) == "hello"
    assert not list(tmp_path.iterdir())


def test_long_text_is_cut_and_saved(tmp_path):
    text = "x" * (LIMIT + 500)
    ids = iter([7])
    out = truncate(text, tmp_path, lambda: next(ids))
    assert out.startswith("x" * LIMIT)
    assert "[truncated: 12500 chars total" in out
    assert ".revagent/out/007.txt" in out
    assert (tmp_path / "007.txt").read_text() == text


def test_exact_limit_untouched(tmp_path):
    text = "y" * LIMIT
    assert truncate(text, tmp_path, lambda: 1) == text


def test_long_text_with_env_footer_preserves_footer_past_the_cut(tmp_path):
    footer = "\n" + ENV_NOTE_PREFIX + " (2 attempts). handoff_runbook is now allowed."
    text = "x" * 20_000 + footer
    ids = iter([9])
    out = truncate(text, tmp_path, lambda: next(ids))
    assert out.endswith(footer)
    assert "[truncated: " + str(len(text)) + " chars total" in out
    assert out.startswith("x" * LIMIT) and out[LIMIT] == "\n"   # body cut to exactly LIMIT
    assert (tmp_path / "009.txt").read_text() == text
    assert (tmp_path / "009.txt").read_text().endswith(footer)


def test_short_text_with_env_footer_returned_untouched(tmp_path):
    footer = "\n" + ENV_NOTE_PREFIX + " (2 attempts). handoff_runbook is now allowed."
    text = "short body" + footer
    assert truncate(text, tmp_path, lambda: 1) == text
    assert not list(tmp_path.iterdir())


def test_long_text_without_footer_behaviour_unchanged(tmp_path):
    # no "\n[env] " marker anywhere: identical to the pre-footer-aware behaviour.
    text = "z" * (LIMIT + 500)
    ids = iter([3])
    out = truncate(text, tmp_path, lambda: next(ids))
    assert out.startswith("z" * LIMIT)
    assert out == (
        text[:LIMIT]
        + f"\n[truncated: {len(text)} chars total. full output: .revagent/out/003.txt "
        + "— page it with bash: sed -n 'A,Bp' .revagent/out/003.txt  or  grep -n PATTERN .revagent/out/003.txt]"
    )


def test_real_env_note_footer_survives_the_cut(tmp_path):
    # the actual string tools append: truncate() must recognise it by its anchor prefix.
    from pathlib import Path as _P
    from revagent.casefile import CaseFile
    from revagent.tools.base import ToolContext
    ctx = ToolContext(problem_dir=tmp_path, work_dir=tmp_path / ".revagent",
                      casefile=CaseFile(tmp_path / "c.md", "p", "d"), llm=None)
    ctx.env_blocked = True
    footer = ctx.env_note()
    out = truncate("x" * 30_000 + footer, tmp_path, lambda: 1)
    assert out.endswith(footer) and "handoff_runbook is now allowed" in out
    assert len(out) < LIMIT + 1_000


def test_junk_after_a_fake_env_line_is_not_treated_as_a_footer(tmp_path):
    # C1: challenge-controlled output containing "\n[env] " must not disable the output cap.
    text = "A" * 100 + "\n[env] " + "B" * 500_000
    out = truncate(text, tmp_path, lambda: 4)
    assert len(out) < LIMIT + 500          # the cap still holds
    assert out.count("B") < LIMIT           # the 500 KB tail was not carried through
    assert out.endswith("]")                # ... and nothing was re-appended after the pointer
    assert ".revagent/out/004.txt" in out
    assert (tmp_path / "004.txt").read_text() == text


def test_env_note_shaped_line_longer_than_the_cap_is_not_a_footer(tmp_path):
    # right prefix, but far too long to be env_note(): cap wins.
    text = "A" * 20_000 + "\n" + ENV_NOTE_PREFIX + " " + "B" * 5_000
    out = truncate(text, tmp_path, lambda: 5)
    assert len(out) < LIMIT + 500

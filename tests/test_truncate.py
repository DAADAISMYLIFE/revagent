from pathlib import Path
from revagent.truncate import truncate, LIMIT


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
    footer = "\n[env] handoff_runbook is now allowed: put everything you learned into its steps."
    text = "x" * 20_000 + footer
    ids = iter([9])
    out = truncate(text, tmp_path, lambda: next(ids))
    assert out.endswith(footer)
    assert "[truncated: " + str(len(text)) + " chars total" in out
    assert out.startswith("x" * LIMIT) and out[LIMIT] == "\n"   # body cut to exactly LIMIT
    assert (tmp_path / "009.txt").read_text() == text
    assert (tmp_path / "009.txt").read_text().endswith(footer)


def test_short_text_with_env_footer_returned_untouched(tmp_path):
    footer = "\n[env] handoff_runbook is now allowed."
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

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

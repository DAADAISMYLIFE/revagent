import os
"""Tests for the bench answer-checking helper (revagent.__main__.check_answer).

A bench run can "solve" a challenge with a wrong flag (e.g. misreading a glyph).
check_answer cross-checks the reported flag against bench/<suite>/ANSWERS.md
(a markdown table `| <dirname> | <flag> |`) and flips a false "solved" to "wrong"."""
from pathlib import Path

from revagent.__main__ import check_answer


def _write_answers(dir_path: Path, body: str) -> None:
    (dir_path / "ANSWERS.md").write_text(body, encoding="utf-8")


def test_solved_matching_flag_is_unchanged(tmp_path):
    _write_answers(tmp_path, "| challenge | flag |\n|---|---|\n| chal | DH{ok} |\n")
    problem_dir = tmp_path / "chal"
    problem_dir.mkdir()
    status, note = check_answer(problem_dir, "solved", "DH{ok}")
    assert status == "solved"
    assert note is None


def test_solved_wrong_flag_flips_to_wrong_with_note(tmp_path):
    _write_answers(tmp_path, "| challenge | flag |\n|---|---|\n| chal | DH{k3y_dr1v3n_ui} |\n")
    problem_dir = tmp_path / "chal"
    problem_dir.mkdir()
    status, note = check_answer(problem_dir, "solved", "DH{k3y_driv3n_ui}")
    assert status == "wrong"
    assert note == "got DH{k3y_driv3n_ui}, expected DH{k3y_dr1v3n_ui}"


def test_unsolved_status_is_unchanged_even_with_answer_row(tmp_path):
    _write_answers(tmp_path, "| challenge | flag |\n|---|---|\n| chal | DH{ok} |\n")
    problem_dir = tmp_path / "chal"
    problem_dir.mkdir()
    status, note = check_answer(problem_dir, "unsolved", None)
    assert status == "unsolved"
    assert note is None


def test_no_answers_file_is_unchanged(tmp_path):
    problem_dir = tmp_path / "chal"
    problem_dir.mkdir()
    status, note = check_answer(problem_dir, "solved", "DH{anything}")
    assert status == "solved"
    assert note is None


def test_row_missing_for_this_challenge_is_unchanged(tmp_path):
    _write_answers(tmp_path, "| challenge | flag |\n|---|---|\n| other_chal | DH{ok} |\n")
    problem_dir = tmp_path / "chal"
    problem_dir.mkdir()
    status, note = check_answer(problem_dir, "solved", "DH{anything}")
    assert status == "solved"
    assert note is None


def test_bench_resolves_relative_dirs_before_running(tmp_path, monkeypatch):
    """Overnight bench and the bronze bench both failed every row after the first with [Errno 2] because
    relative dirs were resolved late, after the working directory had gone stale (DrvFs). Paths must be
    absolute before the first run."""
    import revagent.__main__ as m
    seen = []
    (tmp_path / "a").mkdir(); (tmp_path / "b").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(m, "_preflight", lambda *a, **k: object())
    def fake_run_one(d, args, desc, ask, rt):
        seen.append(d)
        if len(seen) == 1:
            os.chdir("/")          # the first run leaves the cwd behind, as a stale DrvFs cwd does
        return {"status": "unsolved", "steps": 0, "minutes": 0}, 1
    monkeypatch.setattr(m, "_run_one", fake_run_one)
    monkeypatch.setattr(m, "_row", lambda d, r: (d.name, r["status"], "", 0, 0))
    monkeypatch.setattr(m, "_print_bench_table", lambda rows: 0)
    m.main(["bench", "a", "b"])
    assert seen and all(d.is_absolute() for d in seen)
    assert [d.name for d in seen] == ["a", "b"]


def test_stale_cwd_gives_one_clear_message(tmp_path, monkeypatch, capsys):
    import revagent.__main__ as m
    monkeypatch.setattr(m, "_preflight", lambda *a, **k: object())
    def boom(self, *a, **k):
        raise FileNotFoundError(2, "No such file or directory")
    monkeypatch.setattr(m.Path, "resolve", boom)
    assert m.main(["bench", "x"]) == 2
    assert "current directory no longer exists" in capsys.readouterr().err

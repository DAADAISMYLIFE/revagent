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

import pytest
from revagent.casefile import CaseFile, SECTIONS


def test_creates_file_with_sections(tmp_path):
    p = tmp_path / "case.md"
    cf = CaseFile(p, "prob1", "find the flag\nsecond line")
    text = cf.read()
    assert text.startswith("# Case: prob1\n")
    assert "> find the flag\n> second line" in text
    for header in SECTIONS.values():
        assert header in text


def test_does_not_overwrite_existing(tmp_path):
    p = tmp_path / "case.md"
    p.write_text("# Case: old\n\n## Facts\n- kept\n\n## Hypotheses\n\n## Todo\n\n## Log\n")
    CaseFile(p, "new", "desc")
    assert "kept" in p.read_text()


def test_add_appends_bullet_in_right_section(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    cf.add("facts", "main at 0x401000")
    cf.add("todo", "dump opcode table")
    cf.add("facts", "check is xor 0x5a")
    text = cf.read()
    facts = text.split("## Facts")[1].split("## Hypotheses")[0]
    todo = text.split("## Todo")[1].split("## Log")[0]
    assert facts.strip().splitlines() == ["- main at 0x401000", "- check is xor 0x5a"]
    assert todo.strip() == "- dump opcode table"


def test_add_multiline_indents_continuation(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    cf.add("hypotheses", "VM?\nopcode 0x10 = add")
    assert "- VM?\n  opcode 0x10 = add" in cf.read()


def test_add_raw_log_entry(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    cf.add("log", "### compaction 1\n- fact a\n- fact b", bullet=False)
    log = cf.read().split("## Log")[1]
    assert "### compaction 1\n- fact a\n- fact b" in log


def test_unknown_section_raises(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    with pytest.raises(ValueError):
        cf.add("nope", "x")


def test_write_replaces(tmp_path):
    cf = CaseFile(tmp_path / "case.md", "p", "d")
    cf.write("# Case: p\n\n## Facts\n- only\n\n## Hypotheses\n\n## Todo\n\n## Log\n")
    assert cf.read().count("only") == 1

from revagent.detectors import (JACCARD_MIN, LONG_REASONING_CHARS, LONG_REASONING_LIMIT, PREFIX_CHARS,
                                normalize, script_body, similar)


def test_script_body_extracts_heredoc_body():
    cmd = "cd /work/x && python3 - <<'EOF'\nimport pefile\npe = pefile.PE('a.exe')\nprint(pe)\nEOF"
    assert script_body(cmd) == "import pefile\npe = pefile.PE('a.exe')\nprint(pe)"


def test_script_body_extracts_python_c_string():
    assert script_body('cd /w && python3 -c "import json\\nprint(1)"') == "import json\\nprint(1)"
    assert script_body("python3 -c 'print(2)'") == "print(2)"


def test_script_body_extracts_cat_heredoc_to_file():
    cmd = "cat > /tmp/emu.py <<'EOF'\nfrom unicorn import Uc\nmu = Uc()\nEOF\npython3 /tmp/emu.py"
    assert script_body(cmd) == "from unicorn import Uc\nmu = Uc()"


def test_script_body_none_for_plain_commands():
    assert script_body("ls -la && file chall") is None
    assert script_body("objdump -d -M intel chall | head") is None
    assert script_body("") is None


def test_normalize_collapses_whitespace_and_blank_lines():
    assert normalize("a  =  1\n\n\n  b=2  \n") == "a = 1\nb=2"


def test_similar_by_prefix():
    base = "x = 1\n" * 60          # 360 chars, identical first 200
    assert similar(base + "print('a')", base + "print('zzz')")


def test_similar_by_jaccard_of_lines():
    a = "\n".join(f"line{i}" for i in range(10))
    b = "\n".join(f"line{i}" for i in range(2, 10)) + "\nnew1\nnew2"   # 8 shared / 12 union = 0.67
    assert similar(a, b)
    c = "\n".join(f"other{i}" for i in range(10))
    assert not similar(a, c)


def test_similar_thresholds_are_the_spec_values():
    assert (PREFIX_CHARS, JACCARD_MIN, LONG_REASONING_CHARS, LONG_REASONING_LIMIT) == (200, 0.6, 8000, 5)

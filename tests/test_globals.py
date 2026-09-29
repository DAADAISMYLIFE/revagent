"""decompile's [globals] block: DAT_ tables read at the width the C uses, not from a hexdump."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from revagent import globals as g
from revagent.tools import decompile
from revagent.tools import decompile as decompile_mod
from tests.test_tools import ctx_for

SRC = r"""
unsigned int table[18] = {'k','3','y','_','1','s','_','h','3','r','3',0};
unsigned char bytes_[4] = {0xde, 0xad, 0xbe, 0xef};
unsigned int zeros[8];
int main(void) { return table[0] + bytes_[0] + zeros[1]; }
"""


def _build(tmp_path, pie: bool) -> tuple[Path, dict]:
    if not shutil.which("gcc") or not shutil.which("nm"):
        pytest.skip("gcc/nm not available")
    src = tmp_path / "t.c"
    src.write_text(SRC)
    out = tmp_path / ("pie" if pie else "nopie")
    subprocess.run(["gcc", "-O0", "-o", str(out), str(src), "-fpie" if pie else "-fno-pie",
                    "-pie" if pie else "-no-pie"], check=True)
    syms = {}
    for line in subprocess.run(["nm", str(out)], capture_output=True, text=True).stdout.splitlines():
        parts = line.split()
        if len(parts) == 3:
            syms[parts[2]] = int(parts[0], 16) + (g.GHIDRA_PIE_BASE if pie else 0)
    return out, syms


def test_width_comes_from_the_cast():
    c = "if (*(uint *)(&DAT_140003000 + (longlong)i * 4) != (uint)*(byte *)(p + i)) break;"
    assert g.element_width(c, 0x140003000) == 4
    assert g.element_width("x = *(ushort *)(&DAT_00104010 + i * 2);", 0x104010) == 2
    assert g.element_width("x = (&DAT_00104010)[i];", 0x104010) == 1
    assert g.element_width("q = *(ulonglong *)&DAT_00104010;", 0x104010) == 8
    assert g.referenced("(&DAT_00104010)[i]; DAT_00104010 = 1; *(uint *)(&DAT_00104020 + i * 4); DAT_00104030 = 2;") \
        == [0x104010, 0x104020]                         # DAT_00104030 is a scalar: not a table


def test_loop_count_from_the_index_bound():
    c = "while (true) { if (0x17 < local_18) return 1; if ((&DAT_140003000)[(int)local_18] != x) break; }"
    assert g.loop_count(c, 0x140003000) == 0x18
    assert g.loop_count("for (i = 0; i < 12; i++) y += *(uint *)(&DAT_00104010 + (long)i * 4);", 0x104010) == 12
    assert g.loop_count("for (i = 0; i <= 0x10; i++) y += DAT_00104010[i];", 0x104010) == 0x11
    assert g.loop_count("y = (&DAT_00104010)[k];", 0x104010) is None


@pytest.mark.parametrize("pie", [False, True])
def test_describe_reads_a_4_byte_table_as_text(tmp_path, pie):
    exe, syms = _build(tmp_path, pie)
    t, b, z = syms["table"], syms["bytes_"], syms["zeros"]
    c = (f"if (*(uint *)(&DAT_{t:08x} + (long)i * 4) != (uint)p[i]) return 0;\n"
         f"x = (&DAT_{b:08x})[k]; y = *(uint *)(&DAT_{z:08x} + 4);")
    out = g.describe(exe, c)
    assert out.startswith("[globals]")
    assert f"DAT_{t:x} as 12 x 4-byte values (no loop bound found; cut at padding): 0x0000006b 0x00000033" in out
    assert "as characters (one per 4-byte element, up to the first 0): 'k3y_1s_h3r3' (11 chars)" in out
    assert f"DAT_{b:x} as " in out and "de ad be ef" in out
    assert f"DAT_{z:x}: all zero in the file" in out


def test_a_table_indexed_by_data_is_a_lookup_read_whole(tmp_path):
    c = "if ((&DAT_140003020)[*(byte *)(param_1 + (int)i)] != (&DAT_140003000)[(int)i]) break; if (0x11 < i) return 1;"
    assert g.is_lookup(c, 0x140003020) and not g.is_lookup(c, 0x140003000)
    assert g.loop_count(c, 0x140003000) == 0x12
    exe, syms = _build(tmp_path, pie=False)
    t = syms["table"]
    out = g.describe(exe, f"x = (&DAT_{t:08x})[(uint)(k ^ key[j])];")
    assert "a lookup table indexed by data, read whole" in out and "as characters" not in out


def test_describe_uses_the_loop_bound(tmp_path):
    exe, syms = _build(tmp_path, pie=False)
    t = syms["table"]
    out = g.describe(exe, f"for (i = 0; i < 4; i++) if (*(uint *)(&DAT_{t:08x} + (long)i * 4) != p[i]) return 0;")
    assert f"DAT_{t:x} as 4 x 4-byte values (the loop bound in the C reads 4): " in out
    assert "'k3y_'" in out


def test_describe_is_empty_without_globals_or_on_a_bad_file(tmp_path):
    assert g.describe(tmp_path / "missing", "return (&DAT_00104010)[i];") == ""
    (tmp_path / "junk").write_bytes(b"not a binary")
    assert g.describe(tmp_path / "junk", "return (&DAT_00104010)[i];") == ""
    assert g.describe(tmp_path / "junk", "return 0;") == ""


def test_decompile_get_puts_the_block_before_the_c(tmp_path, monkeypatch):
    exe, syms = _build(tmp_path, pie=False)
    t = syms["table"]
    c_text = f"int check(char *p)\n{{\n  return *(uint *)(&DAT_{t:08x} + 4) == (uint)p[1];\n}}\n"
    funcs = [{"name": "check", "entry": "0x401000", "size": 10, "is_thunk": False, "callers": [],
              "callees": [], "string_refs": [], "decompiled_c": c_text}]
    fix = tmp_path / "funcs.json"
    fix.write_text(json.dumps(funcs))
    monkeypatch.setattr(decompile_mod, "analyze", lambda binary, cache_dir, timeout=None: fix)
    c = ctx_for(tmp_path)
    out = decompile.run(c, action="get", target="check", binary=exe.name)
    assert out.startswith("[hint]")                                    # the emulate hint stays first
    assert out.index("[globals]") < out.index("int check(char *p)")
    assert "'k3y_1s_h3r3'" in out and out.endswith(c_text)

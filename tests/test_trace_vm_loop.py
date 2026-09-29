"""Integration: trace_run on bench/mini/vm_loop (a PIE bytecode interpreter) under real qemu-user.
Skips when the binary is not built (bash bench/mini/build.sh) or qemu-x86_64-static is absent."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.conftest import make_ctx

VM_LOOP = Path(__file__).resolve().parents[1] / "bench" / "mini" / "vm_loop" / "vm_loop"
FLAG = "DH{vm_l00p_tr4ce}"

pytestmark = pytest.mark.skipif(
    not VM_LOOP.exists() or (shutil.which("qemu-x86_64-static") is None and shutil.which("qemu-x86_64") is None)
    or shutil.which("nm") is None,
    reason="needs bench/mini/vm_loop (bash bench/mini/build.sh), qemu-x86_64-static and nm")


def _handlers() -> dict[str, int]:
    """Ghidra addresses (PIE base 0x100000) of the op_* handlers (and run_vm, the dispatch loop that
    directly follows them) from the unstripped binary."""
    out = subprocess.run(["nm", str(VM_LOOP)], capture_output=True, text=True, check=True).stdout
    addrs = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and (parts[2].startswith("op_") or parts[2] == "run_vm"):
            addrs[parts[2]] = 0x100000 + int(parts[0], 16)
    assert {"op_load", "op_rol", "op_storej", "op_loado", "op_xor", "op_add", "op_reset", "op_halt"} <= set(addrs)
    return addrs


def _groups(out: str, reps: int) -> list[list[int]]:
    seq = out[out.index("sequence ("):]
    return [[int(x, 16) for x in g.split()] for g in re.findall(r"\(([^)]*)\)×%d\b" % reps, seq)]


def test_vm_loop_sequence_shows_handlers_in_bytecode_order_with_repeats_folded(tmp_path):
    from revagent.tools import trace_run
    shutil.copy(VM_LOOP, tmp_path / "vm_loop")
    ctx = make_ctx(tmp_path)
    out = trace_run.run(ctx, binary="vm_loop", stdin=FLAG + "\n", timeout=120)
    assert "(PIE, Ghidra base 0x100000)" in out and "[image]" in out
    assert "stdout 'Input: Correct!'" in out
    h = _handlers()
    # 17 input bytes: each 3-opcode pass loops 16 times identically, then once with the exit branch
    groups = _groups(out, 16)
    assert len(groups) >= 3, out
    first = groups[0]
    assert h["op_load"] in first and h["op_rol"] in first and h["op_storej"] in first
    rot = first[first.index(h["op_load"]):] + first[:first.index(h["op_load"])]
    assert rot.index(h["op_load"]) < rot.index(h["op_rol"]) < rot.index(h["op_storej"])
    assert h["op_xor"] not in first and h["op_add"] not in first        # pass 1 uses ROL only
    assert h["op_xor"] in groups[1] and h["op_add"] in groups[2]
    assert (tmp_path / ".revagent/out/trace-1.txt").exists()
    assert "trace_run vm_loop:" in ctx.casefile.read()


def test_vm_loop_range_over_the_handlers_only(tmp_path):
    from revagent.tools import trace_run
    shutil.copy(VM_LOOP, tmp_path / "vm_loop")
    ctx = make_ctx(tmp_path)
    trace_run.run(ctx, binary="vm_loop", stdin=FLAG + "\n", timeout=120)   # learns the base
    h = _handlers()
    # the handlers are contiguous op_halt..op_reset; run_vm (the dispatch loop, whose loop-head block would
    # otherwise land in the range) starts right after op_reset
    lo, hi = h["op_halt"], h["run_vm"]
    out = trace_run.run(ctx, binary="vm_loop", stdin=FLAG + "\n", range=f"{lo:#x}..{hi:#x}", timeout=120)
    assert f"sequence (range {lo:#x}..{hi:#x}" in out
    seq = out[out.index("sequence ("):]
    body = seq[seq.index("\n"):]          # below the header line, which repeats the range bounds
    for addr in re.findall(r"0x[0-9a-f]+", body):
        assert lo <= int(addr, 16) < hi
    groups = _groups(out, 16)
    assert len(groups) >= 3, out
    assert h["op_load"] in groups[0] and h["op_rol"] in groups[0] and h["op_storej"] in groups[0]
    assert len(groups[0]) == 4        # op_load, op_rol and the two blocks of op_storej

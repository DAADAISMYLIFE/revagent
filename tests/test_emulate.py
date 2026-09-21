"""emulate_call is exercised with hand-assembled x86-64 fragments in a synthetic Image, so no binary,
Ghidra or cle is needed; load_image is covered by a tiny real ELF built with gcc when available."""
import shutil
import subprocess
from pathlib import Path

import pytest

from revagent.emulate import (BUF_BASE, BUF_MAX, RET_PAGE, STACK_SIZE, EmulateError, Image, Result, emulate_call,
                              load_image)

CODE = 0x100000


def _image(code: bytes, is_pe: bool = False, symbol_at=lambda a: None) -> Image:
    return Image(segments=[(CODE, code + b"\xcc" * 16)], base=CODE, min_addr=CODE, max_addr=CODE + 0x1000,
                 is_pe=is_pe, symbol_at=symbol_at)


def test_sysv_int_args_and_rax():
    # add rdi, rsi ; mov rax, rdi ; ret
    r = emulate_call(_image(bytes.fromhex("4801f7 4889f8 c3")), CODE, [("int", 2), ("int", 3)])
    assert r.stopped is None and r.rax == 5 and r.buffers == []


def test_win64_int_args():
    # add rcx, rdx ; mov rax, rcx ; ret
    r = emulate_call(_image(bytes.fromhex("4801d1 4889c8 c3"), is_pe=True), CODE, [("int", 40), ("int", 2)])
    assert r.stopped is None and r.rax == 42


def test_hex_buffer_is_passed_by_address_and_returned_after_the_call():
    # add byte [rdi], 1 ; add byte [rdi+1], 2 ; ret
    r = emulate_call(_image(bytes.fromhex("800701 80470102 c3")), CODE, [("hex", b"\x41\x41\x41")])
    assert r.stopped is None
    assert r.buffers == [b"\x42\x43\x41"]


def test_out_lens_reads_more_than_the_input():
    # mov byte [rdi+4], 0x5a ; ret   (writes past the 1-byte input)
    r = emulate_call(_image(bytes.fromhex("c647045a c3")), CODE, [("hex", b"\x00")], out_lens=[6])
    assert r.buffers == [b"\x00\x00\x00\x00\x5a\x00"]


def test_win64_buffer_arg_uses_rcx_and_shadow_space():
    # mov rax, [rsp+8]  -> reads the shadow space (callee-owned), must be mapped; then add byte [rcx], 1 ; ret
    r = emulate_call(_image(bytes.fromhex("488b442408 800101 c3"), is_pe=True), CODE, [("hex", b"\x10")])
    assert r.stopped is None and r.buffers == [b"\x11"]


def test_addr_arg_points_into_the_image():
    # movzx eax, byte [rdi] ; ret   with rdi = an address inside the image (the code page itself)
    r = emulate_call(_image(bytes.fromhex("0fb607 c3")), CODE, [("addr", CODE)])
    assert r.stopped is None and r.rax == 0x0F


def test_more_than_six_sysv_args_go_on_the_stack():
    # mov rax, [rsp+8] ; ret   -> 7th argument
    r = emulate_call(_image(bytes.fromhex("488b442408 c3")), CODE, [("int", i) for i in range(1, 8)])
    assert r.stopped is None and r.rax == 7


def test_fs_and_gs_reads_return_zero():
    # mov rax, fs:[0x28] ; mov rcx, gs:[0x60] ; add rax, rcx ; ret
    r = emulate_call(_image(bytes.fromhex("64488b042528000000 65488b0c2560000000 4801c8 c3")), CODE, [])
    assert r.stopped is None and r.rax == 0


def test_call_into_unmapped_address_is_reported_with_symbol_and_arg_regs():
    # mov edi, 7 ; mov rax, 0x500000 ; call rax   (0x500000 is unmapped)
    code = bytes.fromhex("bf07000000 48c7c000005000 ffd0")
    r = emulate_call(_image(code, symbol_at=lambda a: "strlen" if a == 0x500000 else None), CODE, [])
    assert r.stopped["reason"] == "import" and r.stopped["symbol"] == "strlen"
    assert r.stopped["rip"] == 0x500000 and r.stopped["arg_regs"][0] == 7


def test_unmapped_data_access_is_reported():
    # mov rax, [0x600000] ; ret
    r = emulate_call(_image(bytes.fromhex("488b042500006000 c3")), CODE, [])
    assert r.stopped["reason"] == "unmapped" and "0x600000" in r.stopped["detail"]


def test_instruction_limit_stops_an_infinite_loop():
    r = emulate_call(_image(bytes.fromhex("ebfe")), CODE, [], max_insns=1000)
    assert r.stopped["reason"] == "limit"


def test_invalid_instruction_is_reported():
    r = emulate_call(_image(bytes.fromhex("0f0b")), CODE, [])  # ud2
    assert r.stopped["reason"] == "invalid"


def test_func_outside_image_raises():
    with pytest.raises(EmulateError):
        emulate_call(_image(bytes.fromhex("c3")), 0x900000, [])


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc needed to build a tiny ELF")
def test_load_image_pie_elf_at_ghidra_base(tmp_path):
    src = tmp_path / "t.c"
    src.write_text("unsigned char f(unsigned char *p){p[0]^=0x55;return p[0];}\nint main(){return 0;}\n")
    exe = tmp_path / "t"
    subprocess.run(["gcc", "-O0", "-pie", "-fPIE", "-o", str(exe), str(src)], check=True)
    img = load_image(exe)
    assert not img.is_pe and img.base == 0x100000 and img.min_addr >= 0x100000
    # find f via nm and call it through the oracle
    out = subprocess.run(["nm", str(exe)], capture_output=True, text=True).stdout
    f_off = next(int(l.split()[0], 16) for l in out.splitlines() if l.endswith(" T f"))
    r = emulate_call(img, 0x100000 + f_off, [("hex", b"\x00")])
    assert r.stopped is None and r.rax == 0x55 and r.buffers == [b"\x55"]


def test_stack_holds_a_two_megabyte_local_frame():
    # sub rsp, 0x200000 ; mov byte [rsp], 1 ; add rsp, 0x200000 ; ret   (the spec says 8 MB of stack)
    r = emulate_call(_image(bytes.fromhex("4881ec00002000 c6042401 4881c400002000 c3")), CODE, [])
    assert r.stopped is None
    assert STACK_SIZE == 0x800000


def test_overrun_from_one_buffer_faults_instead_of_landing_in_the_next():
    # mov byte [rdi+0x10000], 1 ; ret   -> beyond arg0's mapping, must NOT silently hit arg1
    r = emulate_call(_image(bytes.fromhex("c68700000100 01 c3")), CODE, [("hex", b"\x00"), ("hex", b"\x00")])
    assert r.stopped["reason"] == "unmapped" and r.buffers == [b"\x00", b"\x00"]


def test_hex_argument_size_cap_leaves_a_guard_page():
    r = emulate_call(_image(bytes.fromhex("c3")), CODE, [("hex", b"\x00" * BUF_MAX)])
    assert r.stopped is None and len(r.buffers[0]) == BUF_MAX
    with pytest.raises(EmulateError, match="too large"):
        emulate_call(_image(bytes.fromhex("c3")), CODE, [("hex", b"\x00" * (BUF_MAX + 1))])

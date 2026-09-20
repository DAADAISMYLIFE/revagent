#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
x86_64-w64-mingw32-gcc -O1 -s -o "$HERE/win_console/win_console.exe" "$HERE/src/win_console.c"
x86_64-w64-mingw32-gcc -O1 -s -municode -mwindows -o "$HERE/win_gui/win_gui.exe" "$HERE/src/win_gui.c" -lgdi32
x86_64-w64-mingw32-gcc -O1 -s -municode -mwindows -o "$HERE/win_gui_key/win_gui_key.exe" "$HERE/src/win_gui_key.c" -lgdi32
# dlltool -d nosuch.def with a stdcall-decorated "NoSuchExport@4" entry does not link on x86_64
# (stdcall decoration is a 32-bit-only convention; mingw-w64 x86_64 leaves symbols undecorated, so
# the linker looked for `__imp_NoSuchExport` and never found it). Build a real stub DLL that exports
# NoSuchExport instead, link the exe against it, then delete the DLL: the import table still names
# nosuchdll_zz.dll, but the file is gone, so the loader fails before WinMain runs.
# The stub sources/artifacts live under a scratch dir (not the bench tree) and are removed by a
# trap on exit, so a failed link (or any other error under `set -e`) can never leave them behind
# in the host tree.
STUB_DIR="$(mktemp -d)"
trap 'rm -rf "$STUB_DIR"' EXIT
cat > "$STUB_DIR/stub.c" <<'EOF'
__declspec(dllexport) int __stdcall NoSuchExport(int x) { return x; }
EOF
x86_64-w64-mingw32-gcc -shared -o "$STUB_DIR/nosuchdll_zz.dll" "$STUB_DIR/stub.c" -Wl,--out-implib,"$STUB_DIR/libnosuchdll_zz.a"
x86_64-w64-mingw32-gcc -O1 -s -municode -mwindows -o "$HERE/win_gui_nodll/win_gui_nodll.exe" "$HERE/src/win_gui_nodll.c" -L"$STUB_DIR" -lnosuchdll_zz
echo "built win_console.exe, win_gui.exe, win_gui_key.exe and win_gui_nodll.exe"

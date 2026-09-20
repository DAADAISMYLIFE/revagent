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
cat > "$HERE/win_gui_nodll/stub.c" <<'EOF'
__declspec(dllexport) int __stdcall NoSuchExport(int x) { return x; }
EOF
x86_64-w64-mingw32-gcc -shared -o "$HERE/win_gui_nodll/nosuchdll_zz.dll" "$HERE/win_gui_nodll/stub.c" -Wl,--out-implib,"$HERE/win_gui_nodll/libnosuchdll_zz.a"
x86_64-w64-mingw32-gcc -O1 -s -municode -mwindows -o "$HERE/win_gui_nodll/win_gui_nodll.exe" "$HERE/src/win_gui_nodll.c" -L"$HERE/win_gui_nodll" -lnosuchdll_zz
rm -f "$HERE/win_gui_nodll/stub.c" "$HERE/win_gui_nodll/nosuchdll_zz.dll" "$HERE/win_gui_nodll/libnosuchdll_zz.a"
echo "built win_console.exe, win_gui.exe, win_gui_key.exe and win_gui_nodll.exe"

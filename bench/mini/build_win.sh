#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
x86_64-w64-mingw32-gcc -O1 -s -o "$HERE/win_console/win_console.exe" "$HERE/src/win_console.c"
x86_64-w64-mingw32-gcc -O1 -s -municode -mwindows -o "$HERE/win_gui/win_gui.exe" "$HERE/src/win_gui.c" -lgdi32
x86_64-w64-mingw32-gcc -O1 -s -municode -mwindows -o "$HERE/win_gui_key/win_gui_key.exe" "$HERE/src/win_gui_key.c" -lgdi32
i686-w64-mingw32-gcc -O1 -s -municode -mwindows -o "$HERE/win_gui_32/win_gui_32.exe" "$HERE/src/win_gui_32.c" -lgdi32
echo "built win_console.exe, win_gui.exe, win_gui_key.exe and win_gui_32.exe"

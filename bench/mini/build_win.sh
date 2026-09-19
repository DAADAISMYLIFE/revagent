#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
x86_64-w64-mingw32-gcc -O1 -s -o "$HERE/win_console/win_console.exe" "$HERE/src/win_console.c"
x86_64-w64-mingw32-gcc -O1 -s -municode -mwindows -o "$HERE/win_gui/win_gui.exe" "$HERE/src/win_gui.c" -lgdi32
echo "built win_console.exe and win_gui.exe"

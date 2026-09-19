#!/usr/bin/env bash
# Build the revagent-sandbox image and smoke-test its toolchain.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"
docker build -t revagent-sandbox -f docker/Dockerfile .
echo "== smoke"
docker run --rm --entrypoint bash revagent-sandbox -c '
  set -e
  ls /root/tools | grep -E "^ghidra_|^jdk-21"
  python -c "import angr, z3, unicorn, capstone, pwn, pefile, Crypto; print(\"python stack ok\")"
  gdb --version | head -1
  radare2 -v | head -1
  ldconfig -p | grep -q libssl.so.1.1 && echo "libssl1.1 ok"
  revagent solve --help >/dev/null && echo "revagent ok"
  wine --version
  (Xvfb :99 -screen 0 1280x800x24 -nolisten tcp >/dev/null 2>&1 &) ; sleep 2; xdpyinfo -display :99 >/dev/null && echo "xvfb ok"
  bash /app/bench/mini/build_win.sh
  printf "DH{w1ne_c0ns0le}\n" | WINEDEBUG=-all wine /app/bench/mini/win_console/win_console.exe | grep -q Correct && echo "wine console ok"
  (DISPLAY=:99 WINEDEBUG=-all wine /app/bench/mini/win_gui/win_gui.exe >/dev/null 2>&1 &) ; sleep 5
  import -display :99 -window root /tmp/gui.png && tesseract /tmp/gui.png stdout --psm 6 2>/dev/null | grep -q "DH" && echo "gui ocr ok"
'
docker image inspect revagent-sandbox --format 'image size: {{.Size}} bytes'
echo "== build test PEs into host tree"
docker run --rm -v "$HERE":/app --entrypoint bash revagent-sandbox -c "bash /app/bench/mini/build_win.sh"

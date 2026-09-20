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
  cd /app
  python - <<'"'"'PY'"'"'
from pathlib import Path
from revagent.casefile import CaseFile
from revagent.tools.base import ToolContext
from revagent.tools import run_gui, run_binary
d = Path("/app/bench/mini/win_gui"); w = Path("/tmp/wg"); w.mkdir(exist_ok=True)
ctx = ToolContext(problem_dir=d, work_dir=w, casefile=CaseFile(w/"case.md","g","d"), llm=None, interactive=False)
out = run_gui.run(ctx, path="win_gui.exe", wait_seconds=6)
print(out[:400]); assert "DH" in out, "run_gui OCR did not find DH"
print("run_gui ok")
d = Path("/app/bench/mini/win_gui_key")
ctx = ToolContext(problem_dir=d, work_dir=w, casefile=CaseFile(w/"case.md","g","d"), llm=None, interactive=False)
out = run_gui.run(ctx, path="win_gui_key.exe", wait_seconds=6, actions=["key space"] * 16)
last = [l for l in out.splitlines() if l.startswith("16. key space")]
print(last); assert last and "DH{" in last[0], "run_gui actions did not reveal the key-driven flag"
print("run_gui actions ok")
d = Path("/app/bench/mini/win_gui_32")
ctx = ToolContext(problem_dir=d, work_dir=w, casefile=CaseFile(w/"case.md","g","d"), llm=None, interactive=False)
out = run_binary.run(ctx, path="win_gui_32.exe")
assert out.startswith("[cannot run here]"), "PE32 should be refused by run_binary"
assert ctx.env_blocked, "PE32 run_binary should set env_blocked"
print("env_blocked ok")
PY
'
docker image inspect revagent-sandbox --format 'image size: {{.Size}} bytes'
echo "== build test PEs into host tree"
docker run --rm --user "$(id -u):$(id -g)" -v "$HERE":/app --entrypoint bash revagent-sandbox -c "bash /app/bench/mini/build_win.sh"

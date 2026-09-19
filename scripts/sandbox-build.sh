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
'
docker image inspect revagent-sandbox --format 'image size: {{.Size}} bytes'

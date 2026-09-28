#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
gcc -O1 -s -o "$HERE/xor_check/xor_check" "$HERE/src/xor_check.c"
mkdir -p "$HERE/vm_loop"
gcc -O0 -fPIE -pie -o "$HERE/vm_loop/vm_loop" "$HERE/src/vm_loop.c"
echo "built $HERE/xor_check/xor_check and $HERE/vm_loop/vm_loop"

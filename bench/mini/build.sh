#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
gcc -O1 -s -o "$HERE/xor_check/xor_check" "$HERE/src/xor_check.c"
echo "built $HERE/xor_check/xor_check"

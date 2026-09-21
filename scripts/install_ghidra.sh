#!/usr/bin/env bash
# Installs Temurin JDK 21 and the latest Ghidra release under ~/tools (no sudo),
# then verifies headless analysis + DumpFunctions.java on a small binary.
# SKIP_VERIFY=1 stops after the install (the Docker build runs the verify as a separate, later step
# so that editing revagent/ghidra_scripts does not invalidate the Ghidra layer).
set -euo pipefail
TOOLS="$HOME/tools"
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$HERE/../revagent/ghidra_scripts"
mkdir -p "$TOOLS"
cd "$TOOLS"

if ! ls -d jdk-21* >/dev/null 2>&1; then
  echo "[1/3] JDK 21"
  curl -fL -o jdk21.tar.gz "https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse"
  tar xzf jdk21.tar.gz && rm jdk21.tar.gz
fi
JDK="$(ls -d "$TOOLS"/jdk-21* | tail -1)"
echo "JDK: $JDK"

if ! ls -d ghidra_*_PUBLIC >/dev/null 2>&1; then
  echo "[2/3] Ghidra"
  # GHIDRA_URL pins an exact release (e.g. for reproducible image builds); unset falls back to
  # looking up the latest GitHub release, same as before.
  URL="${GHIDRA_URL:-$(curl -fsSL https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest \
        | grep -oE 'https://[^"]+_PUBLIC_[0-9]+\.zip' | head -1)}"
  echo "  $URL"
  curl -fL -o ghidra.zip "$URL"
  # no unzip on this box; python zipfile drops exec bits, so restore them from external_attr
  python3 - <<'PY'
import os, zipfile
z = zipfile.ZipFile("ghidra.zip")
for info in z.infolist():
    z.extract(info, ".")
    mode = (info.external_attr >> 16) & 0o777
    if mode:
        os.chmod(info.filename, mode)
PY
  rm ghidra.zip
fi
GH="$(ls -d "$TOOLS"/ghidra_*_PUBLIC | tail -1)"
echo "Ghidra: $GH"

if [ "${SKIP_VERIFY:-}" = "1" ]; then
  echo "[3/3] verify skipped (SKIP_VERIFY=1)"
  exit 0
fi

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
if command -v gcc >/dev/null 2>&1; then
  cat > "$T/hello.c" <<'C'
#include <stdio.h>
int main(void){puts("hi");return 0;}
C
  gcc -O1 -o "$T/hello" "$T/hello.c"
  TARGET="$T/hello"
elif [ -e /usr/bin/gnutrue ]; then
  TARGET=/usr/bin/gnutrue
else
  TARGET=/bin/true
fi
echo "[3/3] verify on $TARGET"
export JAVA_HOME="$JDK" PATH="$JDK/bin:$PATH"
timeout 600 "$GH/support/analyzeHeadless" "$T" verify -import "$TARGET" \
  -scriptPath "$SCRIPTS" -postScript DumpFunctions.java "$T/functions.json" -deleteProject \
  > "$T/log.txt" 2>&1 || true
python3 - "$T/functions.json" "$T/log.txt" <<'PY'
import json, sys
try:
    fs = json.load(open(sys.argv[1]))
except Exception as e:
    print("FAILED:", e); print(open(sys.argv[2]).read()[-3000:]); sys.exit(1)
print(f"OK: {len(fs)} functions; sample: {fs[0]['name']} {fs[0]['entry']} {len(fs[0]['decompiled_c'])} chars of C")
PY

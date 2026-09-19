#!/usr/bin/env bash
# Trust an optional extra CA mounted at runtime (TLS-intercepting corporate networks), then run revagent.
set -euo pipefail
CA=/usr/local/share/ca-certificates/extra-ca.crt
if [ -f "$CA" ]; then
  update-ca-certificates >/dev/null 2>&1 || echo "warning: update-ca-certificates failed; the mounted extra-ca.crt may be malformed" >&2
  export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
  export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
  export PIP_CERT=/etc/ssl/certs/ca-certificates.crt
fi
if ! xdpyinfo -display "${DISPLAY:-:99}" >/dev/null 2>&1; then
  Xvfb "${DISPLAY:-:99}" -screen 0 1280x800x24 -nolisten tcp >/dev/null 2>&1 &
  for i in 1 2 3 4 5 6 7 8 9 10; do xdpyinfo -display "${DISPLAY:-:99}" >/dev/null 2>&1 && break; sleep 0.5; done
  xdpyinfo -display "${DISPLAY:-:99}" >/dev/null 2>&1 || echo "warning: Xvfb did not start; run_gui will fail" >&2
fi
exec revagent "$@"

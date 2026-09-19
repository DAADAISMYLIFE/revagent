#!/usr/bin/env bash
# Trust an optional extra CA mounted at runtime (TLS-intercepting corporate networks), then run revagent.
set -euo pipefail
CA=/usr/local/share/ca-certificates/extra-ca.crt
if [ -f "$CA" ]; then
  update-ca-certificates >/dev/null 2>&1 || true
  export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
  export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
  export PIP_CERT=/etc/ssl/certs/ca-certificates.crt
fi
exec revagent "$@"

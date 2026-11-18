#!/bin/sh
# Container health probe.
#
# Defaults to the plaintext listener. A deployment that serves TLS itself must
# point AIRPORT_HEALTHCHECK_URL at https:// and provide the CA that signed the
# certificate in AIRPORT_HEALTHCHECK_CA. Verification is never skipped: without
# a trusted CA the probe fails instead of reporting a false healthy state.
set -eu

url="${AIRPORT_HEALTHCHECK_URL:-http://127.0.0.1:8787/healthz}"

if [ -n "${AIRPORT_HEALTHCHECK_CA:-}" ]; then
    exec curl -fsS --max-time 4 --cacert "$AIRPORT_HEALTHCHECK_CA" "$url"
fi

exec curl -fsS --max-time 4 "$url"

#!/usr/bin/env bash
# Starts the web app (with its embedded background workers) on port 8080.
set -euo pipefail
cd "$(dirname "$0")"
if [[ -f .env ]]; then set -a; source .env; set +a; fi
exec python3 -m uvicorn app.main:app --host "${VT_HOST:-0.0.0.0}" --port "${VT_PORT:-8080}" \
  --proxy-headers --forwarded-allow-ips "${VT_TRUSTED_PROXIES:-127.0.0.1}" "$@"

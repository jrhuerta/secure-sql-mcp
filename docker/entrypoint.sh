#!/usr/bin/env sh
set -eu

OPA_BUNDLE_DIR="${OPA_BUNDLE_DIR:-/app/policy}"
OPA_ADDR="${OPA_ADDR:-127.0.0.1:8181}"

opa run --server --addr "$OPA_ADDR" --bundle "$OPA_BUNDLE_DIR" &
OPA_PID=$!

cleanup() {
  kill "$OPA_PID" 2>/dev/null || true
}

trap cleanup INT TERM EXIT

python /app/wait_for_opa.py

exec python -m secure_sql_mcp.server

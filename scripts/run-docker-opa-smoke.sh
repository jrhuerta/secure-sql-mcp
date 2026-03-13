#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "Running Docker + OPA smoke scenarios (all backends)..."
python -m pytest -q -m "docker_integration and smoke" tests/integration/docker/test_mcp_docker_opa_matrix.py

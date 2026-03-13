"""Wait for OPA health without extra image dependencies.

This project uses a Python-based readiness check instead of curl/wget so the
runtime image can stay minimal and self-contained. `python:3.12-slim` already
ships Python (required by the MCP server), while curl is not guaranteed.
"""

from __future__ import annotations

import os
import time
from urllib import request


def main() -> None:
    opa_url = os.environ.get("OPA_URL", "http://127.0.0.1:8181").rstrip("/")
    health_url = f"{opa_url}/health"

    deadline = time.time() + 15
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            with request.urlopen(health_url, timeout=0.5) as resp:  # noqa: S310
                if 200 <= resp.status < 300:
                    return
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            time.sleep(0.2)

    raise SystemExit(f"OPA failed health check: {last_error}")


if __name__ == "__main__":
    main()

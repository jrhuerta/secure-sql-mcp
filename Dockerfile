FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir . \
    && find /opt/venv -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true

FROM openpolicyagent/opa:1.5.1-static AS opa

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    OPA_URL="http://127.0.0.1:8181" \
    OPA_DECISION_PATH="/v1/data/secure_sql/authz/decision" \
    OPA_TIMEOUT_MS="50" \
    OPA_FAIL_CLOSED="true"

COPY --from=builder /opt/venv /opt/venv
COPY --from=opa /opa /usr/local/bin/opa
COPY policy /app/policy
COPY docker/entrypoint.sh /app/entrypoint.sh
COPY docker/wait_for_opa.py /app/wait_for_opa.py

RUN chmod 0555 /usr/local/bin/opa /app/entrypoint.sh /app/wait_for_opa.py

RUN useradd -r -s /usr/sbin/nologin appuser
USER appuser

ENTRYPOINT ["/app/entrypoint.sh"]

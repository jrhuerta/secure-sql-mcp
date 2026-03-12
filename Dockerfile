FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir . \
    && find /opt/venv -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

COPY --from=builder /opt/venv /opt/venv

RUN useradd -r -s /usr/sbin/nologin appuser
USER appuser

ENTRYPOINT ["python", "-m", "secure_sql_mcp.server"]

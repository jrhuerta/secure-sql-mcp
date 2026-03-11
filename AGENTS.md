## Repository Purpose

`secure-sql-mcp` is a Python MCP server that:
- Executes SQL queries in read-only mode.
- Enforces strict policy-based table/column access.
- Returns clear agent-facing feedback for blocked operations.

Core package: `src/secure_sql_mcp`

## Architecture Overview

- `config.py`
  - Loads env config.
  - Parses `ALLOWED_POLICY_FILE` in strict `table:columns` format.
- `query_validator.py`
  - SQL safety checks (read-only, single statement).
  - Strict table/column authorization checks.
- `database.py`
  - Async SQLAlchemy access.
  - Read-only session preparation and query timeout/row caps.
- `server.py`
  - MCP tool surface (`query`, `list_tables`, `describe_table`).
  - User/agent-facing responses.

## Security Invariants (Do Not Weaken)

1. Never allow mutating SQL operations.
   - This includes DML/DDL/privilege paths and multi-statement chaining attempts.
2. Policy must remain explicit and deny-by-default:
   - table missing in policy => blocked
   - column missing in table rule => blocked
3. `SELECT *` is only valid when table rule is `*`.
   - Also keep strict behavior for aliased `table.*` and multi-table unqualified columns.
4. Keep credentials server-side via environment variables.
5. Do not leak sensitive internals in database error responses.
6. Policy files should be mounted/read-only in containerized usage.

## Security Test Coverage (Current)

- `tests/test_mcp_interface.py`
  - MCP tool-level security behavior:
    - mutation/privilege blocks
    - table/column ACL enforcement
    - `SELECT *` policy behavior
    - join/union/subquery bypass attempts
    - timeout/row-cap/error-hygiene behavior
- `tests/test_query_validator_security.py`
  - Query validator edge and adversarial cases:
    - parser/multi-statement rejection
    - alias resolution behavior
    - strict multi-table column qualification
- `tests/test_mcp_stdio_security.py`
  - Protocol-level checks via real stdio MCP client/session:
    - initialize/list_tools contract
    - blocked and allowed query outcomes across transport

Run core security suites:
- `python -m pytest -q tests/test_mcp_interface.py tests/test_query_validator_security.py tests/test_mcp_stdio_security.py`

## Policy File Contract

`ALLOWED_POLICY_FILE` lines:
- `table_name:col1,col2,col3`
- `table_name:*`
- `#` comments and blank lines are allowed.

Names are normalized to lowercase.

## Local Workflow

- Package index (required for this environment):
  - `export PYTHON_INDEX_URL="https://<your-index>/simple"`
- Install dev dependencies:
  - `python -m pip install --index-url "$PYTHON_INDEX_URL" -e ".[dev]"`
- If using uv:
  - `uv pip install --index-url "$PYTHON_INDEX_URL" -e ".[dev]"`
- Run tests:
  - `python -m pytest -q`
- Run lint/format:
  - `ruff check .`
  - `ruff format .`
- Run type checks:
  - `ty check`

## Pre-commit

Configured in `.pre-commit-config.yaml`.

Setup:
- `pre-commit install`

Run manually:
- `pre-commit run --all-files`

Default hooks:
- `ruff-check`
- `ruff-format`
- `check-yaml`
- `end-of-file-fixer`
- `trailing-whitespace`
- `ty check`

## Change Guidance

- Keep error messages actionable for agents (include next steps like using `list_tables` / `describe_table`).
- Prefer extending tests in `tests/test_mcp_interface.py` for behavior changes.
- Avoid broad refactors that alter MCP tool contracts unless explicitly requested.
- If changing policy semantics, update both:
  - tests
  - `README.md`

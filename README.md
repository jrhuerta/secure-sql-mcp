# Secure SQL MCP Server

Read-only SQL MCP server with strict table/column policy controls.

[![CI](https://github.com/jrhuerta/secure-sql-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/jrhuerta/secure-sql-mcp/actions/workflows/ci.yml)
[![GHCR](https://img.shields.io/badge/ghcr-jrhuerta%2Fsecure--sql--mcp-blue)](https://github.com/jrhuerta/secure-sql-mcp/pkgs/container/secure-sql-mcp)

## Security Model

- Database credentials stay server-side (env vars), never in prompts.
- Only read queries are allowed.
- Policy is strict and file-based:
  - one required file: `ALLOWED_POLICY_FILE`
  - each line is `table:col1,col2,col3` or `table:*`
- If a table/column is not explicitly allowed, it is blocked.

## Implemented Security Controls

- **Query shape enforcement**
  - Exactly one SQL statement is allowed per request.
  - Non-read operations are blocked (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `CREATE`, `TRUNCATE`, `GRANT`, `REVOKE`, `MERGE`, and related command expressions).
- **Strict access policy enforcement**
  - Deny-by-default for tables and columns.
  - Access checks apply across direct queries and composed queries (`JOIN`, `UNION`, subqueries, aliases).
  - `SELECT *` is rejected unless the table policy is `table:*`.
  - Unqualified columns in multi-table queries are rejected under strict mode.
- **Runtime safety controls**
  - Query timeout and row cap are enforced server-side.
  - Row-cap truncation is explicit in response payloads.
- **Safe error behavior**
  - Validation and policy failures return actionable remediation hints.
  - Database execution failures are sanitized to avoid leaking sensitive internal details.

## Policy File Format

`allowed_policy.txt`:

```text
# table:columns
customers:id,email,created_at
orders:*
```

Rules:
- `table:*` allows all columns in that table.
- `#` comments and blank lines are allowed.
- Matching is case-insensitive.

## Agent Discoverability

The MCP server exposes:

- `list_tables()`:
  - tables allowed by policy
  - allowed columns per table (`*` or explicit list)
  - metadata validation status (if DB introspection is possible)
- `describe_table(table)`:
  - allowed columns for that table from policy
  - schema metadata from DB when available
- `query(sql)`:
  - executes only if query is read-only and within table/column policy

## Quick Start (uv)

```bash
git clone <your-repo-url>
cd secure-sql-mcp

# Use your custom package index for uv/pip operations in this repo
export PYTHON_INDEX_URL="https://<your-index>/simple"

cat > .env <<'EOF'
DATABASE_URL=sqlite+aiosqlite:///./example.db
ALLOWED_POLICY_FILE=./policy/allowed_policy.txt
MAX_ROWS=100
QUERY_TIMEOUT=30
LOG_LEVEL=INFO
EOF

mkdir -p policy
cat > policy/allowed_policy.txt <<'EOF'
customers:id,email
orders:*
EOF

uv venv
source .venv/bin/activate
uv pip install --index-url "$PYTHON_INDEX_URL" -e .
python -m secure_sql_mcp.server
```

## Quick Start (Docker)

```bash
git clone <your-repo-url>
cd secure-sql-mcp

mkdir -p policy
cat > policy/allowed_policy.txt <<'EOF'
customers:id,email
orders:*
EOF

cat > .env <<'EOF'
DATABASE_URL=sqlite+aiosqlite:///./example.db
ALLOWED_POLICY_FILE=/run/policy/allowed_policy.txt
MAX_ROWS=100
QUERY_TIMEOUT=30
LOG_LEVEL=INFO
EOF

docker build -t secure-sql-mcp .
docker run -i --rm \
  --env-file .env \
  -v "$(pwd)/policy:/run/policy:ro" \
  secure-sql-mcp
```

## Quick Start (GHCR Image)

Pull the published image:

```bash
docker pull ghcr.io/jrhuerta/secure-sql-mcp:main
```

Run with env file and read-only mounted policy:

```bash
docker run -i --rm \
  --env-file .env \
  -v "$(pwd)/policy:/run/policy:ro" \
  ghcr.io/jrhuerta/secure-sql-mcp:main
```

Version tags are published when Git tags like `v1.2.3` are pushed.

Or with compose:

```bash
docker compose up --build
```

## Secrets Best Practices

- Put credentials only in `.env` (or your secret manager), never in prompts.
- Avoid hardcoding credentials in shell history.
- Mount policy files read-only (`:ro`) in Docker.
- Keep `.env` and policy files out of version control.

## Dev Tooling

```bash
python -m pip install -e ".[dev]"
pre-commit install
pre-commit run --all-files
ruff check .
ruff format .
ty check
python -m pytest -q
```

## Security Test Suite

Run the security-focused suites directly:

```bash
python -m pytest -q \
  tests/test_mcp_interface.py \
  tests/test_query_validator_security.py \
  tests/test_mcp_stdio_security.py
```

What these suites validate:
- read-only enforcement for mutation/privileged SQL operations
- single-statement validation and parser hardening
- strict deny-by-default table/column ACL checks, including join/union/subquery paths
- protocol-level behavior over MCP stdio transport
- timeout, row cap truncation, and non-leaky actionable DB error responses

## CI Security Gate Expectations

For protected branches, treat these checks as merge blockers:

```bash
ruff check .
ty check
python -m pytest -q \
  tests/test_mcp_interface.py \
  tests/test_query_validator_security.py \
  tests/test_mcp_stdio_security.py
```

Recommended policy:
- block merges on any failure in the security suites above
- require test updates when changing query validation, policy parsing, or MCP tool responses
- keep security test fixtures deterministic (no shared state, no external DB dependency by default)

## Contributing

- Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a PR.
- Community behavior expectations are in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Licensing terms are in [LICENSE](LICENSE).
- Review expectations are enforced on `main`:
  - pull request required
  - at least 1 approving review
  - required CI checks (`Lint, Type, Test` and `Docker Build`)
  - linear history required
- Security reports should go to [SECURITY.md](SECURITY.md) and not public issues.

## Security Quick Audit Checklist

Before merging security-sensitive changes, verify:

- query validation still enforces exactly one statement per request
- mutation/DDL/privilege SQL operations are blocked with actionable messaging
- table and column access remains deny-by-default against `ALLOWED_POLICY_FILE`
- `SELECT *` is rejected unless policy explicitly allows `table:*`
- multi-table queries still reject unqualified columns and enforce alias-aware ACLs
- timeout and row-cap protections remain active and tested
- DB error responses stay sanitized and do not expose credentials/internal connection details
- security suites pass:
  - `tests/test_mcp_interface.py`
  - `tests/test_query_validator_security.py`
  - `tests/test_mcp_stdio_security.py`

## Public Rollout Verification Checklist

After merging workflow/docs changes, verify:

- repository visibility is `Public`
- `main` branch protection is active and requires:
  - PR-based merges
  - 1 approving review
  - required checks `Lint, Type, Test` and `Docker Build`
  - linear history, no force-push, no deletion
- CI workflow runs on PRs and on pushes to `main`
- GHCR image publish succeeds on push to `main`
- GHCR pull works:
  - `docker pull ghcr.io/jrhuerta/secure-sql-mcp:main`
- community docs are present:
  - `CONTRIBUTING.md`
  - `CODE_OF_CONDUCT.md`
  - `SECURITY.md`
  - `.github/ISSUE_TEMPLATE/*`
  - `.github/PULL_REQUEST_TEMPLATE.md`

## Example Block Messages

- Mutation blocked:
  - `This server is configured for read-only access. The operation 'UPDATE' is not permitted. If you need to modify data, please escalate to a human operator.`
- Policy blocked table:
  - `Access to table 'secrets' is restricted by the server access policy. ...`
- Policy blocked column:
  - `Access to column(s) ssn on table 'customers' is restricted. ...`

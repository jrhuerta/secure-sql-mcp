# Write Mode Design (Controlled Mutations)

This document describes how to extend `secure-sql-mcp` from read-only execution to
policy-governed writes while preserving security guarantees.

It is intentionally conservative: mutation capability is powerful and should be
introduced behind explicit controls, with deny-by-default behavior at each layer.

## Current state

Today, policy can theoretically return `allow` for non-read operations, but runtime
execution is still read-only:

- query execution uses `execute_read_query(...)`
- DB session is configured read-only for PostgreSQL/MySQL/SQLite
- query wrapper enforces select-style row capping logic

As a result, policy-only changes are not sufficient for write support.

## Goals

- Allow tightly scoped mutation scenarios (for example `INSERT` only).
- Keep deny-by-default and fail-closed behavior.
- Preserve clean, actionable error responses for agents.
- Avoid broad privilege escalation in database credentials.

## Non-goals

- Full unrestricted SQL write access.
- Multi-statement transaction scripting from agents.
- Bypassing policy checks in application code.

## Security invariants to preserve

- Single statement per request unless explicitly designed otherwise.
- Explicit allowlist semantics (tables/columns/actions).
- No sensitive internal error leakage.
- OPA unavailable/timeout behavior remains fail-closed.
- Tool responses remain deterministic and auditable.

## Proposed architecture changes

### 1) Split execution paths by statement class

Introduce separate DB execution methods:

- `execute_read_query(sql)` (existing)
- `execute_write_query(sql)` (new)

`execute_write_query` should:

- run with strict timeout
- return affected row count and optional returning payload
- avoid row-cap wrapper intended for SELECT
- avoid enabling arbitrary transaction control from user SQL

### 2) Expand policy facts for write authorization

Current input facts are SELECT-centric. Add mutation-focused facts in
`QueryValidator._build_query_policy_input(...)`, for example:

- `statement_type` normalized (`insert`, `update`, `delete`, etc.)
- `target_tables`
- `updated_columns`
- `insert_columns`
- `where_present` (for updates/deletes)
- `returning_present`

These facts should be parser-derived, not regex-derived.

### 3) Add explicit write mode config gates

Use coarse-grained runtime toggles in config:

- `WRITE_MODE_ENABLED=false` by default
- optional action toggles:
  - `ALLOW_INSERT=false`
  - `ALLOW_UPDATE=false`
  - `ALLOW_DELETE=false`
- allow these to be configured with flags from the cli also.

OPA remains the final decision engine; these toggles are safety brakes.

### 4) Keep OPA as policy source of truth for permissions

Model policy in Rego with explicit action constraints:

- allow read paths as before
- allow writes only when:
  - statement type is explicitly permitted
  - table is allowed
  - affected columns are allowed
  - optional contextual constraints pass (tenant/env/user role)

### 5) Server-level routing

In `query(...)`, route execution by validated statement class:

- if read -> `execute_read_query`
- if write and allowed -> `execute_write_query`
- else block with actionable message

## Example policy patterns for controlled writes

### Insert-only mode

- allow `insert` on specific tables
- deny `update`, `delete`, DDL

### Update-only specific columns

- allow `update` on table `customers`
- allow only `email` and `phone`
- require `WHERE` clause (no full-table updates)

### Delete with strict guard

- allow `delete` only on maintenance tables
- require `WHERE` and additional context flag (e.g. maintenance window)

## DB credential model

Policy alone is not enough. Use least-privilege DB credentials:

- read-only role for read-only deployments
- separate write-capable role for write mode
- grants limited to intended schemas/tables/actions

Do not rely solely on app-layer checks for write containment.

## Response contract proposal for writes

For write operations, return structured JSON:

```json
{
  "status": "ok",
  "operation": "update",
  "affected_rows": 3,
  "returning": []
}
```

For blocked writes, keep consistent actionable messages and avoid leaking internals.

## Rollout plan

1. Add parser-derived write facts and tests (no write execution yet).
2. Add OPA write policy rules in shadow mode (log only).
3. Add `execute_write_query` path behind `WRITE_MODE_ENABLED`.
4. Enable insert-only in non-production.
5. Expand to update/delete only with dedicated tests and DB grants.

## Test matrix (minimum)

- parser extraction for write facts by dialect
- blocked/allowed decisions for insert/update/delete
- column-restricted updates
- missing-WHERE safeguards
- fail-closed OPA behavior for writes
- sanitized DB error responses
- stdio MCP contract for write and blocked-write outcomes


# Policy Authoring Guide (OPA/Rego)

This guide explains how to write and customize policies for `secure-sql-mcp`.

It is designed to be:
- practical for humans
- structured enough for agents to generate policy variants

## Policy model at a glance

The default bundle composes two policy modules:

- `default_constraints`: baseline guardrails (statement count, operation class, query shape)
- `acl`: table/column access rules

Final decision is an AND:

- allow only when `default_constraints.allow` and `acl.allow` are both true

See:
- `policy/rego/default_constraints.rego`
- `policy/rego/acl.rego`
- `policy/rego/authz.rego`

## Runtime architecture

The server now has split execution paths:

- read statements execute through `execute_read_query(...)`
- write statements execute through `execute_write_query(...)`

Write execution is still deny-by-default and requires *both* runtime gates and policy:

- runtime gates (`WRITE_MODE_ENABLED`, `ALLOW_INSERT/UPDATE/DELETE`)
- policy allow in OPA (`default_constraints`, `acl`, `write_constraints`)

## Input facts available to policy

OPA receives `{"input": ...}` payloads from the server.

### For `query` tool

```json
{
  "tool": { "name": "query" },
  "query": {
    "raw_sql": "SELECT id FROM customers",
    "statement_count": 1,
    "statement_type": "select",
    "is_write_statement": false,
    "has_disallowed_operation": false,
    "is_read_statement": true,
    "referenced_tables": ["customers"],
    "referenced_columns": { "customers": ["id"] },
    "star_tables": [],
    "has_unqualified_multi_table_columns": false,
    "target_table": "",
    "insert_columns": [],
    "updated_columns": [],
    "where_present": false,
    "where_tautological": false,
    "returning_present": false,
    "returning_columns": [],
    "has_select_source": false,
    "source_tables": []
  },
  "config": {
    "write_mode_enabled": false,
    "allow_insert": false,
    "allow_update": false,
    "allow_delete": false,
    "require_where_for_update": true,
    "require_where_for_delete": true,
    "allow_returning": false
  },
  "acl": {
    "tables": {
      "customers": { "columns": ["id", "email"] },
      "orders": { "columns": ["*"] }
    }
  }
}
```

### For `list_tables` tool

```json
{
  "tool": { "name": "list_tables" },
  "acl": { "tables": { "...": { "columns": ["..."] } } }
}
```

### For `describe_table` tool

```json
{
  "tool": { "name": "describe_table" },
  "table": "customers",
  "acl": { "tables": { "...": { "columns": ["..."] } } }
}
```

## ACL data sources

ACL data can come from either:

1. `OPA_ACL_DATA_FILE` (preferred when set), JSON structure at `secure_sql.acl.tables`
2. transformed legacy `ALLOWED_POLICY_FILE`

Use `OPA_ACL_DATA_FILE` when you want native OPA-oriented config.

## Rego patterns you can reuse

Use these as templates when asking an agent to generate a policy.

### 1) Keep strict read-only baseline (default behavior)

```rego
package secure_sql.default_constraints

default allow := false

deny_reasons["multiple_statements"] if input.query.statement_count != 1
deny_reasons["disallowed_operation"] if input.query.has_disallowed_operation
deny_reasons["not_read_query"] if not input.query.is_read_statement

allow if count(deny_reasons) == 0
```

### 2) Relax baseline to allow inserts only (policy example)

```rego
package secure_sql.default_constraints

default allow := false

is_insert if input.query.statement_type == "insert"

deny_reasons["multiple_statements"] if input.query.statement_count != 1
deny_reasons["not_allowed_statement_type"] if {
  not input.query.is_read_statement
  not is_insert
}

allow if count(deny_reasons) == 0
```

### 3) Allow updates only to specific tables/columns (policy example)

```rego
package secure_sql.default_constraints

default allow := false

allowed_update_columns := {
  "customers": {"email"},
  "profiles": {"display_name", "timezone"},
}

is_update if input.query.statement_type == "update"

deny_reasons["multiple_statements"] if input.query.statement_count != 1

deny_reasons["update_column_not_allowed"] if {
  is_update
  table := object.keys(input.query.referenced_columns)[_]
  col := input.query.referenced_columns[table][_]
  not allowed_update_columns[table][col]
}

deny_reasons["not_allowed_statement_type"] if {
  not input.query.is_read_statement
  not is_update
}

allow if count(deny_reasons) == 0
```

### 4) Time-window or environment gating

If you add `context` facts (for example `input.context.environment`), you can gate
by deployment environment or maintenance window.

```rego
deny_reasons["writes_only_allowed_in_maintenance"] if {
  input.query.statement_type == "update"
  input.context.environment != "maintenance"
}
```

## Agent-friendly prompt template

Use this prompt with an agent to generate policy:

```text
Generate Rego policies for secure-sql-mcp.

Constraints:
- Keep authz composition as default_constraints AND acl.
- Tool names are query, list_tables, describe_table.
- Use deny_reasons for explainability.
- Maintain deny-by-default.

Desired behavior:
- [Describe exactly which statements are allowed]
- [Describe table/column restrictions]
- [Describe any time/env/principal restrictions]

Output:
1) default_constraints.rego
2) acl.rego (if ACL behavior changes)
3) authz.rego (if composition changes)
4) short test matrix with allowed/blocked examples
```

## Testing checklist for policy changes

When you relax policy behavior, test all of:

- single-statement enforcement
- disallowed table/column access
- wildcard behavior (`SELECT *`)
- joins/subqueries/unions
- error hygiene (no sensitive leaks)
- OPA fail-closed behavior

Run:

```bash
python -m pytest -q
```


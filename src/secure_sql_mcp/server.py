"""MCP server entrypoint for secure read-only SQL access."""

from __future__ import annotations

import argparse
import json
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from mcp.server.fastmcp import FastMCP

from secure_sql_mcp.config import Settings, load_settings
from secure_sql_mcp.database import AsyncDatabase
from secure_sql_mcp.opa_policy import OpaPolicyEngine
from secure_sql_mcp.query_validator import QueryValidator

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class AppState:
    settings: Settings
    db: AsyncDatabase
    validator: QueryValidator
    policy_engine: OpaPolicyEngine | None


STATE: AppState | None = None


@asynccontextmanager
async def lifespan(_: FastMCP) -> AsyncIterator[None]:
    """Initialize and dispose shared application state."""
    global STATE
    settings = load_settings()
    logging.basicConfig(level=settings.log_level)
    db = AsyncDatabase(settings)
    policy_engine = OpaPolicyEngine(settings) if settings.opa_url else None
    validator = QueryValidator(settings, policy_engine=policy_engine)
    await db.connect()
    STATE = AppState(settings=settings, db=db, validator=validator, policy_engine=policy_engine)
    LOGGER.info("secure-sql-mcp started")
    try:
        yield
    finally:
        await db.dispose()
        STATE = None
        LOGGER.info("secure-sql-mcp stopped")


mcp = FastMCP("secure-sql-mcp", lifespan=lifespan)


def _state() -> AppState:
    if STATE is None:
        raise RuntimeError("Application state is not initialized.")
    return STATE


@mcp.tool()
async def query(sql: str) -> str:
    """Run a SQL query (read-only by default; writes only when explicitly enabled)."""
    app = _state()
    validation = app.validator.validate_query(sql)
    if not validation.ok:
        return validation.error or "Query blocked by policy."

    statement_type = (validation.statement_type or "").lower()
    try:
        if statement_type in {"insert", "update", "delete"}:
            write_result = await app.db.execute_write_query(validation.normalized_sql or sql)
            payload = {
                "status": "ok",
                "operation": statement_type,
                "affected_rows": write_result.affected_rows,
                "returning_columns": write_result.returning_columns,
                "returning": write_result.returning_rows,
                "referenced_tables": validation.referenced_tables or [],
                "referenced_columns": validation.referenced_columns or {},
            }
            return json.dumps(payload, default=str, indent=2)

        result = await app.db.execute_read_query(validation.normalized_sql or sql)
    except TimeoutError:
        return (
            f"Query exceeded the {app.settings.query_timeout}-second timeout. "
            "Try simplifying the query or adding filters."
        )
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("Failed to execute query: %s", type(exc).__name__)
        return (
            "Query execution failed with a database error. "
            "Use list_tables/describe_table to validate allowed targets, "
            "or escalate to a human operator."
        )

    payload = {
        "status": "ok",
        "row_count": len(result.rows),
        "truncated": result.truncated,
        "columns": result.columns,
        "rows": result.rows,
        "referenced_tables": validation.referenced_tables or [],
        "referenced_columns": validation.referenced_columns or {},
    }
    return json.dumps(payload, default=str, indent=2)


@mcp.tool()
async def list_tables() -> str:
    """List tables the agent is allowed to query, validating existence when possible."""
    app = _state()
    if app.policy_engine is not None:
        decision = await app.policy_engine.evaluate(
            _build_tool_policy_input("list_tables", app.settings)
        )
        if not decision.allow:
            return decision.message or "Operation blocked by policy."

    policy = app.settings.effective_acl_policy
    policy_tables = sorted(policy)
    policy_set = {t.lower() for t in policy}
    discovered: list[str] = []
    discovery_error: str | None = None
    try:
        discovered = await app.db.list_tables()
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Failed to list tables for metadata validation: %s", exc)
        discovery_error = "Database metadata access failed."

    discovered_set = {table.lower() for table in discovered}
    if discovered:
        existing_allowed = sorted(table for table in policy_tables if table in discovered_set)
        missing_allowed = sorted(table for table in policy_tables if table not in discovered_set)
        validation_status = "validated"
    else:
        existing_allowed = policy_tables
        missing_allowed = []
        validation_status = "validation_unavailable"

    allowed_columns = {
        table: ("*" if "*" in columns else sorted(columns))
        for table, columns in sorted(policy.items())
    }

    discovered_tables_filtered = sorted(t for t in discovered if t.lower() in policy_set)

    payload = {
        "status": "ok",
        "allowed_tables": existing_allowed,
        "table_count": len(existing_allowed),
        "validation_status": validation_status,
        "unverified_allowlist_tables": missing_allowed,
        "metadata_access_error": discovery_error,
        "allowed_columns_by_table": allowed_columns,
        "discovered_tables": discovered_tables_filtered,
    }
    return json.dumps(payload, indent=2)


@mcp.tool()
async def describe_table(table: str) -> str:
    """Describe columns for an allowed table."""
    app = _state()
    if app.policy_engine is not None:
        payload = _build_tool_policy_input("describe_table", app.settings)
        payload["table"] = table.lower()
        decision = await app.policy_engine.evaluate(payload)
        if not decision.allow:
            return decision.message or "Operation blocked by policy."

    policy_columns = app.validator.lookup_table_policy(table)
    if policy_columns is None:
        available_tables = ", ".join(sorted(app.settings.effective_acl_policy))
        return (
            f"Access to table '{table}' is restricted by the server access policy. "
            f"Allowed tables are: {available_tables}. "
            "Please use list_tables to inspect available tables or escalate to a human operator."
        )

    acl_error = app.validator.table_access_error(table)
    if acl_error:
        return acl_error

    try:
        columns = await app.db.describe_table(table)
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("Failed to describe table: %s", type(exc).__name__)
        return (
            "Unable to describe table due to a database error. "
            "Use list_tables to inspect available tables or escalate to a human operator."
        )

    if not columns:
        return f"Table '{table}' was not found or has no visible columns."

    payload = {
        "status": "ok",
        "table": table.lower(),
        "policy_allowed_columns": "*" if "*" in policy_columns else sorted(policy_columns),
        "columns": columns,
    }
    return json.dumps(payload, default=str, indent=2)


def main() -> None:
    """Run the MCP server with stdio transport."""
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument(
        "--write-mode",
        action="store_true",
        help="Enable write-mode execution path (disabled by default).",
    )
    parser.add_argument(
        "--allow-insert",
        action="store_true",
        help="Allow INSERT statements when write mode is enabled.",
    )
    parser.add_argument(
        "--allow-update",
        action="store_true",
        help="Allow UPDATE statements when write mode is enabled.",
    )
    parser.add_argument(
        "--allow-delete",
        action="store_true",
        help="Allow DELETE statements when write mode is enabled.",
    )
    args, _ = parser.parse_known_args()

    if args.write_mode:
        os.environ["WRITE_MODE_ENABLED"] = "true"
    if args.allow_insert:
        os.environ["ALLOW_INSERT"] = "true"
    if args.allow_update:
        os.environ["ALLOW_UPDATE"] = "true"
    if args.allow_delete:
        os.environ["ALLOW_DELETE"] = "true"

    mcp.run(transport="stdio")


def _build_tool_policy_input(tool_name: str, settings: Settings) -> dict[str, Any]:
    acl_tables = {
        table: {"columns": sorted(columns)}
        for table, columns in sorted(settings.effective_acl_policy.items())
    }
    return {"tool": {"name": tool_name}, "acl": {"tables": acl_tables}}


if __name__ == "__main__":
    main()

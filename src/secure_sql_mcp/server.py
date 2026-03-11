"""MCP server entrypoint for secure read-only SQL access."""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from mcp.server.fastmcp import FastMCP

from secure_sql_mcp.config import Settings, load_settings
from secure_sql_mcp.database import AsyncDatabase
from secure_sql_mcp.query_validator import QueryValidator

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class AppState:
    settings: Settings
    db: AsyncDatabase
    validator: QueryValidator


STATE: AppState | None = None


@asynccontextmanager
async def lifespan(_: FastMCP) -> AsyncIterator[None]:
    """Initialize and dispose shared application state."""
    global STATE
    settings = load_settings()
    logging.basicConfig(level=settings.log_level)
    db = AsyncDatabase(settings)
    validator = QueryValidator(settings)
    await db.connect()
    STATE = AppState(settings=settings, db=db, validator=validator)
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
    """Run a read-only SQL query and return structured results."""
    app = _state()
    validation = app.validator.validate_query(sql)
    if not validation.ok:
        return validation.error or "Query blocked by policy."

    try:
        result = await app.db.execute_read_query(validation.normalized_sql or sql)
    except TimeoutError:
        return (
            f"Query exceeded the {app.settings.query_timeout}-second timeout. "
            "Try simplifying the query or adding filters."
        )
    except Exception:  # noqa: BLE001
        LOGGER.exception("Failed to execute query")
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
    policy = app.settings.allowed_policy
    policy_tables = sorted(policy)
    discovered: list[str] = []
    discovery_error: str | None = None
    try:
        discovered = await app.db.list_tables()
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Failed to list tables for metadata validation: %s", exc)
        discovery_error = str(exc)

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

    payload = {
        "status": "ok",
        "allowed_tables": existing_allowed,
        "table_count": len(existing_allowed),
        "validation_status": validation_status,
        "unverified_allowlist_tables": missing_allowed,
        "metadata_access_error": discovery_error,
        "allowed_columns_by_table": allowed_columns,
        "discovered_tables": sorted(discovered),
    }
    return json.dumps(payload, indent=2)


@mcp.tool()
async def describe_table(table: str) -> str:
    """Describe columns for an allowed table."""
    app = _state()
    policy_columns = app.validator._lookup_table_policy(table)
    if policy_columns is None:
        available_tables = ", ".join(sorted(app.settings.allowed_policy))
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
        LOGGER.exception("Failed to describe table")
        return f"Unable to describe table '{table}' due to a database error: {exc}"

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
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

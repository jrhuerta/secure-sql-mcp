"""Database access layer for secure read-only queries."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncConnection, create_async_engine

from secure_sql_mcp.config import Settings


@dataclass(slots=True)
class QueryExecutionResult:
    """Structured result for executed queries."""

    columns: list[str]
    rows: list[dict[str, Any]]
    truncated: bool


class AsyncDatabase:
    """Async SQLAlchemy wrapper with read-only execution safeguards."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._engine: AsyncEngine | None = None

    async def connect(self) -> None:
        """Initialize async SQLAlchemy engine."""
        self._engine = create_async_engine(self._settings.database_url, pool_pre_ping=True)

    async def dispose(self) -> None:
        """Dispose the engine and release pooled connections."""
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None

    async def execute_read_query(self, sql: str) -> QueryExecutionResult:
        """Execute a read-only SQL query with timeout and row capping."""
        if self._engine is None:
            raise RuntimeError("Database engine is not initialized.")

        limited_sql = self._wrap_with_limit(sql, self._settings.max_rows + 1)
        statement = text(limited_sql)

        async def _run() -> QueryExecutionResult:
            assert self._engine is not None
            async with self._engine.connect() as conn:
                await self._prepare_read_only_session(conn)
                result = await conn.execute(statement)
                rows = [dict(row._mapping) for row in result]
                columns = list(result.keys())
                truncated = len(rows) > self._settings.max_rows
                if truncated:
                    rows = rows[: self._settings.max_rows]
                return QueryExecutionResult(columns=columns, rows=rows, truncated=truncated)

        return await asyncio.wait_for(_run(), timeout=self._settings.query_timeout)

    async def list_tables(self) -> list[str]:
        """List all visible base tables from the connected database."""
        if self._engine is None:
            raise RuntimeError("Database engine is not initialized.")

        async with self._engine.connect() as conn:
            def _list(sync_conn: Any) -> list[str]:
                inspector = inspect(sync_conn)
                names = inspector.get_table_names()
                return sorted(names)

            return await conn.run_sync(_list)

    async def describe_table(self, table_name: str) -> list[dict[str, Any]]:
        """Return column metadata for a table."""
        if self._engine is None:
            raise RuntimeError("Database engine is not initialized.")

        schema, short_name = self._split_table_name(table_name)
        async with self._engine.connect() as conn:
            def _describe(sync_conn: Any) -> list[dict[str, Any]]:
                inspector = inspect(sync_conn)
                columns = inspector.get_columns(short_name, schema=schema)
                return [
                    {
                        "name": col.get("name"),
                        "type": str(col.get("type")),
                        "nullable": bool(col.get("nullable", True)),
                        "default": col.get("default"),
                    }
                    for col in columns
                ]

            return await conn.run_sync(_describe)

    async def _prepare_read_only_session(self, conn: AsyncConnection) -> None:
        """Apply DB-specific read-only and timeout settings."""
        if self._settings.database_url.startswith("postgresql"):
            timeout_ms = self._settings.query_timeout * 1000
            await conn.execute(text("BEGIN READ ONLY"))
            await conn.execute(text(f"SET LOCAL statement_timeout = {timeout_ms}"))
        elif self._settings.database_url.startswith("sqlite"):
            await conn.execute(text("PRAGMA query_only = ON"))

    @staticmethod
    def _wrap_with_limit(sql: str, limit: int) -> str:
        query = sql.strip().rstrip(";")
        return f"SELECT * FROM ({query}) AS secure_sql_mcp_subquery LIMIT {limit}"

    @staticmethod
    def _split_table_name(table_name: str) -> tuple[str | None, str]:
        parts = [p for p in table_name.split(".") if p]
        if len(parts) <= 1:
            return None, parts[0]
        return ".".join(parts[:-1]), parts[-1]

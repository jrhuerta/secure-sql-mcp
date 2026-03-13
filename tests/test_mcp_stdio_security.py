from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from tests.conftest import init_sqlite_db, write_policy


def _first_text(call_result: object) -> str:
    for item in getattr(call_result, "content", []):
        text = getattr(item, "text", None)
        if text is not None:
            return text
    return ""


def _server_params(tmp_path: Path, *, write_mode: bool = False) -> StdioServerParameters:
    db_path = tmp_path / "test.db"
    policy_path = tmp_path / "allowed_policy.txt"
    init_sqlite_db(db_path)
    write_policy(policy_path, "customers:id,email\norders:*\n")

    env = os.environ.copy()
    env.update(
        {
            "DATABASE_URL": f"sqlite+aiosqlite:///{db_path}",
            "ALLOWED_POLICY_FILE": str(policy_path),
            "MAX_ROWS": "100",
            "QUERY_TIMEOUT": "30",
            "LOG_LEVEL": "INFO",
        }
    )
    if write_mode:
        env.update(
            {
                "WRITE_MODE_ENABLED": "true",
                "ALLOW_INSERT": "true",
                "ALLOW_UPDATE": "true",
                "ALLOW_DELETE": "true",
            }
        )

    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "secure_sql_mcp.server"],
        env=env,
    )


def test_mcp_stdio_security_contract(tmp_path: Path) -> None:
    async def _run() -> None:
        async with stdio_client(_server_params(tmp_path)) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                assert init.serverInfo.name == "secure-sql-mcp"

                tools = await session.list_tools()
                tool_names = sorted(tool.name for tool in tools.tools)
                assert tool_names == ["describe_table", "list_tables", "query"]

                list_tables_result = await session.call_tool("list_tables", {})
                list_tables_payload = json.loads(_first_text(list_tables_result))
                assert list_tables_payload["status"] == "ok"
                assert list_tables_payload["allowed_tables"] == ["customers", "orders"]

                describe_result = await session.call_tool("describe_table", {"table": "customers"})
                describe_payload = json.loads(_first_text(describe_result))
                assert describe_payload["status"] == "ok"
                assert describe_payload["policy_allowed_columns"] == ["email", "id"]

                allowed_query_result = await session.call_tool(
                    "query",
                    {"sql": "SELECT id, email FROM customers"},
                )
                allowed_payload = json.loads(_first_text(allowed_query_result))
                assert allowed_payload["status"] == "ok"
                assert allowed_payload["row_count"] == 1

                blocked_query_result = await session.call_tool(
                    "query",
                    {"sql": "SELECT id, ssn FROM customers"},
                )
                blocked_message = _first_text(blocked_query_result)
                assert (
                    "Access to column(s) ssn on table 'customers' is restricted" in blocked_message
                )

    asyncio.run(_run())


def test_mcp_stdio_blocks_multi_statement_payload(tmp_path: Path) -> None:
    async def _run() -> None:
        async with stdio_client(_server_params(tmp_path)) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "query",
                    {"sql": "SELECT id FROM customers; DROP TABLE customers"},
                )
                message = _first_text(result)
                assert "Only a single SQL statement is allowed" in message

    asyncio.run(_run())


def test_mcp_stdio_blocks_insert_select_when_write_disabled(tmp_path: Path) -> None:
    async def _run() -> None:
        async with stdio_client(_server_params(tmp_path)) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "query",
                    {"sql": "INSERT INTO orders (id, total) SELECT id, id FROM orders"},
                )
                message = _first_text(result)
                assert "read-only access" in message
                assert "INSERT" in message

    asyncio.run(_run())


def test_mcp_stdio_write_mode_allows_insert(tmp_path: Path) -> None:
    async def _run() -> None:
        async with stdio_client(_server_params(tmp_path, write_mode=True)) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "query",
                    {"sql": "INSERT INTO customers (id, email) VALUES (2, 'b@example.com')"},
                )
                payload = json.loads(_first_text(result))
                assert payload["status"] == "ok"
                assert payload["operation"] == "insert"
                assert payload["affected_rows"] == 1

    asyncio.run(_run())


def test_mcp_stdio_write_mode_blocks_tautological_delete(tmp_path: Path) -> None:
    async def _run() -> None:
        async with stdio_client(_server_params(tmp_path, write_mode=True)) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "query", {"sql": "DELETE FROM customers WHERE 1 = 1"}
                )
                message = _first_text(result)
                assert "WHERE clause appears tautological" in message

    asyncio.run(_run())

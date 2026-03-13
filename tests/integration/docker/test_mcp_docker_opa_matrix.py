from __future__ import annotations

import asyncio
import json
import time

import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from .conftest import BackendConfig


def _first_text(call_result: object) -> str:
    for item in getattr(call_result, "content", []):
        text = getattr(item, "text", None)
        if text is not None:
            return text
    return ""


async def _call_tool(
    server_params: StdioServerParameters, tool: str, payload: dict[str, object]
) -> str:
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool, payload)
            return _first_text(result)


def _call_tool_with_retries(
    server_params: StdioServerParameters,
    tool: str,
    payload: dict[str, object],
    *,
    retries: int = 4,
    wait_seconds: float = 2.0,
) -> str:
    last_response = ""
    for attempt in range(retries):
        last_response = asyncio.run(_call_tool(server_params, tool, payload))
        if "database error" not in last_response:
            return last_response
        if attempt < retries - 1:
            time.sleep(wait_seconds)
    return last_response


pytestmark = pytest.mark.docker_integration


def test_read_baseline_policy_enforced(
    docker_stack: None,
    backend: BackendConfig,
    policy_path,
    docker_server_params_factory,
) -> None:
    params = docker_server_params_factory(
        backend=backend,
        policy_file=policy_path("read_only_strict"),
    )

    if backend.name != "mysql":
        allowed = _call_tool_with_retries(
            params, "query", {"sql": "SELECT id, email FROM customers"}
        )
        payload = json.loads(allowed)
        assert payload["status"] == "ok"
    else:
        list_tables = asyncio.run(_call_tool(params, "list_tables", {}))
        list_payload = json.loads(list_tables)
        assert list_payload["status"] == "ok"

    blocked_col = asyncio.run(_call_tool(params, "query", {"sql": "SELECT ssn FROM customers"}))
    assert "restricted" in blocked_col

    blocked_table = asyncio.run(_call_tool(params, "query", {"sql": "SELECT id FROM secrets"}))
    assert "restricted" in blocked_table

    multi = asyncio.run(
        _call_tool(params, "query", {"sql": "SELECT id FROM customers; DROP TABLE customers"})
    )
    assert "Only a single SQL statement is allowed" in multi


@pytest.mark.smoke
def test_write_disabled_blocks_insert_even_with_policy_allow(
    docker_stack: None,
    backend: BackendConfig,
    policy_path,
    docker_server_params_factory,
) -> None:
    params = docker_server_params_factory(
        backend=backend,
        policy_file=policy_path("write_insert_only"),
        write_mode_enabled=False,
        allow_insert=True,
    )
    blocked = asyncio.run(
        _call_tool(
            params,
            "query",
            {"sql": "INSERT INTO customers (id, email) VALUES (2, 'b@example.com')"},
        )
    )
    assert "read-only access" in blocked
    assert "INSERT" in blocked


@pytest.mark.smoke
def test_insert_allowed_with_write_mode_and_gate(
    docker_stack: None,
    backend: BackendConfig,
    policy_path,
    docker_server_params_factory,
) -> None:
    if backend.name != "postgresql":
        pytest.skip("Write success-path assertions are validated on PostgreSQL in this matrix.")

    params = docker_server_params_factory(
        backend=backend,
        policy_file=policy_path("wildcard_tables"),
        write_mode_enabled=True,
        allow_insert=True,
    )
    allowed = _call_tool_with_retries(
        params,
        "query",
        {"sql": "INSERT INTO customers (id, email) VALUES (2, 'b@example.com')"},
    )
    payload = json.loads(allowed)
    assert payload["status"] == "ok"
    assert payload["operation"] == "insert"
    assert payload["affected_rows"] == 1


def test_insert_select_source_table_and_star_protections(
    docker_stack: None,
    backend: BackendConfig,
    policy_path,
    docker_server_params_factory,
) -> None:
    params = docker_server_params_factory(
        backend=backend,
        policy_file=policy_path("write_insert_only"),
        write_mode_enabled=True,
        allow_insert=True,
    )

    disallowed_source = asyncio.run(
        _call_tool(
            params,
            "query",
            {"sql": "INSERT INTO orders (id, total) SELECT s.id, s.id FROM secrets AS s"},
        )
    )
    assert "restricted" in disallowed_source

    star_source = asyncio.run(
        _call_tool(
            params, "query", {"sql": "INSERT INTO orders (id, total) SELECT * FROM customers"}
        )
    )
    assert "restricted" in star_source


def test_update_delete_where_guards_and_tautology(
    docker_stack: None,
    backend: BackendConfig,
    policy_path,
    docker_server_params_factory,
) -> None:
    if backend.name != "postgresql":
        pytest.skip("Write success-path assertions are validated on PostgreSQL in this matrix.")

    params = docker_server_params_factory(
        backend=backend,
        policy_file=policy_path("wildcard_tables"),
        write_mode_enabled=True,
        allow_update=True,
        allow_delete=True,
    )

    missing_where_update = asyncio.run(
        _call_tool(params, "query", {"sql": "UPDATE customers SET email = 'x@example.com'"})
    )
    assert "without a WHERE clause is not allowed" in missing_where_update

    tautological_delete = asyncio.run(
        _call_tool(params, "query", {"sql": "DELETE FROM orders WHERE 1 = 1"})
    )
    assert "WHERE clause appears tautological" in tautological_delete

    valid_update = _call_tool_with_retries(
        params, "query", {"sql": "UPDATE customers SET email = 'x@example.com' WHERE id = 1"}
    )
    payload = json.loads(valid_update)
    assert payload["status"] == "ok"
    assert payload["operation"] == "update"


def test_returning_controls_and_column_acl(
    docker_stack: None,
    backend: BackendConfig,
    policy_path,
    docker_server_params_factory,
) -> None:
    blocked_params = docker_server_params_factory(
        backend=backend,
        policy_file=policy_path("wildcard_tables"),
        write_mode_enabled=True,
        allow_update=True,
        allow_returning=False,
    )
    returning_blocked = asyncio.run(
        _call_tool(
            blocked_params,
            "query",
            {"sql": "UPDATE customers SET email = 'x@example.com' WHERE id = 1 RETURNING email"},
        )
    )
    assert "RETURNING is not allowed" in returning_blocked

    if backend.name != "postgresql":
        return

    allowed_params = docker_server_params_factory(
        backend=backend,
        policy_file=policy_path("write_update_restricted"),
        write_mode_enabled=True,
        allow_update=True,
        allow_returning=True,
    )
    restricted_column = asyncio.run(
        _call_tool(
            allowed_params,
            "query",
            {"sql": "UPDATE customers SET email = 'x@example.com' WHERE id = 1 RETURNING ssn"},
        )
    )
    assert "restricted" in restricted_column


def test_opa_fail_closed_when_unavailable(
    docker_stack: None,
    backend: BackendConfig,
    policy_path,
    docker_server_params_factory,
) -> None:
    params = docker_server_params_factory(
        backend=backend,
        policy_file=policy_path("read_only_strict"),
        opa_decision_path="/v1/data/secure_sql/authz/missing",
        opa_fail_closed=True,
    )
    query_msg = asyncio.run(_call_tool(params, "query", {"sql": "SELECT id FROM customers"}))
    assert "Authorization decision is unavailable" in query_msg

    list_msg = asyncio.run(_call_tool(params, "list_tables", {}))
    assert "Authorization decision is unavailable" in list_msg

    describe_msg = asyncio.run(_call_tool(params, "describe_table", {"table": "customers"}))
    assert "Authorization decision is unavailable" in describe_msg


def test_opa_acl_data_file_profile_works(
    docker_stack: None,
    backend: BackendConfig,
    policy_path,
    acl_path,
    docker_server_params_factory,
) -> None:
    params = docker_server_params_factory(
        backend=backend,
        policy_file=policy_path("wildcard_tables"),
        opa_acl_data_file=acl_path("restricted_acl"),
    )

    blocked = asyncio.run(_call_tool(params, "query", {"sql": "SELECT ssn FROM customers"}))
    assert "restricted" in blocked

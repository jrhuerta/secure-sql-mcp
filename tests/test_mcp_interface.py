from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path

import pytest
from pydantic import ValidationError

from secure_sql_mcp import server as mcp_server
from secure_sql_mcp.config import Settings
from secure_sql_mcp.database import AsyncDatabase
from secure_sql_mcp.query_validator import QueryValidator
from secure_sql_mcp.server import AppState


def _init_sqlite_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE customers (
              id INTEGER PRIMARY KEY,
              email TEXT NOT NULL,
              ssn TEXT
            );
            CREATE TABLE orders (
              id INTEGER PRIMARY KEY,
              total NUMERIC
            );
            CREATE TABLE secrets (
              id INTEGER PRIMARY KEY,
              token TEXT
            );
            INSERT INTO customers (id, email, ssn) VALUES (1, 'a@example.com', '111-22-3333');
            INSERT INTO orders (id, total) VALUES (10, 19.99);
            """
        )
        conn.commit()
    finally:
        conn.close()


def _write_policy(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


@pytest.fixture()
def app_state(tmp_path: Path):
    db_path = tmp_path / "test.db"
    _init_sqlite_db(db_path)

    policy_path = tmp_path / "allowed_policy.txt"
    _write_policy(
        policy_path,
        """
        customers:id,email
        orders:*
        """,
    )

    settings = Settings.model_validate(
        {
            "DATABASE_URL": f"sqlite+aiosqlite:///{db_path}",
            "ALLOWED_POLICY_FILE": str(policy_path),
            "MAX_ROWS": 100,
            "QUERY_TIMEOUT": 30,
            "LOG_LEVEL": "INFO",
        }
    )
    db = AsyncDatabase(settings)
    asyncio.run(db.connect())
    state = AppState(settings=settings, db=db, validator=QueryValidator(settings))
    mcp_server.STATE = state

    try:
        yield state
    finally:
        asyncio.run(db.dispose())
        mcp_server.STATE = None


@pytest.fixture()
def limited_app_state(tmp_path: Path):
    db_path = tmp_path / "limited.db"
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            CREATE TABLE orders (
              id INTEGER PRIMARY KEY,
              total NUMERIC
            );
            INSERT INTO orders (id, total) VALUES (10, 19.99);
            INSERT INTO orders (id, total) VALUES (11, 24.99);
            INSERT INTO orders (id, total) VALUES (12, 29.99);
            """
        )
        conn.commit()
    finally:
        conn.close()

    policy_path = tmp_path / "allowed_policy.txt"
    _write_policy(
        policy_path,
        """
        orders:*
        """,
    )

    settings = Settings.model_validate(
        {
            "DATABASE_URL": f"sqlite+aiosqlite:///{db_path}",
            "ALLOWED_POLICY_FILE": str(policy_path),
            "MAX_ROWS": 1,
            "QUERY_TIMEOUT": 2,
            "LOG_LEVEL": "INFO",
        }
    )
    db = AsyncDatabase(settings)
    asyncio.run(db.connect())
    state = AppState(settings=settings, db=db, validator=QueryValidator(settings))
    mcp_server.STATE = state

    try:
        yield state
    finally:
        asyncio.run(db.dispose())
        mcp_server.STATE = None


def test_policy_parsing_valid(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.txt"
    _write_policy(
        policy_path,
        """
        customers:id,email
        orders:*
        """,
    )
    settings = Settings.model_validate(
        {"DATABASE_URL": "sqlite+aiosqlite:///./tmp.db", "ALLOWED_POLICY_FILE": str(policy_path)}
    )
    assert settings.allowed_policy["customers"] == {"id", "email"}
    assert settings.allowed_policy["orders"] == {"*"}


def test_policy_parsing_missing_file_raises() -> None:
    with pytest.raises(ValidationError):
        Settings.model_validate(
            {
                "DATABASE_URL": "sqlite+aiosqlite:///./tmp.db",
                "ALLOWED_POLICY_FILE": "/tmp/does-not-exist-policy.txt",
            }
        )


def test_query_allows_read_for_allowed_columns(app_state: AppState) -> None:
    response = asyncio.run(mcp_server.query("SELECT id, email FROM customers"))
    payload = json.loads(response)
    assert payload["status"] == "ok"
    assert payload["row_count"] == 1


def test_query_blocks_mutation_operation(app_state: AppState) -> None:
    response = asyncio.run(
        mcp_server.query("UPDATE customers SET email = 'x@example.com' WHERE id = 1")
    )
    assert "read-only access" in response
    assert "escalate to a human operator" in response


@pytest.mark.parametrize(
    ("sql", "operation"),
    [
        ("INSERT INTO customers (id, email) VALUES (2, 'b@example.com')", "INSERT"),
        ("DELETE FROM customers WHERE id = 1", "DELETE"),
        ("DROP TABLE customers", "DROP"),
        ("ALTER TABLE customers ADD COLUMN phone TEXT", "ALTER"),
        ("CREATE TABLE audit_log (id INTEGER)", "CREATE"),
        ("TRUNCATE TABLE orders", "TRUNCATETABLE"),
        ("GRANT SELECT ON customers TO analyst", "GRANT"),
        ("REVOKE SELECT ON customers FROM analyst", "REVOKE"),
        (
            "MERGE INTO customers AS c USING orders AS o ON c.id = o.id "
            "WHEN MATCHED THEN UPDATE SET email = 'x@example.com'",
            "MERGE",
        ),
    ],
)
def test_query_blocks_mutation_operations(app_state: AppState, sql: str, operation: str) -> None:
    response = asyncio.run(mcp_server.query(sql))
    assert "read-only access" in response
    assert operation in response


def test_query_blocks_multi_statement_payload(app_state: AppState) -> None:
    response = asyncio.run(mcp_server.query("SELECT id FROM customers; DROP TABLE customers"))
    assert "Only a single SQL statement is allowed" in response


def test_query_blocks_join_to_disallowed_table(app_state: AppState) -> None:
    response = asyncio.run(
        mcp_server.query("SELECT c.id FROM customers AS c JOIN secrets AS s ON s.id = c.id")
    )
    assert "Access to table 'secrets' is restricted" in response


def test_query_blocks_union_branch_with_disallowed_table(app_state: AppState) -> None:
    response = asyncio.run(
        mcp_server.query("SELECT id FROM customers UNION SELECT id FROM secrets")
    )
    assert "Access to table 'secrets' is restricted" in response


def test_query_blocks_subquery_from_disallowed_table(app_state: AppState) -> None:
    response = asyncio.run(
        mcp_server.query("SELECT id FROM customers WHERE id IN (SELECT id FROM secrets)")
    )
    assert "Access to table 'secrets' is restricted" in response


def test_describe_table_blocks_disallowed_table(app_state: AppState) -> None:
    response = asyncio.run(mcp_server.describe_table("secrets"))
    assert "Access to table 'secrets' is restricted" in response
    assert "Allowed tables are: customers, orders" in response


def test_query_blocks_table_not_in_policy(app_state: AppState) -> None:
    response = asyncio.run(mcp_server.query("SELECT id FROM secrets"))
    assert "restricted by the server access policy" in response
    assert "list_tables/describe_table" in response


def test_query_blocks_disallowed_column(app_state: AppState) -> None:
    response = asyncio.run(mcp_server.query("SELECT id, ssn FROM customers"))
    assert "restricted" in response
    assert "Allowed columns: email, id" in response


def test_query_blocks_select_star_without_wildcard(app_state: AppState) -> None:
    response = asyncio.run(mcp_server.query("SELECT * FROM customers"))
    assert "SELECT * is not allowed for table 'customers'" in response


def test_query_allows_select_star_with_wildcard(app_state: AppState) -> None:
    response = asyncio.run(mcp_server.query("SELECT * FROM orders"))
    payload = json.loads(response)
    assert payload["status"] == "ok"
    assert payload["row_count"] == 1


def test_list_tables_shows_allowed_columns_by_table(app_state: AppState) -> None:
    response = asyncio.run(mcp_server.list_tables())
    payload = json.loads(response)
    assert payload["status"] == "ok"
    assert "customers" in payload["allowed_tables"]
    assert payload["allowed_columns_by_table"]["customers"] == ["email", "id"]
    assert payload["allowed_columns_by_table"]["orders"] == "*"


def test_describe_table_includes_policy_columns(app_state: AppState) -> None:
    response = asyncio.run(mcp_server.describe_table("customers"))
    payload = json.loads(response)
    assert payload["status"] == "ok"
    assert payload["policy_allowed_columns"] == ["email", "id"]
    assert any(column["name"] == "email" for column in payload["columns"])


def test_list_tables_metadata_unavailable_still_returns_policy(
    app_state: AppState, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _raise_metadata_error() -> list[str]:
        raise RuntimeError("metadata access denied")

    monkeypatch.setattr(app_state.db, "list_tables", _raise_metadata_error)

    response = asyncio.run(mcp_server.list_tables())
    payload = json.loads(response)
    assert payload["validation_status"] == "validation_unavailable"
    assert payload["metadata_access_error"] == "metadata access denied"
    assert payload["allowed_columns_by_table"]["customers"] == ["email", "id"]


def test_query_respects_row_limit_and_marks_truncated(limited_app_state: AppState) -> None:
    response = asyncio.run(mcp_server.query("SELECT * FROM orders ORDER BY id"))
    payload = json.loads(response)
    assert payload["status"] == "ok"
    assert payload["truncated"] is True
    assert payload["row_count"] == 1
    assert len(payload["rows"]) == 1


def test_query_timeout_returns_actionable_message(
    app_state: AppState, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _raise_timeout(_: str) -> object:
        raise TimeoutError()

    monkeypatch.setattr(app_state.db, "execute_read_query", _raise_timeout)
    response = asyncio.run(mcp_server.query("SELECT id FROM customers"))
    assert f"Query exceeded the {app_state.settings.query_timeout}-second timeout" in response
    assert "Try simplifying the query or adding filters" in response


def test_query_db_error_message_does_not_leak_sensitive_details(
    app_state: AppState, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _raise_db_error(_: str) -> object:
        raise RuntimeError("password=supersecret host=internal-db")

    monkeypatch.setattr(app_state.db, "execute_read_query", _raise_db_error)
    response = asyncio.run(mcp_server.query("SELECT id FROM customers"))
    assert "Query execution failed with a database error" in response
    assert "list_tables" in response
    assert "describe_table" in response
    assert "supersecret" not in response
    assert "internal-db" not in response

from __future__ import annotations

from pathlib import Path

import sqlglot

from secure_sql_mcp.config import Settings
from secure_sql_mcp.query_validator import QueryValidator
from tests.conftest import write_policy


def _validator(tmp_path: Path, **overrides: object) -> QueryValidator:
    policy_path = tmp_path / "allowed_policy.txt"
    write_policy(
        policy_path,
        """
        customers:id,email
        orders:*
        """,
    )
    payload: dict[str, object] = {
        "DATABASE_URL": "sqlite+aiosqlite:///./write-facts.db",
        "ALLOWED_POLICY_FILE": str(policy_path),
    }
    payload.update(overrides)
    settings = Settings.model_validate(payload)
    return QueryValidator(settings)


def test_extract_insert_write_facts(tmp_path: Path) -> None:
    validator = _validator(tmp_path, WRITE_MODE_ENABLED=True, ALLOW_INSERT=True)
    statement = sqlglot.parse_one(
        "INSERT INTO customers (id, email) VALUES (2, 'b@example.com')",
        read=validator._dialect,
    )
    facts = validator._extract_write_facts(statement)
    assert facts is not None
    assert facts.statement_type == "insert"
    assert facts.target_table == "customers"
    assert facts.insert_columns == ["email", "id"]
    assert facts.source_tables == []


def test_extract_update_write_facts_with_tautological_where(tmp_path: Path) -> None:
    validator = _validator(tmp_path, WRITE_MODE_ENABLED=True, ALLOW_UPDATE=True)
    statement = sqlglot.parse_one(
        "UPDATE customers SET email = 'x@example.com' WHERE 1 = 1",
        read=validator._dialect,
    )
    facts = validator._extract_write_facts(statement)
    assert facts is not None
    assert facts.statement_type == "update"
    assert facts.where_present is True
    assert facts.where_tautological is True
    assert facts.updated_columns == ["email"]


def test_extract_delete_write_facts(tmp_path: Path) -> None:
    validator = _validator(tmp_path, WRITE_MODE_ENABLED=True, ALLOW_DELETE=True)
    statement = sqlglot.parse_one(
        "DELETE FROM customers WHERE id = 1",
        read=validator._dialect,
    )
    facts = validator._extract_write_facts(statement)
    assert facts is not None
    assert facts.statement_type == "delete"
    assert facts.where_present is True
    assert facts.where_tautological is False


def test_extract_returning_columns(tmp_path: Path) -> None:
    validator = _validator(
        tmp_path,
        WRITE_MODE_ENABLED=True,
        ALLOW_UPDATE=True,
        ALLOW_RETURNING=True,
    )
    statement = sqlglot.parse_one(
        "UPDATE customers SET email = 'x@example.com' WHERE id = 1 RETURNING email",
        read=validator._dialect,
    )
    facts = validator._extract_write_facts(statement)
    assert facts is not None
    assert facts.returning_present is True
    assert facts.returning_columns == ["email"]


def test_extract_insert_select_source_tables(tmp_path: Path) -> None:
    validator = _validator(tmp_path, WRITE_MODE_ENABLED=True, ALLOW_INSERT=True)
    statement = sqlglot.parse_one(
        "INSERT INTO orders (id, total) SELECT id, total FROM orders",
        read=validator._dialect,
    )
    facts = validator._extract_write_facts(statement)
    assert facts is not None
    assert facts.has_select_source is True
    assert facts.source_tables == ["orders"]


def test_write_mode_disabled_blocks_writes(tmp_path: Path) -> None:
    validator = _validator(tmp_path)
    result = validator.validate_query(
        "INSERT INTO customers (id, email) VALUES (2, 'b@example.com')"
    )
    assert not result.ok
    assert "configured for read-only access" in (result.error or "")


def test_allow_insert_flag_controls_insert(tmp_path: Path) -> None:
    validator = _validator(tmp_path, WRITE_MODE_ENABLED=True, ALLOW_INSERT=False)
    result = validator.validate_query(
        "INSERT INTO customers (id, email) VALUES (2, 'b@example.com')"
    )
    assert not result.ok
    assert "INSERT operations are disabled by server configuration" in (result.error or "")


def test_enable_insert_does_not_enable_update(tmp_path: Path) -> None:
    validator = _validator(tmp_path, WRITE_MODE_ENABLED=True, ALLOW_INSERT=True, ALLOW_UPDATE=False)
    result = validator.validate_query("UPDATE customers SET email = 'x@example.com' WHERE id = 1")
    assert not result.ok
    assert "UPDATE operations are disabled by server configuration" in (result.error or "")


def test_ddl_still_blocked_when_write_mode_enabled(tmp_path: Path) -> None:
    validator = _validator(
        tmp_path,
        WRITE_MODE_ENABLED=True,
        ALLOW_INSERT=True,
        ALLOW_UPDATE=True,
        ALLOW_DELETE=True,
    )
    result = validator.validate_query("DROP TABLE customers")
    assert not result.ok
    assert "read-only access" in (result.error or "")
    assert "DROP" in (result.error or "")

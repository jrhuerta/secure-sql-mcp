from __future__ import annotations

from pathlib import Path

import pytest

from secure_sql_mcp.config import Settings
from secure_sql_mcp.query_validator import QueryValidator


def _write_policy(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


@pytest.fixture()
def validator(tmp_path: Path) -> QueryValidator:
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
            "DATABASE_URL": "sqlite+aiosqlite:///./validator.db",
            "ALLOWED_POLICY_FILE": str(policy_path),
        }
    )
    return QueryValidator(settings)


def test_validator_blocks_multi_statement_sql(validator: QueryValidator) -> None:
    result = validator.validate_query("SELECT id FROM customers; DROP TABLE customers")
    assert not result.ok
    assert "Only a single SQL statement is allowed" in (result.error or "")


def test_validator_blocks_parse_error(validator: QueryValidator) -> None:
    result = validator.validate_query("SELECT FROM")
    assert not result.ok
    assert "Could not parse the SQL query" in (result.error or "")


@pytest.mark.parametrize(
    ("sql", "operation"),
    [
        ("INSERT INTO customers (id, email) VALUES (2, 'b@example.com')", "INSERT"),
        ("DELETE FROM customers WHERE id = 1", "DELETE"),
        ("DROP TABLE customers", "DROP"),
        ("ALTER TABLE customers ADD COLUMN phone TEXT", "ALTER"),
        ("CREATE TABLE audit_log (id INTEGER)", "CREATE"),
        ("GRANT SELECT ON customers TO analyst", "GRANT"),
    ],
)
def test_validator_blocks_mutating_and_privileged_operations(
    validator: QueryValidator, sql: str, operation: str
) -> None:
    result = validator.validate_query(sql)
    assert not result.ok
    assert "read-only access" in (result.error or "")
    assert operation in (result.error or "")


def test_validator_blocks_union_with_disallowed_table(validator: QueryValidator) -> None:
    result = validator.validate_query("SELECT id FROM customers UNION SELECT id FROM secrets")
    assert not result.ok
    assert "Access to table 'secrets' is restricted" in (result.error or "")


def test_validator_blocks_subquery_with_disallowed_table(validator: QueryValidator) -> None:
    result = validator.validate_query(
        "SELECT id FROM customers WHERE id IN (SELECT id FROM secrets)"
    )
    assert not result.ok
    assert "Access to table 'secrets' is restricted" in (result.error or "")


def test_validator_blocks_unqualified_columns_in_multi_table_query(
    validator: QueryValidator,
) -> None:
    result = validator.validate_query(
        "SELECT id FROM customers AS c JOIN orders AS o ON c.id = o.id"
    )
    assert not result.ok
    assert "Unqualified column references are not allowed" in (result.error or "")


def test_validator_allows_qualified_columns_with_aliases(validator: QueryValidator) -> None:
    result = validator.validate_query(
        "SELECT c.id, c.email, o.total FROM customers AS c JOIN orders AS o ON c.id = o.id"
    )
    assert result.ok
    assert result.referenced_tables == ["customers", "orders"]
    assert result.referenced_columns == {
        "customers": ["email", "id"],
        "orders": ["id", "total"],
    }


def test_validator_blocks_select_star_for_non_wildcard_table(validator: QueryValidator) -> None:
    result = validator.validate_query("SELECT c.* FROM customers AS c")
    assert not result.ok
    assert "SELECT * is not allowed for table 'customers'" in (result.error or "")


def test_validator_allows_select_star_for_wildcard_table(validator: QueryValidator) -> None:
    result = validator.validate_query("SELECT o.* FROM orders AS o")
    assert result.ok

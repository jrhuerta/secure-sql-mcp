from __future__ import annotations

from pathlib import Path

import pytest

from secure_sql_mcp.config import Settings
from secure_sql_mcp.query_validator import QueryValidator
from tests.conftest import write_policy


@pytest.fixture()
def validator(tmp_path: Path) -> QueryValidator:
    policy_path = tmp_path / "allowed_policy.txt"
    write_policy(
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


def test_validator_blocks_explain(validator: QueryValidator) -> None:
    """EXPLAIN/EXPLAIN ANALYZE can execute queries in PostgreSQL; must be blocked."""
    result = validator.validate_query("EXPLAIN SELECT id FROM customers")
    assert not result.ok
    assert "read-only access" in (result.error or "")


def test_validator_blocks_explain_analyze(validator: QueryValidator) -> None:
    result = validator.validate_query("EXPLAIN ANALYZE SELECT id FROM customers")
    assert not result.ok
    assert "read-only access" in (result.error or "")


def test_validator_blocks_information_schema(validator: QueryValidator) -> None:
    """information_schema is not in policy; must be blocked."""
    result = validator.validate_query("SELECT * FROM information_schema.tables")
    assert not result.ok
    assert "restricted" in (result.error or "")


def test_validator_blocks_sqlite_master(validator: QueryValidator) -> None:
    """sqlite_master is not in policy; must be blocked."""
    result = validator.validate_query("SELECT * FROM sqlite_master")
    assert not result.ok
    assert "restricted" in (result.error or "")


def test_validator_blocks_cte_with_disallowed_table(validator: QueryValidator) -> None:
    """CTE referencing disallowed table must be blocked."""
    result = validator.validate_query("WITH cte AS (SELECT id FROM secrets) SELECT * FROM cte")
    assert not result.ok
    assert "restricted" in (result.error or "")


def test_validator_blocks_intersect_with_disallowed_table(validator: QueryValidator) -> None:
    result = validator.validate_query("SELECT id FROM customers INTERSECT SELECT id FROM secrets")
    assert not result.ok
    assert "Access to table 'secrets' is restricted" in (result.error or "")


def test_validator_blocks_except_with_disallowed_table(validator: QueryValidator) -> None:
    result = validator.validate_query("SELECT id FROM customers EXCEPT SELECT id FROM secrets")
    assert not result.ok
    assert "Access to table 'secrets' is restricted" in (result.error or "")


def test_validator_uses_mysql_dialect_for_mysql_url(tmp_path: Path) -> None:
    policy_path = tmp_path / "allowed_policy.txt"
    write_policy(
        policy_path,
        """
        customers:id,email
        """,
    )
    settings = Settings.model_validate(
        {
            "DATABASE_URL": "mysql://user:pass@localhost:3306/appdb",
            "ALLOWED_POLICY_FILE": str(policy_path),
        }
    )
    validator = QueryValidator(settings)

    assert validator._dialect == "mysql"


def test_validator_allows_insert_when_write_mode_enabled(tmp_path: Path) -> None:
    policy_path = tmp_path / "allowed_policy.txt"
    write_policy(policy_path, "customers:id,email\n")
    settings = Settings.model_validate(
        {
            "DATABASE_URL": "sqlite+aiosqlite:///./validator.db",
            "ALLOWED_POLICY_FILE": str(policy_path),
            "WRITE_MODE_ENABLED": True,
            "ALLOW_INSERT": True,
        }
    )
    validator = QueryValidator(settings)
    result = validator.validate_query(
        "INSERT INTO customers (id, email) VALUES (2, 'b@example.com')"
    )
    assert result.ok
    assert result.statement_type == "insert"


def test_validator_blocks_update_without_where_in_write_mode(tmp_path: Path) -> None:
    policy_path = tmp_path / "allowed_policy.txt"
    write_policy(policy_path, "customers:id,email\n")
    settings = Settings.model_validate(
        {
            "DATABASE_URL": "sqlite+aiosqlite:///./validator.db",
            "ALLOWED_POLICY_FILE": str(policy_path),
            "WRITE_MODE_ENABLED": True,
            "ALLOW_UPDATE": True,
        }
    )
    validator = QueryValidator(settings)
    result = validator.validate_query("UPDATE customers SET email = 'x@example.com'")
    assert not result.ok
    assert "UPDATE without a WHERE clause is not allowed" in (result.error or "")


def test_validator_blocks_tautological_where_in_write_mode(tmp_path: Path) -> None:
    policy_path = tmp_path / "allowed_policy.txt"
    write_policy(policy_path, "customers:id,email\n")
    settings = Settings.model_validate(
        {
            "DATABASE_URL": "sqlite+aiosqlite:///./validator.db",
            "ALLOWED_POLICY_FILE": str(policy_path),
            "WRITE_MODE_ENABLED": True,
            "ALLOW_DELETE": True,
        }
    )
    validator = QueryValidator(settings)
    result = validator.validate_query("DELETE FROM customers WHERE 1 = 1")
    assert not result.ok
    assert "WHERE clause appears tautological" in (result.error or "")


def test_validator_blocks_insert_select_when_write_mode_disabled(tmp_path: Path) -> None:
    policy_path = tmp_path / "allowed_policy.txt"
    write_policy(policy_path, "customers:id,email\norders:*\n")
    settings = Settings.model_validate(
        {
            "DATABASE_URL": "sqlite+aiosqlite:///./validator.db",
            "ALLOWED_POLICY_FILE": str(policy_path),
            "WRITE_MODE_ENABLED": False,
            "ALLOW_INSERT": True,
        }
    )
    validator = QueryValidator(settings)
    result = validator.validate_query("INSERT INTO orders (id, total) SELECT id, id FROM customers")
    assert not result.ok
    assert "configured for read-only access" in (result.error or "")


def test_validator_blocks_update_with_subquery_when_update_disabled(tmp_path: Path) -> None:
    policy_path = tmp_path / "allowed_policy.txt"
    write_policy(policy_path, "customers:id,email\norders:*\n")
    settings = Settings.model_validate(
        {
            "DATABASE_URL": "sqlite+aiosqlite:///./validator.db",
            "ALLOWED_POLICY_FILE": str(policy_path),
            "WRITE_MODE_ENABLED": True,
            "ALLOW_UPDATE": False,
        }
    )
    validator = QueryValidator(settings)
    result = validator.validate_query(
        "UPDATE customers SET email = (SELECT 'x@example.com') WHERE id = 1"
    )
    assert not result.ok
    assert "UPDATE operations are disabled" in (result.error or "")


def test_validator_blocks_delete_with_subquery_when_delete_disabled(tmp_path: Path) -> None:
    policy_path = tmp_path / "allowed_policy.txt"
    write_policy(policy_path, "customers:id,email\norders:*\n")
    settings = Settings.model_validate(
        {
            "DATABASE_URL": "sqlite+aiosqlite:///./validator.db",
            "ALLOWED_POLICY_FILE": str(policy_path),
            "WRITE_MODE_ENABLED": True,
            "ALLOW_DELETE": False,
        }
    )
    validator = QueryValidator(settings)
    result = validator.validate_query(
        "DELETE FROM customers WHERE id IN (SELECT id FROM customers)"
    )
    assert not result.ok
    assert "DELETE operations are disabled" in (result.error or "")


def test_validator_blocks_returning_by_default(tmp_path: Path) -> None:
    policy_path = tmp_path / "allowed_policy.txt"
    write_policy(policy_path, "customers:id,email\n")
    settings = Settings.model_validate(
        {
            "DATABASE_URL": "sqlite+aiosqlite:///./validator.db",
            "ALLOWED_POLICY_FILE": str(policy_path),
            "WRITE_MODE_ENABLED": True,
            "ALLOW_UPDATE": True,
        }
    )
    validator = QueryValidator(settings)
    result = validator.validate_query(
        "UPDATE customers SET email = 'x@example.com' WHERE id = 1 RETURNING email"
    )
    assert not result.ok
    assert "RETURNING is not allowed" in (result.error or "")


def test_validator_blocks_insert_select_star_from_non_wildcard_source(tmp_path: Path) -> None:
    policy_path = tmp_path / "allowed_policy.txt"
    write_policy(policy_path, "customers:id,email\norders:*\n")
    settings = Settings.model_validate(
        {
            "DATABASE_URL": "sqlite+aiosqlite:///./validator.db",
            "ALLOWED_POLICY_FILE": str(policy_path),
            "WRITE_MODE_ENABLED": True,
            "ALLOW_INSERT": True,
        }
    )
    validator = QueryValidator(settings)
    result = validator.validate_query("INSERT INTO orders (id, total) SELECT * FROM customers")
    assert not result.ok
    assert "SELECT * is not allowed for table 'customers'" in (result.error or "")


def test_validator_accepts_qualified_target_table_with_short_policy_name(tmp_path: Path) -> None:
    policy_path = tmp_path / "allowed_policy.txt"
    write_policy(policy_path, "customers:id,email\n")
    settings = Settings.model_validate(
        {
            "DATABASE_URL": "sqlite+aiosqlite:///./validator.db",
            "ALLOWED_POLICY_FILE": str(policy_path),
            "WRITE_MODE_ENABLED": True,
            "ALLOW_UPDATE": True,
        }
    )
    validator = QueryValidator(settings)
    result = validator.validate_query(
        "UPDATE main.customers SET email = 'x@example.com' WHERE id = 1"
    )
    assert result.ok

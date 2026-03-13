"""Tests for config and policy parsing."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from secure_sql_mcp.config import Settings
from tests.conftest import write_policy


@pytest.mark.parametrize(
    ("database_url", "expected_url"),
    [
        (
            "postgresql://user:pass@localhost:5432/appdb",
            "postgresql+asyncpg://user:pass@localhost:5432/appdb",
        ),
        (
            "mysql://user:pass@localhost:3306/appdb",
            "mysql+aiomysql://user:pass@localhost:3306/appdb",
        ),
        (
            "sqlite:///./tmp.db",
            "sqlite+aiosqlite:///./tmp.db",
        ),
        (
            "postgresql+asyncpg://user:pass@localhost:5432/appdb",
            "postgresql+asyncpg://user:pass@localhost:5432/appdb",
        ),
        (
            "mysql+aiomysql://user:pass@localhost:3306/appdb",
            "mysql+aiomysql://user:pass@localhost:3306/appdb",
        ),
    ],
)
def test_database_url_injects_or_preserves_async_driver(
    tmp_path: Path, database_url: str, expected_url: str
) -> None:
    policy_path = tmp_path / "policy.txt"
    write_policy(policy_path, "customers:id\n")
    settings = Settings.model_validate(
        {
            "DATABASE_URL": database_url,
            "ALLOWED_POLICY_FILE": str(policy_path),
        }
    )
    assert settings.database_url == expected_url


def test_policy_invalid_format_no_colon_raises(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.txt"
    write_policy(policy_path, "customers id email\n")
    with pytest.raises(ValidationError):
        Settings.model_validate(
            {
                "DATABASE_URL": "sqlite+aiosqlite:///./tmp.db",
                "ALLOWED_POLICY_FILE": str(policy_path),
            }
        )


def test_policy_missing_table_name_raises(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.txt"
    write_policy(policy_path, ":id,email\n")
    with pytest.raises(ValidationError):
        Settings.model_validate(
            {
                "DATABASE_URL": "sqlite+aiosqlite:///./tmp.db",
                "ALLOWED_POLICY_FILE": str(policy_path),
            }
        )


def test_policy_missing_columns_raises(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.txt"
    write_policy(policy_path, "customers:\n")
    with pytest.raises(ValidationError):
        Settings.model_validate(
            {
                "DATABASE_URL": "sqlite+aiosqlite:///./tmp.db",
                "ALLOWED_POLICY_FILE": str(policy_path),
            }
        )


def test_policy_wildcard_with_columns_raises(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.txt"
    write_policy(policy_path, "customers:*,id,email\n")
    with pytest.raises(ValidationError):
        Settings.model_validate(
            {
                "DATABASE_URL": "sqlite+aiosqlite:///./tmp.db",
                "ALLOWED_POLICY_FILE": str(policy_path),
            }
        )


def test_policy_empty_file_raises(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.txt"
    write_policy(policy_path, "")
    with pytest.raises(ValidationError):
        Settings.model_validate(
            {
                "DATABASE_URL": "sqlite+aiosqlite:///./tmp.db",
                "ALLOWED_POLICY_FILE": str(policy_path),
            }
        )


def test_policy_path_is_directory_raises(tmp_path: Path) -> None:
    dir_path = tmp_path / "policydir"
    dir_path.mkdir()
    with pytest.raises(ValidationError):
        Settings.model_validate(
            {
                "DATABASE_URL": "sqlite+aiosqlite:///./tmp.db",
                "ALLOWED_POLICY_FILE": str(dir_path),
            }
        )


def test_policy_duplicate_table_merges_columns(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.txt"
    write_policy(
        policy_path,
        """
        customers:id,email
        customers:ssn
        """,
    )
    settings = Settings.model_validate(
        {
            "DATABASE_URL": "sqlite+aiosqlite:///./tmp.db",
            "ALLOWED_POLICY_FILE": str(policy_path),
        }
    )
    assert settings.allowed_policy["customers"] == {"id", "email", "ssn"}


def test_policy_comments_and_blank_lines_ignored(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.txt"
    write_policy(
        policy_path,
        """
        # comment
        customers:id,email
        # another
        orders:*
        """,
    )
    settings = Settings.model_validate(
        {
            "DATABASE_URL": "sqlite+aiosqlite:///./tmp.db",
            "ALLOWED_POLICY_FILE": str(policy_path),
        }
    )
    assert settings.allowed_policy["customers"] == {"id", "email"}
    assert settings.allowed_policy["orders"] == {"*"}


def test_normalize_log_level(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.txt"
    write_policy(policy_path, "customers:id\n")
    settings = Settings.model_validate(
        {
            "DATABASE_URL": "sqlite+aiosqlite:///./tmp.db",
            "ALLOWED_POLICY_FILE": str(policy_path),
            "LOG_LEVEL": "  debug  ",
        }
    )
    assert settings.log_level == "DEBUG"


def test_opa_acl_data_file_preferred_over_allowed_policy(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.txt"
    write_policy(policy_path, "customers:id\n")
    opa_acl_path = tmp_path / "acl.json"
    opa_acl_path.write_text(
        """
        {
          "secure_sql": {
            "acl": {
              "tables": {
                "orders": {"columns": ["*"]}
              }
            }
          }
        }
        """,
        encoding="utf-8",
    )

    settings = Settings.model_validate(
        {
            "DATABASE_URL": "sqlite+aiosqlite:///./tmp.db",
            "ALLOWED_POLICY_FILE": str(policy_path),
            "OPA_ACL_DATA_FILE": str(opa_acl_path),
        }
    )

    assert settings.allowed_policy == {"customers": {"id"}}
    assert settings.effective_acl_policy == {"orders": {"*"}}


def test_invalid_opa_acl_json_raises(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.txt"
    write_policy(policy_path, "customers:id\n")
    opa_acl_path = tmp_path / "acl.json"
    opa_acl_path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(ValidationError):
        Settings.model_validate(
            {
                "DATABASE_URL": "sqlite+aiosqlite:///./tmp.db",
                "ALLOWED_POLICY_FILE": str(policy_path),
                "OPA_ACL_DATA_FILE": str(opa_acl_path),
            }
        )

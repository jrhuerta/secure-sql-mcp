"""Configuration for the secure SQL MCP server."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    database_url: str = Field(alias="DATABASE_URL")
    allowed_policy_file: str = Field(alias="ALLOWED_POLICY_FILE")
    allowed_policy: dict[str, set[str]] = Field(default_factory=dict)
    effective_acl_policy: dict[str, set[str]] = Field(default_factory=dict)
    opa_url: str | None = Field(default=None, alias="OPA_URL")
    opa_decision_path: str = Field(
        default="/v1/data/secure_sql/authz/decision", alias="OPA_DECISION_PATH"
    )
    opa_timeout_ms: int = Field(default=50, alias="OPA_TIMEOUT_MS", ge=1, le=5000)
    opa_fail_closed: bool = Field(default=True, alias="OPA_FAIL_CLOSED")
    opa_acl_data_file: str | None = Field(default=None, alias="OPA_ACL_DATA_FILE")
    write_mode_enabled: bool = Field(default=False, alias="WRITE_MODE_ENABLED")
    allow_insert: bool = Field(default=False, alias="ALLOW_INSERT")
    allow_update: bool = Field(default=False, alias="ALLOW_UPDATE")
    allow_delete: bool = Field(default=False, alias="ALLOW_DELETE")
    require_where_for_update: bool = Field(default=True, alias="REQUIRE_WHERE_FOR_UPDATE")
    require_where_for_delete: bool = Field(default=True, alias="REQUIRE_WHERE_FOR_DELETE")
    allow_returning: bool = Field(default=False, alias="ALLOW_RETURNING")
    max_rows: int = Field(default=100, alias="MAX_ROWS", ge=1, le=10000)
    query_timeout: int = Field(default=30, alias="QUERY_TIMEOUT", ge=1, le=300)
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    @field_validator("database_url", mode="before")
    @classmethod
    def inject_async_driver(cls, value: Any) -> str:
        """Ensure SQLAlchemy async URLs include an async driver suffix."""
        database_url = str(value).strip()
        if "://" not in database_url:
            return database_url

        scheme = database_url.split("://", 1)[0]
        if "+" in scheme:
            return database_url

        async_driver_map = {
            "postgresql": "asyncpg",
            "mysql": "aiomysql",
            "sqlite": "aiosqlite",
        }
        driver = async_driver_map.get(scheme)
        if driver is None:
            return database_url

        return database_url.replace(f"{scheme}://", f"{scheme}+{driver}://", 1)

    @model_validator(mode="after")
    def load_allowed_policy(self) -> Settings:
        """Load strict table:columns policy from file."""
        self.allowed_policy = self._parse_allowed_policy_file(self.allowed_policy_file)
        self.effective_acl_policy = self._load_effective_acl_policy(
            self.allowed_policy, self.opa_acl_data_file
        )
        return self

    @field_validator("opa_decision_path", mode="before")
    @classmethod
    def normalize_opa_decision_path(cls, value: Any) -> str:
        path = str(value).strip()
        if not path:
            return "/v1/data/secure_sql/authz/decision"
        return path if path.startswith("/") else f"/{path}"

    @field_validator("log_level", mode="before")
    @classmethod
    def normalize_log_level(cls, value: Any) -> str:
        level = str(value).upper().strip()
        return level or "INFO"

    @staticmethod
    def _parse_allowed_policy_file(path: str) -> dict[str, set[str]]:
        """Parse table:columns policy lines from the allowed policy file."""
        file_path = Path(path).expanduser()
        if not file_path.exists():
            raise ValueError(f"Allowed policy file does not exist: {file_path}")
        if not file_path.is_file():
            raise ValueError(f"Allowed policy path is not a file: {file_path}")

        policy: dict[str, set[str]] = {}
        lines = file_path.read_text(encoding="utf-8").splitlines()
        for line_number, raw_line in enumerate(lines, start=1):
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue

            if ":" not in line:
                raise ValueError(
                    f"Invalid policy format on line {line_number}: '{raw_line}'. "
                    "Expected 'table:col1,col2' or 'table:*'."
                )

            table_part, columns_part = line.split(":", 1)
            table_name = table_part.strip().lower()
            if not table_name:
                raise ValueError(f"Missing table name on line {line_number}.")

            column_tokens = [
                token.strip().lower() for token in columns_part.split(",") if token.strip()
            ]
            if not column_tokens:
                raise ValueError(
                    f"Missing columns for table '{table_name}' on line {line_number}. "
                    "Use '*' to allow all columns."
                )

            if "*" in column_tokens and len(column_tokens) > 1:
                raise ValueError(
                    f"Invalid wildcard usage for table '{table_name}' on line {line_number}. "
                    "Use only '*' or an explicit column list."
                )

            existing = policy.setdefault(table_name, set())
            existing.update(column_tokens)

        if not policy:
            raise ValueError("Allowed policy file is empty. Add at least one table rule.")
        return policy

    @classmethod
    def _load_effective_acl_policy(
        cls, allowed_policy: dict[str, set[str]], opa_acl_data_file: str | None
    ) -> dict[str, set[str]]:
        """Load ACL from OPA-native data file when available, else fallback to legacy policy."""
        if not opa_acl_data_file:
            return {table: set(columns) for table, columns in allowed_policy.items()}

        acl_path = Path(opa_acl_data_file).expanduser()
        if not acl_path.exists():
            raise ValueError(f"OPA ACL data file does not exist: {acl_path}")
        if not acl_path.is_file():
            raise ValueError(f"OPA ACL data path is not a file: {acl_path}")

        try:
            payload = json.loads(acl_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"OPA ACL data file must be valid JSON: {exc.msg}") from exc

        tables_payload = cls._extract_opa_tables_payload(payload)
        parsed: dict[str, set[str]] = {}
        for raw_table, raw_rule in tables_payload.items():
            table = str(raw_table).strip().lower()
            if not table:
                continue
            if not isinstance(raw_rule, dict):
                raise ValueError(f"OPA ACL rule for table '{table}' must be an object.")
            raw_columns = raw_rule.get("columns")
            if not isinstance(raw_columns, list) or not raw_columns:
                raise ValueError(
                    f"OPA ACL rule for table '{table}' must include non-empty 'columns' list."
                )
            columns = {str(column).strip().lower() for column in raw_columns if str(column).strip()}
            if not columns:
                raise ValueError(
                    f"OPA ACL rule for table '{table}' includes no valid column entries."
                )
            if "*" in columns and len(columns) > 1:
                raise ValueError(
                    f"OPA ACL wildcard for table '{table}' must be used alone in 'columns'."
                )
            parsed[table] = columns

        if not parsed:
            raise ValueError("OPA ACL data file resolved to an empty ACL policy.")
        return parsed

    @staticmethod
    def _extract_opa_tables_payload(payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("OPA ACL data file root must be a JSON object.")

        if "tables" in payload and isinstance(payload["tables"], dict):
            return payload["tables"]

        secure_sql = payload.get("secure_sql")
        if not isinstance(secure_sql, dict):
            raise ValueError("OPA ACL data must define either 'tables' or 'secure_sql.acl.tables'.")
        acl = secure_sql.get("acl")
        if not isinstance(acl, dict):
            raise ValueError("OPA ACL data missing object at 'secure_sql.acl'.")
        tables = acl.get("tables")
        if not isinstance(tables, dict):
            raise ValueError("OPA ACL data missing object at 'secure_sql.acl.tables'.")
        return tables


def load_settings() -> Settings:
    """Load typed settings from environment variables."""
    return Settings.model_validate({})

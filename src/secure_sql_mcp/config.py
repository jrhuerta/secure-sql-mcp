"""Configuration for the secure SQL MCP server."""

from __future__ import annotations

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
    max_rows: int = Field(default=100, alias="MAX_ROWS", ge=1, le=10000)
    query_timeout: int = Field(default=30, alias="QUERY_TIMEOUT", ge=1, le=300)
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    @model_validator(mode="after")
    def load_allowed_policy(self) -> Settings:
        """Load strict table:columns policy from file."""
        self.allowed_policy = self._parse_allowed_policy_file(self.allowed_policy_file)
        return self

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


def load_settings() -> Settings:
    """Load typed settings from environment variables."""
    return Settings.model_validate({})

"""OPA policy evaluation helpers."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any
from urllib import error, request

from secure_sql_mcp.config import Settings


@dataclass(slots=True)
class PolicyDecision:
    """Normalized policy decision returned to callers."""

    allow: bool
    deny_reasons: list[str] = field(default_factory=list)
    message: str | None = None
    raw_result: dict[str, Any] | None = None


class OpaPolicyEngine:
    """Evaluates policy decisions against a local OPA server."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def evaluate(self, payload: dict[str, Any]) -> PolicyDecision:
        return await asyncio.to_thread(self._evaluate_sync, payload)

    def evaluate_sync(self, payload: dict[str, Any]) -> PolicyDecision:
        return self._evaluate_sync(payload)

    def _evaluate_sync(self, payload: dict[str, Any]) -> PolicyDecision:
        if not self.settings.opa_url:
            return PolicyDecision(
                allow=False,
                deny_reasons=["opa_unconfigured"],
                message=(
                    "Authorization service is not configured. Please escalate to a human operator."
                ),
            )

        endpoint = f"{self.settings.opa_url.rstrip('/')}{self.settings.opa_decision_path}"
        body = json.dumps({"input": payload}).encode("utf-8")
        req = request.Request(  # noqa: S310
            endpoint,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )

        try:
            with request.urlopen(req, timeout=self.settings.opa_timeout_ms / 1000) as response:  # noqa: S310
                data = json.loads(response.read().decode("utf-8"))
        except (error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            if self.settings.opa_fail_closed:
                return PolicyDecision(
                    allow=False,
                    deny_reasons=["opa_unavailable"],
                    message=(
                        "Authorization service is unavailable. "
                        "Please retry or escalate to a human operator."
                    ),
                )
            return PolicyDecision(
                allow=True,
                deny_reasons=[],
                message=None,
                raw_result={"warning": str(exc)},
            )

        result = self._extract_result(data)
        if result is None:
            return PolicyDecision(
                allow=not self.settings.opa_fail_closed,
                deny_reasons=["opa_undefined"],
                message=(
                    "Authorization decision is unavailable. "
                    "Please retry or escalate to a human operator."
                ),
            )

        if isinstance(result, bool):
            return PolicyDecision(allow=result, raw_result={"allow": result})

        if not isinstance(result, dict):
            return PolicyDecision(
                allow=False,
                deny_reasons=["opa_invalid_result"],
                message="Authorization decision format is invalid.",
            )

        allow = bool(result.get("allow", False))
        deny_reasons = [str(reason) for reason in result.get("deny_reasons", [])]
        message = result.get("message")
        if message is not None:
            message = str(message)

        if not allow and not message:
            message = self._message_for_reasons(deny_reasons)

        return PolicyDecision(
            allow=allow,
            deny_reasons=deny_reasons,
            message=message,
            raw_result=result,
        )

    @staticmethod
    def _extract_result(response_payload: dict[str, Any]) -> Any | None:
        # OPA REST response shape: {"result": ...}
        if "result" in response_payload:
            return response_payload.get("result")
        return None

    @staticmethod
    def _message_for_reasons(deny_reasons: list[str]) -> str:
        if "multiple_statements" in deny_reasons:
            return (
                "Only a single SQL statement is allowed. "
                "Please remove additional statements and try again."
            )
        if "ddl_or_privilege_operation" in deny_reasons:
            return (
                "DDL and privilege operations are not permitted. "
                "Please escalate to a human operator."
            )
        if "disallowed_operation" in deny_reasons:
            return (
                "This server is configured for read-only access. "
                "If you need to modify data, please escalate to a human operator."
            )
        if "write_not_enabled" in deny_reasons:
            return (
                "Write operations are disabled by server configuration. "
                "Please escalate to a human operator."
            )
        if "insert_not_allowed" in deny_reasons:
            return (
                "INSERT operations are not permitted by server configuration. "
                "Please escalate to a human operator."
            )
        if "update_not_allowed" in deny_reasons:
            return (
                "UPDATE operations are not permitted by server configuration. "
                "Please escalate to a human operator."
            )
        if "delete_not_allowed" in deny_reasons:
            return (
                "DELETE operations are not permitted by server configuration. "
                "Please escalate to a human operator."
            )
        if "insert_columns_missing" in deny_reasons:
            return (
                "INSERT statements must include an explicit column list under strict mode. "
                "Please specify target columns explicitly."
            )
        if "not_read_query" in deny_reasons:
            return "Only read-only SELECT queries are allowed."
        if "missing_where_on_update" in deny_reasons:
            return "UPDATE without a WHERE clause is not allowed."
        if "missing_where_on_delete" in deny_reasons:
            return "DELETE without a WHERE clause is not allowed."
        if "tautological_where_clause" in deny_reasons:
            return (
                "The WHERE clause appears tautological and may update/delete too broadly. "
                "Please provide a restrictive predicate."
            )
        if "returning_not_allowed" in deny_reasons:
            return "RETURNING is not allowed for this write policy."
        if "table_restricted" in deny_reasons:
            return (
                "Access to one or more tables is restricted by the server access policy. "
                "Please use list_tables/describe_table to view allowed targets."
            )
        if "write_source_table_restricted" in deny_reasons:
            return (
                "INSERT ... SELECT references one or more source tables restricted by policy. "
                "Please use list_tables/describe_table to view allowed targets."
            )
        if "write_column_restricted" in deny_reasons:
            return (
                "Write access to one or more target columns is restricted by policy. "
                "Use describe_table to inspect allowed columns."
            )
        if "column_restricted" in deny_reasons:
            return (
                "Access to one or more selected columns is restricted by policy. "
                "Use describe_table to inspect allowed columns."
            )
        if "star_not_allowed" in deny_reasons:
            return (
                "SELECT * is not allowed under strict policy for one or more tables. "
                "Please select explicit allowed columns."
            )
        if "unqualified_multi_table_column" in deny_reasons:
            return (
                "Unqualified column references are not allowed in multi-table queries "
                "under strict mode."
            )
        return "Query blocked by policy."

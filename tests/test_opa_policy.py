from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast
from urllib import error

from secure_sql_mcp.config import Settings
from secure_sql_mcp.opa_policy import OpaPolicyEngine, PolicyDecision
from secure_sql_mcp.query_validator import QueryValidator
from tests.conftest import write_policy


class _FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload
        self.status = 200

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_: object) -> None:
        return None


class _CaptureEngine:
    def __init__(self, decision: PolicyDecision) -> None:
        self.decision = decision
        self.last_payload: dict[str, object] | None = None

    def evaluate_sync(self, payload: dict[str, object]) -> PolicyDecision:
        self.last_payload = payload
        return self.decision


def _settings(tmp_path: Path) -> Settings:
    policy_path = tmp_path / "allowed_policy.txt"
    write_policy(policy_path, "customers:id,email\norders:*\n")
    return Settings.model_validate(
        {
            "DATABASE_URL": "sqlite+aiosqlite:///./tmp.db",
            "ALLOWED_POLICY_FILE": str(policy_path),
            "OPA_URL": "http://127.0.0.1:8181",
            "OPA_FAIL_CLOSED": True,
        }
    )


def test_opa_engine_fail_closed_on_transport_error(tmp_path: Path, monkeypatch) -> None:
    settings = _settings(tmp_path)
    engine = OpaPolicyEngine(settings)

    def _raise_url_error(*_: object, **__: object):
        raise error.URLError("connection refused")

    monkeypatch.setattr("secure_sql_mcp.opa_policy.request.urlopen", _raise_url_error)
    decision = engine.evaluate_sync({"tool": {"name": "query"}, "query": {"statement_count": 1}})

    assert decision.allow is False
    assert "opa_unavailable" in decision.deny_reasons


def test_opa_engine_parses_decision_payload(tmp_path: Path, monkeypatch) -> None:
    settings = _settings(tmp_path)
    engine = OpaPolicyEngine(settings)

    def _ok(*_: object, **__: object):
        return _FakeResponse({"result": {"allow": False, "deny_reasons": ["table_restricted"]}})

    monkeypatch.setattr("secure_sql_mcp.opa_policy.request.urlopen", _ok)
    decision = engine.evaluate_sync({"tool": {"name": "query"}, "query": {"statement_count": 1}})

    assert decision.allow is False
    assert decision.deny_reasons == ["table_restricted"]
    assert "restricted" in (decision.message or "")


def test_validator_builds_policy_input_for_opa(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    capture_engine = _CaptureEngine(PolicyDecision(allow=True))
    validator = QueryValidator(settings, policy_engine=cast(Any, capture_engine))

    result = validator.validate_query(
        "SELECT c.id, o.total FROM customers c JOIN orders o ON c.id = o.id"
    )

    assert result.ok
    assert capture_engine.last_payload is not None
    payload = capture_engine.last_payload
    assert payload["tool"] == {"name": "query"}
    assert payload["query"]["statement_count"] == 1
    assert sorted(payload["query"]["referenced_tables"]) == ["customers", "orders"]

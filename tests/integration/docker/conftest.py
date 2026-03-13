from __future__ import annotations

import os
import sqlite3
import subprocess
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from mcp.client.stdio import StdioServerParameters


@dataclass(frozen=True, slots=True)
class BackendConfig:
    name: str
    database_url: str
    needs_deps: bool


ROOT = Path(__file__).resolve().parents[3]
COMPOSE_FILE = ROOT / "docker-compose.test.yml"
POLICY_DIR = ROOT / "tests" / "integration" / "docker" / "policies"
ACL_DIR = ROOT / "tests" / "integration" / "docker" / "acl"


def _run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        command,
        cwd=ROOT,
        check=check,
        text=True,
        capture_output=True,
    )


@pytest.fixture(scope="session")
def docker_available() -> None:
    try:
        _run(["docker", "version"])
        _run(["docker", "compose", "version"])
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("Docker or docker compose is unavailable on this host.")


@pytest.fixture(scope="session")
def compose_project_name() -> str:
    return f"secure_sql_it_{uuid.uuid4().hex[:10]}"


@pytest.fixture(scope="session")
def docker_stack(docker_available: None, compose_project_name: str) -> Iterator[None]:
    compose = ["docker", "compose", "-p", compose_project_name, "-f", str(COMPOSE_FILE)]
    _run([*compose, "build", "secure-sql-mcp"])
    _run([*compose, "up", "-d", "postgres", "mysql"])
    try:
        yield
    finally:
        _run([*compose, "down", "-v", "--remove-orphans"], check=False)


@pytest.fixture(params=["sqlite", "postgresql", "mysql"])
def backend(request: pytest.FixtureRequest) -> BackendConfig:
    backend_name = str(request.param)
    if backend_name == "sqlite":
        return BackendConfig(
            name="sqlite",
            database_url="sqlite+aiosqlite:///run/sqlite/test.db",
            needs_deps=False,
        )
    if backend_name == "postgresql":
        return BackendConfig(
            name="postgresql",
            database_url="postgresql+asyncpg://secure:secure@postgres:5432/secure_sql_test",
            needs_deps=True,
        )
    return BackendConfig(
        name="mysql",
        database_url="mysql+aiomysql://secure:secure@mysql:3306/secure_sql_test",
        needs_deps=True,
    )


@pytest.fixture
def policy_path() -> Callable[[str], Path]:
    def _resolve(policy_name: str) -> Path:
        path = POLICY_DIR / f"{policy_name}.txt"
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")
        return path

    return _resolve


@pytest.fixture
def acl_path() -> Callable[[str], Path]:
    def _resolve(acl_name: str) -> Path:
        path = ACL_DIR / f"{acl_name}.json"
        if not path.exists():
            raise FileNotFoundError(f"ACL file not found: {path}")
        return path

    return _resolve


@pytest.fixture
def sqlite_db_dir(tmp_path: Path) -> Path:
    db_dir = tmp_path / "sqlite"
    db_dir.mkdir(parents=True, exist_ok=True)
    db_path = db_dir / "test.db"
    conn = sqlite3.connect(db_path)
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
            INSERT INTO secrets (id, token) VALUES (99, 'top-secret-token');
            """
        )
        conn.commit()
    finally:
        conn.close()
    return db_dir


@pytest.fixture
def docker_server_params_factory(
    compose_project_name: str,
    sqlite_db_dir: Path,
) -> Callable[..., StdioServerParameters]:
    def _factory(
        *,
        backend: BackendConfig,
        policy_file: Path,
        write_mode_enabled: bool = False,
        allow_insert: bool = False,
        allow_update: bool = False,
        allow_delete: bool = False,
        require_where_for_update: bool = True,
        require_where_for_delete: bool = True,
        allow_returning: bool = False,
        opa_fail_closed: bool = True,
        opa_url: str = "http://127.0.0.1:8181",
        opa_decision_path: str = "/v1/data/secure_sql/authz/decision",
        opa_acl_data_file: Path | None = None,
    ) -> StdioServerParameters:
        args = ["run", "--rm", "-i"]
        if backend.needs_deps:
            args.extend(["--network", f"{compose_project_name}_default"])

        args.extend(
            [
                "-e",
                f"DATABASE_URL={backend.database_url}",
                "-e",
                "ALLOWED_POLICY_FILE=/run/policy/allowed_policy.txt",
                "-e",
                f"OPA_URL={opa_url}",
                "-e",
                f"OPA_DECISION_PATH={opa_decision_path}",
                "-e",
                f"OPA_FAIL_CLOSED={'true' if opa_fail_closed else 'false'}",
                "-e",
                f"WRITE_MODE_ENABLED={'true' if write_mode_enabled else 'false'}",
                "-e",
                f"ALLOW_INSERT={'true' if allow_insert else 'false'}",
                "-e",
                f"ALLOW_UPDATE={'true' if allow_update else 'false'}",
                "-e",
                f"ALLOW_DELETE={'true' if allow_delete else 'false'}",
                "-e",
                (f"REQUIRE_WHERE_FOR_UPDATE={'true' if require_where_for_update else 'false'}"),
                "-e",
                (f"REQUIRE_WHERE_FOR_DELETE={'true' if require_where_for_delete else 'false'}"),
                "-e",
                f"ALLOW_RETURNING={'true' if allow_returning else 'false'}",
                "-v",
                f"{policy_file}:/run/policy/allowed_policy.txt:ro",
            ]
        )

        if backend.name == "sqlite":
            args.extend(["-v", f"{sqlite_db_dir}:/run/sqlite:rw"])

        if opa_acl_data_file is not None:
            args.extend(
                [
                    "-e",
                    "OPA_ACL_DATA_FILE=/run/policy/acl.json",
                    "-v",
                    f"{opa_acl_data_file}:/run/policy/acl.json:ro",
                ]
            )

        args.append("secure-sql-mcp:test")
        return StdioServerParameters(command="docker", args=args, env=os.environ.copy())

    return _factory

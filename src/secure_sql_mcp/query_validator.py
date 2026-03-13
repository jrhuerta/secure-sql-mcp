"""SQL validation utilities for read-only and ACL enforcement."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

import sqlglot
from sqlglot import exp

from secure_sql_mcp.config import Settings
from secure_sql_mcp.opa_policy import OpaPolicyEngine


@dataclass(slots=True)
class ValidationResult:
    """Validation outcome for a query."""

    ok: bool
    normalized_sql: str | None = None
    referenced_tables: list[str] | None = None
    referenced_columns: dict[str, list[str]] | None = None
    error: str | None = None


class QueryValidator:
    """Validates SQL query safety constraints."""

    _DISALLOWED_EXPRESSIONS = (
        exp.Insert,
        exp.Update,
        exp.Delete,
        exp.Drop,
        exp.Alter,
        exp.Create,
        exp.TruncateTable,
        exp.Grant,
        exp.Revoke,
        exp.Merge,
        exp.Command,
    )

    def __init__(self, settings: Settings, policy_engine: OpaPolicyEngine | None = None) -> None:
        self.settings = settings
        self.policy_engine = policy_engine or (
            OpaPolicyEngine(settings) if settings.opa_url else None
        )

    def validate_query(self, sql: str) -> ValidationResult:
        """Validate SQL and authorize according to configured policy backend."""
        query = sql.strip()
        if not query:
            return ValidationResult(ok=False, error="Query is empty.")

        try:
            statements = sqlglot.parse(query, read=self._dialect)
        except sqlglot.errors.ParseError:
            return ValidationResult(
                ok=False,
                error="Could not parse the SQL query. Please check the syntax and try again.",
            )

        if not statements or statements[0] is None:
            return ValidationResult(
                ok=False,
                error="Could not parse the SQL query. Please check the syntax and try again.",
            )

        statement = statements[0]
        statement_type = statement.key.upper() if statement.key else "UNKNOWN"
        statement_count = len(statements)
        has_disallowed_operation = any(
            stmt is not None and self._contains_disallowed_operation(stmt) for stmt in statements
        )
        is_read_statement = statement_count == 1 and self._is_read_statement(statement)

        referenced_tables: list[str] = []
        referenced_columns: dict[str, set[str]] = {}
        star_tables: set[str] = set()
        has_unqualified_multi_table_columns = False

        if statement_count == 1:
            referenced_tables = self.extract_referenced_tables(statement)
            if self.policy_engine is None:
                if has_disallowed_operation:
                    return ValidationResult(
                        ok=False,
                        error=(
                            "This server is configured for read-only access. "
                            f"The operation '{statement_type}' is not permitted. "
                            "If you need to modify data, please escalate to a human operator."
                        ),
                    )
                if not is_read_statement:
                    return ValidationResult(
                        ok=False,
                        error=(
                            "Only read-only SELECT queries are allowed. "
                            f"Received '{statement_type}'."
                        ),
                    )

                table_policy = self._resolve_table_policy(referenced_tables)
                if isinstance(table_policy, str):
                    return ValidationResult(ok=False, error=table_policy)

                columns_result = self.extract_referenced_columns(statement, referenced_tables)
                if isinstance(columns_result, str):
                    return ValidationResult(ok=False, error=columns_result)

                referenced_columns, star_tables = columns_result
                columns_error = self._validate_column_access(
                    table_policy, referenced_columns, star_tables
                )
                if columns_error:
                    return ValidationResult(ok=False, error=columns_error)

                for table in referenced_tables:
                    access_error = self.table_access_error(table, table_policy=table_policy)
                    if access_error:
                        return ValidationResult(ok=False, error=access_error)
            else:
                referenced_columns, star_tables, has_unqualified_multi_table_columns = (
                    self._extract_referenced_columns_relaxed(statement, referenced_tables)
                )

        if self.policy_engine is None:
            if statement_count != 1:
                return ValidationResult(
                    ok=False,
                    error=(
                        "Only a single SQL statement is allowed. "
                        "Please remove additional statements and try again."
                    ),
                )
            if has_disallowed_operation:
                return ValidationResult(
                    ok=False,
                    error=(
                        "This server is configured for read-only access. "
                        f"The operation '{statement_type}' is not permitted. "
                        "If you need to modify data, please escalate to a human operator."
                    ),
                )
            if not is_read_statement:
                return ValidationResult(
                    ok=False,
                    error=(
                        "Only read-only SELECT queries are allowed. "
                        f"Received '{statement_type}'."
                    ),
                )
        else:
            decision = self.policy_engine.evaluate_sync(
                self._build_query_policy_input(
                    sql=query,
                    statement_count=statement_count,
                    statement_type=statement_type.lower(),
                    has_disallowed_operation=has_disallowed_operation,
                    is_read_statement=is_read_statement,
                    referenced_tables=referenced_tables,
                    referenced_columns=referenced_columns,
                    star_tables=star_tables,
                    has_unqualified_multi_table_columns=has_unqualified_multi_table_columns,
                )
            )
            if not decision.allow:
                return ValidationResult(
                    ok=False, error=decision.message or "Query blocked by policy."
                )

        return ValidationResult(
            ok=True,
            normalized_sql=(
                statement.sql(dialect=self._dialect) if self._dialect else statement.sql()
            ),
            referenced_tables=referenced_tables,
            referenced_columns={
                table: sorted(columns) for table, columns in referenced_columns.items()
            },
        )

    def table_access_error(
        self, table_name: str, table_policy: dict[str, set[str]] | None = None
    ) -> str | None:
        """Return policy error message if table access is restricted."""
        effective_policy = table_policy or self._resolve_table_policy([table_name])
        if isinstance(effective_policy, str):
            return (
                f"Access to table '{table_name}' is restricted by the server access policy. "
                "Please use list_tables/describe_table to view allowed targets, "
                "or escalate to a human operator."
            )
        return None

    def extract_referenced_tables(self, statement: exp.Expression) -> list[str]:
        """Collect table names referenced in the statement."""
        tables: set[str] = set()
        for table in statement.find_all(exp.Table):
            table_name = self._table_to_name(table)
            if table_name:
                tables.add(table_name.lower())
        return sorted(tables)

    def extract_referenced_columns(
        self, statement: exp.Expression, referenced_tables: list[str]
    ) -> tuple[dict[str, set[str]], set[str]] | str:
        """Collect referenced columns and SELECT * targets."""
        alias_map = self._build_alias_map(statement)
        columns_by_table: defaultdict[str, set[str]] = defaultdict(set)
        unqualified_columns: set[str] = set()
        star_tables: set[str] = set()

        for column in statement.find_all(exp.Column):
            if isinstance(column.this, exp.Star):
                continue
            if not column.name:
                continue

            col_name = column.name.lower()
            qualifier = (column.table or "").lower()
            if qualifier:
                table_name = alias_map.get(qualifier, qualifier)
                columns_by_table[table_name].add(col_name)
            else:
                unqualified_columns.add(col_name)

        for select in statement.find_all(exp.Select):
            for expression in select.expressions:
                if isinstance(expression, exp.Star):
                    if len(referenced_tables) == 1:
                        star_tables.add(referenced_tables[0])
                    elif len(referenced_tables) > 1:
                        star_tables.update(referenced_tables)
                elif isinstance(expression, exp.Column) and isinstance(expression.this, exp.Star):
                    qualifier = (expression.table or "").lower()
                    if qualifier:
                        star_tables.add(alias_map.get(qualifier, qualifier))

        if unqualified_columns:
            if len(referenced_tables) == 1:
                columns_by_table[referenced_tables[0]].update(unqualified_columns)
            elif len(referenced_tables) > 1:
                cols = ", ".join(sorted(unqualified_columns))
                return (
                    "Unqualified column references are not allowed in multi-table queries "
                    "under strict mode. "
                    f"Columns: {cols}. Please qualify each column with its table alias/name."
                )

        return dict(columns_by_table), star_tables

    def _resolve_table_policy(self, tables: list[str]) -> dict[str, set[str]] | str:
        resolved: dict[str, set[str]] = {}
        available = ", ".join(sorted(self.settings.effective_acl_policy))

        for table in tables:
            policy_columns = self.lookup_table_policy(table)
            if policy_columns is None:
                return (
                    f"Access to table '{table}' is restricted by the server access policy. "
                    f"Allowed tables are: {available}. "
                    "Please use list_tables/describe_table or escalate to a human operator."
                )
            resolved[table] = policy_columns
        return resolved

    def _validate_column_access(
        self,
        table_policy: dict[str, set[str]],
        referenced_columns: dict[str, set[str]],
        star_tables: set[str],
    ) -> str | None:
        for table, columns in referenced_columns.items():
            allowed_columns = table_policy.get(table, set())
            if "*" in allowed_columns:
                continue
            disallowed = sorted(column for column in columns if column not in allowed_columns)
            if disallowed:
                allowed_text = ", ".join(sorted(allowed_columns))
                return (
                    f"Access to column(s) {', '.join(disallowed)} on table '{table}' "
                    "is restricted. "
                    f"Allowed columns: {allowed_text}. "
                    "Use describe_table to inspect policy or escalate to a human operator."
                )

        for table in sorted(star_tables):
            allowed_columns = table_policy.get(table, set())
            if "*" not in allowed_columns:
                allowed_text = ", ".join(sorted(allowed_columns))
                return (
                    f"SELECT * is not allowed for table '{table}' under strict policy. "
                    f"Allowed columns: {allowed_text}. "
                    "Please select explicit allowed columns or escalate to a human operator."
                )
        return None

    @property
    def _dialect(self) -> str | None:
        if self.settings.database_url.startswith("postgresql"):
            return "postgres"
        if self.settings.database_url.startswith("mysql"):
            return "mysql"
        if self.settings.database_url.startswith("sqlite"):
            return "sqlite"
        return None

    def _contains_disallowed_operation(self, statement: exp.Expression) -> bool:
        return any(statement.find(kind) is not None for kind in self._DISALLOWED_EXPRESSIONS)

    @staticmethod
    def _is_read_statement(statement: exp.Expression) -> bool:
        if isinstance(statement, exp.Select):
            return True
        if isinstance(statement, (exp.Union, exp.Intersect, exp.Except)):
            return True
        return statement.find(exp.Select) is not None

    @staticmethod
    def _table_to_name(table: exp.Table) -> str:
        parts: list[str] = []
        if table.catalog:
            parts.append(str(table.catalog))
        if table.db:
            parts.append(str(table.db))
        if table.name:
            parts.append(str(table.name))
        return ".".join(parts).lower()

    def lookup_table_policy(self, table_name: str) -> set[str] | None:
        """Return allowed columns for a table from policy, or None if not allowed."""
        normalized = table_name.lower()
        candidates = (normalized, normalized.split(".")[-1])
        for candidate in candidates:
            if candidate in self.settings.effective_acl_policy:
                return set(self.settings.effective_acl_policy[candidate])
        return None

    def _build_alias_map(self, statement: exp.Expression) -> dict[str, str]:
        alias_map: dict[str, str] = {}
        for table in statement.find_all(exp.Table):
            table_name = self._table_to_name(table)
            if not table_name:
                continue
            short_name = table_name.split(".")[-1]
            alias_map[short_name] = table_name
            alias_expr = table.args.get("alias")
            if isinstance(alias_expr, exp.TableAlias) and alias_expr.name:
                alias_name = alias_expr.name.lower()
                alias_map[alias_name] = table_name
        return alias_map

    def _extract_referenced_columns_relaxed(
        self, statement: exp.Expression, referenced_tables: list[str]
    ) -> tuple[dict[str, set[str]], set[str], bool]:
        alias_map = self._build_alias_map(statement)
        columns_by_table: defaultdict[str, set[str]] = defaultdict(set)
        unqualified_columns: set[str] = set()
        star_tables: set[str] = set()

        for column in statement.find_all(exp.Column):
            if isinstance(column.this, exp.Star):
                continue
            if not column.name:
                continue

            col_name = column.name.lower()
            qualifier = (column.table or "").lower()
            if qualifier:
                table_name = alias_map.get(qualifier, qualifier)
                columns_by_table[table_name].add(col_name)
            else:
                unqualified_columns.add(col_name)

        has_unqualified_multi_table_columns = bool(
            unqualified_columns and len(referenced_tables) > 1
        )
        if unqualified_columns and len(referenced_tables) == 1:
            columns_by_table[referenced_tables[0]].update(unqualified_columns)

        for select in statement.find_all(exp.Select):
            for expression in select.expressions:
                if isinstance(expression, exp.Star):
                    if len(referenced_tables) == 1:
                        star_tables.add(referenced_tables[0])
                    elif len(referenced_tables) > 1:
                        star_tables.update(referenced_tables)
                elif isinstance(expression, exp.Column) and isinstance(expression.this, exp.Star):
                    qualifier = (expression.table or "").lower()
                    if qualifier:
                        star_tables.add(alias_map.get(qualifier, qualifier))

        return dict(columns_by_table), star_tables, has_unqualified_multi_table_columns

    def _build_query_policy_input(
        self,
        *,
        sql: str,
        statement_count: int,
        statement_type: str,
        has_disallowed_operation: bool,
        is_read_statement: bool,
        referenced_tables: list[str],
        referenced_columns: dict[str, set[str]],
        star_tables: set[str],
        has_unqualified_multi_table_columns: bool,
    ) -> dict[str, Any]:
        acl_tables = {
            table: {"columns": sorted(columns)}
            for table, columns in sorted(self.settings.effective_acl_policy.items())
        }
        return {
            "tool": {"name": "query"},
            "query": {
                "raw_sql": sql,
                "statement_count": statement_count,
                "statement_type": statement_type,
                "has_disallowed_operation": has_disallowed_operation,
                "is_read_statement": is_read_statement,
                "referenced_tables": referenced_tables,
                "referenced_columns": {
                    table: sorted(columns) for table, columns in sorted(referenced_columns.items())
                },
                "star_tables": sorted(star_tables),
                "has_unqualified_multi_table_columns": has_unqualified_multi_table_columns,
            },
            "acl": {"tables": acl_tables},
        }

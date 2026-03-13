"""SQL validation utilities for read-only and ACL enforcement."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

import sqlglot
from sqlglot import exp

from secure_sql_mcp.config import Settings
from secure_sql_mcp.opa_policy import OpaPolicyEngine

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ValidationResult:
    """Validation outcome for a query."""

    ok: bool
    normalized_sql: str | None = None
    referenced_tables: list[str] | None = None
    referenced_columns: dict[str, list[str]] | None = None
    statement_type: str | None = None
    error: str | None = None


@dataclass(slots=True)
class WriteFacts:
    """Parser-derived facts for write statements."""

    statement_type: str
    target_table: str
    insert_columns: list[str]
    updated_columns: list[str]
    where_present: bool
    where_tautological: bool
    returning_present: bool
    returning_columns: list[str]
    has_select_source: bool
    source_tables: list[str]


class QueryValidator:
    """Validates SQL query safety constraints."""

    _ALWAYS_DISALLOWED = (
        exp.Drop,
        exp.Alter,
        exp.Create,
        exp.TruncateTable,
        exp.Grant,
        exp.Revoke,
        exp.Merge,
        exp.Command,
    )
    _WRITE_EXPRESSIONS = (exp.Insert, exp.Update, exp.Delete)

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
        statement_type = self._statement_type(statement)
        statement_type_upper = statement_type.upper()
        statement_count = len(statements)
        has_disallowed_operation = any(
            stmt is not None and self._contains_always_disallowed_operation(stmt)
            for stmt in statements
        )
        is_read_statement = statement_count == 1 and self._is_read_statement(statement)
        is_write_statement = statement_count == 1 and self._is_write_statement(statement)

        referenced_tables: list[str] = []
        referenced_columns: dict[str, set[str]] = {}
        star_tables: set[str] = set()
        has_unqualified_multi_table_columns = False
        write_facts: WriteFacts | None = None

        if statement_count == 1:
            referenced_tables = self.extract_referenced_tables(statement)
            if is_write_statement:
                write_facts = self._extract_write_facts(statement)
                if write_facts is None:
                    return ValidationResult(
                        ok=False,
                        error=(
                            "Could not determine write operation details from SQL. "
                            "Please use an explicit INSERT/UPDATE/DELETE statement."
                        ),
                    )

                if not self.settings.write_mode_enabled:
                    self._warn_if_policy_would_allow_blocked_write(
                        sql=query,
                        statement_count=statement_count,
                        statement_type=statement_type,
                        has_disallowed_operation=has_disallowed_operation,
                        is_read_statement=is_read_statement,
                        referenced_tables=referenced_tables,
                        referenced_columns=referenced_columns,
                        star_tables=star_tables,
                        has_unqualified_multi_table_columns=has_unqualified_multi_table_columns,
                        write_facts=write_facts,
                        blocked_reason="WRITE_MODE_ENABLED",
                    )
                    return ValidationResult(
                        ok=False,
                        statement_type=statement_type,
                        error=(
                            "This server is configured for read-only access. "
                            f"The operation '{statement_type_upper}' is not permitted. "
                            "Please escalate to a human operator."
                        ),
                    )

                if not self._is_write_action_enabled(statement_type):
                    gate_name = f"ALLOW_{statement_type_upper}"
                    self._warn_if_policy_would_allow_blocked_write(
                        sql=query,
                        statement_count=statement_count,
                        statement_type=statement_type,
                        has_disallowed_operation=has_disallowed_operation,
                        is_read_statement=is_read_statement,
                        referenced_tables=referenced_tables,
                        referenced_columns=referenced_columns,
                        star_tables=star_tables,
                        has_unqualified_multi_table_columns=has_unqualified_multi_table_columns,
                        write_facts=write_facts,
                        blocked_reason=gate_name,
                    )
                    return ValidationResult(
                        ok=False,
                        statement_type=statement_type,
                        error=(
                            f"{statement_type_upper} operations are disabled "
                            "by server configuration. "
                            "Please escalate to a human operator."
                        ),
                    )

                if write_facts.statement_type == "insert" and not write_facts.insert_columns:
                    return ValidationResult(
                        ok=False,
                        statement_type=statement_type,
                        error=(
                            "INSERT statements must include an explicit "
                            "column list under strict mode. "
                            "Please specify allowed target columns explicitly."
                        ),
                    )
                if (
                    write_facts.statement_type in {"update", "delete"}
                    and self.settings.require_where_for_update
                    and write_facts.statement_type == "update"
                    and not write_facts.where_present
                ):
                    return ValidationResult(
                        ok=False,
                        statement_type=statement_type,
                        error=f"{statement_type_upper} without a WHERE clause is not allowed.",
                    )
                if (
                    write_facts.statement_type in {"update", "delete"}
                    and self.settings.require_where_for_delete
                    and write_facts.statement_type == "delete"
                    and not write_facts.where_present
                ):
                    return ValidationResult(
                        ok=False,
                        statement_type=statement_type,
                        error=f"{statement_type_upper} without a WHERE clause is not allowed.",
                    )
                if (
                    write_facts.statement_type in {"update", "delete"}
                    and write_facts.where_tautological
                ):
                    return ValidationResult(
                        ok=False,
                        statement_type=statement_type,
                        error=(
                            "The WHERE clause appears tautological and may "
                            "update/delete too broadly. "
                            "Please provide a restrictive predicate."
                        ),
                    )

                if write_facts.returning_present and not self.settings.allow_returning:
                    return ValidationResult(
                        ok=False,
                        statement_type=statement_type,
                        error="RETURNING is not allowed for this write policy.",
                    )

                if self.policy_engine is None:
                    write_acl_error = self._validate_write_acl(write_facts)
                    if write_acl_error:
                        return ValidationResult(
                            ok=False, statement_type=statement_type, error=write_acl_error
                        )

                    columns_result = self.extract_referenced_columns(statement, referenced_tables)
                    if isinstance(columns_result, str):
                        return ValidationResult(
                            ok=False, statement_type=statement_type, error=columns_result
                        )
                    referenced_columns, star_tables = columns_result

                    table_policy = self._resolve_table_policy(referenced_tables)
                    if isinstance(table_policy, str):
                        return ValidationResult(
                            ok=False, statement_type=statement_type, error=table_policy
                        )
                    columns_error = self._validate_column_access(
                        table_policy, referenced_columns, star_tables
                    )
                    if columns_error:
                        return ValidationResult(
                            ok=False, statement_type=statement_type, error=columns_error
                        )
                else:
                    referenced_columns, star_tables, has_unqualified_multi_table_columns = (
                        self._extract_referenced_columns_relaxed(statement, referenced_tables)
                    )
            elif is_read_statement:
                if self.policy_engine is None:
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
            else:
                referenced_columns, star_tables, has_unqualified_multi_table_columns = (
                    self._extract_referenced_columns_relaxed(statement, referenced_tables)
                )

        if self.policy_engine is None:
            if statement_count != 1:
                return ValidationResult(
                    ok=False,
                    statement_type=statement_type,
                    error=(
                        "Only a single SQL statement is allowed. "
                        "Please remove additional statements and try again."
                    ),
                )
            if has_disallowed_operation:
                return ValidationResult(
                    ok=False,
                    statement_type=statement_type,
                    error=(
                        "This server is configured for read-only access. "
                        f"The operation '{statement_type_upper}' is not permitted. "
                        "If you need to modify data, please escalate to a human operator."
                    ),
                )
            if not (is_read_statement or is_write_statement):
                return ValidationResult(
                    ok=False,
                    statement_type=statement_type,
                    error=(
                        "Only read-only SELECT queries or explicitly enabled "
                        "write operations are allowed. "
                        f"Received '{statement_type_upper}'."
                    ),
                )
        else:
            decision = self.policy_engine.evaluate_sync(
                self._build_query_policy_input(
                    sql=query,
                    statement_count=statement_count,
                    statement_type=statement_type,
                    has_disallowed_operation=has_disallowed_operation,
                    is_read_statement=is_read_statement,
                    referenced_tables=referenced_tables,
                    referenced_columns=referenced_columns,
                    star_tables=star_tables,
                    has_unqualified_multi_table_columns=has_unqualified_multi_table_columns,
                    write_facts=write_facts,
                )
            )
            if not decision.allow:
                return ValidationResult(
                    ok=False,
                    statement_type=statement_type,
                    error=decision.message or "Query blocked by policy.",
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
            statement_type=statement_type,
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

    def _contains_always_disallowed_operation(self, statement: exp.Expression) -> bool:
        return any(statement.find(kind) is not None for kind in self._ALWAYS_DISALLOWED)

    def _is_write_statement(self, statement: exp.Expression) -> bool:
        return isinstance(statement, self._WRITE_EXPRESSIONS)

    @staticmethod
    def _statement_type(statement: exp.Expression) -> str:
        key = (statement.key or "unknown").lower()
        return key

    def _is_write_action_enabled(self, statement_type: str) -> bool:
        if statement_type == "insert":
            return self.settings.allow_insert
        if statement_type == "update":
            return self.settings.allow_update
        if statement_type == "delete":
            return self.settings.allow_delete
        return False

    @staticmethod
    def _is_read_statement(statement: exp.Expression) -> bool:
        if isinstance(statement, exp.Select):
            return True
        if isinstance(statement, (exp.Union, exp.Intersect, exp.Except)):
            return True
        return False

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

    def _extract_write_facts(self, statement: exp.Expression) -> WriteFacts | None:
        statement_type = self._statement_type(statement)
        if statement_type not in {"insert", "update", "delete"}:
            return None

        target_table = self._extract_target_table(statement)
        if not target_table:
            return None

        insert_columns: list[str] = []
        updated_columns: list[str] = []
        where_present = False
        where_tautological = False
        returning_present = (
            bool(statement.args.get("returning")) or statement.find(exp.Returning) is not None
        )
        returning_columns = self._extract_returning_columns(statement)
        source_tables: list[str] = []

        if isinstance(statement, exp.Insert):
            insert_columns = self._extract_insert_columns(statement)
            source_expr = statement.args.get("expression")
            if isinstance(source_expr, exp.Expression):
                source_tables = self.extract_referenced_tables(source_expr)
        elif isinstance(statement, exp.Update):
            updated_columns = self._extract_update_columns(statement)
            where_expr = statement.args.get("where")
            where_present = where_expr is not None
            if isinstance(where_expr, exp.Expression):
                where_tautological = self._is_tautological_where(where_expr)
        elif isinstance(statement, exp.Delete):
            where_expr = statement.args.get("where")
            where_present = where_expr is not None
            if isinstance(where_expr, exp.Expression):
                where_tautological = self._is_tautological_where(where_expr)

        if not source_tables:
            all_tables = self.extract_referenced_tables(statement)
            source_tables = sorted(table for table in all_tables if table != target_table)

        return WriteFacts(
            statement_type=statement_type,
            target_table=target_table,
            insert_columns=sorted(set(insert_columns)),
            updated_columns=sorted(set(updated_columns)),
            where_present=where_present,
            where_tautological=where_tautological,
            returning_present=returning_present,
            returning_columns=returning_columns,
            has_select_source=bool(source_tables),
            source_tables=sorted(set(source_tables)),
        )

    def _extract_target_table(self, statement: exp.Expression) -> str | None:
        target_expr = statement.args.get("this")
        if isinstance(target_expr, exp.Schema):
            target_expr = target_expr.this
        if isinstance(target_expr, exp.Table):
            return self._table_to_name(target_expr)
        if isinstance(target_expr, exp.Expression):
            table = target_expr.find(exp.Table)
            if isinstance(table, exp.Table):
                return self._table_to_name(table)
        return None

    def _extract_insert_columns(self, statement: exp.Insert) -> list[str]:
        target_expr = statement.args.get("this")
        if isinstance(target_expr, exp.Schema):
            columns: list[str] = []
            for column in target_expr.expressions:
                if isinstance(column, exp.Column) and column.name:
                    columns.append(column.name.lower())
                elif isinstance(column, exp.Identifier) and column.this:
                    columns.append(str(column.this).lower())
            return columns
        return []

    @staticmethod
    def _extract_update_columns(statement: exp.Update) -> list[str]:
        columns: set[str] = set()
        for assignment in statement.expressions:
            lhs = assignment.args.get("this") if isinstance(assignment, exp.Expression) else None
            if isinstance(lhs, exp.Column) and lhs.name:
                columns.add(lhs.name.lower())
        return sorted(columns)

    @staticmethod
    def _extract_returning_columns(statement: exp.Expression) -> list[str]:
        returning_expr = statement.args.get("returning")
        if not isinstance(returning_expr, exp.Returning):
            return []

        columns: set[str] = set()
        for expression in returning_expr.expressions:
            if isinstance(expression, exp.Star):
                columns.add("*")
                continue
            if isinstance(expression, exp.Column):
                if isinstance(expression.this, exp.Star):
                    columns.add("*")
                    continue
                if expression.name:
                    columns.add(expression.name.lower())
                    continue
            for nested_column in expression.find_all(exp.Column):
                if isinstance(nested_column.this, exp.Star):
                    columns.add("*")
                    continue
                if nested_column.name:
                    columns.add(nested_column.name.lower())
        return sorted(columns)

    def _is_tautological_where(self, where_expr: exp.Expression) -> bool:
        expr = where_expr.this if isinstance(where_expr, exp.Where) else where_expr
        if isinstance(expr, exp.Paren):
            return self._is_tautological_where(expr.this)
        if isinstance(expr, exp.Boolean):
            return bool(expr.this)
        if isinstance(expr, exp.Not):
            child = expr.this
            return isinstance(child, exp.Boolean) and not bool(child.this)
        if isinstance(expr, exp.Literal):
            if expr.is_string:
                return expr.this.strip().lower() in {"true", "t", "yes", "on", "1"}
            return str(expr.this).strip() in {"1"}
        if isinstance(expr, exp.Or):
            return self._is_tautological_where(expr.left) or self._is_tautological_where(expr.right)
        if isinstance(expr, exp.And):
            return self._is_tautological_where(expr.left) and self._is_tautological_where(
                expr.right
            )
        if isinstance(expr, exp.EQ):
            left = expr.left
            right = expr.right
            if isinstance(left, exp.Literal) and isinstance(right, exp.Literal):
                return str(left.this) == str(right.this) and left.is_string == right.is_string
            if isinstance(left, exp.Column) and isinstance(right, exp.Column):
                return (
                    left.name.lower() == right.name.lower()
                    and (left.table or "").lower() == (right.table or "").lower()
                )
        return False

    def _validate_write_acl(self, write_facts: WriteFacts) -> str | None:
        target_policy = self.lookup_table_policy(write_facts.target_table)
        if target_policy is None:
            available = ", ".join(sorted(self.settings.effective_acl_policy))
            return (
                f"Access to table '{write_facts.target_table}' "
                "is restricted by the server access policy. "
                f"Allowed tables are: {available}. "
                "Please use list_tables/describe_table or escalate to a human operator."
            )

        changed_columns = set(write_facts.insert_columns or write_facts.updated_columns)
        if changed_columns and "*" not in target_policy:
            disallowed = sorted(column for column in changed_columns if column not in target_policy)
            if disallowed:
                allowed_text = ", ".join(sorted(target_policy))
                return (
                    f"Write access to column(s) {', '.join(disallowed)} "
                    f"on table '{write_facts.target_table}' "
                    "is restricted. "
                    f"Allowed columns: {allowed_text}. "
                    "Use describe_table to inspect policy or escalate to a human operator."
                )

        if write_facts.returning_present:
            if "*" in write_facts.returning_columns and "*" not in target_policy:
                allowed_text = ", ".join(sorted(target_policy))
                return (
                    f"RETURNING * is not allowed for table '{write_facts.target_table}' "
                    "under strict policy. "
                    f"Allowed columns: {allowed_text}. "
                    "Please list explicit allowed RETURNING columns."
                )
            if "*" not in target_policy:
                disallowed_returning = sorted(
                    column
                    for column in write_facts.returning_columns
                    if column != "*" and column not in target_policy
                )
                if disallowed_returning:
                    allowed_text = ", ".join(sorted(target_policy))
                    return (
                        f"RETURNING column(s) {', '.join(disallowed_returning)} on table "
                        f"'{write_facts.target_table}' are restricted. "
                        f"Allowed columns: {allowed_text}. "
                        "Use describe_table to inspect policy or escalate to a human operator."
                    )

        return None

    def _warn_if_policy_would_allow_blocked_write(
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
        write_facts: WriteFacts | None,
        blocked_reason: str,
    ) -> None:
        if self.policy_engine is None or write_facts is None:
            return

        shadow_payload = self._build_query_policy_input(
            sql=sql,
            statement_count=statement_count,
            statement_type=statement_type,
            has_disallowed_operation=has_disallowed_operation,
            is_read_statement=is_read_statement,
            referenced_tables=referenced_tables,
            referenced_columns=referenced_columns,
            star_tables=star_tables,
            has_unqualified_multi_table_columns=has_unqualified_multi_table_columns,
            write_facts=write_facts,
            config_overrides={
                "write_mode_enabled": True,
                "allow_insert": True,
                "allow_update": True,
                "allow_delete": True,
                "allow_returning": True,
            },
        )
        decision = self.policy_engine.evaluate_sync(shadow_payload)
        if decision.allow:
            operation = statement_type.upper()
            gate_name = blocked_reason.upper()
            enabled_flag = "true" if self.settings.write_mode_enabled else "false"
            action_flag = "true" if self._is_write_action_enabled(statement_type) else "false"
            LOGGER.warning(
                "Write operation '%s' blocked by config gate "
                "(%s, WRITE_MODE_ENABLED=%s, ALLOW_%s=%s).",
                operation,
                gate_name,
                enabled_flag,
                operation,
                action_flag,
            )

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
        write_facts: WriteFacts | None,
        config_overrides: dict[str, bool] | None = None,
    ) -> dict[str, Any]:
        acl_tables = {
            table: {"columns": sorted(columns)}
            for table, columns in sorted(self.settings.effective_acl_policy.items())
        }
        write_mode_enabled = (
            config_overrides["write_mode_enabled"]
            if config_overrides and "write_mode_enabled" in config_overrides
            else self.settings.write_mode_enabled
        )
        allow_insert = (
            config_overrides["allow_insert"]
            if config_overrides and "allow_insert" in config_overrides
            else self.settings.allow_insert
        )
        allow_update = (
            config_overrides["allow_update"]
            if config_overrides and "allow_update" in config_overrides
            else self.settings.allow_update
        )
        allow_delete = (
            config_overrides["allow_delete"]
            if config_overrides and "allow_delete" in config_overrides
            else self.settings.allow_delete
        )
        require_where_for_update = (
            config_overrides["require_where_for_update"]
            if config_overrides and "require_where_for_update" in config_overrides
            else self.settings.require_where_for_update
        )
        require_where_for_delete = (
            config_overrides["require_where_for_delete"]
            if config_overrides and "require_where_for_delete" in config_overrides
            else self.settings.require_where_for_delete
        )
        allow_returning = (
            config_overrides["allow_returning"]
            if config_overrides and "allow_returning" in config_overrides
            else self.settings.allow_returning
        )
        return {
            "tool": {"name": "query"},
            "query": {
                "raw_sql": sql,
                "statement_count": statement_count,
                "statement_type": statement_type,
                "is_write_statement": write_facts is not None,
                "has_disallowed_operation": has_disallowed_operation,
                "is_read_statement": is_read_statement,
                "referenced_tables": referenced_tables,
                "referenced_columns": {
                    table: sorted(columns) for table, columns in sorted(referenced_columns.items())
                },
                "star_tables": sorted(star_tables),
                "has_unqualified_multi_table_columns": has_unqualified_multi_table_columns,
                "target_table": write_facts.target_table if write_facts else "",
                "insert_columns": write_facts.insert_columns if write_facts else [],
                "updated_columns": write_facts.updated_columns if write_facts else [],
                "where_present": write_facts.where_present if write_facts else False,
                "where_tautological": write_facts.where_tautological if write_facts else False,
                "returning_present": write_facts.returning_present if write_facts else False,
                "returning_columns": write_facts.returning_columns if write_facts else [],
                "has_select_source": write_facts.has_select_source if write_facts else False,
                "source_tables": write_facts.source_tables if write_facts else [],
            },
            "config": {
                "write_mode_enabled": write_mode_enabled,
                "allow_insert": allow_insert,
                "allow_update": allow_update,
                "allow_delete": allow_delete,
                "require_where_for_update": require_where_for_update,
                "require_where_for_delete": require_where_for_delete,
                "allow_returning": allow_returning,
            },
            "acl": {"tables": acl_tables},
        }

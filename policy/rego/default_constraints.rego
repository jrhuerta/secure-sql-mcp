package secure_sql.default_constraints

default allow := false

is_query_tool if input.tool.name == "query"

deny_reasons["multiple_statements"] if {
  is_query_tool
  input.query.statement_count != 1
}

deny_reasons["disallowed_operation"] if {
  is_query_tool
  input.query.has_disallowed_operation
}

deny_reasons["not_read_query"] if {
  is_query_tool
  not input.query.is_read_statement
}

deny_reasons["unqualified_multi_table_column"] if {
  is_query_tool
  input.query.has_unqualified_multi_table_columns
}

allow if not is_query_tool

allow if {
  is_query_tool
  count(deny_reasons) == 0
}

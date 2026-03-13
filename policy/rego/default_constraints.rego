package secure_sql.default_constraints

default allow = false

is_query_tool if input.tool.name == "query"
is_write_query if {
  is_query_tool
  object.get(input.query, "is_write_statement", false)
}

statement_type := lower(object.get(input.query, "statement_type", ""))

write_mode_enabled := object.get(object.get(input, "config", {}), "write_mode_enabled", false)
allow_insert := object.get(object.get(input, "config", {}), "allow_insert", false)
allow_update := object.get(object.get(input, "config", {}), "allow_update", false)
allow_delete := object.get(object.get(input, "config", {}), "allow_delete", false)

deny_reasons["multiple_statements"] if {
  is_query_tool
  input.query.statement_count != 1
}

deny_reasons["ddl_or_privilege_operation"] if {
  is_query_tool
  input.query.has_disallowed_operation
}

deny_reasons["not_read_query"] if {
  is_query_tool
  not input.query.is_read_statement
  not is_write_query
}

deny_reasons["write_not_enabled"] if {
  is_write_query
  not write_mode_enabled
}

deny_reasons["insert_not_allowed"] if {
  is_write_query
  statement_type == "insert"
  not allow_insert
}

deny_reasons["update_not_allowed"] if {
  is_write_query
  statement_type == "update"
  not allow_update
}

deny_reasons["delete_not_allowed"] if {
  is_write_query
  statement_type == "delete"
  not allow_delete
}

deny_reasons["insert_columns_missing"] if {
  is_write_query
  statement_type == "insert"
  count(object.get(input.query, "insert_columns", [])) == 0
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

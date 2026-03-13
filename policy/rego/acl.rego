package secure_sql.acl

default allow := false

acl_tables := object.get(object.get(input, "acl", {}), "tables", {})

is_query_tool if input.tool.name == "query"
is_list_tables_tool if input.tool.name == "list_tables"
is_describe_table_tool if input.tool.name == "describe_table"

table_allowed(table) if object.get(acl_tables, table, null) != null

allowed_columns(table) := object.get(object.get(acl_tables, table, {}), "columns", [])

column_allowed(table, col) if {
  allowed_columns(table)[_] == "*"
}

column_allowed(table, col) if {
  allowed_columns(table)[_] == col
}

deny_reasons["table_restricted"] if {
  is_query_tool
  table := input.query.referenced_tables[_]
  not table_allowed(table)
}

deny_reasons["column_restricted"] if {
  is_query_tool
  table := object.keys(input.query.referenced_columns)[_]
  col := input.query.referenced_columns[table][_]
  not column_allowed(table, col)
}

deny_reasons["star_not_allowed"] if {
  is_query_tool
  table := input.query.star_tables[_]
  not column_allowed(table, "*")
}

deny_reasons["table_restricted"] if {
  is_describe_table_tool
  not table_allowed(input.table)
}

allow if is_list_tables_tool

allow if {
  is_describe_table_tool
  table_allowed(input.table)
}

allow if {
  is_query_tool
  count(deny_reasons) == 0
}

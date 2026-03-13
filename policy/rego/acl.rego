package secure_sql.acl

default allow = false

acl_tables := object.get(object.get(input, "acl", {}), "tables", {})

is_query_tool if input.tool.name == "query"
is_list_tables_tool if input.tool.name == "list_tables"
is_describe_table_tool if input.tool.name == "describe_table"
is_write_query if {
  is_query_tool
  object.get(input.query, "is_write_statement", false)
}

normalized_table(table) := lower(table)
short_table_name(table) := name if {
  parts := split(normalized_table(table), ".")
  idx := count(parts) - 1
  name := parts[idx]
}

table_allowed(table) if object.get(acl_tables, normalized_table(table), null) != null
table_allowed(table) if object.get(acl_tables, short_table_name(table), null) != null

allowed_columns(table) := cols if {
  full := object.get(acl_tables, normalized_table(table), null)
  full != null
  cols := object.get(full, "columns", [])
}

allowed_columns(table) := cols if {
  full := object.get(acl_tables, normalized_table(table), null)
  full == null
  short := object.get(acl_tables, short_table_name(table), {})
  cols := object.get(short, "columns", [])
}

column_allowed(table, col) if {
  allowed_columns(table)[_] == "*"
}

column_allowed(table, col) if {
  allowed_columns(table)[_] == col
}

deny_reasons["table_restricted"] if {
  is_query_tool
  not is_write_query
  table := input.query.referenced_tables[_]
  not table_allowed(table)
}

deny_reasons["column_restricted"] if {
  is_query_tool
  not is_write_query
  table := object.keys(input.query.referenced_columns)[_]
  col := input.query.referenced_columns[table][_]
  not column_allowed(table, col)
}

deny_reasons["star_not_allowed"] if {
  is_query_tool
  not is_write_query
  table := input.query.star_tables[_]
  not column_allowed(table, "*")
}

deny_reasons["star_not_allowed"] if {
  is_write_query
  table := input.query.star_tables[_]
  not column_allowed(table, "*")
}

deny_reasons["table_restricted"] if {
  is_write_query
  target := object.get(input.query, "target_table", "")
  target != ""
  not table_allowed(target)
}

write_columns[col] if {
  is_write_query
  col := object.get(input.query, "insert_columns", [])[_]
}

write_columns[col] if {
  is_write_query
  col := object.get(input.query, "updated_columns", [])[_]
}

deny_reasons["write_column_restricted"] if {
  is_write_query
  target := object.get(input.query, "target_table", "")
  target != ""
  col := write_columns[_]
  not column_allowed(target, col)
}

deny_reasons["write_source_table_restricted"] if {
  is_write_query
  src := object.get(input.query, "source_tables", [])[_]
  not table_allowed(src)
}

deny_reasons["write_column_restricted"] if {
  is_write_query
  table := object.keys(input.query.referenced_columns)[_]
  col := input.query.referenced_columns[table][_]
  not column_allowed(table, col)
}

deny_reasons["write_column_restricted"] if {
  is_write_query
  target := object.get(input.query, "target_table", "")
  target != ""
  col := object.get(input.query, "returning_columns", [])[_]
  col != "*"
  not column_allowed(target, col)
}

deny_reasons["star_not_allowed"] if {
  is_write_query
  target := object.get(input.query, "target_table", "")
  target != ""
  object.get(input.query, "returning_columns", [])[_] == "*"
  not column_allowed(target, "*")
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

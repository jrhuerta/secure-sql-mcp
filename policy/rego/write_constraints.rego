package secure_sql.write_constraints

is_query_tool if input.tool.name == "query"
is_write_query if {
  is_query_tool
  object.get(input.query, "is_write_statement", false)
}

statement_type := lower(object.get(input.query, "statement_type", ""))
where_present := object.get(input.query, "where_present", false)
where_tautological := object.get(input.query, "where_tautological", false)
returning_present := object.get(input.query, "returning_present", false)

require_where_for_update := object.get(
  object.get(input, "config", {}),
  "require_where_for_update",
  true,
)
require_where_for_delete := object.get(
  object.get(input, "config", {}),
  "require_where_for_delete",
  true,
)
allow_returning := object.get(object.get(input, "config", {}), "allow_returning", false)

deny_reasons["missing_where_on_update"] if {
  is_write_query
  statement_type == "update"
  require_where_for_update
  not where_present
}

deny_reasons["missing_where_on_delete"] if {
  is_write_query
  statement_type == "delete"
  require_where_for_delete
  not where_present
}

deny_reasons["tautological_where_clause"] if {
  is_write_query
  statement_type == "update"
  where_present
  where_tautological
}

deny_reasons["tautological_where_clause"] if {
  is_write_query
  statement_type == "delete"
  where_present
  where_tautological
}

deny_reasons["returning_not_allowed"] if {
  is_write_query
  returning_present
  not allow_returning
}

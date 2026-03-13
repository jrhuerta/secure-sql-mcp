package secure_sql.authz

import data.secure_sql.acl
import data.secure_sql.default_constraints
import data.secure_sql.write_constraints

default allow = false

deny_reasons[reason] if default_constraints.deny_reasons[reason]
deny_reasons[reason] if acl.deny_reasons[reason]
deny_reasons[reason] if write_constraints.deny_reasons[reason]

allow if {
  default_constraints.allow
  acl.allow
  count(deny_reasons) == 0
}

decision := {
  "allow": allow,
  "deny_reasons": [reason | deny_reasons[reason]],
}

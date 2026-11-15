# Shared helpers for policies evaluated against `terraform show -json tfplan` output.
package terraform.lib

import rego.v1

# Resource changes that create or update something (replace = ["delete","create"] is included).
resources_changing contains rc if {
	some rc in input.resource_changes
	some action in rc.change.actions
	action in {"create", "update"}
}

resources_deleting contains rc if {
	some rc in input.resource_changes
	"delete" in rc.change.actions
}

# Normalise a possibly-null / missing value into an array.
as_array(x) := x if {
	is_array(x)
} else := []

# True when the attribute will only be known after apply.
unknown(rc, attr) if rc.change.after_unknown[attr] == true

# Wrap a scalar in a list (IAM Action/Resource/Principal may be a string or a list).
as_list(x) := x if {
	is_array(x)
} else := [x]

# Parsed IAM / resource policy statements from a JSON string attribute.
policy_statements(raw) := [s | some s in as_list(json.unmarshal(raw).Statement)] if {
	is_string(raw)
	raw != ""
}

# Value of a single nested block (Terraform plan renders blocks as lists of objects).
block(obj, name) := b if {
	some b in as_array(object.get(obj, name, []))
} else := {}

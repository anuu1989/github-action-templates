# Blast radius: stop unexpectedly large plans (refactors gone wrong, wrong workspace/backend...).
# Override with conftest --data: blast_radius: {max_deletes: 20, max_changes: 200}
package terraform.blast_radius

import data.terraform.lib
import rego.v1

default_limits := {"max_deletes": 5, "max_changes": 50}

limits := object.union(default_limits, data.blast_radius) if {
	is_object(data.blast_radius)
} else := default_limits

changes := [rc | some rc in input.resource_changes; not rc.change.actions in [["no-op"], ["read"]]]

deny_too_many_deletes contains msg if {
	n := count(lib.resources_deleting)
	n > limits.max_deletes
	msg := sprintf("plan deletes/replaces %d resources (limit %d)", [n, limits.max_deletes])
}

warn contains msg if {
	count(changes) > limits.max_changes
	msg := sprintf("plan changes %d resources (soft limit %d): double-check workspace & backend", [count(changes), limits.max_changes])
}

# `terraform plan -var allow_large_change=true` acknowledges an intentional large delete.
exception contains rules if {
	input.variables.allow_large_change.value == true
	rules := ["too_many_deletes"]
}

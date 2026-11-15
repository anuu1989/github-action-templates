# RBAC least privilege.
package kubernetes.rbac

import data.kubernetes.lib
import rego.v1

role_kinds := {"Role", "ClusterRole"}

binding_kinds := {"RoleBinding", "ClusterRoleBinding"}

escalation_verbs := {"escalate", "bind", "impersonate"}

read_verbs := {"get", "list", "watch", "*"}

deny contains msg if {
	input.kind in role_kinds
	some rule in input.rules
	some field in ["verbs", "resources", "apiGroups"]
	"*" in object.get(rule, field, [])
	msg := sprintf("%s: wildcard '*' in %s", [lib.name, field])
}

deny contains msg if {
	input.kind in role_kinds
	some rule in input.rules
	some verb in rule.verbs
	verb in escalation_verbs
	msg := sprintf("%s: grants privilege-escalation verb '%s'", [lib.name, verb])
}

deny contains msg if {
	input.kind == "ClusterRole"
	some rule in input.rules
	"secrets" in object.get(rule, "resources", [])
	some verb in rule.verbs
	verb in read_verbs
	msg := sprintf("%s: cluster-wide '%s' on secrets", [lib.name, verb])
}

warn contains msg if {
	input.kind == "Role"
	some rule in input.rules
	"secrets" in object.get(rule, "resources", [])
	"list" in rule.verbs
	msg := sprintf("%s: 'list' on secrets returns secret values: scope with resourceNames", [lib.name])
}

deny contains msg if {
	input.kind in binding_kinds
	input.roleRef.name == "cluster-admin"
	msg := sprintf("%s binds cluster-admin", [lib.name])
}

deny contains msg if {
	input.kind in binding_kinds
	some subject in input.subjects
	subject.name in {"system:anonymous", "system:unauthenticated"}
	msg := sprintf("%s grants access to %s", [lib.name, subject.name])
}

package kubernetes.rbac_test

import data.kubernetes.rbac
import rego.v1

role(kind, rules) := {"kind": kind, "metadata": {"name": "r"}, "rules": rules}

test_wildcard_cluster_role_denied if {
	count(rbac.deny) == 3 with input as role("ClusterRole", [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}])
}

test_scoped_role_allowed if {
	count(rbac.deny) == 0 with input as role("Role", [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "watch"]}])
}

test_cluster_secret_read_denied if {
	count(rbac.deny) == 1 with input as role("ClusterRole", [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}])
}

test_escalation_verbs_denied if {
	count(rbac.deny) == 2 with input as role("Role", [{"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["roles"], "verbs": ["bind", "escalate"]}])
}

test_namespaced_secret_list_warns if {
	count(rbac.warn) == 1 with input as role("Role", [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["list"]}])
}

test_cluster_admin_binding_denied if {
	b := {"kind": "ClusterRoleBinding", "metadata": {"name": "b"}, "roleRef": {"name": "cluster-admin"}, "subjects": [{"kind": "Group", "name": "system:unauthenticated"}]}
	count(rbac.deny) == 2 with input as b
}

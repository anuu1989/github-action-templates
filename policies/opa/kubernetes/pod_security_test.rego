package kubernetes.pod_security_test

import data.kubernetes.fixtures as f
import data.kubernetes.pod_security
import rego.v1

test_compliant_clean if {
	count(pod_security.deny) == 0 with input as f.deployment
}

test_missing_drop_all_denied if {
	d := f.with_container({"securityContext": {"capabilities": {"drop": ["NET_RAW"]}}})
	count(pod_security.deny) == 1 with input as d
}

test_added_sys_admin_denied if {
	d := f.with_container({"securityContext": {"capabilities": {"drop": ["ALL"], "add": ["SYS_ADMIN", "NET_BIND_SERVICE"]}}})
	count(pod_security.deny) == 1 with input as d
}

test_container_unconfined_seccomp_denied if {
	d := f.with_container({"securityContext": {"capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "Unconfined"}}})
	count(pod_security.deny) == 1 with input as d
}

test_hostpath_and_hostport_denied if {
	d1 := f.with_pod_spec({"volumes": [{"name": "docker", "hostPath": {"path": "/var/run/docker.sock"}}]})
	count(pod_security.deny) == 1 with input as d1
	d2 := f.with_container({"ports": [{"containerPort": 80, "hostPort": 80}]})
	count(pod_security.deny) == 1 with input as d2
}

test_default_service_account_warns if {
	d := f.with_pod_spec({"serviceAccountName": "default", "automountServiceAccountToken": true})
	count(pod_security.warn) == 2 with input as d
}

test_configmap_ignored if {
	count(pod_security.warn) == 0 with input as {"kind": "ConfigMap", "metadata": {"name": "c"}}
}

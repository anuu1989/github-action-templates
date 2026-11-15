package kubernetes.security_test

import data.kubernetes.security
import rego.v1

good_container := {
	"name": "app",
	"image": "ghcr.io/acme/app:1.4.2",
	"securityContext": {"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true},
	"resources": {"limits": {"memory": "256Mi"}, "requests": {"cpu": "100m"}},
	"readinessProbe": {"httpGet": {"path": "/healthz", "port": 8080}},
}

deployment(container, pod_sc) := {
	"apiVersion": "apps/v1",
	"kind": "Deployment",
	"metadata": {"name": "web"},
	"spec": {"template": {"spec": {"securityContext": pod_sc, "containers": [container]}}},
}

test_hardened_deployment_passes if {
	count(security.deny) == 0 with input as deployment(good_container, {"runAsNonRoot": true})
	count(security.warn) == 0 with input as deployment(good_container, {"runAsNonRoot": true})
}

test_root_denied if {
	count(security.deny) == 1 with input as deployment(good_container, {})
}

test_container_overrides_pod_non_root if {
	c := object.union(good_container, {"securityContext": {"allowPrivilegeEscalation": false, "runAsNonRoot": false, "readOnlyRootFilesystem": true}})
	count(security.deny) == 1 with input as deployment(c, {"runAsNonRoot": true})
}

test_latest_and_untagged_images_denied if {
	count(security.deny) == 1 with input as deployment(object.union(good_container, {"image": "nginx:latest"}), {"runAsNonRoot": true})
	count(security.deny) == 1 with input as deployment(object.union(good_container, {"image": "registry:5000/team/nginx"}), {"runAsNonRoot": true})
}

test_digest_and_registry_port_allowed if {
	count(security.deny) == 0 with input as deployment(object.union(good_container, {"image": "registry:5000/nginx@sha256:abc"}), {"runAsNonRoot": true})
}

test_privileged_without_limits_denied if {
	c := object.union(object.remove(good_container, ["resources"]), {"securityContext": {"privileged": true, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}})
	count(security.deny) == 2 with input as deployment(c, {"runAsNonRoot": true})
}

test_cronjob_supported if {
	cj := {"kind": "CronJob", "metadata": {"name": "nightly"}, "spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [object.union(good_container, {"image": "busybox"})]}}}}}}
	count(security.deny) == 2 with input as cj # root + untagged
}

test_non_workload_ignored if {
	count(security.deny) == 0 with input as {"kind": "ConfigMap", "metadata": {"name": "cfg"}, "data": {}}
}

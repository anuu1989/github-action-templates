# Shared, fully compliant manifests used by the per-package tests.
package kubernetes.fixtures

import rego.v1

container := {
	"name": "app",
	"image": "ghcr.io/acme/app:1.4.2",
	"ports": [{"containerPort": 8080}],
	"securityContext": {
		"allowPrivilegeEscalation": false,
		"readOnlyRootFilesystem": true,
		"capabilities": {"drop": ["ALL"]},
	},
	"resources": {"limits": {"memory": "256Mi"}, "requests": {"cpu": "100m"}},
	"readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}},
	"livenessProbe": {"httpGet": {"path": "/live", "port": 8080}},
}

labels := {"app.kubernetes.io/name": "web", "team": "payments"}

deployment := {
	"apiVersion": "apps/v1",
	"kind": "Deployment",
	"metadata": {"name": "web", "namespace": "payments", "labels": labels},
	"spec": {
		"replicas": 3,
		"template": {
			"metadata": {"labels": labels},
			"spec": {
				"serviceAccountName": "web",
				"automountServiceAccountToken": false,
				"securityContext": {"runAsNonRoot": true, "seccompProfile": {"type": "RuntimeDefault"}},
				"topologySpreadConstraints": [{"maxSkew": 1, "topologyKey": "topology.kubernetes.io/zone", "whenUnsatisfiable": "ScheduleAnyway"}],
				"containers": [container],
			},
		},
	},
}

service := {
	"apiVersion": "v1",
	"kind": "Service",
	"metadata": {"name": "web", "namespace": "payments", "labels": labels},
	"spec": {"type": "ClusterIP", "ports": [{"port": 80, "targetPort": 8080}]},
}

ingress := {
	"apiVersion": "networking.k8s.io/v1",
	"kind": "Ingress",
	"metadata": {"name": "web", "namespace": "payments", "labels": labels},
	"spec": {
		"tls": [{"hosts": ["web.acme.io"], "secretName": "web-tls"}],
		"rules": [{"host": "web.acme.io"}],
	},
}

# Replace a key in the first container of the deployment
with_container(patch) := json.patch(deployment, [{"op": "replace", "path": "/spec/template/spec/containers/0", "value": object.union(container, patch)}])

with_pod_spec(patch) := json.patch(deployment, [{"op": "replace", "path": "/spec/template/spec", "value": object.union(deployment.spec.template.spec, patch)}])

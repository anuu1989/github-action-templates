# Shared helpers for Kubernetes manifests (one YAML document = one input).
package kubernetes.lib

import rego.v1

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}

is_workload if input.kind in workload_kinds

is_workload if input.kind in {"CronJob", "Pod"}

pod_spec := input.spec.template.spec if input.kind in workload_kinds

pod_spec := input.spec.jobTemplate.spec.template.spec if input.kind == "CronJob"

pod_spec := input.spec if input.kind == "Pod"

pod_metadata := input.spec.template.metadata if input.kind in workload_kinds

pod_metadata := input.spec.jobTemplate.spec.template.metadata if input.kind == "CronJob"

pod_metadata := input.metadata if input.kind == "Pod"

# Regular + init containers
containers contains c if some c in pod_spec.containers

containers contains c if some c in pod_spec.initContainers

# Long-running (non-init) containers only
app_containers contains c if some c in pod_spec.containers

name := sprintf("%s/%s", [input.kind, input.metadata.name])

labels := object.get(input.metadata, "labels", {})

annotations := object.get(input.metadata, "annotations", {})

as_list(x) := x if {
	is_array(x)
} else := [x]

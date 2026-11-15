# Metadata conventions: required labels, no `default` namespace, selector labels on pods.
package kubernetes.metadata

import data.kubernetes.lib
import rego.v1

required_labels := {"app.kubernetes.io/name", "team"}

labelled_kinds := {"Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job", "Service", "Ingress"}

deny contains msg if {
	input.kind in labelled_kinds
	missing := required_labels - object.keys(lib.labels)
	count(missing) > 0
	msg := sprintf("%s is missing required labels: %v", [lib.name, sort(missing)])
}

deny contains msg if {
	input.metadata.namespace == "default"
	msg := sprintf("%s must not be deployed to the 'default' namespace", [lib.name])
}

warn contains msg if {
	lib.is_workload
	input.kind != "Pod"
	not lib.pod_metadata.labels["app.kubernetes.io/name"]
	msg := sprintf("%s: pod template should carry the app.kubernetes.io/name label", [lib.name])
}

# Availability & operability: replicas, probes, PDBs that don't block node drains, HPA floor.
package kubernetes.availability

import data.kubernetes.lib
import rego.v1

warn contains msg if {
	input.kind in {"Deployment", "StatefulSet"}
	object.get(input.spec, "replicas", 1) < 2
	msg := sprintf("%s: replicas < 2 is a single point of failure", [lib.name])
}

warn contains msg if {
	input.kind in {"Deployment", "StatefulSet", "DaemonSet"}
	some c in lib.app_containers
	not c.livenessProbe
	msg := sprintf("%s: container '%s' should define a livenessProbe", [lib.name, c.name])
}

deny contains msg if {
	input.kind == "PodDisruptionBudget"
	input.spec.maxUnavailable in {0, "0", "0%"}
	msg := sprintf("%s: maxUnavailable 0 blocks node drains", [lib.name])
}

deny contains msg if {
	input.kind == "PodDisruptionBudget"
	input.spec.minAvailable == "100%"
	msg := sprintf("%s: minAvailable 100%% blocks node drains", [lib.name])
}

deny contains msg if {
	input.kind == "HorizontalPodAutoscaler"
	object.get(input.spec, "minReplicas", 1) < 2
	msg := sprintf("%s: minReplicas must be >= 2", [lib.name])
}

warn contains msg if {
	input.kind == "Deployment"
	object.get(input.spec, "replicas", 1) >= 2
	object.get(lib.pod_spec, "topologySpreadConstraints", null) in {null, []}
	not lib.pod_spec.affinity.podAntiAffinity
	msg := sprintf("%s: add topologySpreadConstraints or podAntiAffinity to spread replicas", [lib.name])
}

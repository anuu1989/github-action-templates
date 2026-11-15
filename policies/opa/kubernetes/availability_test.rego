package kubernetes.availability_test

import data.kubernetes.availability
import data.kubernetes.fixtures as f
import rego.v1

test_single_replica_warns if {
	d := json.patch(f.deployment, [{"op": "replace", "path": "/spec/replicas", "value": 1}])
	count(availability.warn) == 1 with input as d
}

test_no_spread_warns if {
	d := json.patch(f.deployment, [{"op": "remove", "path": "/spec/template/spec/topologySpreadConstraints"}])
	count(availability.warn) == 1 with input as d
}

test_missing_liveness_warns if {
	c := object.remove(f.container, ["livenessProbe"])
	d := json.patch(f.deployment, [{"op": "replace", "path": "/spec/template/spec/containers/0", "value": c}])
	count(availability.warn) == 1 with input as d
}

test_blocking_pdbs_denied if {
	count(availability.deny) == 1 with input as {"kind": "PodDisruptionBudget", "metadata": {"name": "p"}, "spec": {"maxUnavailable": 0}}
	count(availability.deny) == 1 with input as {"kind": "PodDisruptionBudget", "metadata": {"name": "p"}, "spec": {"minAvailable": "100%"}}
}

test_hpa_floor_denied if {
	count(availability.deny) == 1 with input as {"kind": "HorizontalPodAutoscaler", "metadata": {"name": "h"}, "spec": {"minReplicas": 1}}
}

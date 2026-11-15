package kubernetes.networking_test

import data.kubernetes.fixtures as f
import data.kubernetes.networking
import rego.v1

svc(spec, annotations, labels) := json.patch(f.service, [
	{"op": "add", "path": "/spec", "value": spec},
	{"op": "add", "path": "/metadata/annotations", "value": annotations},
	{"op": "add", "path": "/metadata/labels", "value": object.union(f.labels, labels)},
])

test_nodeport_denied if {
	count(networking.deny) == 1 with input as svc({"type": "NodePort"}, {}, {})
}

test_public_lb_denied if {
	count(networking.deny) == 1 with input as svc({"type": "LoadBalancer"}, {}, {})
}

test_internal_lb_allowed if {
	a := {"service.beta.kubernetes.io/aws-load-balancer-scheme": "internal"}
	count(networking.deny) == 0 with input as svc({"type": "LoadBalancer"}, a, {})
}

test_explicitly_public_lb_allowed if {
	count(networking.deny) == 0 with input as svc({"type": "LoadBalancer"}, {}, {"exposure": "public"})
}

test_external_ips_denied if {
	count(networking.deny) == 1 with input as svc({"type": "ClusterIP", "externalIPs": ["1.2.3.4"]}, {}, {})
}

test_ingress_without_tls_or_host_denied if {
	i := json.patch(f.ingress, [{"op": "add", "path": "/spec", "value": {"rules": [{"http": {}}]}}])
	count(networking.deny) == 2 with input as i
}

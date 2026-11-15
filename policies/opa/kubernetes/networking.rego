# Exposure controls for Services & Ingresses.
package kubernetes.networking

import data.kubernetes.lib
import rego.v1

internal_lb if lib.annotations["service.beta.kubernetes.io/aws-load-balancer-scheme"] == "internal"

internal_lb if lib.annotations["service.beta.kubernetes.io/aws-load-balancer-internal"] == "true"

internal_lb if lib.annotations["networking.gke.io/load-balancer-type"] == "Internal"

internal_lb if lib.annotations["service.beta.kubernetes.io/azure-load-balancer-internal"] == "true"

deny contains msg if {
	input.kind == "Service"
	input.spec.type == "NodePort"
	msg := sprintf("%s: NodePort services are not allowed: use an Ingress or internal LoadBalancer", [lib.name])
}

deny contains msg if {
	input.kind == "Service"
	input.spec.type == "LoadBalancer"
	not internal_lb
	not lib.labels.exposure == "public"
	msg := sprintf("%s: LoadBalancer must be internal (annotation) or explicitly labelled exposure=public", [lib.name])
}

deny contains msg if {
	input.kind == "Service"
	count(object.get(input.spec, "externalIPs", [])) > 0
	msg := sprintf("%s: spec.externalIPs is not allowed (CVE-2020-8554)", [lib.name])
}

deny contains msg if {
	input.kind == "Ingress"
	count(object.get(input.spec, "tls", [])) == 0
	msg := sprintf("%s: Ingress must terminate TLS (spec.tls)", [lib.name])
}

deny contains msg if {
	input.kind == "Ingress"
	some rule in input.spec.rules
	not rule.host
	msg := sprintf("%s: every Ingress rule must set a host (no catch-all)", [lib.name])
}

# Pod Security Standards ("restricted" profile) beyond the basics in security.rego.
package kubernetes.pod_security

import data.kubernetes.lib
import rego.v1

allowed_added_capabilities := {"NET_BIND_SERVICE"}

ok_seccomp := {"RuntimeDefault", "Localhost"}

drops_all(c) if {
	some cap in c.securityContext.capabilities.drop
	upper(cap) == "ALL"
}

deny contains msg if {
	some c in lib.containers
	not drops_all(c)
	msg := sprintf("%s: container '%s' must drop ALL capabilities", [lib.name, c.name])
}

deny contains msg if {
	some c in lib.containers
	some cap in c.securityContext.capabilities.add
	not upper(cap) in allowed_added_capabilities
	msg := sprintf("%s: container '%s' adds capability %s", [lib.name, c.name, cap])
}

seccomp_ok(c) if c.securityContext.seccompProfile.type in ok_seccomp

seccomp_ok(c) if {
	lib.pod_spec.securityContext.seccompProfile.type in ok_seccomp
	not c.securityContext.seccompProfile
}

deny contains msg if {
	some c in lib.containers
	not seccomp_ok(c)
	msg := sprintf("%s: container '%s' needs seccompProfile RuntimeDefault (pod or container level)", [lib.name, c.name])
}

deny contains msg if {
	some v in lib.pod_spec.volumes
	v.hostPath
	msg := sprintf("%s: hostPath volume '%s' is not allowed", [lib.name, v.name])
}

deny contains msg if {
	some c in lib.containers
	some p in c.ports
	p.hostPort
	msg := sprintf("%s: container '%s' uses hostPort %d", [lib.name, c.name, p.hostPort])
}

deny contains msg if {
	some c in lib.containers
	c.securityContext.runAsUser == 0
	msg := sprintf("%s: container '%s' sets runAsUser 0 (root)", [lib.name, c.name])
}

warn contains msg if {
	lib.is_workload
	not lib.pod_spec.automountServiceAccountToken == false
	msg := sprintf("%s: set automountServiceAccountToken: false unless the pod calls the Kubernetes API", [lib.name])
}

warn contains msg if {
	lib.is_workload
	object.get(lib.pod_spec, "serviceAccountName", "default") == "default"
	msg := sprintf("%s: uses the 'default' ServiceAccount: create a dedicated one", [lib.name])
}

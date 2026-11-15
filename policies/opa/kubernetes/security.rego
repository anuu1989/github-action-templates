# Kubernetes workload hardening (evaluated per YAML document by conftest).
package kubernetes.security

import data.kubernetes.lib
import rego.v1

pod_spec := lib.pod_spec

containers := lib.containers

name := lib.name

deny contains msg if {
	some c in containers
	c.securityContext.privileged == true
	msg := sprintf("%s: container '%s' must not run privileged", [name, c.name])
}

deny contains msg if {
	some c in containers
	not runs_as_non_root(c)
	msg := sprintf("%s: container '%s' must set securityContext.runAsNonRoot = true (pod or container level)", [name, c.name])
}

runs_as_non_root(c) if c.securityContext.runAsNonRoot == true

runs_as_non_root(c) if {
	pod_spec.securityContext.runAsNonRoot == true
	not c.securityContext.runAsNonRoot == false
}

deny contains msg if {
	some c in containers
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("%s: container '%s' must set securityContext.allowPrivilegeEscalation = false", [name, c.name])
}

deny contains msg if {
	some c in containers
	mutable_tag(c.image)
	msg := sprintf("%s: container '%s' image '%s' must use a pinned tag or digest (not latest/untagged)", [name, c.name, c.image])
}

mutable_tag(image) if endswith(image, ":latest")

mutable_tag(image) if {
	not contains(image, "@")
	parts := split(image, "/")
	not contains(parts[count(parts) - 1], ":")
}

deny contains msg if {
	some c in lib.app_containers
	not c.resources.limits.memory
	msg := sprintf("%s: container '%s' must set resources.limits.memory", [name, c.name])
}

deny contains msg if {
	some field in ["hostNetwork", "hostPID", "hostIPC"]
	pod_spec[field] == true
	msg := sprintf("%s: must not set %s = true", [name, field])
}

warn contains msg if {
	some c in lib.app_containers
	not c.resources.requests.cpu
	msg := sprintf("%s: container '%s' should set resources.requests.cpu", [name, c.name])
}

warn contains msg if {
	some c in containers
	not c.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("%s: container '%s' should set readOnlyRootFilesystem = true", [name, c.name])
}

warn contains msg if {
	input.kind in {"Deployment", "StatefulSet"}
	some c in lib.app_containers
	not c.readinessProbe
	msg := sprintf("%s: container '%s' should define a readinessProbe", [name, c.name])
}

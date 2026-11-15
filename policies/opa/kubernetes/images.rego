# Supply chain: images only from approved registries; no imagePullPolicy Never in clusters.
# Override with conftest --data: allowed_registries: ["ghcr.io/acme/", "registry.acme.io/"]
package kubernetes.images

import data.kubernetes.lib
import rego.v1

default_registries := {"ghcr.io/acme/", "public.ecr.aws/acme/", "registry.k8s.io/"}

allowed_registries := {r | some r in data.allowed_registries} if {
	data.allowed_registries
} else := default_registries

# Any private ECR registry is allowed
allowed(image) if regex.match(`^[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/`, image)

allowed(image) if {
	some prefix in allowed_registries
	startswith(image, prefix)
}

deny contains msg if {
	some c in lib.containers
	not allowed(c.image)
	msg := sprintf("%s: container '%s' image '%s' is not from an approved registry", [lib.name, c.name, c.image])
}

warn contains msg if {
	some c in lib.containers
	c.imagePullPolicy == "Never"
	msg := sprintf("%s: container '%s' uses imagePullPolicy Never", [lib.name, c.name])
}

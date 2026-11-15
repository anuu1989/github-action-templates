package kubernetes.images_test

import data.kubernetes.fixtures as f
import data.kubernetes.images
import rego.v1

test_docker_hub_denied if {
	count(images.deny) == 1 with input as f.with_container({"image": "nginx:1.27"})
}

test_private_ecr_allowed if {
	count(images.deny) == 0 with input as f.with_container({"image": "123456789012.dkr.ecr.eu-west-1.amazonaws.com/web:1.0"})
}

test_registries_overridable if {
	count(images.deny) == 0 with input as f.with_container({"image": "registry.internal/web:1.0"})
		with data.allowed_registries as ["registry.internal/"]
}

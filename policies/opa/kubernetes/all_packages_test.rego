# The compliant fixtures must pass every Kubernetes package with zero denies and zero warnings.
package kubernetes.all_packages_test

import data.kubernetes.availability
import data.kubernetes.fixtures
import data.kubernetes.images
import data.kubernetes.metadata
import data.kubernetes.networking
import data.kubernetes.pod_security
import data.kubernetes.rbac
import data.kubernetes.security
import rego.v1

findings := array.concat(
	[m | some m in (security.deny | security.warn)],
	array.concat(
		[m | some m in (pod_security.deny | pod_security.warn)],
		array.concat(
			[m | some m in (metadata.deny | metadata.warn)],
			array.concat(
				[m | some m in (images.deny | images.warn)],
				array.concat(
					[m | some m in networking.deny],
					array.concat([m | some m in (rbac.deny | rbac.warn)], [m | some m in (availability.deny | availability.warn)]),
				),
			),
		),
	),
)

test_compliant_deployment_clean if {
	findings == [] with input as fixtures.deployment
}

test_compliant_service_clean if {
	findings == [] with input as fixtures.service
}

test_compliant_ingress_clean if {
	findings == [] with input as fixtures.ingress
}

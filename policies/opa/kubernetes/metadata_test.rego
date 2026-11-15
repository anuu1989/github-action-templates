package kubernetes.metadata_test

import data.kubernetes.fixtures as f
import data.kubernetes.metadata
import rego.v1

test_missing_team_label_denied if {
	d := json.patch(f.deployment, [{"op": "remove", "path": "/metadata/labels/team"}])
	count(metadata.deny) == 1 with input as d
}

test_default_namespace_denied if {
	d := json.patch(f.service, [{"op": "replace", "path": "/metadata/namespace", "value": "default"}])
	count(metadata.deny) == 1 with input as d
}

test_pod_template_label_warns if {
	d := json.patch(f.deployment, [{"op": "replace", "path": "/spec/template/metadata/labels", "value": {}}])
	count(metadata.warn) == 1 with input as d
}

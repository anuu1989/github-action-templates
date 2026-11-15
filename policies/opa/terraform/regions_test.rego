package terraform.regions_test

import data.terraform.regions
import rego.v1

provider(region) := {"configuration": {"provider_config": {"aws": {"name": "aws", "expressions": {"region": {"constant_value": region}}}}}}

test_unapproved_provider_region_denied if {
	count(regions.deny) == 1 with input as provider("ap-south-1")
}

test_approved_provider_region_allowed if {
	count(regions.deny) == 0 with input as provider("eu-west-1")
}

test_per_resource_region_denied if {
	p := {"resource_changes": [{"address": "aws_s3_bucket.b", "type": "aws_s3_bucket", "change": {"actions": ["create"], "after": {"region": "sa-east-1"}}}]}
	count(regions.deny) == 1 with input as p
}

test_regions_overridable_with_data if {
	count(regions.deny) == 0 with input as provider("ap-south-1") with data.allowed_regions as ["ap-south-1"]
}

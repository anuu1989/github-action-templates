# Data residency: only approved AWS regions (provider config and per-resource `region`, AWS provider v6+).
# Override with conftest --data: allowed_regions: [eu-west-1, eu-central-1]
package terraform.regions

import data.terraform.lib
import rego.v1

default_regions := {"us-east-1", "us-west-2", "eu-west-1"}

allowed_regions := {r | some r in data.allowed_regions} if {
	data.allowed_regions
} else := default_regions

deny contains msg if {
	some key, provider in input.configuration.provider_config
	provider.name == "aws"
	region := provider.expressions.region.constant_value
	not region in allowed_regions
	msg := sprintf("provider %s targets region '%s'; allowed: %v", [key, region, sort(allowed_regions)])
}

deny contains msg if {
	some rc in lib.resources_changing
	startswith(rc.type, "aws_")
	region := rc.change.after.region
	is_string(region)
	not region in allowed_regions
	msg := sprintf("%s is placed in region '%s'; allowed: %v", [rc.address, region, sort(allowed_regions)])
}

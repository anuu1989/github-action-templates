# Every taggable AWS resource must carry the mandatory tags (provider default_tags count, via tags_all).
package terraform.tags

import data.terraform.lib
import rego.v1

required_tags := {"Owner", "Environment", "CostCenter"}

taggable(rc) if {
	startswith(rc.type, "aws_")
	some key in {"tags", "tags_all"}
	key in object.keys(rc.change.after)
}

resource_tags(rc) := tags if {
	tags := rc.change.after.tags_all
	is_object(tags)
} else := tags if {
	tags := rc.change.after.tags
	is_object(tags)
} else := {}

deny contains msg if {
	some rc in lib.resources_changing
	taggable(rc)
	not lib.unknown(rc, "tags_all")
	missing := required_tags - object.keys(resource_tags(rc))
	count(missing) > 0
	msg := sprintf("%s is missing required tags: %v", [rc.address, sort(missing)])
}

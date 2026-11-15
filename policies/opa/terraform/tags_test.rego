package terraform.tags_test

import data.terraform.tags
import rego.v1

all_tags := {"Owner": "platform", "Environment": "prod", "CostCenter": "1234"}

plan(type, actions, after) := {"resource_changes": [{
	"address": sprintf("%s.this", [type]),
	"type": type,
	"change": {"actions": actions, "after": after, "after_unknown": {}},
}]}

test_missing_tags_denied if {
	result := tags.deny with input as plan("aws_s3_bucket", ["create"], {"tags": {"Owner": "a"}, "tags_all": {"Owner": "a"}})
	count(result) == 1
}

test_all_tags_via_default_tags_allowed if {
	result := tags.deny with input as plan("aws_s3_bucket", ["create"], {"tags": null, "tags_all": all_tags})
	count(result) == 0
}

test_null_tags_denied if {
	result := tags.deny with input as plan("aws_sqs_queue", ["update"], {"tags": null})
	count(result) == 1
}

test_non_taggable_resource_ignored if {
	result := tags.deny with input as plan("aws_iam_role_policy_attachment", ["create"], {"role": "x"})
	count(result) == 0
}

test_delete_ignored if {
	result := tags.deny with input as plan("aws_s3_bucket", ["delete"], null)
	count(result) == 0
}

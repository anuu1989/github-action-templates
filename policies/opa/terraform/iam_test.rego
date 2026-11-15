package terraform.iam_test

import data.terraform.iam
import rego.v1

plan(type, after) := {"resource_changes": [{
	"address": sprintf("%s.this", [type]),
	"type": type,
	"change": {"actions": ["create"], "after": after, "after_unknown": {}},
}]}

doc(statements) := json.marshal({"Version": "2012-10-17", "Statement": statements})

test_admin_policy_denied if {
	p := plan("aws_iam_policy", {"policy": doc([{"Effect": "Allow", "Action": "*", "Resource": "*"}])})
	count(iam.deny) == 1 with input as p
}

test_iam_star_on_all_resources_denied if {
	p := plan("aws_iam_role_policy", {"policy": doc([{"Effect": "Allow", "Action": ["s3:GetObject", "iam:*"], "Resource": ["*"]}])})
	count(iam.deny) == 1 with input as p
}

test_scoped_policy_allowed if {
	p := plan("aws_iam_policy", {"policy": doc([{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::bucket/*"}])})
	count(iam.deny) == 0 with input as p
}

test_deny_statement_with_wildcards_allowed if {
	p := plan("aws_iam_policy", {"policy": doc([{"Effect": "Deny", "Action": "*", "Resource": "*"}])})
	count(iam.deny) == 0 with input as p
}

test_public_bucket_policy_denied if {
	p := plan("aws_s3_bucket_policy", {"policy": doc([{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}])})
	count(iam.deny) == 1 with input as p
}

test_public_principal_with_condition_allowed if {
	p := plan("aws_s3_bucket_policy", {"policy": doc([{
		"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*",
		"Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-123"}},
	}])})
	count(iam.deny) == 0 with input as p
}

test_role_trust_anyone_denied if {
	p := plan("aws_iam_role", {"assume_role_policy": doc([{"Effect": "Allow", "Principal": {"AWS": ["*"]}, "Action": "sts:AssumeRole"}])})
	count(iam.deny) == 1 with input as p
}

test_access_key_denied if {
	count(iam.deny) == 1 with input as plan("aws_iam_access_key", {"user": "ci"})
}

test_admin_attachment_denied if {
	count(iam.deny) == 1 with input as plan("aws_iam_role_policy_attachment", {"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"})
}

test_not_action_warns if {
	p := plan("aws_iam_policy", {"policy": doc([{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}])})
	count(iam.warn) == 1 with input as p
}

# IAM & resource policies: no admin wildcards, no public principals, no long-lived user keys.
package terraform.iam

import data.terraform.lib
import rego.v1

# resource type -> attribute holding a JSON policy document
policy_attrs := {
	"aws_iam_policy": "policy",
	"aws_iam_role_policy": "policy",
	"aws_iam_user_policy": "policy",
	"aws_iam_group_policy": "policy",
	"aws_iam_role": "assume_role_policy",
	"aws_s3_bucket_policy": "policy",
	"aws_sqs_queue_policy": "policy",
	"aws_sns_topic_policy": "policy",
	"aws_kms_key": "policy",
	"aws_ecr_repository_policy": "policy",
	"aws_secretsmanager_secret_policy": "policy",
	"aws_lambda_layer_version_permission": "policy",
}

resource_policy_types := {
	"aws_s3_bucket_policy", "aws_sqs_queue_policy", "aws_sns_topic_policy", "aws_kms_key",
	"aws_ecr_repository_policy", "aws_secretsmanager_secret_policy", "aws_iam_role",
}

# Services where "<svc>:*" on "*" is effectively privilege escalation.
sensitive_services := {"iam", "sts", "kms", "organizations", "secretsmanager"}

statements contains [rc, s] if {
	some rc in lib.resources_changing
	attr := policy_attrs[rc.type]
	not lib.unknown(rc, attr)
	some s in lib.policy_statements(rc.change.after[attr])
}

allows(s) if s.Effect == "Allow"

actions(s) := lib.as_list(object.get(s, "Action", []))

resources(s) := lib.as_list(object.get(s, "Resource", []))

deny contains msg if {
	some [rc, s] in statements
	allows(s)
	"*" in actions(s)
	"*" in resources(s)
	msg := sprintf("%s grants full admin (Action \"*\" on Resource \"*\")", [rc.address])
}

deny contains msg if {
	some [rc, s] in statements
	allows(s)
	"*" in resources(s)
	some action in actions(s)
	parts := split(lower(action), ":")
	parts[0] in sensitive_services
	parts[1] == "*"
	msg := sprintf("%s grants '%s' on all resources", [rc.address, action])
}

warn contains msg if {
	some [rc, s] in statements
	allows(s)
	s.NotAction
	msg := sprintf("%s uses Allow + NotAction: prefer explicit Action lists", [rc.address])
}

public_principal(p) if p == "*"

public_principal(p) if "*" in lib.as_list(p.AWS)

deny contains msg if {
	some [rc, s] in statements
	rc.type in resource_policy_types
	allows(s)
	public_principal(s.Principal)
	not s.Condition
	msg := sprintf("%s allows a public principal (\"*\") without a Condition", [rc.address])
}

deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_iam_access_key"
	msg := sprintf("%s creates a long-lived IAM access key: use OIDC / IAM roles instead", [rc.address])
}

warn contains msg if {
	some rc in lib.resources_changing
	rc.type in {"aws_iam_user_policy", "aws_iam_user_policy_attachment"}
	msg := sprintf("%s attaches permissions directly to a user: use groups or roles", [rc.address])
}

deny contains msg if {
	some rc in lib.resources_changing
	rc.type in {"aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment", "aws_iam_group_policy_attachment"}
	rc.change.after.policy_arn == "arn:aws:iam::aws:policy/AdministratorAccess"
	msg := sprintf("%s attaches AdministratorAccess", [rc.address])
}

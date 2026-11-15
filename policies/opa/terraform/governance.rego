# Governance: minimum Terraform version, approved module sources, pinned module versions.
package terraform.governance

import rego.v1

min_terraform_version := "1.5.0"

approved_module_prefixes := [
	"./", "../",
	"app.terraform.io/acme/",
	"git::https://github.com/acme/",
	"terraform-aws-modules/",
]

deny contains msg if {
	input.terraform_version
	semver.compare(input.terraform_version, min_terraform_version) < 0
	msg := sprintf("plan produced by Terraform %s; minimum is %s", [input.terraform_version, min_terraform_version])
}

module_calls contains [name, call] if {
	some name, call in input.configuration.root_module.module_calls
}

local_source(src) if startswith(src, "./")

local_source(src) if startswith(src, "../")

git_source(src) if regex.match(`^(git::|github\.com/|git@)`, src)

deny contains msg if {
	some [name, call] in module_calls
	not approved_source(call.source)
	msg := sprintf("module.%s source '%s' is not from an approved location", [name, call.source])
}

approved_source(src) if {
	some prefix in approved_module_prefixes
	startswith(src, prefix)
}

deny contains msg if {
	some [name, call] in module_calls
	git_source(call.source)
	not contains(call.source, "?ref=")
	msg := sprintf("module.%s git source must be pinned with ?ref=<tag|sha>", [name])
}

warn contains msg if {
	some [name, call] in module_calls
	not local_source(call.source)
	not git_source(call.source)
	not call.version_constraint
	msg := sprintf("module.%s registry source has no version constraint", [name])
}

package terraform.governance_test

import data.terraform.governance
import rego.v1

with_modules(calls) := {"terraform_version": "1.9.8", "configuration": {"root_module": {"module_calls": calls}}}

test_old_terraform_denied if {
	count(governance.deny) == 1 with input as {"terraform_version": "1.3.9"}
}

test_new_terraform_allowed if {
	count(governance.deny) == 0 with input as {"terraform_version": "1.9.8"}
}

test_approved_modules_allowed if {
	m := with_modules({
		"vpc": {"source": "terraform-aws-modules/vpc/aws", "version_constraint": "~> 5.0"},
		"app": {"source": "./modules/app"},
		"shared": {"source": "git::https://github.com/acme/tf-modules.git//s3?ref=v1.2.0"},
	})
	count(governance.deny) == 0 with input as m
	count(governance.warn) == 0 with input as m
}

test_unapproved_and_unpinned_git_denied if {
	m := with_modules({"x": {"source": "git::https://github.com/random/mod.git"}})
	count(governance.deny) == 2 with input as m
}

test_registry_without_version_warns if {
	count(governance.warn) == 1 with input as with_modules({"vpc": {"source": "terraform-aws-modules/vpc/aws"}})
}

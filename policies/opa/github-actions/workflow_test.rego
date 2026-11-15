package github_actions_test

import data.github_actions
import rego.v1

safe := {
	"on": {"pull_request": {}},
	"permissions": {"contents": "read"},
	"jobs": {"build": {
		"runs-on": "ubuntu-latest",
		"timeout-minutes": 15,
		"steps": [
			{"uses": "actions/checkout@v4"},
			{"name": "greet", "env": {"TITLE": "${{ github.event.pull_request.title }}"}, "run": "echo \"$TITLE\""},
			{"uses": "aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502", "with": {"role-to-assume": "arn:aws:iam::1:role/x"}},
		],
	}},
}

with_step(step) := json.patch(safe, [{"op": "add", "path": "/jobs/build/steps/-", "value": step}])

test_safe_workflow_clean if {
	count(github_actions.deny) == 0 with input as safe
	count(github_actions.warn) == 0 with input as safe
}

test_yaml11_on_key_supported if {
	w := json.patch(safe, [{"op": "remove", "path": "/on"}, {"op": "add", "path": "/true", "value": ["push", "pull_request_target"]}])
	github_actions.triggers == {"push", "pull_request_target"} with input as w
}

test_script_injection_denied if {
	count(github_actions.deny) == 1 with input as with_step({"run": "echo \"${{ github.event.issue.title }}\""})
	count(github_actions.deny) == 1 with input as with_step({"run": "git checkout ${{ github.head_ref }}"})
}

test_github_script_injection_denied if {
	s := {"uses": "actions/github-script@v7", "with": {"script": "console.log('${{ github.event.comment.body }}')"}}
	count(github_actions.deny) == 1 with input as with_step(s)
}

test_safe_context_in_run_allowed if {
	count(github_actions.deny) == 0 with input as with_step({"run": "echo ${{ github.sha }} ${{ github.event.pull_request.number }}"})
}

test_pwn_request_denied if {
	w := json.patch(safe, [
		{"op": "replace", "path": "/on", "value": {"pull_request_target": {}}},
		{"op": "replace", "path": "/jobs/build/steps/0", "value": {"uses": "actions/checkout@v4", "with": {"ref": "${{ github.event.pull_request.head.sha }}"}}},
	])
	count(github_actions.deny) == 1 with input as w
}

test_write_all_denied if {
	count(github_actions.deny) == 1 with input as json.patch(safe, [{"op": "replace", "path": "/permissions", "value": "write-all"}])
}

test_missing_permissions_warns if {
	count(github_actions.warn) == 1 with input as json.patch(safe, [{"op": "remove", "path": "/permissions"}])
}

test_branch_pinned_action_denied if {
	count(github_actions.deny) == 1 with input as with_step({"uses": "some-org/some-action@main"})
}

test_tag_pinned_third_party_warns if {
	count(github_actions.warn) == 1 with input as with_step({"uses": "hashicorp/setup-terraform@v3"})
}

test_self_hosted_on_pr_denied if {
	count(github_actions.deny) == 1 with input as json.patch(safe, [{"op": "replace", "path": "/jobs/build/runs-on", "value": ["self-hosted", "linux"]}])
}

test_static_aws_keys_denied if {
	s := {"uses": "aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502", "with": {"aws-access-key-id": "x", "aws-secret-access-key": "${{ secrets.KEY }}"}}
	count(github_actions.deny) == 1 with input as with_step(s)
}

test_unsecure_commands_denied if {
	count(github_actions.deny) == 1 with input as json.patch(safe, [{"op": "add", "path": "/env", "value": {"ACTIONS_ALLOW_UNSECURE_COMMANDS": true}}])
}

test_no_timeout_and_secrets_inherit_warn if {
	w := json.patch(safe, [
		{"op": "remove", "path": "/jobs/build/timeout-minutes"},
		{"op": "add", "path": "/jobs/deploy", "value": {"uses": "acme/templates/.github/workflows/x.yml@v1", "secrets": "inherit"}},
	])
	count(github_actions.warn) == 2 with input as w
}

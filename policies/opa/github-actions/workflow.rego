# GitHub Actions workflow security (conftest test .github/workflows/*.yml).
# Covers script injection, pwn-request patterns, token permissions, action pinning and runner hygiene.
package github_actions

import rego.v1

# YAML 1.1 parsers (incl. conftest's) read the `on:` key as boolean true -> "true".
triggers_raw := input.on if {
	input.on
} else := input["true"] if {
	input["true"]
} else := {}

triggers contains t if {
	is_string(triggers_raw)
	t := triggers_raw
}

triggers contains t if {
	is_array(triggers_raw)
	some t in triggers_raw
}

triggers contains t if {
	is_object(triggers_raw)
	some t, _ in triggers_raw
}

privileged_triggers := {"pull_request_target", "workflow_run", "issue_comment"}

as_list(x) := x if {
	is_array(x)
} else := [x]

steps contains [job_id, step] if {
	some job_id, job in input.jobs
	some step in object.get(job, "steps", [])
}

# --- Script injection ------------------------------------------------------------------------
untrusted_context := `\$\{\{\s*(github\.head_ref|github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref|head\.label|head\.repo\.default_branch)|comment\.body|review\.body|review_comment\.body|discussion\.(title|body)|pages\.[^}]*\.page_name|commits\.[^}]*\.(message|author\.(email|name))|head_commit\.(message|author\.(email|name))|workflow_run\.(head_branch|head_commit\.message|display_title)))`

deny contains msg if {
	some [job_id, step] in steps
	regex.match(untrusted_context, object.get(step, "run", ""))
	msg := sprintf("job '%s' step '%s': untrusted github.event data interpolated into run: pass it via env: instead", [job_id, step_name(step)])
}

deny contains msg if {
	some [job_id, step] in steps
	startswith(object.get(step, "uses", ""), "actions/github-script")
	regex.match(untrusted_context, object.get(object.get(step, "with", {}), "script", ""))
	msg := sprintf("job '%s' step '%s': untrusted github.event data interpolated into github-script", [job_id, step_name(step)])
}

step_name(step) := object.get(step, "name", object.get(step, "uses", "run"))

# --- Pwn request: privileged trigger + checkout of PR code -----------------------------------
deny contains msg if {
	some t in triggers
	t in privileged_triggers
	some [job_id, step] in steps
	startswith(object.get(step, "uses", ""), "actions/checkout")
	ref := object.get(object.get(step, "with", {}), "ref", "")
	regex.match(`github\.event\.(pull_request\.head|workflow_run\.head)|github\.head_ref|refs/pull/`, ref)
	msg := sprintf("job '%s': '%s' workflow checks out untrusted PR code (%s)", [job_id, t, ref])
}

# --- Token permissions ----------------------------------------------------------------------
deny contains "top-level permissions: write-all is not allowed" if input.permissions == "write-all"

deny contains msg if {
	some job_id, job in input.jobs
	job.permissions == "write-all"
	msg := sprintf("job '%s': permissions: write-all is not allowed", [job_id])
}

warn contains "no top-level permissions block: GITHUB_TOKEN gets the repository default (often write)" if {
	not input.permissions
	some job_id, job in input.jobs
	not job.permissions
}

# --- Third-party action pinning -------------------------------------------------------------
first_party_owners := {"actions", "github"}

third_party(uses) if {
	not startswith(uses, "./")
	not startswith(uses, "docker://")
	not split(uses, "/")[0] in first_party_owners
}

action_ref(uses) := split(uses, "@")[1]

deny contains msg if {
	some [job_id, step] in steps
	uses := object.get(step, "uses", "")
	third_party(uses)
	action_ref(uses) in {"main", "master", "latest", "HEAD"}
	msg := sprintf("job '%s': %s tracks a mutable branch: pin to a release tag or commit SHA", [job_id, uses])
}

warn contains msg if {
	some [job_id, step] in steps
	uses := object.get(step, "uses", "")
	third_party(uses)
	ref := action_ref(uses)
	not ref in {"main", "master", "latest", "HEAD"}
	not regex.match(`^[0-9a-f]{40}$`, ref)
	msg := sprintf("job '%s': pin third-party action %s to a full commit SHA", [job_id, uses])
}

# --- Runner & job hygiene -------------------------------------------------------------------
deny contains msg if {
	some t in triggers
	t in {"pull_request", "pull_request_target"}
	some job_id, job in input.jobs
	"self-hosted" in as_list(object.get(job, "runs-on", []))
	msg := sprintf("job '%s': self-hosted runners must not run pull request workflows", [job_id])
}

warn contains msg if {
	some job_id, job in input.jobs
	not job.uses
	not job["timeout-minutes"]
	msg := sprintf("job '%s' has no timeout-minutes (default is 360)", [job_id])
}

warn contains msg if {
	some job_id, job in input.jobs
	job.secrets == "inherit"
	msg := sprintf("job '%s' uses secrets: inherit: pass only the secrets the called workflow needs", [job_id])
}

deny contains msg if {
	some [job_id, step] in steps
	startswith(object.get(step, "uses", ""), "aws-actions/configure-aws-credentials")
	object.get(step, "with", {})["aws-secret-access-key"]
	msg := sprintf("job '%s': static AWS keys: use OIDC (role-to-assume) instead", [job_id])
}

deny contains "ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables the deprecated set-env/add-path commands" if {
	some env in env_blocks
	lower(sprintf("%v", [env.ACTIONS_ALLOW_UNSECURE_COMMANDS])) == "true"
}

env_blocks contains input.env if input.env

env_blocks contains job.env if {
	some job in input.jobs
	job.env
}

env_blocks contains step.env if {
	some [_, step] in steps
	step.env
}

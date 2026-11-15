# Policy as code: OPA/Conftest and Checkov

Two complementary engines are included. Both come with **unit tests and end-to-end scenario fixtures**, so a policy change that silently stops catching something fails CI.

| | **OPA / Conftest** (`policies/opa`) | **Checkov** (`policies/checkov`) |
|---|---|---|
| Built-in rules | none (you write them) | 1000+ (CIS, AWS, K8s, Docker, GHA…) |
| Input | any JSON/YAML/HCL/Dockerfile, **Terraform plan JSON**, workflow YAML | Terraform source/plan, CFN/SAM, K8s, Helm, Dockerfile, GHA, secrets |
| Best for | org-specific rules on *resolved* plan values, cross-resource logic, data-driven limits | broad baseline coverage, graph/connection rules, compliance reports |
| Custom rules | Rego + `opa test` | Python or YAML graph policies |

---

## OPA policy library

154 unit tests (`opa test policies/opa`) and 9 end-to-end Conftest scenarios (`tests/run-conftest-fixtures.sh`).

### Terraform plan (`policies/opa/terraform`, input: `terraform show -json tfplan`)

| Package | Deny | Warn |
|---|---|---|
| `terraform.tags` | missing `Owner` / `Environment` / `CostCenter` (honours provider `default_tags` via `tags_all`) | |
| `terraform.security_groups` | 22/3389 open to `0.0.0.0/0` or `::/0` (inline, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`, port ranges, protocol `-1`) | |
| `terraform.iam` | `*`:`*` admin; `iam:*`/`sts:*`/`kms:*`/`organizations:*`/`secretsmanager:*` on `*`; public principal without `Condition` in resource and trust policies; `aws_iam_access_key`; `AdministratorAccess` attachment | `Allow` + `NotAction`; policies attached directly to users |
| `terraform.s3` | public ACLs; incomplete public access block | versioning suspended |
| `terraform.rds` | unencrypted storage; `publicly_accessible` | no deletion protection |
| `terraform.kms` | symmetric key without rotation | deletion window < 14 days |
| `terraform.encryption` | unencrypted EBS / EFS / Redshift / DocDB / Neptune / ElastiCache (rest + transit) / instance block devices / SQS | SNS and log groups without a CMK |
| `terraform.logging` | log groups that never expire; single-region CloudTrail or no log validation; EKS without `audit` logs | ALB access logs off; new VPC without a flow log |
| `terraform.network` | HTTP listener not redirecting; pre-TLS 1.2 `ssl_policy`; EKS endpoint open to the world; CloudFront `allow-all` or old TLS | ALB `drop_invalid_header_fields`; subnets auto-assigning public IPs |
| `terraform.lambda` | function URL `NONE` auth; `principal = "*"`; deprecated runtimes; secret-looking env var names | service principal without `source_arn`; X-Ray off |
| `terraform.ecr` | mutable tags; no scan on push | no lifecycle policy |
| `terraform.ec2` | unapproved instance family (data-driven); IMDSv1 | |
| `terraform.regions` | provider or per-resource region outside the allow-list (data-driven) | |
| `terraform.governance` | Terraform < 1.5; module sources outside approved prefixes; unpinned git modules | registry module without a version constraint |
| `terraform.blast_radius` | `deny_too_many_deletes` (> 5 by default) | > 50 changes |
| `terraform.destroy` | `deny_protected_destroy`: destroy or replace of stateful resources | every destroy |

### Kubernetes (`policies/opa/kubernetes`, one input per YAML document)

| Package | Deny | Warn |
|---|---|---|
| `kubernetes.security` | privileged; not `runAsNonRoot`; `allowPrivilegeEscalation`; `:latest` or untagged image; no memory limit; `hostNetwork`/`hostPID`/`hostIPC` | no CPU request; writable root FS; no readiness probe |
| `kubernetes.pod_security` | capabilities not dropping `ALL`; added capabilities other than `NET_BIND_SERVICE`; seccomp not `RuntimeDefault`; `hostPath`; `hostPort`; `runAsUser: 0` | SA token automount; `default` ServiceAccount |
| `kubernetes.metadata` | missing `app.kubernetes.io/name` / `team`; `default` namespace | pod template without the name label |
| `kubernetes.images` | image outside approved registries (data-driven; any private ECR is allowed) | `imagePullPolicy: Never` |
| `kubernetes.networking` | `NodePort`; public `LoadBalancer` without internal annotation or `exposure=public`; `externalIPs`; Ingress without TLS or without host | |
| `kubernetes.rbac` | `*` verbs/resources/apiGroups; `escalate`/`bind`/`impersonate`; cluster-wide secret reads; `cluster-admin` bindings; anonymous subjects | namespaced `list secrets` |
| `kubernetes.availability` | PDB that blocks drains; HPA `minReplicas` < 2 | replicas < 2; no liveness probe; no spread or anti-affinity |

`kubernetes.lib` holds shared helpers (`pod_spec`, `containers` for Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, Job and CronJob). `all_packages_test.rego` checks that the compliant fixtures produce **zero** findings across all packages.

### Dockerfile (`policies/opa/docker`)

**Deny:**
- `:latest` or untagged `FROM` (stage aliases are handled)
- root or missing `USER`
- `sudo`
- secrets in `ENV`/`ARG`
- `EXPOSE 22/23/3389`
- `chmod 777`
- `curl -k` / `--no-check-certificate`
- base image outside an approved registry (opt-in through `--data`)

**Warn:**
- `ADD`
- `curl | sh`
- no `HEALTHCHECK`
- apt without `--no-install-recommends` or without list cleanup
- `apt-get upgrade`
- `apk add` without `--no-cache`
- pip without `--no-cache-dir`
- shell-form `CMD`/`ENTRYPOINT`
- relative `WORKDIR`

### GitHub Actions workflows (`policies/opa/github-actions`)

| Deny | Warn |
|---|---|
| Script injection: untrusted `github.event.*` or `github.head_ref` in `run:` or `github-script` | No top-level `permissions` |
| Pwn request: `pull_request_target` / `workflow_run` / `issue_comment` checking out PR head code | Third-party action not pinned to a commit SHA |
| `permissions: write-all` | No `timeout-minutes` |
| Third-party action pinned to `@main`/`@master` | `secrets: inherit` |
| Self-hosted runners on PR triggers | |
| Static AWS keys in `configure-aws-credentials` | |
| `ACTIONS_ALLOW_UNSECURE_COMMANDS` | |

This handles the YAML 1.1 quirk where `on:` is parsed as the key `true`. The repo's own workflows and examples are checked against this pack in CI.

### Running locally

```bash
opa test policies/opa -v
opa fmt --list --fail policies/opa
tests/run-conftest-fixtures.sh            # needs conftest on PATH (or CONFTEST=/path/to/conftest)

terraform plan -out=tfplan && terraform show -json tfplan > tfplan.json
conftest test tfplan.json -p policies/opa/terraform --all-namespaces
conftest test k8s/ -p policies/opa/kubernetes --all-namespaces
conftest test Dockerfile -p policies/opa/docker
conftest test .github/workflows/ -p policies/opa/github-actions --namespace github_actions
```

### Data-driven policies (per environment)

Pass `--data <dir>` with YAML/JSON files at the top level:

```yaml
# policies/data/prod/limits.yaml
allowed_instance_families: [m7i, m7g, r7g]          # terraform.ec2
allowed_regions: [eu-west-1, eu-central-1]           # terraform.regions
blast_radius: { max_deletes: 2, max_changes: 30 }    # terraform.blast_radius
allowed_registries: ["123456789012.dkr.ecr.eu-west-1.amazonaws.com/", "ghcr.io/acme/"]  # kubernetes.images
allowed_base_registries: ["public.ecr.aws/", "cgr.dev/chainguard/"]                      # docker
```

### Exceptions (break-glass)

Conftest `exception` rules switch off named `deny_<name>` rules. Two are built in. Declare the variable in the root module and set it for that one run:

| Variable | Excepts |
|---|---|
| `-var allow_destroy=true` | `terraform.destroy.deny_protected_destroy` |
| `-var allow_large_change=true` | `terraform.blast_radius.deny_too_many_deletes` |

```rego
exception contains rules if {
	input.variables.allow_destroy.value == true
	rules := ["protected_destroy"]
}
```

---

## Checkov custom checks

22 custom checks, each with at least one passing **and** one failing scenario in `tests/fixtures/checkov/`.
`tests/run-checkov-scenarios.py` asserts that the *exact* sets of passed and failed resources match `expected.json`.

| ID | Type | Framework | Rule |
|---|---|---|---|
| `CKV_ORG_1` | Python | terraform | EC2 approved instance families |
| `CKV_ORG_2` | Python | terraform | Lambda runtime not deprecated |
| `CKV_ORG_3` | Python | terraform | IAM policies: no `*`:`*` or sensitive `svc:*` on `*` (handles `jsonencode` and JSON strings) |
| `CKV_ORG_4` | Python | terraform | HTTP listeners must redirect |
| `CKV_ORG_5` | Python | terraform | ECR immutable tags + scan on push |
| `CKV_ORG_6` | Python | terraform | Log group retention 30–3653 days |
| `CKV_ORG_7` | Python | kubernetes | Required labels on workloads, Services and Ingresses |
| `CKV_ORG_8` | Python | kubernetes | Container images from approved registries (`BaseK8sContainerCheck`) |
| `CKV_ORG_9` | Python | dockerfile | Base images from approved registries (stage aliases allowed) |
| `CKV_ORG_10` | Python | cloudformation | `AWS::Logs::LogGroup` RetentionInDays ≥ 30 |
| `CKV_ORG_11` | Python | cloudformation | Lambda / SAM function runtimes not deprecated |
| `CKV2_ORG_1` | YAML attribute | terraform | S3 `Owner` + `DataClassification` tags (value within allowed set) |
| `CKV2_ORG_2` | YAML connection | terraform | S3 bucket has a public access block |
| `CKV2_ORG_3` | YAML `or`/`and` | terraform | KMS rotation (asymmetric keys exempt) |
| `CKV2_ORG_4` | YAML attribute | terraform | DynamoDB point-in-time recovery |
| `CKV2_ORG_5` | YAML `or`/`and` | terraform | EKS endpoint private, or public with restricted CIDRs |
| `CKV2_ORG_6` | YAML connection | terraform | RDS uses a managed DB subnet group |
| `CKV2_ORG_7` | YAML connection | terraform | Lambda has a managed log group |
| `CKV2_ORG_8` | YAML connection + `or` | terraform | Internet-facing ALB has WAFv2 (internal ALBs and NLBs exempt) |
| `CKV2_ORG_9` | YAML `or` | terraform | SQS has a DLQ (queues named `*-dlq` exempt) |
| `CKV2_ORG_10` | YAML connection | terraform | Security group is attached to something |
| `CKV2_ORG_11` | YAML connection + attribute on connected resource | terraform | S3 uses SSE-KMS |

### Adding a check

1. Drop a `.py` or `.yaml` file in `policies/checkov/custom_checks/` with a new `CKV_ORG_n` / `CKV2_ORG_n` ID.
2. Add `pass_*` and `fail_*` resources to the matching fixture in `tests/fixtures/checkov/`.
3. Add the expected resource IDs to `tests/fixtures/checkov/expected.json`.
4. Run `python tests/run-checkov-scenarios.py`. It fails if a check has no scenarios or if results drift.

### Usage scenarios

[`examples/checkov-scenarios.yml`](../examples/checkov-scenarios.yml) shows each of these as a separate job:

| Scenario | Technique |
|---|---|
| Adopting Checkov on a legacy repo | `--create-baseline` once, then `baseline:` so only *new* findings fail |
| Org guardrails | `--soft-fail --hard-fail-on <CKV_ORG_*>` |
| Per-environment strictness | `--config-file .checkov/{dev,prod}.yaml` (see [`configs/checkov/`](../configs/checkov)) |
| Fast PR feedback | scan only `git diff` files with repeated `-f` |
| Many frameworks | matrix over terraform, cloudformation, kubernetes, helm (`--var-file` per env), dockerfile, github_actions, secrets |
| Terraform plan | `-f tfplan.json --framework terraform_plan --repo-root-for-plan-enrichment --deep-analysis` |
| PR feedback | JSON output → sticky PR comment table |
| Security dashboard | nightly full scan → SARIF → code scanning |

### Suppressions

Every suppression needs a reason:

```hcl
resource "aws_s3_bucket" "public_site" {
  #checkov:skip=CKV2_AWS_6: public website bucket, fronted by CloudFront OAC
  bucket = "acme-public-site"
}
```

```yaml
metadata:
  annotations:
    checkov.io/skip1: CKV_ORG_8=Vendor image mirrored nightly, tracked in SEC-123
```

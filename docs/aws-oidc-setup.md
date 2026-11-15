# AWS authentication with GitHub OIDC (no long-lived keys)

Every AWS workflow here uses `aws-actions/configure-aws-credentials` with **OIDC**. No `AWS_ACCESS_KEY_ID` secrets are needed.

## 1. Create the OIDC provider and role (once per account)

Use the module in [`examples/terraform/github-oidc`](../examples/terraform/github-oidc/main.tf):

```bash
cd examples/terraform/github-oidc
terraform init
terraform apply \
  -var 'repositories=["acme/infra","acme/orders-service"]' \
  -var 'allowed_environments=["production"]' \
  -var 'role_name=gha-terraform' \
  -var 'managed_policy_arns=["arn:aws:iam::aws:policy/AdministratorAccess"]'   # scope this down!
```

Or with the AWS CLI:

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com
```

Trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
      "StringLike":   { "token.actions.githubusercontent.com:sub": "repo:acme/infra:environment:production" }
    }
  }]
}
```

## 2. Choose the right `sub` condition

| Pattern | Who can assume the role |
|---|---|
| `repo:ORG/REPO:*` | Any workflow in the repo (incl. PRs from branches): only for **read-only** roles |
| `repo:ORG/REPO:ref:refs/heads/main` | Jobs running on `main` without an environment |
| `repo:ORG/REPO:environment:production` | Only jobs bound to the `production` GitHub Environment (approvals apply) |
| `repo:ORG/REPO:pull_request` | PR workflows: pair with a plan-only / read-only role |

> When a job declares `environment:`, the `sub` claim is the **environment** form, not the ref form.
> All deploy/apply jobs in these templates set `environment`, so use the environment pattern for write roles.

## 3. Recommended role split

| Role | Used by | Permissions |
|---|---|---|
| `gha-terraform-readonly` | PR plans, drift detection | `ReadOnlyAccess` + state bucket read/write + lock table |
| `gha-terraform` | apply (environment-bound) | scoped admin for the stack |
| `gha-ecr-push` | docker-build-push | `ecr:*Layer*`, `ecr:PutImage`, `ecr:GetAuthorizationToken`, … on specific repos |
| `gha-ecs-deploy` | aws-ecs-deploy | `ecs:Describe*`, `ecs:RegisterTaskDefinition`, `ecs:UpdateService`, `iam:PassRole` (task roles) |
| `gha-lambda-deploy` | aws-lambda-deploy | `lambda:UpdateFunctionCode`, `PublishVersion`, `*Alias`, `GetFunction*` |
| `gha-web-deploy` | aws-s3-static-deploy | `s3:ListBucket/PutObject/DeleteObject` on the bucket, `cloudfront:CreateInvalidation/GetInvalidation` |
| `gha-eks-deploy` | eks-helm-deploy | `eks:DescribeCluster` + EKS access entry with a namespaced k8s role |

## 4. Reusable workflows and OIDC

The caller job must grant `id-token: write`:

```yaml
jobs:
  deploy:
    uses: your-org/github-actions-templates/.github/workflows/aws-ecs-deploy.yml@v1
    permissions:
      contents: read
      id-token: write
```

The token's `sub` is that of the **calling** repository. To additionally restrict which reusable workflow may
assume a role, add a condition on `token.actions.githubusercontent.com:job_workflow_ref`, e.g.
`your-org/github-actions-templates/.github/workflows/terraform-plan-apply.yml@refs/tags/v1`.

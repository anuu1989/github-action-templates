# Bootstraps GitHub Actions -> AWS OIDC trust. Apply once per AWS account (locally or via a bootstrap pipeline).
#
#   terraform init && terraform apply -var 'github_org=acme' -var 'repositories=["acme/infra","acme/orders-service"]'

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "repositories" {
  description = "owner/repo entries allowed to assume the role"
  type        = list(string)
}

variable "allowed_environments" {
  description = "Restrict to these GitHub Environments (empty = any ref of the repos)"
  type        = list(string)
  default     = []
}

variable "role_name" {
  description = "Name of the IAM role GitHub Actions will assume"
  type        = string
  default     = "gha-terraform"
}

variable "managed_policy_arns" {
  description = "Managed policies to attach to the role"
  type        = list(string)
  default     = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
}

variable "tags" {
  description = "Tags applied to all resources"
  type        = map(string)
  default = {
    Owner       = "platform"
    Environment = "shared"
    CostCenter  = "platform"
  }
}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"] # no longer validated by AWS, but required by older providers
  tags            = var.tags
}

locals {
  # Subject claim formats:
  #   repo:ORG/REPO:ref:refs/heads/main
  #   repo:ORG/REPO:environment:production
  #   repo:ORG/REPO:pull_request
  subjects = length(var.allowed_environments) == 0 ? [
    for r in var.repositories : "repo:${r}:*"
    ] : flatten([
      for r in var.repositories : [for e in var.allowed_environments : "repo:${r}:environment:${e}"]
  ])
}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = local.subjects
    }
  }
}

resource "aws_iam_role" "github" {
  name                 = var.role_name
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
  tags                 = var.tags
}

resource "aws_iam_role_policy_attachment" "github" {
  for_each   = toset(var.managed_policy_arns)
  role       = aws_iam_role.github.name
  policy_arn = each.value
}

output "role_arn" {
  description = "Use as aws-role-arn in the reusable workflows"
  value       = aws_iam_role.github.arn
}

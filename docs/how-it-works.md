# How it works: from your workflow file to the templates

This page explains what happens when a workflow in **your repository** calls a template in
**`anuu1989/github-action-templates`**: the layers involved, how inputs, secrets, permissions and
outputs flow between them, and how a full pipeline runs end to end.

- [1. The layers](#1-the-layers)
- [2. What happens at runtime](#2-what-happens-at-runtime)
- [3. What crosses the boundary: inputs, secrets, permissions, outputs](#3-what-crosses-the-boundary)
- [4. Application golden path (`pipeline-app.yml`)](#4-application-golden-path)
- [5. Terraform golden path (`pipeline-terraform.yml`)](#5-terraform-golden-path)
- [6. Bundled policies: zero setup](#6-bundled-policies-zero-setup)
- [7. AWS authentication with OIDC](#7-aws-authentication-with-oidc)
- [8. Versioning: what `@v1` means](#8-versioning)
- [9. Getting started in one command](#9-getting-started-in-one-command)

---

## 1. The layers

You can call the templates at whichever level suits you:

| Level | What you write | Use when |
|---|---|---|
| **Golden path** | ~10 lines calling `pipeline-app.yml` / `pipeline-terraform.yml` | you want a complete, opinionated pipeline |
| **Building blocks** | a few jobs calling `java-build.yml`, `docker-build-push.yml`, … | you need a custom job graph |
| **Composite actions** | individual steps such as `actions/setup-aws`, `actions/detect-project` | you are adding steps to your own job |

```mermaid
flowchart TB
    subgraph CALLER["Your repository"]
        W[".github/workflows/pipeline.yml<br/>on: push / pull_request"]
    end

    subgraph TEMPLATES["anuu1989/github-action-templates @ v1"]
        direction TB
        subgraph GP["Golden paths"]
            PA["pipeline-app.yml"]
            PT["pipeline-terraform.yml"]
        end
        subgraph BB["Building blocks (reusable workflows)"]
            direction LR
            B1["java / node / python /<br/>go / dotnet -build.yml"]
            B2["docker-build-push.yml"]
            B3["secret-scan.yml<br/>trivy-scan.yml<br/>codeql.yml"]
            B4["terraform-static-analysis.yml<br/>checkov.yml<br/>terraform-plan-apply.yml"]
            B5["aws-ecs-deploy.yml<br/>eks-helm-deploy.yml<br/>aws-lambda / s3 / cdk / sam / cfn"]
            B6["notify-slack.yml"]
        end
        subgraph CA["Composite actions"]
            A1["actions/detect-project"]
            A2["actions/setup-aws"]
            A3["actions/setup-policy-tools"]
        end
        POL[("policies/<br/>OPA + Checkov")]
    end

    subgraph EXT["Third-party actions & services"]
        M["actions/checkout, setup-*<br/>docker/*, aws-actions/*<br/>hashicorp/setup-terraform …"]
        AWS["AWS: STS, ECR, ECS, EKS"]
        REG["GHCR / ECR"]
        SLACK["Slack"]
    end

    W -- "uses: …/pipeline-app.yml@v1" --> PA
    W -. "or call building blocks directly" .-> BB
    PA --> A1
    PA --> B1 & B2 & B3 & B5 & B6
    PT --> B4 & B6
    B4 -. "checkout if not in your repo" .-> POL
    B1 & B2 & B3 & B4 & B5 --> M
    B2 --> REG
    B5 --> AWS
    B4 --> AWS
    B6 --> SLACK
```

---

## 2. What happens at runtime

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer
    participant GH as GitHub Actions
    participant Caller as Your repo<br/>pipeline.yml
    participant Tpl as Templates repo<br/>(@v1)
    participant Runner as Hosted runner
    participant STS as AWS STS (OIDC)
    participant AWS as AWS (ECR / ECS)

    Dev->>GH: git push / open PR
    GH->>Caller: load .github/workflows/pipeline.yml
    Caller->>GH: jobs.pipeline.uses: anuu1989/github-action-templates/…/pipeline-app.yml@v1
    GH->>Tpl: resolve tag v1 → commit SHA, fetch pipeline-app.yml
    Tpl-->>GH: workflow definition (+ nested uses: …@v1, resolved the same way)
    Note over GH: Builds one job graph. Every job runs in the CALLER's context:<br/>caller's GITHUB_TOKEN, secrets passed explicitly,<br/>permissions ≤ what the caller granted
    GH->>Runner: run detect, build, scans, image, deploy jobs
    Runner->>Runner: actions/checkout checks out YOUR repo (not the templates)
    Runner->>GH: request OIDC token (id-token: write)
    GH-->>Runner: JWT, sub = repo:you/app:environment:prod
    Runner->>STS: AssumeRoleWithWebIdentity(role_arn, JWT)
    STS-->>Runner: short-lived credentials (1h)
    Runner->>AWS: push image / update service
    Runner-->>GH: job outputs (image-ref, digest, …)
    GH-->>Caller: workflow outputs available as needs.pipeline.outputs.*
    GH-->>Dev: checks, PR comments, job summaries, Slack
```

**Key facts:**
- **One run, one job graph.** A called workflow is not a separate run. Its jobs appear inside your run, named `pipeline / build-java / Build (JDK 21)`.
- **Code checked out is yours.** `actions/checkout` inside a template checks out the *calling* repository at the triggering commit.
- **Templates never see your secrets implicitly.** They receive only what you pass under `secrets:`, and these templates never use `secrets: inherit`.
- **Nesting.** Your workflow calls a golden path, which calls building blocks: 2 levels of a maximum of 10.

---

## 3. What crosses the boundary

```mermaid
flowchart LR
    subgraph C["Caller job"]
        direction TB
        CI["with:<br/>app-name, environments, …"]
        CS["secrets:<br/>SLACK_WEBHOOK_URL, NPM_TOKEN"]
        CP["permissions:<br/>contents: read<br/>packages: write<br/>id-token: write"]
    end
    subgraph T["Reusable workflow"]
        direction TB
        TI["on.workflow_call.inputs<br/>(typed: string / boolean / number,<br/>defaults applied)"]
        TS["on.workflow_call.secrets<br/>(required or optional)"]
        TP["jobs.*.permissions<br/>must be ≤ caller grant"]
        TO["on.workflow_call.outputs<br/>image-ref, digest, has-changes …"]
    end
    CI -- "validated at start-up" --> TI
    CS -- "only if listed" --> TS
    CP -- "upper bound" --> TP
    TO -- "needs.&lt;job&gt;.outputs.*" --> NEXT["Your next job<br/>e.g. a custom smoke test"]
```

| Error you might see | Cause | Fix |
|---|---|---|
| `The nested job 'image' is requesting 'packages: write', but is only allowed 'none'` | caller didn't grant the permission | add it under the calling job's `permissions:` |
| `Invalid input, xyz is not defined in the referenced workflow` | typo or input not supported | check the inputs table in the template header |
| `Unable to resolve action …, unable to find version …` | tag missing upstream | pin to an existing tag or SHA (see [releases](https://github.com/anuu1989/github-action-templates/releases)) |
| `Could not assume role with OIDC` | trust policy `sub` doesn't match | see [aws-oidc-setup.md](aws-oidc-setup.md) |

---

## 4. Application golden path

`pipeline-app.yml`: **detect → build → scan → image → deploy env by env → notify**

```mermaid
flowchart LR
    D["detect<br/><i>actions/detect-project</i><br/>language, versions,<br/>Dockerfile, chart"]

    subgraph BUILD["build (exactly one runs)"]
        direction TB
        BJ["java-build<br/>maven / gradle"]
        BN["node-build<br/>npm / yarn / pnpm"]
        BP["python-build"]
        BG["go-build"]
        BD["dotnet-build"]
    end

    subgraph SEC["security (parallel)"]
        direction TB
        S1["secret-scan<br/>gitleaks"]
        S2["trivy-fs<br/>deps + misconfig"]
        S3["codeql<br/>(optional)"]
    end

    IMG["image<br/>hadolint → buildx → push<br/>SBOM + provenance → trivy<br/>→ cosign (optional)"]

    subgraph DEP["deploy: max-parallel 1, push to main only"]
        direction LR
        E1["dev"] --> E2["staging"] --> E3["prod<br/>🔒 required reviewers"]
    end

    N["notify<br/>Slack (if webhook set)"]

    D --> BUILD
    D --> S3
    BUILD --> IMG
    SEC --> IMG
    IMG -->|"image-ref<br/>(image@sha256:…)"| DEP
    DEP --> N
    IMG -.-> N
```

| Trigger | detect | build | scans | image | deploy |
|---|---|---|---|---|---|
| Pull request | ✅ | ✅ | ✅ | built and scanned, **not pushed** | ❌ |
| Push to a feature branch | ✅ | ✅ | ✅ | pushed (branch tag) | ❌ |
| Push to `deploy-branch` | ✅ | ✅ | ✅ | pushed (`latest`, `sha-xxxxxxx`) | ✅ in order |
| Tag `v1.2.3` | ✅ | ✅ | ✅ | pushed (`1.2.3`, `1.2`) | ❌ (set `deploy-branch` to deploy tags) |

---

## 5. Terraform golden path

`pipeline-terraform.yml`: **static checks + Checkov → per-environment plan (with OPA gate) → approval-gated apply**

```mermaid
flowchart TB
    START(["push / pull_request"]) --> ST & CK & RS

    ST["static<br/>fmt · validate · TFLint · Trivy"]
    CK["checkov<br/>built-in + org custom checks"]
    RS["resolve<br/>fill per-env defaults:<br/>backends/&lt;env&gt;.hcl<br/>envs/&lt;env&gt;.tfvars"]

    ST & CK & RS --> LOOP

    subgraph LOOP["for each environment, in order (max-parallel 1)"]
        direction TB
        P["plan<br/>OIDC → init → validate →<br/>plan -detailed-exitcode"]
        O{"OPA gate<br/>conftest on<br/>tfplan.json"}
        C["PR comment<br/>(sticky, per env)"]
        Q{"push to<br/>apply-branch<br/>and has changes?"}
        A["apply<br/>🔒 GitHub Environment approval<br/>applies the exact reviewed tfplan"]
        P --> O
        O -->|deny| X(["❌ fail"])
        O -->|pass| C --> Q
        Q -->|no| DONE(["next env"])
        Q -->|yes| A --> DONE
    end

    LOOP --> N["notify"]
```

---

## 6. Bundled policies: zero setup

The policy-aware templates (`terraform-plan-apply`, `opa-conftest`, `checkov`, `k8s-validate`) look for the
policy path **in your repo first**. If it isn't there, they check out the template's own `policies/` at
`templates-ref` (default `v1`). You get the full policy library without copying anything, and can override it
whenever you like.

```mermaid
flowchart LR
    I["policy path input<br/>e.g. policies/opa/terraform"] --> Q{"exists in<br/>your repo?"}
    Q -->|yes| R["use your policies<br/>(full control)"]
    Q -->|no| B["sparse-checkout templates repo<br/>@ templates-ref → .gha-templates/policies<br/>::notice:: using bundled policies"]
    Q -->|"input is empty"| S["policy step skipped"]
    R & B --> E["conftest / checkov"]
```

---

## 7. AWS authentication with OIDC

```mermaid
flowchart LR
    J["Job with<br/>permissions: id-token: write<br/>environment: prod"] -->|"1. request JWT"| G["GitHub OIDC provider<br/>token.actions.githubusercontent.com"]
    G -->|"2. JWT<br/>aud = sts.amazonaws.com<br/>sub = repo:org/app:environment:prod"| J
    J -->|"3. AssumeRoleWithWebIdentity"| STS["AWS STS"]
    STS -->|"4. trust policy matches sub?"| R["IAM role<br/>gha-deploy"]
    R -->|"5. temp credentials, 1h"| J
    J -->|"6. aws ecs update-service …"| AWS["AWS account"]
```

There are no stored AWS keys anywhere. Restricting the role's trust policy to `environment:prod` means only
jobs that passed the prod environment's approval rules can assume the prod role.

---

## 8. Versioning

```mermaid
gitGraph
    commit id: "8a0f7fc initial"
    commit id: "b169255 repo refs" tag: "v1.0.0"
    commit id: "1798066 trivy fix" tag: "v1.0.1"
    commit id: "golden paths" tag: "v1.1.0"
    commit id: "next feature"
```

| Reference | Moves? | Use for |
|---|---|---|
| `@v1` | yes: always the latest `v1.x.y` | most consumers: fixes and features, no breaking changes |
| `@v1.1.0` | never | strict reproducibility; Dependabot proposes upgrades |
| `@<40-char SHA>` | never | regulated environments |
| `@main` | every commit | testing unreleased changes only |

Pushing a `vX.Y.Z` tag triggers [`release.yml`](../.github/workflows/release.yml). It creates the GitHub
release and moves `vX` automatically. Breaking changes ship as `v2`.

---

## 9. Getting started in one command

```bash
cd your-repo
curl -sSfL https://raw.githubusercontent.com/anuu1989/github-action-templates/v1/scripts/init-pipeline.sh | bash
# options: --type app|terraform|security  --deploy none|ecs|eks-helm  --registry ghcr|ecr  --dir infra
```

The script detects the project type, writes `.github/workflows/{pipeline|terraform,security}.yml` and
`dependabot.yml`, and prints the remaining steps: role ARNs, GitHub Environments and an optional Slack secret.
Organizations can instead publish [`workflow-templates/`](../workflow-templates) to their `.github`
repository so the golden paths appear under **Actions → New workflow**.

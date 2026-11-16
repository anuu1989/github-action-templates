# Starter workflows

These appear in **Actions → New workflow** for every repository in an organization once copied into
the org's public `.github` repository under `workflow-templates/`:

```bash
gh repo create <org>/.github --public    # if it doesn't exist yet
git clone https://github.com/<org>/.github && cd .github
mkdir -p workflow-templates && cp /path/to/github-action-templates/workflow-templates/* workflow-templates/
rm workflow-templates/README.md && git add . && git commit -m "Add starter workflows" && git push
```

`$default-branch` is replaced with the repository's default branch automatically.

> Starter workflows are an **organization** feature. For personal accounts, use
> [`scripts/init-pipeline.sh`](../scripts/init-pipeline.sh) instead.

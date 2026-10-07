# HUNT: GitHub Actions Vulnerabilities in .NET Repositories

## Target Repositories
- `dotnet/aspnetcore`
- `dotnet/runtime`
- `dotnet/sdk` (sdk2)
- `dotnet/roslyn`
- `dotnet/aspire`

## Executive Summary

**No clear-cut MSRC-eligible GitHub Actions vulnerabilities were identified across any of the five repositories.** All five repos demonstrate mature, defense-in-depth security practices for their GitHub Actions workflows. The engineering teams have consistently applied correct mitigations for all five vulnerability classes investigated.

Total workflow files analyzed: 151+ across all repositories.

---

## Vulnerability Class 1: Expression Injection (${{ }} in run: blocks)

### What We Looked For
User-controlled GitHub event data (comment body, PR title/body, branch name, issue title) injected directly into `run:` blocks via `${{ }}` expressions, enabling arbitrary command execution.

### Findings: NO VULNERABILITIES FOUND

**Every single workflow that processes user-controlled input uses the safe environment variable pattern.** No workflow injects `github.event.comment.body`, `github.event.pull_request.title`, `github.event.pull_request.body`, `github.event.pull_request.head.ref`, or `github.event.issue.title` directly into `run:` blocks.

#### Safe Pattern Observed Everywhere

All repos consistently use:
```yaml
env:
  COMMENT_BODY: ${{ github.event.comment.body }}
run: |
  echo "$COMMENT_BODY"  # Shell variable, not expression injection
```

#### Specific Workflows Verified

| Workflow | Repo | User Input | Pattern |
|----------|------|-----------|---------|
| `pr-validation.yml` | roslyn | comment body | `env: COMMENT_BODY` (line 246) |
| `aot-size-analysis.yml` | sdk | comment body | `env: COMMENT_BODY` (line 64) |
| `update-xlf-on-comment.yml` | sdk | comment body | `env: COMMENT_BODY` (line 37) |
| `fix-completions-on-comment.yml` | sdk | comment body | `env: COMMENT_BODY` (line 40) |
| `ci-eval.yml` | runtime | comment body | `env: COMMENT_BODY` (line 174) |
| `skill-evals.yml` | aspnetcore | comment body | `env: COMMENT_BODY` (line 164) |
| `apply-test-attributes.yml` | aspire | comment body | Parsed in `actions/github-script` JS |
| `backport.yml` | aspire | comment body | Regex-extracted branch name |

#### One Apparent Expression in run: Block (NOT Exploitable)

**`runtime/.github/workflows/ci-eval.yml` line 278:**
```yaml
run: gh pr checkout ${{ github.event.issue.number }}
```
`github.event.issue.number` is an integer field controlled by GitHub, not by the user. It cannot contain shell metacharacters. NOT injectable.

#### Branch Name Sanitization

Where branch names from PR events are used, they are regex-constrained:
- `aspire/backport.yml`: `/^\/backport to ([a-zA-Z\d\/\.\-\_]+)/` - only alphanumeric, slash, dot, hyphen, underscore
- `roslyn/pr-validation.yml`: Rejects branches containing `` ` $ ' " { } ( ) `` (line 170-173)
- `sdk/detect-netsdk-diagnostics.yml`: Uses only `base.sha` and `head.sha` (hex-only commit hashes)

---

## Vulnerability Class 2: pull_request_target + Checkout of PR Code

### What We Looked For
Workflows triggered by `pull_request_target` that check out the PR head (untrusted fork code) and then run it with access to secrets.

### Findings: NO VULNERABILITIES FOUND

#### All pull_request_target Workflows Analyzed

| Workflow | Repo | Checks Out PR Code? | What It Does |
|----------|------|---------------------|-------------|
| `dogfood-comment.yml` | aspire | NO | Posts a comment only |
| `organization-funded-copilot-reviews.yml` | aspire | NO | Requests Copilot review via API |
| `labeler-predict-pulls.yml` | aspire, runtime, roslyn, sdk | NO | ML label prediction, no checkout |
| `labeler-area-paths.yml` | aspnetcore | NO | Applies area labels, no checkout |
| `locker.yml` | runtime | NO (checks out external action repo) | Lock/unlock stale issues |
| `check-no-merge-label.yml` | runtime | NO | Label checking only |
| `check-service-labels.yml` | runtime | NO | Label checking only |
| `breaking-change-doc.lock.yml` | runtime | NO (gh-aw, fork validation) | Only on merged+labeled PRs |
| `detect-netsdk-diagnostics.yml` | sdk | Checks out BASE, fetches PR for diff only | Reads .xlf diff, no code execution |
| `pr-analysis.yml` | sdk | NO | Label checking only |
| `add-lockdown-label.yml` | sdk | Checks out eng/Versions.props only | Reads version data, no code execution |
| `add-servicing-consider-label.yml` | sdk | NO | Label management only |
| `remove-lockdown-label.yml` | sdk | NO | Label management only |
| `ci-quality-monitor.lock.yml` | sdk | gh-aw with fork validation | Auto-generated with standard controls |

**Key finding: `detect-netsdk-diagnostics.yml`** checks out the base branch and uses `git fetch` to get the PR head, but only for `git diff ... -- '*.xlf'`. It never executes any PR code, and it clears `GITHUB_TOKEN` and `GH_TOKEN` environment variables before the fetch/diff steps.

---

## Vulnerability Class 3: Artifact Poisoning / Supply Chain

### What We Looked For
Workflows that download artifacts from other workflow runs and then execute the contents (running scripts, loading configs, etc.), which could allow a malicious PR to poison an artifact that gets executed in a privileged context.

### Findings: NO VULNERABILITIES FOUND

#### Artifact Usage Patterns

**sdk/aot-size-analysis.yml**: Downloads artifacts but only reads size data for posting comments. The `analyze` job explicitly clears sensitive tokens:
```yaml
env:
  GITHUB_TOKEN: ""
  GH_TOKEN: ""
  ACTIONS_ID_TOKEN_REQUEST_URL: ""
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: ""
  ACTIONS_RESULTS_URL: ""
  ACTIONS_RUNTIME_URL: ""
  ACTIONS_RUNTIME_TOKEN: ""
```
And checks out with `ref: ${{ github.workflow_sha }}` (trusted revision).

**sdk/update-xlf-on-comment.yml** and **sdk/fix-completions-on-comment.yml**: Both download change archives from a previous `upload-artifact` step, but validate them using a **trusted validation script checked out from the default branch** (not from the PR). The validation restricts allowed file extensions (`.xlf` only, or `.verified.sh/.zsh/.fish/.ps1/.nu` only) and uses `git -c core.hooksPath=/dev/null -c core.attributesFile=/dev/null commit` to prevent execution of git hooks from the PR.

**aspnetcore/skill-evals.yml**: Downloads artifacts for evaluation but has a fork guard (refuses fork PRs), validates commits belong to the same repo, and uses trusted control plane scripts from the default branch.

**gh-aw .lock.yml files**: All auto-generated agentic workflow files use `actions/download-artifact` with SHA-pinned versions and process artifacts only through the gh-aw framework's sandboxed agent containers.

---

## Vulnerability Class 4: workflow_run Triggered Workflows

### What We Looked For
Workflows triggered by `workflow_run` that inherit untrusted context from the triggering workflow, potentially running attacker-controlled code with elevated privileges.

### Findings: NO VULNERABILITIES FOUND

#### All workflow_run Workflows Analyzed

| Workflow | Repo | Security Controls |
|----------|------|-------------------|
| `auto-rerun-outerloop-failures.yml` | aspire | Excludes PR runs; operates only on existing workflow runs |
| `auto-rerun-transient-ci-failures.yml` | aspire | Validates source CI run; dry-run analysis first |
| `analyze-ci-failure.lock.yml` | aspire | Fork validation: `github.event.workflow_run.repository.id == github.repository_id`; gh-aw framework with firewall containers; only triggers on `main` branch |

The `analyze-ci-failure.lock.yml` is the most complex case. It triggers on `workflow_run: completed` for the CI workflow but:
1. Only runs on `main` branch (not PR branches)
2. Has explicit fork validation
3. Uses gh-aw sandboxed containers with network firewalls
4. Auto-generated with standard gh-aw security controls
5. Carries a `# zizmor: ignore[dangerous-triggers]` annotation with documented rationale

---

## Vulnerability Class 5: Self-Hosted Runner Exposure

### What We Looked For
Workflows that run on self-hosted runners AND are triggered by pull requests, which could allow attackers to execute code on persistent infrastructure.

### Findings: NO VULNERABILITIES FOUND

**No GitHub Actions workflow in any of the five repositories uses `runs-on: self-hosted`.** All workflows run on GitHub-hosted runners (`ubuntu-latest`, `windows-latest`, `macos-latest`, `ubuntu-slim`). The only reference to `self-hosted` appears in Azure DevOps template comments, not in GitHub Actions workflows.

---

## Additional Security Analysis: gh-aw (GitHub Agentic Workflows)

Multiple repositories use auto-generated `.lock.yml` files from GitHub's Agentic Workflows framework. These represent a large attack surface (complex AI agent workflows with access to COPILOT_PAT secrets), but are hardened by the gh-aw framework:

### Security Controls in gh-aw Workflows

1. **Pinned dependencies**: All actions use SHA-pinned versions (e.g., `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`)
2. **Container-based isolation**: Agent execution runs inside sandboxed containers with firewall proxies
3. **Fork validation**: Standard `!github.event.repository.fork` checks
4. **Role-based access**: Pre-activation jobs check for admin/maintainer/write roles
5. **Daily AI credit limits**: Guardrails against runaway agent execution
6. **Lock file integrity checks**: Stale lock file detection
7. **OAuth token validation**: Checks for proper token configuration
8. **Safe output tools**: Agent outputs go through `safeoutputs` MCP server (controlled output methods)

### gh-aw Workflows Found

| Workflow | Repo | Trigger | Purpose |
|----------|------|---------|---------|
| `community-pr-issue-check.lock.yml` | aspnetcore | `pull_request` (labeled) | Check community PR has issue |
| `pull-request-review.lock.yml` | aspnetcore | `issue_comment` (/review) | AI code review |
| `pr-attention-pulse.lock.yml` | aspnetcore | (various) | PR attention tracking |
| `browsertesting-deps-update.lock.yml` | aspnetcore | (various) | Browser testing deps |
| `cswin32-update.lock.yml` | aspnetcore | (various) | CsWin32 updates |
| `test-quarantine.lock.yml` | aspnetcore | (various) | Test quarantine management |
| `pr-docs-check.lock.yml` | aspnetcore, aspire | `pull_request` (closed) | Docs check |
| `issue-triage-agent.lock.yml` | aspnetcore | `issues` (opened) | AI issue triage |
| `breaking-change-doc.lock.yml` | runtime | `pull_request_target` | Breaking change docs |
| `ci-failure-fix.lock.yml` | runtime | `schedule`/`workflow_dispatch` | CI failure auto-fix |
| `ci-failure-scan.lock.yml` | runtime | `schedule`/`workflow_dispatch` | CI failure scanning |
| `ci-failure-scan-feedback.lock.yml` | runtime | (various) | CI scan feedback |
| `closed-issue-reference-check.lock.yml` | runtime | (various) | Closed issue checks |
| `holistic-review.lock.yml` | runtime | (dispatched) | Holistic review worker |
| `build-failure-analysis-command.lock.yml` | sdk | `issue_comment` | Build failure analysis |
| `build-failure-analysis.lock.yml` | sdk | (various) | Auto build failure analysis |
| `ci-quality-monitor.lock.yml` | sdk | `pull_request_target` | CI quality monitoring |
| `issue-monster.lock.yml` | sdk | (various) | Issue management |
| `issue-monster-assigner.lock.yml` | sdk | (various) | Issue assignment |
| `issue-triage.lock.yml` | sdk | (various) | Issue triage |
| `parallel-safety-audit-command.lock.yml` | sdk | `issue_comment` | Parallel safety audit |
| `resource-lock-refactoring.lock.yml` | sdk | (various) | Resource lock refactoring |
| `add-tactics-template-on-comment.lock.yml` | sdk | `issue_comment` | Tactics template |
| `analyze-ci-failure.lock.yml` | aspire | `workflow_run`/`workflow_dispatch` | CI failure analysis |
| `extension-changelog.lock.yml` | aspire | (various) | Extension changelog |
| `daily-repo-status.lock.yml` | aspire | (various) | Daily status |
| `milestone-changelog.lock.yml` | aspire | (various) | Milestone changelog |
| `release-notes-generate.lock.yml` | aspire | (various) | Release notes |
| `release-update-support-mdx.lock.yml` | aspire | (various) | Support MDX updates |
| `repo-pulse.lock.yml` | aspire | (various) | Repository pulse |
| `ai-artifact-audit.lock.yml` | roslyn | (various) | AI artifact audit |

**Assessment**: The gh-aw framework itself is maintained by GitHub, and vulnerabilities in it would be GitHub's responsibility, not the .NET team's. The individual repositories' usage of gh-aw appears correct and follows the framework's security guidelines.

---

## Additional Security Controls Observed

### Authorization Patterns

All `issue_comment`-triggered workflows that perform privileged operations enforce authorization:

1. **Write access check**: `repos.getCollaboratorPermissionLevel` verifying `admin`, `write`, or `maintain` permission
2. **Org membership check**: `orgs.checkMembershipForUser` for `microsoft` org (roslyn, aspnetcore)
3. **Author association check**: `context.payload.comment.author_association` for `OWNER` or `MEMBER` (runtime)

### Fork Guards

Workflows consistently refuse to operate on fork PRs:
- `sdk/update-xlf-on-comment.yml`: "The PR author must be from the same repository"
- `sdk/fix-completions-on-comment.yml`: Same pattern
- `aspnetcore/skill-evals.yml`: `pr.head.repo.full_name !== pr.base.repo.full_name` check
- `aspire/apply-test-attributes.yml`: `pr.head.repo.full_name !== context.repo.owner/context.repo.repo` check
- `aspire/deployment-test-command.yml`: Fork guard before dispatch

### Token Hygiene

Multiple workflows clear sensitive tokens before running untrusted operations:
```yaml
env:
  GITHUB_TOKEN: ""
  GH_TOKEN: ""
  ACTIONS_ID_TOKEN_REQUEST_URL: ""
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: ""
```

### Git Hook Disabling

Workflows that commit changes disable git hooks to prevent execution of hooks from PR code:
```bash
git -c core.hooksPath=/dev/null -c core.attributesFile=/dev/null commit
```

---

## Marginal Leads Investigated and Dismissed

### 1. Branch Name Interpolation in JavaScript Strings

Several backport workflows interpolate regex-extracted branch names into JavaScript string literals:
```javascript
const target_branch = '${{ steps.target-branch-extractor.outputs.result }}'
```
The regex constraint (`[a-zA-Z\d\/\.\-\_]+`) prevents injection of single quotes or other JS-breakout characters. **Dismissed**: regex is tight enough.

### 2. PR Number in Shell Command

`runtime/ci-eval.yml:278`:
```yaml
run: gh pr checkout ${{ github.event.issue.number }}
```
`github.event.issue.number` is GitHub-controlled integer. **Dismissed**: not user-controllable.

### 3. Azure DevOps Pipeline Trigger

`roslyn/pr-validation.yml` triggers Azure DevOps pipelines with PR parameters. The workflow has multiple authorization layers (write access + Microsoft org membership + commit validation). **Dismissed**: multiple defense layers make exploitation infeasible.

### 4. Copilot PAT Pool Secrets in gh-aw Workflows

Many gh-aw workflows have access to `COPILOT_PAT_0` through `COPILOT_PAT_9`. These are used inside sandboxed agent containers with network firewalls. The gh-aw framework controls access to these secrets, not the individual workflows. **Dismissed**: framework-level concern, not repo-level.

---

## Conclusion

These repositories represent some of the most security-hardened GitHub Actions configurations in the open source ecosystem. The .NET team has systematically addressed all five vulnerability classes with consistent, well-documented security patterns. No MSRC-eligible vulnerabilities were identified.

The primary attack surface is the gh-aw (GitHub Agentic Workflows) framework, but vulnerabilities there would be in GitHub's platform code, not in the .NET repositories' usage of it.

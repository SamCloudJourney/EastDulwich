# HUNT: GitHub Actions / agentic-workflow CI surface across in-scope dotnet repos

Hunted directly (no subagents), 2026-10-17. Authorized MSRC .NET bug bounty research.
Static analysis only — no workflow was triggered, no PR or issue was created anywhere.

## VERDICT: CLEAN. No bounty-eligible finding.

| # | Candidate | Verdict |
|---|---|---|
| A1 | aspnetcore gh-aw agentic workflows — prompt injection → privileged action | **CLEAN** (hardened; one low-impact config smell, below) |
| A2 | `issue-triage-agent` cross-target comment chain → `pull-request-review` | **CLEAN** (chain target is toolless) |
| B1 | `pull_request_target` + untrusted-code checkout (22 workflows) | **CLEAN** (both real cases correctly gated) |
| B2 | Script injection into `run:` blocks | **CLEAN** (all hits are `if:` exprs or quoted env vars) |
| B3 | `workflow_run` artifact/privilege escalation | **N/A** — zero `workflow_run` triggers in all 5 repos |
| B4 | Unpinned third-party actions | **CLEAN** (SHA-pinned throughout) |

## Why this surface was chosen
The live MSRC .NET bounty page lists **"GitHub Actions in the associated .NET and ASP.NET
Core GitHub repositories"** as in scope, and records a **scope expansion on 2025-07-31**.
The `dotnet/core` `bug-bounty-preview-scopes.md` page is stale (last updated 2021-11-15,
still listing .NET 6 HTTP/3), so the MSRC page is the authoritative scope.

Scope notes recorded for future hunts:
- **"Insecure documentation or samples" is a paid category**, up to $10,000 — underexploited.
- **Out of scope:** "Low impact CSRF bugs" and **"server-side information disclosure"**.
  The former independently confirms our OIDC `iss` finding is worth $0.
- Moderate and Low severity pay **$0** regardless of category.

## Corpus
`dotnet/aspnetcore` (full, already local) plus blobless sparse clones of `.github` + `eng`
from `dotnet/runtime`, `dotnet/sdk`, `dotnet/core`, `dotnet/efcore`, `dotnet/roslyn`.
**101 workflow files** (runtime 33, sdk 36, core 13, efcore 10, roslyn 9) + 23 in aspnetcore.

## A. The agentic-workflow surface (gh-aw) — hardened
aspnetcore runs GitHub Agentic Workflows: `.md` prompt + compiled `.lock.yml` pairs
(`issue-triage-agent`, `pull-request-review`, `community-pr-issue-check`,
`pr-attention-pulse`, `pr-docs-check`, `test-quarantine`, `cswin32-update`,
`browsertesting-deps-update`). AI agents processing untrusted issue/PR text — a genuinely
new, high-interest surface. It is **not** soft:

- **No direct interpolation.** `grep` for `github.event.issue.{body,title}` and the
  `pull_request`/`comment` equivalents in `issue-triage-agent.lock.yml`: **0 hits.** No
  shell-injection path.
- **Sanitizer step** (`id: sanitized`, `.lock.yml:291`) feeds
  `GH_AW_STEPS_SANITIZED_OUTPUTS_{BODY,TITLE}`; untrusted text travels in **env vars** with
  `__GH_AW_*__` placeholder substitution, never as `${{ }}` inside prompt text.
- **Explicit anti-injection prompt block**: `xpia.md` (cross-prompt-injection) is composed
  into every prompt via `GH_AW_PROMPT_CONFIG`.
- **Agent is read-only**: `permissions: contents/issues/pull-requests: read`. Writes happen
  only in separate privileged output jobs. A source comment states it plainly: *"gh-aw
  grants PR write to output/conclusion jobs, never the agent."*
- **Safe-outputs are allowlisted**: `add-labels` limited to 30 named labels, `max: 3`;
  `set-issue-type` to `[Bug, Feature, Task]`, `max: 1`.
- **Supply chain pinned**: every action by commit SHA (e.g. `actions/checkout@3d3c42e5…`
  v7.0.1), every container by digest.
- **Egress firewall**: `ghcr.io/github/gh-aw-firewall/{agent,api-proxy,squid}` plus an
  explicit `GH_AW_ALLOWED_DOMAINS` allowlist.
- `pull-request-review` goes further: `tools: bash: false, github: false, edit: false,
  cli-proxy: false`; `add-comment target: triggering`; built-in `GITHUB_TOKEN` rather than
  an ambient PAT; `freeze_pr_head` + `verify_live_head` jobs (explicit TOCTOU guard on PR
  head); `threat-detection` enabled; and inherited OTEL credentials deliberately blanked,
  commented *"Do not expose inherited telemetry credentials to a process reading untrusted
  pull request text."*

### Config smell (reported for completeness, NOT eligible)
`issue-triage-agent` combines three loose settings:
- `roles: all` — any user, including a first-time external account, triggers it by opening
  an issue;
- `tools: github: min-integrity: none` — the DIFC integrity threshold is disabled, so
  low-integrity (untrusted) content is not filtered out of the agent's tool results;
- `add-comment: { max: 1, target: "*" }` — `"*"` permits a comment on an **arbitrary**
  issue/PR, not just the triggering one.

**Impact ceiling even assuming a fully successful prompt injection:** ≤3 labels from a
fixed 30-label allowlist, an issue type among 3 values, and **one** bot comment, possibly
on an unrelated issue/PR. That is Spoofing/Tampering at **Low → $0**. MSRC would also very
likely treat LLM prompt injection as a known limitation of the agent product rather than a
.NET vulnerability, and the sanitizer and `xpia.md` are GitHub's `gh-aw` code, not .NET's —
a flaw there belongs to GitHub's program, not this one.

**The escalation chain does not exist.** `target: "*"` was attractive because
`pull-request-review` triggers on `issue_comment` with `roles: [admin, maintainer, write]`,
so a bot comment could plausibly re-enter a second agent. But that agent has **no tools at
all** (`bash/github/edit/cli-proxy` all `false`) and `target: triggering`, so it grants an
attacker nothing. Chain dead.

`test-quarantine` carries a deliberate DIFC bypass — a step running with *"full GitHub
token access"* that injects external-contributor PR data into the agent prompt,
self-documented as *"bypassing DIFC filtering"*. It is `schedule`-triggered only, and its
safe-outputs are equally bounded, so the same Low ceiling applies.

## B. Classic high-severity Actions patterns — clean
**22 workflows use `pull_request_target`.** Only two check out a ref that is not the base;
both are correctly gated:

1. **`efcore/agent-harness-evaluation.yml`** — checks out `trusted_sha` *and* `head_sha`
   (untrusted PR code) but the job is gated `if: … can_use_secrets == 'true'` (`:443`), and
   `canUseSecrets` (`:124-126`) is sound:
   - author permission from **`repos.getCollaboratorPermissionLevel`** — the authoritative
     API, not the spoofable `author_association`;
   - requires `admin`/`maintain`/`write`;
   - **`synchronize` is excluded from `automatic`**, which kills the classic "open a benign
     PR, get authorized, then push malicious commits" TOCTOU;
   - `pull` is re-fetched via `pulls.get` rather than trusted from the event payload;
   - a manual `commit_sha` is hex-validated **and** must appear in that PR's commit list;
   - `mergedIntoDefault` requires `action === 'closed' && pull.merged === true && base.ref
     === default_branch`;
   - the `isBot()` path skips the permission check but requires `fromBranch`
     (`head.repo.id === base.repo.id`), i.e. a branch inside the repo, which needs write
     access anyway. The bot names are also unreachable by a real account: GitHub usernames
     cannot contain `[`, `]` or `/`, so `includes('[bot]')` and `startsWith('app/')` can't
     be satisfied, and `copilot`/`dotnet-bot` are taken.
2. **`efcore/api-review-baselines.yml`** — `if: workflow_dispatch || pull_request.merged
   == true` (`:26`). Merged code only; already trusted.

The remaining non-base checkouts resolve to trusted refs: `base.sha`
(`runtime/breaking-change-doc.lock.yml`), `base.ref`
(`sdk/detect-netsdk-diagnostics.yml`), `ref: main` (`sdk/ci-quality-monitor.lock.yml`), and
a SHA-pinned third-party action (`runtime/locker.yml`).

**Script injection: none.** Every hit for untrusted `.title`/`.body` inside workflows is
either an `if:` expression — evaluated by the Actions expression engine, never a shell — or
the correct env-var pattern. The one case that reaches a shell,
`roslyn/pr-validation.yml:246`, is **properly quoted**: `echo "$COMMENT_BODY" | grep -q`,
and the values it writes to `$GITHUB_OUTPUT` are hardcoded constants, so there is no output
injection either.

That workflow is the most attractive target in the corpus — it holds Azure OIDC credentials
(`AZURE_CLIENT_ID`/`TENANT_ID`/`SUBSCRIPTION_ID`, `id-token: write`) and fires on
`issue_comment`. It is defended in depth: `getCollaboratorPermissionLevel` on
**`context.actor`** (the commenter — the correct principal, not the PR author) requiring
admin/write/maintain, **plus** a second Microsoft-org-membership check, **plus** a protected
`environment: roslyn_perf`, **plus** SHA-pinned actions.

**`workflow_run`: zero occurrences** across all 101 workflows — the whole
download-untrusted-artifact-in-privileged-context class is absent by construction.

## Limitations (what was reasoned vs. measured)
- Entirely **static**. Nothing was executed; no issue, comment or PR was created in any
  Microsoft repository. Triggering these workflows to confirm behaviour would mean
  interacting with production repos, which is out of bounds for unsolicited research.
- The gh-aw sanitizer and DIFC implementation are **runtime-downloaded `.cjs` from
  `github/gh-aw-actions/setup`** and were not reviewed; they are GitHub's product, outside
  the .NET program.
- `runtime`/`sdk`/`core`/`efcore`/`roslyn` were sparse-cloned to `.github` + `eng`, so
  reusable composite actions living elsewhere in those trees were not reviewed.
- Checked for the known pattern classes above; this is not a proof of absence.

## Honest eligibility
**~0%.** Nothing here crosses a security boundary in a way that pays. The CI configuration
across these repos is markedly better than the ecosystem norm: SHA-pinned actions,
authoritative permission APIs, `synchronize` excluded from re-authorization, protected
environments, and agentic workflows with read-only agents behind an egress firewall.

The `issue-triage-agent` `target: "*"` + `min-integrity: none` pairing is worth a courtesy
GitHub issue as a hardening nit — narrow the comment target to `triggering` and raise
`min-integrity` — but it is not a bounty submission.

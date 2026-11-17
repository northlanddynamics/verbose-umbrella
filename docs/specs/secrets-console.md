# Secrets Console (powered by Kingfisher) — Product Spec

Nov 16, 2026 · @George

> Source: https://claude.ai/artifact/DAii346MJj65hxnKMRePVc (imported Nov 17, 2026)

## Summary

We will build Secrets Console, a GitGuardian-style secrets-security web app that uses MongoDB's open-source Kingfisher scanner (Apache 2.0) as its detection, validation and revocation engine. Kingfisher already finds, live-validates and revokes leaked credentials across Git, cloud storage and collaboration tools. It runs as a CLI and has no persistent console, so this spec covers the platform layer and six approved screens: Overview, Incidents, Incident detail, Perimeter, Detection rules, and Prevention & integrations.

**Problem.** Kingfisher runs produce JSON/SARIF reports and a client-side viewer. Security teams need findings that persist across scans, have owners and status, are scheduled across the whole perimeter, and route to the tools they already use.

**Goals**

- One incident per unique secret, deduplicated across sources and scan runs by a platform-computed secret identity.
- Active (live-validated) credentials surface first, everywhere in the product.
- Scheduled and on-push scanning of every integrated source, with coverage and health visible.
- Shift-left: CI and pre-commit scanning driven by a workspace policy, with a managed baseline.
- Alerts and tickets reach Slack, Jira, webhooks and SIEM without manual export.

**Non-goals (v1)**

- Honeytokens, vault/cloud NHI inventory, and public-GitHub discovery monitoring.
- Forking Kingfisher. The engine is consumed as a pinned release; upstream changes go through PRs.

## Scope

v1 ships the six approved wireframes. Identities & blast radius (screen 4) and the Revoke workflow (screen 6) were not approved and are deferred to a redesign. Their entry points on approved screens stay behind feature flags.

| # | Screen | v1 status | Note |
| --- | --- | --- | --- |
| 1 | Overview | In scope |  |
| 2 | Secret incidents | In scope |  |
| 3 | Incident detail | In scope | Blast-radius preview and Revoke button behind flags until 4 and 6 are redesigned |
| 4 | Identities & blast radius | Deferred | Needs a new design |
| 5 | Perimeter | In scope |  |
| 6 | Revoke workflow | Deferred | Needs a new design; v1 offers single-click revoke with confirmation only if flag enabled |
| 7 | Detection rules | In scope |  |
| 8 | Prevention & integrations | In scope |  |

The wireframes live on the [design canvas](https://claude.ai/artifact/2Nhxezeup6oUxm154HZWpW). Mock data on them is illustrative.

## Architecture

Kingfisher stays unmodified as the scanning engine; everything that makes findings into managed incidents is new platform code.

&#91;embedded content: architecture · engine, platform layer, outputs\]

Scan workers run Kingfisher per source and emit JSON. Ingest upserts incidents by secret identity, occurrences by Kingfisher fingerprint, and fires events. The console and outbound integrations read only from the platform, never from raw scan output.

## Data model

An incident is one secret, keyed by a platform-computed secret identity (secret\_id). Each place that secret was found is an Occurrence, carrying Kingfisher's per-location fingerprint. Every scan run upserts into these rather than creating new rows.

| Entity | Key fields | Populated from |
| --- | --- | --- |
| Incident | id, secret\_id, rule\_id, provider, severity, status, assignee, team, first\_seen, last\_seen, validity, validated\_at, tags | secret\_id computed in the worker; rule.id, finding.confidence, finding.validation; provider derived from rule id; platform (severity, status, assignee) |
| Occurrence | incident\_id, kf\_fingerprint, source\_id, kind (history / working tree / non-Git), path, line, column\_start, column\_end, commit\_sha, author, committer, commit\_date (day), present\_in\_head | finding.fingerprint, path, line, columns, git\_metadata; present\_in\_head derived |
| Secret vault record | incident\_id, encrypted secret, encrypted dependent captures, created\_at, retention | finding.snippet and finding.dependent\_captures, captured in the worker before redaction |
| Validation event | incident\_id, status (Active / Inactive / Not attempted + tag), raw\_outcome, checked\_at, trigger (scan, manual, scheduled) | finding.validation.outcome and status; response stored redacted |
| Source | id, integration\_id, kind, name, criticality, owner\_team, git\_history\_mode, schedule, last\_scan\_at, last\_scan\_result, health | Platform; updated from audit.repositories\[\] |
| Integration | id, kind (GitHub, GitLab, Bitbucket, S3, GCS, Docker, Slack, Teams, Jira, Confluence, Postman, filesystem), credentials\_ref, status | Platform |
| Scan run | id, kf\_run\_id, source\_ids, started\_at, finished\_at, kingfisher\_version, args, summary counts, per-repo fetch/scan status, errors | metadata (kingfisher\_version, command\_line\_args, summary) and audit (run\_id, repositories\[\]) |
| Rule | id, name, description, provider, confidence, validates, revokes, maps\_access, enabled, origin (built-in / custom), yaml | `rules list` (id, name, confidence); provider from mapping table; capability flags parsed from rule YAML |
| Baseline entry | secret\_id, rule\_id, reason, created\_by, expires\_at, approver | Platform; expanded to per-occurrence fingerprints on export |
| Notifier | id, kind (webhook, Slack, Jira, SIEM, PagerDuty), filter, config | Platform |
| Audit event | at, actor, action, target, details | Platform + Kingfisher repository audit |

Raw secret values are never persisted outside the vault. The platform keeps secret\_id, a redacted preview (first 4 and last 4 characters) and the encrypted vault record, with configurable retention.

## Engine contract

The platform depends on these Kingfisher output fields and rules. Verified against Kingfisher 2.18.1 JSON/JSONL output on a test Git repository with fake credentials; items under "Not yet verified" still need a check.

**Invocation (one job per source):** `kingfisher scan <target> --no-dedup --git-history full --commit-metadata true --format jsonl`, validation on, Kingfisher version pinned. One job per source means every finding is attributed to that job's source, since history findings carry only a repo-relative path.

**Field mapping**

| Kingfisher field | Used for |
| --- | --- |
| rule.id | Rule; provider lookup |
| rule.name, rule.description | Detector label; remediation text |
| finding.fingerprint | Occurrence.kf\_fingerprint; baseline export |
| finding.snippet | secret\_id input; vault copy; redacted preview. Never persisted raw |
| finding.dependent\_captures | Vault copy for re-validation (e.g. the AWS secret key half) |
| finding.confidence, finding.entropy | Severity rules |
| finding.validation.outcome, .status, .response | Validation event (mapping below) |
| finding.path, line, column\_start, column\_end, language | Occurrence location |
| finding.git\_metadata.commit (id, date, author, committer) | Occurrence commit fields |
| finding.git\_metadata.file.git\_command | Fetching code context |
| finding.validate\_command, blast\_radius\_command | Not stored: both contain the secret |
| metadata (kingfisher\_version, command\_line\_args, summary) | Scan run |
| audit (run\_id, repositories\[\].fetch, .scan, .git) | Scan run; Perimeter health |

**Rules the platform applies**

1. Secret identity: secret\_id = HMAC-SHA256(workspace key, rule\_id + secret). Kingfisher's fingerprint hashes the match plus its byte offsets, so the same token in two files gave four different fingerprints in testing. The `--redact` tag is stable per secret but only 32 bits, so it is not a safe key either.
2. Dedup: always `--no-dedup`. Kingfisher's default dedup keeps one location per secret and drops the rest, which would hide occurrences.
3. Redaction: the worker reads unredacted output in memory, writes secret and dependent captures to the vault, then strips snippet, validate\_command, blast\_radius\_command and validation.response before anything is persisted or logged.
4. Present in HEAD: true when the same secret\_id also appears as a working-tree finding (no git\_metadata) at that path in the current checkout; otherwise history only.
5. Code context: snippet holds only the secret. Fetch 2 lines either side via `git show` (from git\_metadata) or the source's API, then mask.
6. Provider: no provider field exists; derive it from rule id through a maintained mapping (e.g. betterleaks.github-pat → GitHub, kingfisher.aws.\* → AWS).
7. Rule capabilities: `kingfisher rules list --format json` returns only id, name, pattern, confidence, examples and visible. Validate, revoke and access-map support are parsed from the rule YAML in the pinned release.
8. Baseline: the platform suppresses by secret\_id. Export expands each entry to every known occurrence fingerprint in Kingfisher's baseline format (version 2: repository id, path, fingerprint, rule\_id, line), so CI suppresses known locations. A new copy of a baselined secret is auto-suppressed by the platform and added on the next export.
9. Dates: commit dates are day precision. Ordering within a day uses scan time.
10. Rule count varies by release (2.18.1 loaded 502 rules; the docs site cites 734+). The UI reads the count from the pinned release, never a constant.

**Validation state mapping**

| Kingfisher state | UI bucket |
| --- | --- |
| active | Active |
| inactive | Inactive |
| invalid material | Inactive, tagged "invalid material" |
| not\_attempted, unknown, skipped | Not attempted |
| locally derived, assumed valid | Not attempted, tagged with the state |

Only `not_attempted` was observed directly; the other names come from Kingfisher's summary counters and filter options, and their exact enum strings need confirming.

**Not yet verified**

- Location fields for S3, GCS, Docker, Slack, Teams, Jira, Confluence and Postman findings.
- The `access_map` structure (needed only for the deferred screens).
- The response payload of an Active validation; needs real credentials and network access.

## Screen 1 · Overview

The landing page answers one question: how many live secrets are exposed right now, and where.

**Requirements**

1. KPI tiles: Open incidents (unique secrets), Active credentials (validity = Active), High blast radius (count of incidents flagged admin/write-to-prod; hidden while the access-map flag is off), Sources monitored.
2. Date range picker (7 / 30 / 90 days, custom); applies to the trend chart only. KPIs are point-in-time.
3. Trend chart with Detect / Remediate / Prevent tabs: new incidents vs. resolved per week; Prevent shows CI/pre-commit blocks per week.
4. Open incidents by validity: Active, Inactive, Not attempted, as bars with counts. Clicking a bar opens Incidents filtered to it.
5. Sources at risk: top 5 sources by open incidents, with Active count; links to Perimeter.
6. Top providers with live secrets: top 5 providers by Active count; links to Detection rules.
7. "Run scan now" queues a scan of all sources the user's role can scan.

**Acceptance**

- Every number links to the list it summarises, with the matching filter applied.
- Page loads in under 2 s at 50k incidents.

## Screen 2 · Secret incidents

A filterable list with one row per unique secret, defaulting to Active, Triggered incidents sorted by severity then first seen.

**Columns:** select, Severity, Secret / detector (redacted preview, links to detail), Validity, Blast radius summary (flagged), Occurrences, Sources, Status, Assignee, First seen.

**Requirements**

1. Search across secret preview, file path, source name and author.
2. Filters: Validity, Status (Triggered, Assigned, Resolved, Ignored), Severity, Provider, Source type, Has blast radius (flagged), Hide baselined, Assignee, Team. Filters persist in the URL; users can save views.
3. Bulk actions on selected rows: Assign, Re-validate, Add to baseline (with reason), Resolve. Revoke appears only when the revoke flag is on.
4. Import report: accepts Kingfisher JSON/JSONL/SARIF, Gitleaks JSON and TruffleHog JSON/JSONL, mirroring the Kingfisher viewer. Imported non-Kingfisher findings are marked Not attempted and cannot be validated or revoked.
5. Export the filtered set as CSV or JSON.
6. Severity is computed by platform rules (below) and can be overridden per incident; overrides are audited.
7. Pagination at 50 rows; total and Active counts shown above the table.

**Default severity rules (editable in Settings)**

| Condition | Severity |
| --- | --- |
| Active and admin/write access to a critical source or prod resource | Critical |
| Active, any other case | High |
| Not attempted, rule confidence High | Medium |
| Inactive, or Not attempted with Medium/Low confidence | Low |

## Screen 3 · Incident detail

Everything needed to judge and close one secret on one page: where it is, whether it works, who owns it, what happened.

**Header:** validity, severity and status pills; detector name and redacted secret; rule id, confidence, last validated time, occurrence and source counts.

**Actions:** Re-validate, Assign, Resolve (reason: revoked, rotated, false positive, test credential), Ignore → baseline (reason + expiry required). Revoke secret is behind the revoke flag.

**Requirements**

1. Tabs: Occurrences, Timeline, Remediation. A Blast radius tab appears only with the access-map flag on.
2. Occurrences table: source, location (file:line or object key or message link), commit + author + age, Present (in HEAD, history only, or yes for non-Git sources). Each row deep-links to the source.
3. Code context: up to 5 lines around the match from the stored snippet, secret masked.
4. Timeline: detection, every validation result, severity changes, assignment, alerts sent, status changes, each with actor and time.
5. Details panel: fingerprint, provider, first seen, assignee, team, tags (editable).
6. Remediation checklist: provider-specific steps from the rule; items tick off and are saved. Closing as Resolved/revoked requires a re-validation showing Inactive.
7. Notify developer: creates a share link (expires in 30 days) showing the occurrence and steps, without other incidents.
8. Re-validate calls `kingfisher validate` for the rule with the vault copy of the secret and its dependent captures, and records a validation event.

## Screen 5 · Perimeter

Shows what is monitored, how often, and what is failing, so coverage gaps are visible before they become leaks.

**Requirements**

1. Coverage cards: Integrations (with unreachable-source badge), Scheduled coverage (% of sources scanned within their schedule window), Last scan OK (%), Team owned (%). Each card filters the table.
2. Integration tiles for GitHub, GitLab, Bitbucket, S3, GCS, Docker images, Slack, Microsoft Teams, Jira, Confluence, Postman, and filesystem/CI workspaces. Each shows source count and state (OK, unreachable, token expiring, not connected) and opens a connect/configure flow.
3. Sources table: source, integration, criticality (editable: Critical/High/Medium/Low), Git history mode (full / none), schedule, last scan, open incidents, health. Default filter: Has open incidents; sorted by open incidents.
4. Schedules per source or integration: on push (via VCS webhook), on publish (registries), hourly, every 6 h, daily. Webhook-triggered scans run Kingfisher on the changed refs only.
5. Historical scan: runs a full-history scan for selected sources; shows progress and estimated time.
6. Health checks every 15 min per integration: credential valid, permissions sufficient, source reachable. Failures raise a banner and an audit event.
7. Add source: pick integration, select sources (org-wide or individual), set criticality, owner team and schedule.

**Kingfisher mapping:** each scan job runs a pinned Kingfisher container with the target's scan subcommand, validation on, JSON output; the platform ingests the output and updates Source and Scan run records.

## Screen 7 · Detection rules

A browsable catalog of Kingfisher's built-in rules (count read from the pinned release) plus the workspace's custom rules, with per-rule enable/disable.

**Requirements**

1. Table: rule id, provider, confidence, Validate, Revoke and Access map support, open incident count, Enabled toggle.
2. Search by provider or rule id; filters for confidence, validates live, can revoke, maps access, origin (built-in / custom).
3. Disabling a rule stops new incidents from it; existing incidents stay, with a "rule disabled" tag.
4. Custom rule editor: YAML in Kingfisher's rule format, syntax-checked on type. "Test against sample" runs the rule on pasted text in a sandbox and shows matches and validation outcome.
5. Saving a custom rule versions it; scans use the version current at scan start, recorded on the Scan run.
6. Built-in catalog refreshes when the pinned Kingfisher version is upgraded; a changelog lists added, changed and removed rules.

**Acceptance:** a custom rule saved here is picked up by the next scheduled scan and by CI configs generated on screen 8.

## Screen 8 · Prevention & integrations

One place to stop secrets before they land, manage what is accepted, route alerts, and see who did what.

**Requirements**

1. Shift-left setup: copyable snippets for GitHub Actions, GitLab CI, pre-commit and Docker, using the pinned Kingfisher image. Option to fail builds on Active secrets only or on any finding. SARIF output for code-scanning upload.
2. Workspace policy: console settings (confidence threshold, validation on, Git history mode, excludes, disabled rules) generate a `kingfisher.yaml`. Users can download it or open PRs to selected repos.
3. Baseline: table of fingerprint, rule, reason, created by, expiry. Add, remove, regenerate. The platform suppresses by secret identity and exports a Kingfisher baseline file listing every known occurrence fingerprint, so CI suppresses the same locations. Expired entries reopen their incident.
4. Alerting & ticketing: Webhook (native Kingfisher alert webhook format), Slack, Jira, SIEM (Splunk, Sentinel) and PagerDuty notifiers. Each has a filter (severity, validity, team, source) and a test button.
5. Jira: one ticket per Active incident by default; ticket status syncs back to incident status.
6. Audit log: time, actor, action, target for every UI/API action and scan; filter and export to CSV. Retained 1 year.

**Acceptance:** a commit containing an Active GitHub token fails the generated GitHub Actions job, and the same fingerprint, if baselined, does not.

## Platform requirements

These cut across every screen and are entirely new platform work.

**Access control**

| Role | Can |
| --- | --- |
| Admin | Everything, incl. integrations, notifiers, policy, roles |
| Manager | Triage, assign, resolve, baseline, edit rules and schedules for their teams' sources |
| Member | View and act on incidents for their teams' sources |
| Restricted | View incidents shared with them or assigned to them |

- SSO via SAML 2.0 and OIDC; SCIM for user and team provisioning.
- Team perimeter: each source has an owner team; Managers and Members only see their teams' sources.

**API:** REST API covering incidents, occurrences, sources, scans, rules, baseline and audit, with scoped tokens. Every UI action is available through it.

**Non-functional**

- Deployment: SaaS and self-hosted (Helm chart); scan workers run in the customer network when self-hosted.
- Scale: 50k open incidents, 10k sources, 1k scans/hour per workspace.
- Security: secrets encrypted at rest (KMS), never logged, masked in UI and exports; worker egress limited to provider APIs needed for validation.
- Engine: Kingfisher pinned per workspace; upgrades are staged and can be rolled back.
- Availability: 99.9% for the console; scan backlog alert when any source is 2× past its schedule.

## Delivery, metrics and open questions

**Phases** (dates to be set with engineering)

1. Foundation: scan worker running pinned Kingfisher, ingest pipeline, incident store keyed by fingerprint, SSO and roles.
2. Triage: Incidents list, Incident detail, severity rules, Slack and webhook notifiers.
3. Coverage: Perimeter with integrations, schedules, health checks, historical scans; Overview dashboard.
4. Prevention: Detection rules and custom rule editor, CI snippets, policy file generation, baseline sync, Jira and SIEM, audit log.
5. Redesign and ship the deferred screens: Identities & blast radius, Revoke workflow.

**Success metrics**

| Metric | Target |
| --- | --- |
| Median time from detection to Active-incident alert | under 5 min for on-push sources |
| Median time to remediate Active incidents | down 50% vs. baseline at 90 days |
| Sources scanned within schedule | 95% or more |
| Repos with CI scanning enabled | 80% of critical repos at 90 days |
| Incidents closed as false positive | under 10% |

**Open questions**

- [ ] Store an encrypted copy of secrets for re-validation, or re-scan the source each time?
- [ ] Is revoke allowed in v1 behind a flag, or CLI-only until screen 6 is redesigned?
- [ ] Which Kingfisher release do we pin first, and who owns upgrades?
- [ ] Do we contribute platform needs (stable finding schema, webhook format) upstream to Kingfisher?
- [ ] Self-hosted from v1, or SaaS first?

## Sources

- [Kingfisher docs](https://mongodb.github.io/kingfisher/)
- [Kingfisher report viewer](https://mongodb.github.io/kingfisher/features/report-viewer/)
- [Kingfisher: validation, blast radius and revocation](https://mongodb.github.io/kingfisher/blog/2026/04/28/beyond-detection-live-validation-blast-radius-and-one-command-revocation/)
- [GitGuardian monitored perimeter](https://docs.gitguardian.com/platform/monitor-perimeter/monitored-perimeter)
- [GitGuardian perimeter management](https://docs.gitguardian.com/internal-monitoring/integrate-sources/monitored-perimeter)
- [Wireframes canvas](https://claude.ai/artifact/2Nhxezeup6oUxm154HZWpW)

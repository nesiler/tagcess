# AGENTS.md: tagcess

These instructions are for every coding agent (Claude Code, Codex, OpenCode and others). Claude reads them through
`CLAUDE.md`. Human contributors: see `CONTRIBUTING.md` and `docs/development.md`.

## Project
tagcess is an access-management portal for a self-hosted VPN. It ties together Caddy (internal sites and their role
rules), Headscale (policy, devices, DNS) and an OIDC identity provider (Zitadel today; a driver structure for others
is planned). The IdP is the only user and role store. tagcess is a Go single binary with a server-rendered UI and
SQLite. Licence: MIT.
- Overview and function IDs (S-, Y-, H-, K-, P-, A-, NFR-): `docs/overview.md`. Requirements, architecture,
  security: `docs/requirements.md`, `docs/architecture.md`, `docs/security.md`. Decisions: `docs/adr/`.
- Work items: GitHub Issues, grouped by Milestones. The process: `docs/development.md`.

## Hard rules
1. **Never run write commands against any production system.** Read-only inspection only when the developer asks
   for it in the current conversation. The developer's local guard config (`$HOME/.config/tagcess/guard-patterns.txt`,
   read by the Bash guard hook) lists the production hosts; the guard is a safety net, not permission.
2. **No secrets** in the repo, issues, PRs, docs, logs or test fixtures. Read secrets from files or env at runtime.
   Fixtures use generic values (`example.com`, RFC 5737 IPs, users like `alice`).
3. **The IdP is the only user/role store.** tagcess reads roles; it never creates users or grants roles.
4. **Scope is the VPN/access layer only.** Do not discuss or fix the applications behind the sites.
5. **Decisions belong to the developer.** Mark your proposals: **[Proposed]** in docs, `Proposed` in ADRs.
   Never write a proposal as a decision (**[Decided]**). If an issue depends on an **[Open]** point, stop and ask.
6. **Everything manageable from the UI.** Do not design features that leave manual config steps behind.
7. **Fail safe.** If the IdP, Headscale or Caddy cannot be read or validated, keep the last known good state.
   Never widen access.
8. **Git by role.** Workers commit and push only their own `issue/<n>-<slug>` branch and open its PR. Reviewers
   never commit or push. Only the coordinator merges PRs into `main`, and pushes `main`. The release flow is [Open]; nobody tags or publishes yet.
   Nobody commits without such a role or an explicit request from the developer.
9. **No attribution lines.** No `Co-Authored-By` or "Generated with" lines in commits, PRs or issues.

## Language
- Everything in the repo is English: code, identifiers, comments, docs, issues, PRs, commit messages.
- The UI is English and Turkish (i18n). Turkish strings live only in the UI translations.

## Roles and the issue workflow
One issue = one branch = one PR. Details: `docs/development.md`.

| Role | Skill | Does | Never |
|---|---|---|---|
| developer | – | decides, approves `risk:auth` and security PRs, changes defaults | – |
| coordinator | `coordinator` | plans milestones and issues, picks worker and reviewer models, spawns and watches sessions, merges after green CI and a clean review, keeps the milestone and `CHANGELOG.md` (squash merge and the CHANGELOG commit are the proposed default, pending the developer's decision) | writes code or reviews, answers a child's question itself |
| worker | `issue` | reads one issue, branch `issue/<n>-<slug>`, test first, `make check`, opens a PR with `Closes #n` and an acceptance criterion → test map | merges, pushes `main`, works outside its issue |
| reviewer | `review` | reviews one PR against its issue with the reviewer agents, posts a PR review comment with findings by severity | pushes, edits the branch, merges |

- The reviewer is a different model from the writer. Defaults: `.agents/roles.conf`; the developer can override
  them per issue (labels `model:<profile>` / `reviewer:<profile>`, a `Model:`/`Reviewer:` line in the issue body,
  or by telling the coordinator).
- `risk:auth` and other security-relevant PRs need the developer's approval before the merge.
- "Done" for a PR: `make check` and CI pass, every acceptance criterion maps to a passing test, and the review has
  no open high or medium finding.

## Commands
| Command | What it does |
|---|---|
| `make check-fast` | gofmt, vet and `go test ./...` (the Stop hook runs it) |
| `make check` | Full gate: agent files up to date, guard and coordinator tests, installer lint, golangci-lint, `go test -race`, generated code up to date |
| `make agents` | Regenerate `.codex/agents/*.toml` and `.opencode/agent/*.md` from `.agents/agents/*.md` |
| `make generate` | Run the pinned code generators (templ, sqlc) |
| `scripts/coord/coord.sh` | Coordinator tool: spawn, send, wait, status, peek, profiles, review-for, doctor |

## Skills (`.agents/skills/`)
| Skill | Use for |
|---|---|
| `coordinator` | Plan milestones and issues, assign models, run child sessions, merge PRs, CHANGELOG |
| `issue` | Work one issue as the worker, up to an open PR |
| `review` | Review one PR as the independent reviewer |
| `adr` | Record a decision in `docs/adr/` |
| `stack-notes` | Verified facts about the external systems (versions, paths, APIs); read before touching integrations |

## Agents (`.agents/agents/`)
All reviewer agents are read-only and report findings; they do not edit.

| Agent | Role |
|---|---|
| `code-reviewer` | PR diff vs the issue's acceptance criteria; correctness and fail-safe only |
| `security-reviewer` | Auth, webhook signatures, injection into generated config, secrets; required for `risk:auth` |
| `plan-reviewer` | Docs, ADRs, milestones and issues vs decisions; testability and issue size |
| `researcher` | Verifies facts about external APIs, with sources |

## Child sessions
When the coordinator started you, your prompt begins with a protocol (`.agents/coord/protocol.md`). Report with
`scripts/coord/tell.sh question|done|blocked "<message>"`, then wait or stop. Ask questions as plain text, not
through interactive menus.

## Go conventions (until ADRs say more)
- Standard library first; every new dependency needs a reason in the issue, the PR or an ADR.
- Stack (ADR 0006, 0007): `modernc.org/sqlite`, own embedded migrator, `sqlc`; `templ` + htmx + own
  `internal/web/ui` components (no Bootstrap; rules in `docs/ui-guide.md`), CodeMirror 6 for HuJSON. Code
  generators are pinned as `go tool` deps; generated code is committed.
- Table-driven tests. Integration tests run behind the `integration` build tag against local Docker Compose
  (Headscale, Caddy, oauth2-proxy) and a lab IdP (ADR 0014; there is no local Zitadel).
- Generated config (Caddyfile, policy, DNS records) must be deterministic, and golden-file tested.

<!-- agent-kit:begin -->
## Agent management (agent-kit)

- Level 2: task source `github` (issues; specs in `docs`), gate command `make check`.
- The coordinator (Claude) hands work to child sessions: `scripts/coord/coord.sh spawn|send|wait|verify` (wrapper
  around `scripts/agent-kit/ak`). Profiles: `coord.sh profiles`. Herdr is the primary terminal layer (run the
  coordinator inside Herdr); tmux is the fallback.
- Children run without permission prompts, so the protocol rules are binding: git only as the role allows, no
  production writes, no secrets.
- "Done" is a claim: the coordinator re-checks CI, the PR and the diff itself.
- Independent review: `.agents/roles.conf` (`review:<writer>`) wins over agent-kit's `review-for` default; any
  profile can still be chosen.
- One code-writing session per working tree; parallel writers get their own git worktree.
- Standard: `~/.claude/skills/agent-kit/reference/contract.md` (when installed). Project settings:
  `.agents/agent-kit/kit.conf`.
<!-- agent-kit:end -->

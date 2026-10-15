# Development process

How work moves from an idea to `main` in tagcess. It applies to humans and to AI agents alike; the agent-specific
rules are in `AGENTS.md`. Markers: **[Decided]** the developer decided it, **[Proposed]** a proposal that still
needs the developer's approval, **[Open]** not decided yet.

## 1. Principles
- **[Decided]** Work is tracked in GitHub Issues, grouped by Milestones. There are no task or phase files in the repo.
- **[Decided]** One issue = one branch = one PR.
- **[Decided]** Every PR gets an independent review by a different, equivalent model (or a human).
- **[Decided]** PRs labelled `risk:auth`, and other security-relevant PRs, need the developer's final approval.
- **[Decided]** Only the coordinator merges into `main` and pushes `main`.
- **[Decided]** Everything in the repo is English. The UI is English and Turkish.
- `docs/` stays the source of specs and decisions; issues reference it.

## 2. Roles
| Role | Who | Does | Never |
|---|---|---|---|
| Developer | the maintainer | decides; approves `risk:auth`/security PRs; overrides model choices; owns releases | – |
| Coordinator | a Claude Code session, skill `coordinator` | plans milestones and issues; picks worker and reviewer models; spawns and watches child sessions; relays their questions; merges after green CI and a clean review; keeps the milestone and `CHANGELOG.md` | writes code or reviews; answers a child's question itself |
| Worker | a child session, skill `issue` (or a human contributor) | reads one issue; branch `issue/<n>-<slug>`; test first; `make check`; opens the PR | merges; pushes `main`; works outside the issue |
| Reviewer | a child session, skill `review` (or a human) | reviews one PR against its issue, using the reviewer agents; posts a PR review comment | pushes; edits the branch; merges |

Each role does only its own job. A child that needs a decision asks it as a `question` through
`scripts/coord/tell.sh`; the coordinator passes it to the developer word for word.

## 3. Flow
```
issue (task form, labels, milestone)
  └─ worker: branch issue/<n>-<slug> → failing tests → code → make check → PR "Closes #n"
       └─ CI runs the gate on the PR
       └─ reviewer (different model): PR review comment, findings high/medium/low
            ├─ high/medium findings → fix round on the same branch (at most 2, then the developer decides)
            └─ clean → risk:auth? → developer approval
                 └─ coordinator: squash merge to main, delete branch, CHANGELOG line
```

### 3.1 Issues
- Use the issue forms in `.github/ISSUE_TEMPLATE/`: **Task** (planned work, used by the coordinator), **Feature
  request** and **Bug report** (anyone).
- A task issue has a goal, context (function IDs, ADRs, docs), testable acceptance criteria (EARS:
  `WHEN … THE system SHALL …`, `IF … THEN THE system SHALL …`, each naming its test), a risk and a scope.
- Size: one session and one reviewable PR, roughly 1–5 files, one concern.
- Dependencies: `Depends on #n` in the body. A worker does not start while a dependency is open.
- An issue that waits for a decision carries `needs-developer`.
- Spec work (requirements, architecture, security, ADRs) is a `type:docs` issue and goes through a PR like code.

### 3.2 Branches and commits
- Branch name: `issue/<n>-<short-kebab-slug>`, from `origin/main`.
- Commit messages: English, imperative, with `#<n>`. No `Co-Authored-By` or "Generated with" lines.
- One code-writing session per working tree. Parallel workers get their own git worktree
  (`git worktree add ../tagcess-wt/issue-<n> -b issue/<n>-<slug> origin/main`).

### 3.3 Pull requests
The PR template (`.github/PULL_REQUEST_TEMPLATE.md`) asks for:
- `Closes #<n>`;
- every acceptance criterion mapped to a test (name, package, result);
- the gate command and its result (`make check`);
- the risk (`normal` or `auth`) and the labels of the issue;
- follow-ups that were left out of scope.

If behaviour or a decision changes, the docs (or the ADR) change in the same PR. Generated code is committed.

### 3.4 Review
- The reviewer reads the PR (`gh pr view`, `gh pr diff`) and the issue, tests in a separate read-only checkout,
  and runs the reviewer agents: `code-reviewer` for code, `security-reviewer` for `risk:auth` or security-relevant
  diffs, `plan-reviewer` for docs and planning, `researcher` for doubtful external facts.
- The result is one PR review comment: a verdict (`clean` or `changes needed`), findings by severity
  (high/medium/low) with `file:line`, scenario and fix, and the acceptance criterion → test status.
- Only correctness, requirement, fail-safe and security gaps count. No style nits.

### 3.5 Merge
The coordinator merges (`gh pr merge --squash --delete-branch`) only when:
1. CI is green;
2. the latest review has no open high or medium finding;
3. for `risk:auth` or security-relevant PRs, the developer approved it (§6);
4. there is no conflict with `main`.

**[Proposed]** Squash merges, so `main` has one commit per issue. After the merge the coordinator adds a line under
`## Unreleased` in `CHANGELOG.md` for user-visible changes; that bookkeeping commit is the only direct commit to
`main`.

## 4. Labels
The label set is defined in `.github/labels.yml`; the coordinator creates or updates the labels with `gh label`.

| Label | Meaning |
|---|---|
| `type:feature`, `type:bug`, `type:chore`, `type:docs` | Kind of work; exactly one per issue |
| `risk:auth` | Touches authn/authz, webhook verification, policy or ACL writes, generated config, node expiry or secrets. Needs `security-reviewer` and the developer's approval |
| `area:<group>` | Package group (web, sync, idp, policy, headscale, caddy, k8s, store, monitoring, deploy, tooling) |
| `model:<profile>` | Override the worker model for this issue |
| `reviewer:<profile>` | Override the reviewer model for this issue |
| `needs-developer` | Waits for a decision or an approval from the developer |

## 5. Milestones
- A milestone is one goal with measurable exit criteria in its description, for example "a fresh install on one
  host reaches a working portal".
- Its first issue sets up any harness the others need; its last issue proves the exit criteria end to end.
- When its last issue closes, the coordinator checks the exit criteria and reports; the developer closes it.

## 6. Developer approval (risk:auth and security)
- The coordinator labels the PR `needs-developer` when it is ready and asks the developer.
- The developer approves with a GitHub "Approve" review. When GitHub does not allow it (the PR was opened from the
  developer's own account, which is the case for agent PRs today), the developer approves explicitly in the
  coordinator session, and the coordinator records it as a PR comment ("Developer approval given in the
  coordinator session on YYYY-MM-DD") before it removes `needs-developer` and merges.
- Agents never approve on the developer's behalf.
- **[Open]** Separate GitHub accounts for agents (so that approvals and authorship are distinct).

## 7. Models: defaults and overrides
**[Decided]** Today's defaults stay, and the developer can change them per issue.

Defaults live in one file, `.agents/roles.conf`:

| Role | Default profile |
|---|---|
| Writer (simple and medium issues, UI, tests, docs fixes) | `deepseek` |
| Writer for `risk:auth`, security logic, e2e, cross-package or unclear design | `sonnet` |
| Fix round | `sonnet` |
| Escalation after two failed attempts | `sonnet` |
| Research, ADR proposals, technical recommendations | `opus` |
| Reviewer of a `deepseek` PR | `sonnet` |
| Reviewer of a `sonnet` PR | `codex` |
| Reviewer of an `opus` PR | `codex` |
| Reviewer of a `codex` PR | `opus` |
| Reviewer of docs/ADR/planning PRs, very important or hard reviews | `opus` |

Strength order for escalation and review: `opus` > `codex` > `sonnet` > `deepseek`.

Re-review after a fix round: the reviewer is chosen from the fixer's profile (`review:<fix profile>`), never the same
model that wrote the fix.

Override for one issue, highest priority first:
1. the developer tells the coordinator;
2. a label `model:<profile>` or `reviewer:<profile>`;
3. a line in the issue body, `Model: <profile>` or `Reviewer: <profile>` (optional fields of the task form);
4. `.agents/roles.conf`.

Profiles are machine setup (install directories, proxies, model names) and are not in the repo:
`scripts/coord/coord.sh profiles` merges `~/.config/tagcess/profiles.conf` (tagcess-local), the repo's test
profile (`.agents/coord/profiles.conf`) and the agent-kit machine library (`~/.config/agent-kit/profiles.conf`).
Every profile named in `roles.conf` must exist there.

## 8. Child sessions
The coordinator runs workers and reviewers as child sessions in Herdr panes (tmux as fallback) with
`scripts/coord/coord.sh` (a wrapper around the vendored agent-kit dispatcher `scripts/agent-kit/ak`).
- `spawn` puts `.agents/coord/protocol.md` on top of the prompt. Children report with
  `scripts/coord/tell.sh question|done|blocked`; harness hooks add `idle` and `exit` events.
- Children run without permission prompts, so the protocol rules (git by role, no production writes, no secrets)
  are binding. Claude children inherit the project hooks, including the Bash guard; Codex and OpenCode children
  have no such guard, so production-adjacent work goes to Claude profiles.
- Run state lives outside the repo (`~/.local/state/tagcess-coord/`). `make coord-test` tests the tooling with a
  fake agent.

## 9. Gates and CI
| Gate | Where | Contents |
|---|---|---|
| `make check-fast` | Claude Stop hook, any time | gofmt, `go vet`, `go test ./...` |
| `make check` | before every PR | `agents-check`, `guard-test`, `coord-test`, `installer-lint`, `notices-check`, `notices-test`, golangci-lint, `go test -race`, `generate-check`, `generate-test` |
| CI (`.github/workflows/ci.yml`) | every PR and push to `main` | the `make check` pieces that run without local tools: `agents-check`, `guard-test`, `notices-check`, `notices-test`, `generate-check`, `generate-test`, golangci-lint, `go test -race` (`coord-test` and `installer-lint` stay local: they need tmux, ansible-lint, shellcheck) |

`THIRD_PARTY_NOTICES` lists the licences of the dependencies that ship in the binaries (built from
`./cmd/...`) and the embedded web assets. `make notices` regenerates it; `make notices-check` fails
when it is out of date or a licence is off the allowlist (issue #12, `docs/product-decisions.md` §5).

A PR is mergeable only with green CI. Integration and e2e targets (`make lab-integration`, `make e2e`, …) need a
lab and run on demand; the PR says when they were run.

## 10. Versions and releases
- **[Decided]** Versions grow minimally inside `0.1.x`.
- **[Decided]** The first release and the first code push to `main` are generic: no company names, hosts, IPs or
  people.
- **[Open]** The release flow (tags, release notes, container image, artefacts) is decided later. Until then nobody
  tags or publishes a release.

## 11. Contributors
External contributions follow the same flow; see `CONTRIBUTING.md` (a CLA is required). Security issues are
reported privately; see `SECURITY.md`.

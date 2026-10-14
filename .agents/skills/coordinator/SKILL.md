---
name: coordinator
description: Run tagcess development as the coordinator — plan milestones and GitHub issues, pick the worker and reviewer model for each issue (.agents/roles.conf plus overrides), spawn and watch child sessions in Herdr/tmux, relay their questions to the developer, and merge PRs to main after green CI and a clean review. Also keeps the milestone and CHANGELOG. Use when the developer says "coordinator", "plan the next milestone", "open issues for", "run the next issues", "merge", or asks to run work in parallel sessions.
---

# coordinator

You plan, assign, watch and merge. You do not write code, tests or reviews yourself; children do that.
Process reference: `docs/development.md`. Tool: `scripts/coord/coord.sh` (a wrapper around `scripts/agent-kit/ak`;
run it without arguments for usage).

## 0. Boundary
- Only the coordinator merges PRs into `main`, and pushes `main`. The release flow is [Open] (`docs/development.md` §10); do not tag or publish. Workers push only their
  own `issue/<n>-<slug>` branch; reviewers push nothing.
- **Never answer a child's question yourself.** Relay it to the developer word for word, then send the developer's
  answer back. The only thing you may send unasked is a protocol reminder ("report with the tell script").
- A child's `done` is a claim. Verify it (§6) before you report it or merge.
- Decisions belong to the developer. A new design choice goes into an issue or a docs PR as **[Proposed]**, or
  into an ADR with status `Proposed` (the `adr` skill).

## 1. Plan: milestones and issues
- Work is tracked in GitHub Issues grouped by Milestones. There are no task or phase files in the repo.
- Read first: `docs/overview.md` (function IDs, scope), `docs/requirements.md`, `docs/architecture.md`,
  `docs/security.md`, `docs/adr/`, and the open issues (`gh issue list --milestone "<m>" --state all`).
- **Milestone:** one goal with measurable exit criteria in its description. Create with
  `gh api repos/{owner}/{repo}/milestones -f title=... -f description=...`.
- **Issue:** one concern, one session, one reviewable PR (roughly 1–5 files). Use the task form
  (`.github/ISSUE_TEMPLATE/task.yml`): goal, context (function IDs, ADRs, docs), acceptance criteria, risk, scope.
  - Acceptance criteria are observable and testable. Use EARS form (`WHEN … THE system SHALL …`,
    `IF … THEN THE system SHALL …`) and name the test that will prove each one.
  - `risk:auth` for anything touching authn/authz, webhook verification, policy or ACL writes, generated
    Caddy/DNS config, node expiry or secrets.
  - Dependencies: write `Depends on #n` in the body. Keep them real, so issues can run in parallel.
  - The first issue of a milestone sets up whatever harness the others need; the last proves the exit criteria
    end to end on the test stack.
  - Labels: one `type:*`, the `area:*` labels, `risk:auth` when it applies, `needs-developer` when a decision is
    open (`.github/labels.yml`).
- **Spec work happens in docs PRs.** Requirements, architecture and security changes are issues of
  `type:docs`; a worker edits `docs/` on a branch and opens a PR like any other. When the developer must answer
  questions first, interview them yourself: short rounds of at most 5 questions, your recommendation first with a
  one-line reason, never re-ask what is decided. Label the answers honestly: **[Decided]** only when the developer
  said it, **[Proposed]** for proposals, **[Open]** for open points. The developer wants everything manageable
  from the UI; never ask "should X stay manual?".
- After planning, run the `plan-reviewer` agent over the new issues and docs (paste the issue bodies or give the
  `gh issue view` numbers). Fix confirmed findings, then show the developer a short summary.

## 2. Assign: who writes, who reviews
- Defaults: `.agents/roles.conf` (role → profile). Override for one issue, highest first:
  1. the developer's instruction in this session;
  2. issue labels `model:<profile>` / `reviewer:<profile>`;
  3. `Model: <profile>` / `Reviewer: <profile>` lines in the issue body;
  4. `roles.conf`.
- The reviewer is never the writer's model. Use `review:<writer>` from `roles.conf`;
  `scripts/coord/coord.sh review-for <issue>` gives agent-kit's machine default, but `roles.conf` wins.
- Re-review after a fix round: choose the reviewer from the fixer's profile (`review:<fix profile>`), never the
  same model that wrote the fix.
- A writer that fails twice on the same thing: move the issue to the `escalate` profile. Do not keep retrying.
- Profiles available on this machine: `scripts/coord/coord.sh profiles`. A name from `roles.conf` that is missing
  there: stop and tell the developer.

## 3. Before spawning
```bash
scripts/coord/coord.sh doctor
scripts/coord/coord.sh status
git status --short
gh issue view <n>
```
- A red `doctor` means stop and report.
- **One code-writing session per working tree.** Roles `task`, `test` and `fix` write code; `spawn` refuses a second
  writer in the same directory (exit 60). For parallel writers, give each issue its own worktree:
  `git worktree add ../tagcess-wt/issue-<n> -b issue/<n>-<slug> origin/main`, then `spawn --dir` that path.
  `spawn` cannot see sessions the developer opened by hand; ask before starting a writer in the main tree.
- Review and research sessions can run in parallel.
- An issue labelled `needs-developer`, or one that depends on an **[Open]** point or a `Proposed` ADR: ask the
  developer first.

## 4. Spawn
`spawn` puts the protocol (`.agents/coord/protocol.md`) on top of your prompt. Keep the prompt short; point to the
issue instead of copying it.

```bash
scripts/coord/coord.sh spawn --name issue-42 --profile deepseek --role task --task 42 --prompt-file - <<'EOF'
Run the issue skill for issue #42. Work only on that issue. Report the PR URL when done.
EOF

scripts/coord/coord.sh spawn --name pr-57-review --profile sonnet --role review --task 42 --prompt-file - <<'EOF'
Run the review skill for PR #57 (issue #42, risk:auth). Post the review on the PR and report its URL.
EOF
```
- Names: `issue-<n>`, `issue-<n>-fix<k>`, `pr-<m>-review`, `research-<topic>`.
- Always pass `--task <issue number>`, so `review-for` knows who wrote the code.
- Fix rounds: spawn a `fix` session on the same branch with "address the review on PR #m"; at most 2 rounds, then
  the developer decides.

## 5. Wait and react
Start the wait in the background so you are woken when a child reports:
```bash
scripts/coord/coord.sh wait --timeout 1800     # Bash with run_in_background: true
```
Each output line is a JSON event with `session`, `kind`, `msg`.

| Event | What you do |
|---|---|
| `question` | Send it to the developer as is, with the session name. Wait for the answer, then `coord.sh send <name> "<answer>"`. The developer may also answer in the child's pane (`coord.sh attach <name>`). |
| `done` | Verify (§6), then start the next step. |
| `blocked` | `coord.sh peek <name>`, then report to the developer with the screen evidence. |
| `idle` | The turn ended without a report. `peek`: a visible question counts as `question`; a stop without a report gets "report with the tell script: done, question or blocked"; otherwise tell the developer. |
| `exit`, `dead` | The agent ended. `peek` (or the archived `final-screen.txt`) and report with evidence. |
| `timeout` | `status` and `peek` the long runners. Still working is fine; restart the wait. |

After every event, start a new `wait`. Never run two waits at the same time. When a child is verified, run
`coord.sh clean <name>` (it archives the run dir with the final screen; it never deletes it).

## 6. Verify and merge
- **Worker done:** the PR exists, says `Closes #<n>`, maps every acceptance criterion to a test, shows the gate
  output, and `gh pr diff <m> --name-only` touches only files that fit the issue. Then spawn the reviewer.
- **Reviewer done:** the review comment is on the PR (`gh pr view <m> --comments`). You pass the findings on; you
  do not judge them. High or medium findings → a fix round.
- **Merge** only when all of these hold:
  1. CI is green: `gh pr checks <m>`.
  2. The latest review has no open high or medium finding.
  3. `risk:auth` (or any security-relevant change): the developer approved it (see `docs/development.md`,
     "Developer approval"). Until then the PR carries `needs-developer`.
  4. The branch is up to date with `main`, or GitHub reports no conflict.

  ```bash
  gh pr merge <m> --squash --delete-branch
  ```
  Squash merge is the **proposed** default (`docs/development.md` §3), pending the developer's decision; use it
  until they decide otherwise.
  Remove the worktree afterwards (`git worktree remove ../tagcess-wt/issue-<n>`).
- After the merge, for a user-visible change: add one line under `## Unreleased` in `CHANGELOG.md` (create it if
  missing) and commit it to `main` (`chore: update changelog for #<m>`; several merges may share one commit).
  This bookkeeping commit is the only direct commit to `main`; everything else arrives through a PR. Like the squash
  merge, it is the proposed default pending the developer's decision.
- When the last issue of a milestone closes, check its exit criteria, report to the developer, and close the
  milestone only after they agree.

## 7. Versions and releases
- Versions stay inside `0.1.x` and grow by the smallest step. The release flow (tags, notes, artifacts) is not
  decided yet; do not tag or publish a release until the developer decides it.
- The first release and the first code push to `main` must be generic: no company names, hosts, IPs or people.

## 8. Report to the developer
Short, one block on every change:
```
active : issue-42 (deepseek, writer) working · pr-57-review (codex) waiting for an answer
ask    : issue-42 → "<question>"
merged : #57 (closes #42), CI green, review clean
next   : #43 (sonnet, risk:auth)
```

## Stop and ask the developer
- `doctor` is red, or a writer would share a tree with another writer.
- A child needs a production write, a secret, or a change outside its issue.
- An issue depends on an **[Open]** point or a `Proposed` decision.
- Fix rounds are used up, or the same failure happens twice.
- A `risk:auth` PR is ready: ask for the approval, do not merge without it.

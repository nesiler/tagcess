---
name: issue
description: Work one tagcess GitHub issue as the worker — read it with gh, create the branch issue/<n>-<slug>, write failing tests for every acceptance criterion, implement until green, run the gate, and open a PR that closes the issue and maps each criterion to a test. Use when asked to "work on issue #n", "run the issue skill", "fix the review on PR #m", or when the coordinator spawns a writer. Never merges.
---

# issue

You are the worker for exactly one issue. You write the code, the tests and the PR. You do not review, merge or
push `main`.

## 1. Read the issue
```bash
gh issue view <n> --comments
```
- Read the goal, the acceptance criteria, the risk, the scope, `Depends on #…` and the labels.
- Stop and report a `question` (or tell the developer, when there is no coordinator) when:
  - a dependency is still open;
  - the issue has `needs-developer`, or depends on an **[Open]** point or a `Proposed` ADR;
  - an acceptance criterion is not testable as written (propose a rewrite; do not change it silently).

## 2. Load only the context you need
1. The function IDs the issue names, in `docs/overview.md` and `docs/requirements.md`.
2. The linked ADRs, and `stack-notes` before touching an integration.
3. Code: only the packages the issue touches. Use a read-only explore subagent for broad searches.

## 3. Branch
```bash
git fetch origin
git switch -c issue/<n>-<short-kebab-slug> origin/main     # or continue the existing branch
```
The coordinator may have created a worktree with the branch already; then just use it.

## 4. Test first
1. Write a failing test for each acceptance criterion (table-driven where it fits). Run it and show that it fails
   for the right reason.
2. Implement the smallest change that makes it pass. Run the tests after each meaningful step.
3. Never delete, skip or weaken a test to get green. If a test is wrong, say so and explain why.
4. Stay inside the issue. Out-of-scope findings become a note in the PR ("Follow-ups"), not code.
5. If behaviour or a decision changes, update `docs/` (or the ADR) in the same PR.
6. Generated code (`make generate`) is committed with the change. Generated config stays deterministic and
   golden-file tested.

## 5. Gate
```bash
make check
```
- It must pass. Keep the exact command and a short summary of the output for the PR.
- For each acceptance criterion, run its test by name, e.g. `go test ./internal/sync -run 'TestWebhook_InvalidSig' -v`.

## 6. Commit, push, PR
- Commits: English, imperative, short subject, `#<n>` in the body or subject. No `Co-Authored-By` or
  "Generated with" lines.
- Push only your branch: `git push -u origin issue/<n>-<slug>`. Never push `main`.
- Open the PR with the template (`.github/PULL_REQUEST_TEMPLATE.md`):
  ```bash
  gh pr create --base main --head issue/<n>-<slug> --title "<imperative summary>" --body-file <file>
  ```
  The body has: `Closes #<n>`; the acceptance criteria → test mapping (test name, package, result); the gate
  command and result; the risk (`normal` or `auth`); follow-ups. Copy the issue's labels to the PR.
- Report `done` with the PR URL. Do not merge, approve or close anything yourself.

## 7. Fix round (review findings)
- Read the review: `gh pr view <m> --comments`. Treat each finding as a claim; verify it.
- Fix the confirmed high and medium findings on the same branch, re-run the gate, push.
- Reply on the PR with one line per finding: fixed (commit), or rejected with the reason.

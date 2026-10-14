---
name: review
description: Review one tagcess pull request as the independent reviewer — read the PR and its issue with gh, check the diff against the issue's acceptance criteria, run the specialised reviewer agents (code-reviewer, security-reviewer for risk:auth, plan-reviewer for docs), and post the result as a PR review comment with findings by severity. Use when asked to "review PR #m", "run the review skill", or when the coordinator spawns a reviewer. Never pushes or merges.
---

# review

You review one PR. You do not edit the branch, push, approve for the developer, or merge.
You must be a different model from the one that wrote the PR (`.agents/roles.conf`).

## 1. Read the PR and its issue
```bash
gh pr view <m> --json number,title,body,labels,headRefName,baseRefName,closingIssuesReferences,files
gh pr diff <m>
gh issue view <n> --comments          # n from "Closes #n"
gh pr checks <m>
```
- The issue's acceptance criteria and scope are the yardstick, not the PR description.
- To run tests, use a separate read-only checkout, so you never touch the worker's tree:
  ```bash
  git fetch origin <headRefName>
  git worktree add --detach "$(mktemp -d)/pr-<m>" FETCH_HEAD
  ```
  Remove it when you are done (`git worktree remove <path>`).

## 2. Pick the reviewers
| Change | Agent |
|---|---|
| any code | `code-reviewer` |
| `risk:auth` label, or the diff touches auth, webhooks, policy/ACL writes, generated config, node expiry or secrets | also `security-reviewer` |
| `docs/`, ADRs, issue or milestone planning | `plan-reviewer` |
| an external API fact looks wrong or unverified | `researcher` |

- **Claude Code:** Agent tool, `subagent_type: <name>`; independent agents can run in parallel.
- **Codex:** the custom agent `<name>` from `.codex/agents/`. **OpenCode:** the subagent `<name>` from `.opencode/agent/`.
- Give each agent: the PR number, the issue number, the path of the read-only checkout and the diff range
  (`origin/main...FETCH_HEAD`). Not your own summary; let it read the source.

## 3. Judge the findings
- Treat every agent finding as a claim. Verify it in the code or by running the test before you post it.
- Keep only correctness, requirement, fail-safe and security gaps. No style nits, no redesigns.
- Check each acceptance criterion: is there a test, does it really test the criterion, did it pass?

## 4. Post the review
```bash
gh pr review <m> --comment --body-file <file>
```
Body format:
```
## Review (<profile>, <agents used>)
Verdict: clean | changes needed

### Findings
- **high** `path/file.go:123`: <scenario: input → wrong result>. Fix: <concrete fix>.
- **medium** …
- **low** …

### Acceptance criteria
| Criterion | Test | Status |
|---|---|---|

### What I ran
<commands and short results>
```
- "clean" means no open high or medium finding.
- `risk:auth`: end with "Needs developer approval before merge."
- Report `done` with the review URL. Never push to the branch, never merge, never close the issue.

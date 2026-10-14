# Contributing to tagcess

Thank you for your interest. tagcess is in a pre-release phase; the process below is how all work, including the
maintainers' own, reaches `main`. The full description is in [docs/development.md](docs/development.md).

## Before you start
- **Licence.** tagcess is released under the MIT License. By contributing you agree that your contribution is
  licensed under the same terms. There is no CLA.
- **Security issues** are never reported as public issues. See [SECURITY.md](SECURITY.md).
- **Conduct.** See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## How work flows
1. **Open or pick an issue.** Bugs and feature requests use the issue forms. Larger changes start with a
   discussion in the issue, so the design is agreed before code is written. Planned work uses the Task form with
   testable acceptance criteria and a risk field.
2. **One issue = one branch = one PR.** Branch `issue/<n>-<short-slug>` from `main`.
3. **Test first.** Write a failing test for each acceptance criterion, then make it pass. Never delete or weaken a
   test to get green.
4. **Run the gate:** `make check` (Go toolchain, golangci-lint, tmux and jq are needed; `make check-fast` is the
   quick subset).
5. **Open a PR** with the template: `Closes #<n>`, each acceptance criterion mapped to a test, the gate output and
   the risk.
6. **Review.** Every PR gets an independent review. PRs that touch authentication, authorisation, webhooks,
   policy/ACL writes, generated configuration, node expiry or secrets (`risk:auth`) also need a security review and
   the maintainer's approval.
7. **Merge.** The coordinator (a maintainer acting in that role) merges after green CI and a clean review.

## Rules that matter here
- **Fail safe.** If the IdP, Headscale or Caddy cannot be read or validated, keep the last known good state. Never
  widen access.
- **The IdP is the only user and role store.** tagcess reads roles; it never creates users or grants roles.
- **Everything manageable from the UI.** Avoid features that need manual configuration steps.
- **Scope** is the VPN/access layer, not the applications behind the sites.
- **No secrets or real data** in code, fixtures, logs, issues or PRs. Use `example.com`, RFC 5737 addresses and
  users like `alice`.
- **Standard library first.** A new dependency needs a reason in the issue or PR.
- **Generated code is committed** (`make generate`). Generated configuration is deterministic and golden-file tested.
- **English** for code, comments, docs, commits and PRs. The UI ships English and Turkish.

## Commits
English, imperative mood, with the issue number (`Verify webhook signature over the raw body (#42)`). No
`Co-Authored-By` or "Generated with" lines.

## AI agents
The repository includes instructions for coding agents (`AGENTS.md`, `.agents/`). Agent-written PRs follow exactly
the same rules and reviews as human ones.

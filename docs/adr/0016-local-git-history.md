# 0016: Generated artifacts are committed to a local git history

- Status: Accepted
- Date: 2026-09-30
- Decided by: the developer
- Related: A-02, A-01, A-03, NFR-04

## Context
When generated artifacts (Caddyfile, Headscale policy, MagicDNS/`extra-records` and other generated files)
are applied, a retrospective trail is needed: who changed which file and when. `audit_events` and
`applied_artifacts` in SQLite hold this at row level, but an exact version history of file contents is also wanted; the
A-03 rollback relies on it. The developer approved A-02: generated files get an automatic local git
commit.

## Decision
Every generated artifact is committed automatically to a local git repository **after** it was applied successfully in the change
chain and verified by read-back/hash; only verified final artifacts are committed. The commit actor is the user
who made the change (`system:sync` if it came from sync); the commit carries the actor, the apply time, the list of
changed files and the resulting revision ID. Secret values are not committed (NFR-04, A-01.1). The commit is added to the
`applied_artifacts` flow and does not block it, nor the main acceptance path. A missing revision is not
shown as success, and an uncertain artifact (one whose application cannot be verified) is not committed.
The developer's wording: "automatic local Git commits for generated Caddyfile, MagicDNS and other generated files,
including policy; who/when/which-file history".

## Consequences
- Pro: file versions and the who/when/which-file history are visible; it is the basis of A-03 rollback.
- Con: the git repository is a new state store; it adds disk usage and a secret leak surface. Mitigation: only generated
  files and secret-free commits; the secret scan is verified by an acceptance test.
- Commit order and failed-commit behaviour are decided **[Decided]**: the commit happens after apply + verification; on a git error
  the verified live/disk state is kept, an audit entry + a critical warning are written, and the commit is queued as a persistent,
  ordered retry intent. Safety boundary: the running config is not broken and access is not widened
  (NFR-05); see [architecture.md](../architecture.md) §4 step 7.
- Policy versions are also committed to git; but re-applying a policy from the UI is out of scope for this decision
  (A-03 policy rollback is a separate item, see [ADR 0017](0017-rollback-from-the-ui.md)).
- The resulting revision ID is recorded/returned; A-03 (ADR 0017) ties the durable version of the site source model to this
  revision (A-03.4).

## Alternatives considered
- Tracking only with SQLite (`applied_artifacts`): does not give an exact version history of file contents, not enough for A-03.
- Committing to the main source repository: mixes generated state with code history; out of scope.

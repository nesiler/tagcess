# 0005: Caddy config is generated as a Caddyfile

- Status: Accepted
- Date: 2026-09-28
- Decided by: the developer ("the other proposals are fine")
- Related: S-03, S-04, A-02, A-03

## Context
Caddy is managed today with a hand-written Caddyfile. tagcess keeps the sites in its own database and generates the
config.

## Decision
- Sites are generated as a **Caddyfile** from the records in SQLite, using a template. The snippets (`vpn_site`,
  `vpn_site_api`, `k8s`) keep the current structure.
- Apply flow (corrected 2026-09-28, see the note below):
  1. Generate.
  2. Check the syntax with the admin API `/adapt`.
  3. Load with the admin API `/load`. Caddy builds the new config in isolation; if it fails, the running config does
     not change and the file is not touched.
  4. If the load succeeded, write the file atomically (temporary file + rename).
  5. If the write fails, restore the previous content with `/load` and raise a critical warning.
- The generated file is also written to the local git repository.

## Consequences
- Pro: readable. Easy to diff and roll back. Manual intervention is possible even when tagcess is not running.
- Con: user input enters a text template. Every field must be validated strictly and escaped
  (scope of the security reviewer).
- Follow-up: the first version must generate an exact equivalent of the current Caddyfile. A golden-file test verifies this.

## Alternatives considered
- JSON config through the admin API: structured and more resistant to injection. But less readable, hard to diff,
  and detached from the current structure.

## Change notes
- 2026-09-28: the apply order changed from "write -> load" to "load -> write if successful". Reason: on a Caddy
  restart (systemd `caddy run --config`, no `--resume`) Caddy reads the file on disk. With the old order, if tagcess crashed
  between the write and the load, an unloadable file would stay on disk and all sites would go down at the next restart.
  The new order matches the architecture document and S-04.1.
  Decision: the developer ("proposals are fine for all ADRs"); a Codex consultation recommended fixing it in place.

# 0006: SQLite driver, migrations and query layer

- Status: Accepted
- Date: 2026-09-28
- Decided by: the developer, who delegated with "ask fable and codex... pick the best and most sensible option".
  The decisions were made through two independent model consultations.
- Related: NFR-06, A-01

## Context
- All tagcess state is kept in SQLite: sites, audit, sync history, settings.
- A single process runs; write traffic is low.
- The target is a single static binary.

## Decision
1. **Driver: `modernc.org/sqlite`**, pure Go, no CGO.
   - Codex and Fable made the same choice in the first round.
   - These settings are mandatory when a connection is opened: `journal_mode=WAL`, `busy_timeout`, `foreign_keys=ON`.
2. **Migrations: our own small migrator.**
   - Numbered SQL files are embedded in the binary with `embed`; the version is tracked with `PRAGMA user_version`.
   - Each migration runs in its own transaction.
   - Migrations only go forward. A file backup of the database is taken before migrating.
   - This was the coordinator's decision. The disagreement persisted after two rounds: Codex said `pressly/goose`, Fable
     insisted on our own migrator. Reason: the AGENTS.md rule "standard library first"; for one SQLite and a small
     schema goose's multi-DB abstraction is unnecessary; ordering and transaction guarantees are covered by a single table test.
3. **Query layer: `sqlc`.**
   - It reads the numbered migration files as the schema source.
   - Generated code is committed to the repository; there is no extra runtime dependency.
   - Both models recommended this.

## Consequences
- Pro: a single `go build`, no CGO, few dependencies. SQL is validated against the schema at compile time.
- Con: modernc is somewhat slower than the CGO driver; irrelevant at this scale. We write the migrator's tests ourselves.
- Follow-up: the `sqlc` and `templ` tools are pinned with the `tool` directive in `go.mod` and run with `go tool`;
  no global install is needed. `make check` verifies that generated code is up to date.

## Alternatives considered
- `mattn/go-sqlite3`: needs CGO, against the single static binary goal.
- `ncruces/go-sqlite3`: pure Go and solid but younger, and adds a wasm layer.
- `pressly/goose`: a mature tool, but an unnecessary dependency at this scale.
- `golang-migrate`: heavy dependency tree.

# 0001: Headscale policy is stored in database mode

- Status: Accepted
- Date: 2026-09-28
- Decided by: the developer. Gave conditional approval first ("if this is the best-practice recommendation, fine"),
  then approved explicitly after seeing the documentation quote (2026-09-28).
- Related: Y-03, H-04, H-05

## Context
- An existing installation runs Headscale with `policy.mode: file` (`/etc/headscale/policy.hujson`).
- tagcess will write the policy from the UI and through sync.
- In file mode, writing the policy through the API (`SetPolicy`) is rejected; every change means writing the file and reloading.
- Headscale documentation: "storing the policy in the database is typically only required in case a web interface is used"
  (https://headscale.net/stable/ref/policy/).

## Decision
The policy is kept in database mode. tagcess reads and writes the policy only through the Headscale API.

## Consequences
- Pro: no edit-file-and-reload step; changes apply immediately. Headscale validates in the API.
- Con: the policy no longer lives in a file. tagcess's audit log and local git copy (A-01, A-02) become the
  only readable history.
- Follow-up: switching from file mode to database mode is a production step.
  To do: load the existing policy through the API, change the config, restart, verify.
  Verified: the switch does not copy the policy; an empty DB policy is treated as "no policy". The switch must be
  done without a moment where the policy is empty (requirements G-02.2).

## Alternatives considered
- File mode + writing the file + SIGHUP: the `SetPolicy` API is rejected in file mode. Headscale's validation
  and immediate apply are only possible through the API.

# 0021: The Headscale host helper works with a maintenance flag and a journal

- Status: Accepted
- Date: 2026-09-29
- Changed: 2026-10-02: the 2026-10-01 simplification decision and the 2026-10-02 developer decisions were folded into the main text;
  the a-f detail proposals were accepted as written the same day.
- Decided by: the developer (2026-09-29: "yes"; 2026-10-01: "everything is APPROVED apart from these"; 2026-10-02: decisions on maintenance scope, recovery, simplifications and the a-f details)
- Related: H-07, [ADR 0008](0008-headscale-restart-helper.md)

## Context
Headscale v0.29.4 runs on the host under systemd, tagcess runs in a container. A `.path` notification is not proof of
delivery or success. The container is not given the Docker socket, host D-Bus or root privileges. H-07 and the helper are a separate
feature; the rest of the UI does not wait for them. Sources: the Headscale research notes and [stack-notes](../../.agents/skills/stack-notes/reference.md).

## Decision
- **[Decided] (2026-10-01)** The barrier is a persistent maintenance flag in the DB; on the host side `flock` and a journal file are used.
- **[Decided] (2026-10-01)** There is no automatic rollback. If an error occurs, the operation stops and the state is shown in the UI;
  recovery is manual and controlled from the UI. An error, timeout or reopen does not restore the old config.
- **[Decided] (2026-09-29; confirmed 2026-10-01)** The container sends only an allow-listed patch request. The candidate config
  is built on the host from the current config, keeping secrets and fields outside the patch.
- **[Decided] (ADR 0008; kept on 2026-10-01)** Flow: `configtest` -> backup -> atomic replace -> restart ->
  health check. On a validation error the live file is not changed; an error after the replace does not start a restore.
- **[Decided] (2026-10-01)** The first step is only `oidc.allowed_groups`; DNS fields are a later step.
  Before enabling, the `groups` claim in a real Headscale OIDC login is verified in a systemd container lab.
  The existing `allowed_domains`/`allowed_users`, issuer, secrets, policy mode and file paths are not changed.
- **[Decided] (developer, 2026-10-02)** The maintenance flag stops only **widening** writes: policy, re-enable, tag,
  route, pre-auth key creation and DNS. **Narrowing** writes continue during maintenance: Y-04 expire, revoking an unused key,
  manual expire/delete by devops. If Headscale is unreachable during the restart, these use the existing error/retry path;
  so the <=5 min bound can be exceeded by at most the restart window (~120 s).
- **[Decided] (developer, 2026-10-02)** Leaving a stuck maintenance: a "close maintenance" action for devops in the UI (explicit confirmation, shows the host state,
  audited, does not touch the config). Recovery is an ordinary new patch; there is no `recovery_of` and no ownership transfer.
- **[Decided] (developer, 2026-10-02)** Simplifications: the journal has 5 states (`accepted`, `applying`, `succeeded`, `failed`,
  `interrupted`); the time limit is provided by the systemd oneshot `TimeoutStartSec=120` + `KillMode=control-group` instead of per-step deadlines;
  the request has no `created_at`/`deadline_at`; only the last result is kept (no persistent UUID result archive); the host-kill test is done after the first trial.
- **[Decided] (developer, 2026-10-02)** The first piece of work for this feature is a preparation task run by the developer: lab accounts and groups-claim
  variants, and a read-only production inventory of the OIDC domain/user filters. The helper and H-07 work depend on it.

## Simplification (2026-10-01)
**Change note (2026-10-02):** The decision above replaces the old operation/recovery model.
A DB flag for maintenance and `flock` + journal for the host are enough. The old protocol built on automatic restore and
proof of non-widening access was removed. The status of the ADR stays **Accepted**; the 2026-10-02 **[Decided]** items above are folded into the text. The a-f details below were
also accepted as written on 2026-10-02. This document is not code, unit/script, or lab/production evidence; evidence belongs to the implementation work.

## Details (a-f)
**[Decided] (developer, 2026-10-02)** The a-f proposals below were accepted as written. The scope is only `oidc.allowed_groups`;
DNS fields and their schemas are a later step to be planned separately. Lab and production evidence belong to the implementation work.

### a. Patch schema and validation [Decided]
A version 1 request is UTF-8 JSON: `version` (1), `request_id` (lowercase UUID), `base_rev` (64 lowercase hex), `patch`.
There is no time field; there is no `recovery_of`. The patch has a single form,
`{"oidc":{"allowed_groups":["devops","developer","standart"]}}`; this example does not mean that all three groups are mandatory.
The list is the full new value; JSON Patch, key deletion and full YAML are not accepted.

The container and the helper perform the same validation: 1-3 unique values, only `devops`, `developer`, `standart`;
`devops` is mandatory. An empty/null list, an empty string, duplicates, an unknown/duplicate JSON key and extra fields are rejected.
`base_rev` is the SHA-256 of the canonical JSON of the secret-free projection published by the host (for now only `allowed_groups`); the hash is not
published over the raw/secret-containing config (alternative considered: an opaque revision counter on the host). The host compares `base_rev` with the
value recomputed from the current config; a stale request is rejected.
Only the target list is changed; other values, secret references and the file owner/mode are preserved.
The config/binary/unit/health address is fixed at installation; a request cannot carry a command, path, URL or secret.

### b. Files, limits and time [Decided]
- Host root `/var/lib/tagcess-headscale/`: `requests/` is writable by the container, `results/` is read-only;
  `private/` (journal, request copy, candidate and backup) is owned by root with mode **0700**. The container mounts only the `requests/` and `results/`
  directories; `private/` and the real config are not mounted. The lab uses the same structure; there is no extra queue service.
- A single pending operation: `requests/<UUID>.json` is published by an atomic rename from a temporary file, then
  the UUID is written into the fixed `requests/request.ready` in the same way. The `.path` unit uses `PathExists` for this marker.
- File safety: the helper opens the marker and the request with `openat(dirfd, ..., O_NOFOLLOW|O_NONBLOCK)`; it does the owner, regular-file and size
  checks with `fstat` on the opened fd (not through the path). The UUID is validated with a strict lowercase regex
  (`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`); only the file derived from this UUID is opened.
  Symlinks/non-regular files, a wrong owner and oversize are rejected. The validated content is copied under `private/`, the journal
  is written durably, the marker is consumed; the candidate is built only from this copy.
- A request and a result are at most **4 KiB**, the marker **64 bytes**. Only the **last** result is kept: `results/result.json` is published atomically
  (`version`, `request_id`, `state`, `phase`, `finished_at`, `error_code`, `config_changed`, `health_verified`); there is no persistent UUID archive.
  If the change is unknown on failure, `config_changed` is null. There is no raw config/command output.
  The UI/audit actor is matched with the request ID in the DB; the result of another ID is not counted as success. The same ID is not re-run
  (it is compared with the last journal/result ID). The single journal does not move to a new ID before the terminal result of the previous ID is published.
- At startup and at the end of an operation the helper publishes `results/status.json` (at most 4 KiB): the last ID/state/phase, the current `allowed_groups`
  and `base_rev`. The UI uses this secret-free snapshot; the raw config or a masked full YAML is not returned.
  When a stale `base_rev` is rejected, the snapshot is refreshed; if it cannot be read there is no new patch. If the helper cannot read the config, `status.json`
  carries `config_error: "config_unreadable"` and `allowed_groups` is `null`, `base_rev` is empty (no empty list is invented) **[Proposed]**.
- The time limit is in systemd: the oneshot service has `TimeoutStartSec=120` and `KillMode=control-group`; when the time is up all child processes
  are terminated. There is no per-step deadline; the `configtest`/restart/health steps use the values of ADR 0008 (15/45/30 s) only as their own
  timeouts. An uncertain result is not success; losing the UI connection does not cancel the operation. If the result cannot be written, the
  journal and the maintenance flag are kept; an interrupted operation becomes `interrupted` at the next start.

### c. Journal and reopening [Decided]
A single root-owned `private/journal.json` (0600), under `flock` on a persistent `private/helper.lock`;
the journal is written atomically and file/directory durability is ensured. Fields: ID, state, last phase (`validate`, `backup`, `replace`,
`restart`, `check`), base/candidate hashes (only inside `private/`), the host-owned backup reference and error code; there is no raw config/secret.

| State | Meaning |
|---|---|
| `accepted` | The host copied the request; the marker can be consumed. |
| `applying` | `configtest` -> backup -> atomic replace -> restart -> health check is in progress (in the phase field). |
| `succeeded` | Health (service active, fixed localhost `/health`, gRPC read-only) and that the current config is the candidate were verified. This is not proof of an OIDC login. |
| `failed` | A known error (for example `configtest`, health); the operation stopped. |
| `interrupted` | A half-finished operation (kill/timeout/reopen), a lost/corrupt journal or an uncertain result; UI review is needed. |

When the container reopens, the DB flag and ID are kept; it waits for the result of the same ID from a running helper.
When the host/helper reopens, an operation in `applying` is not resumed automatically, it becomes `interrupted`. An old request that was published but
not taken into the journal is not run either; the marker is consumed and an interrupted result is produced. A lost/corrupt journal
is preserved, `interrupted` is published and new writes start with a new sound journal; if the config cannot be read and parsed there is no write.
A deadline or container restart does not close the maintenance flag automatically.

Recovery is an ordinary **new patch**: from the current host snapshot, with a new ID, through the same validation/preview/approval chain;
the previous group list can be chosen if wanted. The backup is not copied back. While the flag is on and the host is in a terminal state
(`failed`/`interrupted`), a new patch updates the same flag with the new ID; there is no separate transfer. The helper verifies under `flock` that the previous
operation has finished and that `base_rev` is fresh. If the host state cannot be verified the write is blocked; the UI shows the reason.
On success the DB stores the result durably, maintenance closes and the current Zitadel reconcile runs before admin writes;
widening admin writes are not opened until the pending reconcile finishes. On a failed/interrupted operation the flag stays on.

**Close maintenance:** devops closes the flag with explicit confirmation in the UI; the screen shows the host state (last ID/state/phase; a warning
if `applying`), the action is audited, the config is not touched; on closing, the reconcile runs first as well.

### d. Writes that stop during maintenance [Decided]
Under the existing shared writer lock an operation in progress completes; if there is a known uncertain policy/key result,
a config request is not started **[Decided]**; this rule applies only when maintenance is being opened (`off -> active`); while maintenance is on and the host is in a terminal
state, a recovery patch is not blocked by uncertain expire/key results that arose during maintenance, and the UI shows them **[Decided]**. The marker is not published until the maintenance flag + request ID are durably written to the DB.
At the entry of every widening Headscale write the flag is checked under the same lock; the helper does not connect to the DB directly.

**[Decided]** Stopped during maintenance: policy (UI, Y-03 sync, rollback/recovery), re-enabling a personal device, tag, route/exit-node approval,
pre-auth key creation and DNS (Headscale DNS writes from H-06/sites; a site flow that produces DNS is rejected before the external write starts).
Continuing: Y-04 expire, revoking an unused personal key, manual expire/delete by devops. An admin request is rejected with "maintenance in progress";
automatic sync that is stopped is kept as a persistent pending reconcile intent. Read-only operations, webhook signature checks and recording of reconcile
triggers continue. For writes not in the list **[Decided]**: extending/re-opening an expiry is widening and stops; renaming a device continues.
If Headscale is unreachable during the restart, narrowing writes follow the existing error/retry path; the <=5 min bound can be exceeded by at most the
restart window (~120 s). The UI shows the maintenance duration.

### e. Real groups claim lab evidence [Decided]
1. In a single Linux/systemd container: pinned Headscale **v0.29.4**, the helper's `.path`/oneshot units;
   the existing lab Zitadel is used (ADR 0014), no local Zitadel or extra VM is set up. A separate lab Tailscale client is used.
   Accounts and groups-claim variants are set up in the developer's preparation task.
2. The lab OIDC callback/issuer/scope and groups claim production are verified from the UI; secret files exist only at runtime.
   The developer sets the Zitadel role of the lab account; tagcess does not create users/roles. The domain/user filters are recorded
   and the tests are chosen so that they pass these too (v0.29.4 AND semantics).
2. (continued) First `allowed_groups=["devops"]` is applied through the helper. Without a fresh browser session and without an auth key,
   a real `tailscale up --login-server=<lab>` -> Zitadel OIDC login accepts the devops account.
4. In the same flow only the developer account is rejected; an account with a missing/empty `groups` claim and an account without a VPN role are also
   rejected. Then `["devops","developer"]` is applied with a UI patch: developer accepted, a standart-only account rejected.
   An existing Tailscale session is not reused.
5. The evidence is only the anonymous scenario/result, request ID and version; no token/cookie/claim body is logged.
   The H-07 write is not opened for use until this accept/reject matrix proves real claim consumption.
   In the same lab a configtest error, a post-replace health error and a `TimeoutStartSec` overrun are tried: no automatic
   restore/restart, maintenance continues, the UI continues with a new patch or "close maintenance". The helper/host-kill test
   is done after the first trial.

### f. Production criterion [Decided]
The first `allowed_groups` application in production (there is none there today; this is a **narrowing**) is tried right after success, while existing sessions are open,
with a devops login on a fresh device. If it fails, maintenance continues and it is fixed with a new patch. Production installation and application are the developer's.

## Consequences
- Secrets stay only on the host in the candidate/backup; the request/result, UI, audit and git contain no raw config.
- After an error the config may have changed or the service may be stopped; it is not shown as "last known good"/success.
- A restart interruption is possible; during maintenance narrowing writes continue, and the delay is at most the restart window. There is no lab evidence yet.
- The a-f details were accepted. What remains open: lab evidence (e) and production evidence (f); the DNS patch schema is not in scope
  and will be planned separately in a later step.

## Alternatives considered
- Full YAML or free JSON Patch: enlarges the allowed-field/secret boundary.
- Automatic rollback or automatically resuming a half-finished operation: does not fit the accepted stop-and-show model.
- Docker socket/host D-Bus: violates the privilege boundary of ADR 0008.

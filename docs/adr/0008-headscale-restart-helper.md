# 0008: Headscale config changes are applied by a systemd helper on the host

- Status: Accepted
- Date: 2026-09-28
- Changed: 2026-10-02: the 2026-10-01 simplification was folded into the main flow.
- Decided by: the developer ("suitable"; 2026-10-01 simplification)
- Related: H-07, ADR 0004, [ADR 0021](0021-headscale-host-operation-protocol.md)

## Context
- Headscale runs on the host as a systemd service; tagcess runs in Docker.
- Changing `config.yaml` (in the first step only `oidc.allowed_groups`) requires a restart.
- tagcess is not given the Docker socket, D-Bus or root privileges.

## Decision
**[Decided]** A small systemd `.path` + `.service` (oneshot) helper runs on the host:
1. tagcess writes only an allow-listed **patch request**; it does not send a full config or a candidate file.
   The container can write to the request directory and can only read the result directory.
2. The helper runs on the host with `flock` + a journal; the barrier on the tagcess side is a DB maintenance flag.
   The helper validates the request and builds a candidate from the real config, keeping secrets and every value outside the patch.
   The maintenance flag stops only widening writes (policy, re-enable, tag, route, pre-auth key creation, DNS);
   Y-04 expiry, key revocation and manual expire/delete continue. The total time is bounded by systemd `TimeoutStartSec=120`.
3. Flow: `headscale configtest` -> back up the current config -> replace atomically ->
   `systemctl restart headscale` -> `/health` check within 30 seconds.
4. **There is no automatic rollback.** On any error or timeout the operation stops;
   the helper does not restore the backup automatically and does not start a recovery restart.
5. The helper publishes a persistent result; tagcess shows it in the UI and writes it to the audit log.
   Recovery from a failed or interrupted operation is manual and controlled, from the UI.

## Update (2026-10-01)
Status stays **Accepted**. The decisions that the container sends a patch request instead of preparing a candidate file,
and that it stops after an error instead of restoring automatically, apply. H-07 and the helper are a separate
feature and do not block the rest of the UI.
[ADR 0021](0021-headscale-host-operation-protocol.md) is the current protocol record; the exact schema, directory/format,
size/time and journal/reopen details are there. The maintenance scope, the "close maintenance" action, the
simplifications and the a-f details are developer decisions (2026-10-02).

## Consequences
- The restart lives in a small, auditable helper on the host; the candidate and secrets never leave the host.
- A `.path` notification is not proof of delivery or success; ID, journal and result record are used (ADR 0021).
- After an error the new config may remain on disk or the service may be stopped; the UI does not count this as success.
- The units/scripts are kept under `deploy/` and validated in a systemd container lab.
  Installation is a production step done by the developer; this document change is not production or lab evidence.

## Alternatives considered
- Mounting the Docker socket or host D-Bus: in practice equal to root.
- Moving tagcess into a systemd service: contradicts the Docker decision (ADR 0004).

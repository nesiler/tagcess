# 0013: MagicDNS extra records are written atomically to a separate directory and verified from the resolver

- Status: Accepted
- Date: 2026-09-28
- Decided by: the developer ("the proposals are fine for all ADRs"); the Codex review confirmed the proposal on all
  items
- Related: S-03, H-06, ADR 0004, ADR 0008

## Context
- Headscale v0.29.4 has no API for extra records; there is only the `dns.extra_records_path` file.
- The file is watched with `fsnotify`. Atomic rename works. With an invalid or empty file the old records are kept.
  On a successful load, a push is sent to connected clients without a restart.
- The current file is `/etc/headscale/extra-records.json`. `config.yaml` and the OIDC secret are in the same directory.
  The architecture planned to mount this file read-write. Rename cannot be done onto a single-file bind mount
  (Linux EBUSY; not verified in our setup).
- Headscale does not validate the same name with different values.

## Decision
1. tagcess writes the records to a directory it owns, for example `/var/lib/tagcess/dns/extra-records.json`. The directory is mounted
   read-write into the container; the Headscale user can read the file (group permission).
2. Headscale `dns.extra_records_path` is pointed at this file once. Because the ADR 0008 helper comes later, this is a
   one-time runbook step, like G-02.3: the developer changes the config, runs `headscale configtest`
   and restarts. It is a step of the G-01 takeover.
3. Generation:
   - An `A` record is generated for every host of sites with `magicdns=true`; the value comes from a global setting (today `100.64.0.4`).
   - The manual records in H-06 are added too.
   - Sorted by `name`, `type`, `value`; format is JSON with 2-space indent. A record with the same name and a different value is rejected.
4. Writing is done in the same directory with a temporary file + `fsync` + `rename`. Before the rename the temporary file is written with
   permissions Headscale can read (for example `0640`, group `headscale`); the directory gives the Headscale user `x`
   (traverse) permission. Otherwise Headscale cannot read the new file and the old records silently stay.
5. Verification: after writing, the changed names are queried at `100.100.100.100` (tagcess is on the host network, the VPN host is a
   tailnet node). If the expected answer does not arrive within 10 seconds, a warning is raised and written to the audit log; the file is kept,
   because the problem may be propagation delay. If a later step in the same change chain (Caddy, Zitadel) fails,
   the previous file is written back with the rollback rule in architecture §4.

## Consequences
- Pro: `/etc/headscale` is not exposed to the container. Atomic writes do not hit the bind-mount problem.
- Pro: the application is seen from the resolver where it is actually distributed.
- Con: a one-time Headscale config change and restart are needed.
- Con: verification measures only the VPN host's own view; it does not measure whether clients received the push.
- Follow-up: the rename + permissions + reload + `dig` flow is tested in the compose environment.

## Alternatives considered
- Mounting the current file read-write as a single file and writing in place: no config change needed. But rename
  is impossible and partial-write moments occur (Headscale ignores them but there is a delay).
- Mounting the `/etc/headscale` directory: exposes the config and OIDC secret to the container.
- The static `dns.extra_records` config key: every change needs a restart.

# 0004: tagcess runs in Docker on the VPN host, on the host network, bound to 127.0.0.1 only

- Status: Accepted
- Date: 2026-09-28
- Decided by: the developer ("on the VPN server, maybe Docker", then "the other proposals are fine")
- Related: all modules

## Context
Places tagcess has to reach:
- Caddy admin API (`localhost:2019`)
- Headscale gRPC (unix socket `/var/run/headscale/headscale.sock`)
- its own UI behind oauth2-proxy
- Zitadel and Kubernetes (over Tailscale)

All of them are on the VPN host's localhost or on its tailnet.

## Decision
- The container runs with `network_mode: host`.
- The UI listens on a Unix socket with restricted permissions; Caddy proxies to it. Identity headers are trusted
  only on requests that arrive through this socket (NFR-02). Approved by the developer (2026-09-28).
- The webhook listens directly on the VPN host's Tailscale address (`100.64.0.4:<port>`); Caddy is not used. Traffic
  is encrypted by WireGuard; the HMAC signature is mandatory. The Headscale ACL allows this port only to `tag:k8s`.
  Approved by the developer (2026-09-28). Reason: pods cannot resolve internal DNS names.
- The outside world is reached through Caddy.
- Persistent data lives in a volume: SQLite and the local git repository.
- Host mounts **[Proposed]**:
  - `/etc/caddy` rw: Caddyfile generation (ADR 0005)
  - `/etc/headscale/policy.hujson` **ro**: import (G-01). The real `config.yaml` is not mounted; config changes go through
    the candidate directory of ADR 0008, and the UI uses the secret-free `status.json` projection (ADR 0021 b).
  - `/var/run/headscale/headscale.sock`: gRPC
  - `/var/lib/tagcess-headscale/requests` rw and `/var/lib/tagcess-headscale/results` ro: the patch request and the
    result/status directories of ADR 0021 b; the helper's `private/` directory is not mounted.
  - ~~`/etc/headscale/extra-records.json` rw~~: MagicDNS records now live under `/var/lib/tagcess/dns/` (see change notes)
  - `/etc/letsencrypt/live` ro: certificate expiry dates
  - secret files ro
- Secrets are read from files mounted read-only.

## Consequences
- Pro: no extra network setup for localhost APIs. Tailscale access is the same as the host's.
- Con: no container network isolation. Any process on the host can reach localhost; that is why the UI uses a Unix
  socket.
- Headscale restart: [ADR 0008](0008-headscale-restart-helper.md).

## Alternatives considered
- Binary directly under systemd: fewer moving parts. The developer said "on the VPN server, maybe Docker", then approved
  the Docker proposal ("the other proposals are fine").
- Bridge network: needs extra setup and open ports for localhost APIs.

## Change notes
- 2026-10-02: the mount list was updated: the container sees only `/var/lib/tagcess-headscale/requests` (rw) and
  `/var/lib/tagcess-headscale/results` (ro); the `/var/lib/tagcess-hostapply` and `/etc/headscale/config.yaml` mounts were removed.
- 2026-09-28: the MagicDNS records file is written to tagcess's own `/var/lib/tagcess/dns/extra-records.json` instead of
  mounting `/etc/headscale/extra-records.json`; Headscale `extra_records_path` is pointed there once.
  Reason: atomic rename does not work on a single-file bind mount, and `/etc/headscale` is not exposed to the container.
  Source: [ADR 0013](0013-magicdns-records-file.md).

# Architecture

Sources: [overview.md](overview.md), [requirements.md](requirements.md), the ADRs (`adr/`).
Labels: the package structure, data model and flow details in this document are **[Proposed]**. Items tied to an ADR are
the decision itself.

## 1. Components (VPN host)
```
                 Tailscale (devops)                     Zitadel (k8s)
                        │                                  │  webhook (tag:k8s → 100.64.0.4:<hook>)
                        ▼                                  ▼
  Caddy :443 ── forward_auth ──▶ oauth2-proxy      ┌──────────────── tagcess (Docker, host network) ────────────────┐
     │  (devops role)                               │  web (templ+htmx)  ◀── unix socket /run/tagcess/ui.sock        │
     └──── reverse_proxy unix//run/tagcess/ui.sock ▶│  hook listener     ◀── 100.64.0.4:<hook>                       │
                                                    │  change pipeline ── sync ── scheduler                          │
                                                    │  store (SQLite) · audit · git (artifact history)               │
                                                    └───┬─────────┬──────────┬───────────┬──────────┬───────────────┘
                                                        │         │          │           │          │
                                         Headscale gRPC │  Caddy admin API   │  Zitadel API (HTTPS) │ k8s API (ro)
                                          (unix socket) │  localhost:2019    │  patch request       │
                                                        ▼         ▼          ▼           ▼          ▼
                                                   Headscale    Caddy   headscale-apply.path   auth.*   k8s-host :6443
                                                                       (host systemd, ADR 0008/0021)
```
tagcess is not in the path traffic takes (NFR-01). Caddy's site traffic goes to oauth2-proxy, not to tagcess.

The diagram shows the adopt layout (Headscale and Caddy under systemd on the host). On a fresh server the same
components run as one Docker Compose project managed through the host helper; see §8.2 and
[setup-flow.md](setup-flow.md) **[Proposed]**.

## 2. Packages
| Package | Responsibility |
|---|---|
| `cmd/tagcess` | Startup, config reading, wiring dependencies, graceful shutdown |
| `internal/config` | tagcess's own settings file (paths, sockets, intervals). Secrets are passed only as file paths |
| `internal/store` | Opening SQLite (WAL, busy_timeout, foreign_keys), embedded migrator, sqlc queries (ADR 0006) |
| `internal/model` | Domain types such as Site, Role, Change, AuditEvent and their validation rules (§5) |
| `internal/render` | Deterministic generation: Caddyfile, policy `groups`, DNS records, Zitadel URI list. Golden-tested |
| `internal/change` | Change pipeline (§4): render → diff → validate → confirm → apply → verify → audit/git; single writer lock (`WithWriterLock`). The policy writer (§4.1) also uses this lock |
| `internal/sync` | Zitadel → Headscale reconcile, protection threshold (Y-03.4), expire decision (Y-04), dry run |
| `internal/hook` | Webhook receiver: signature, time window, replay protection, debounce; only triggers a reconcile |
| `internal/zitadel` | Zitadel API client: grant list, user state, oauth2-proxy app URIs |
| `internal/headscale` | Headscale gRPC client (unix socket), the narrow sync client: policy `GetPolicy`/`CheckPolicy`/`SetPolicy`, `ListUsers`/`ListNodes`, `ExpireNode`. Its surface is fixed by `TestHeadscale_ExportedSurface` |
| `internal/headscale/admin` | Administrator client **[Proposed]**: a separate Go type from the sync client; same socket, only destructive/administrative RPCs (device delete/name/tag/route, pre-auth and API keys, expiry). Used only by devops-confirmed UI flows and by the narrow `KeyRevoker` interface; least privilege at code level |
| `internal/hsadmin` | Administrator operation pipeline **[Proposed]**: the single entry point for device, route, tag and key writes. Under the shared writer lock: fresh read → protection/staleness check → "started" audit → RPC → read-back → result audit; an RPC is not blindly retried. Nodes with server tags (a list in settings) cannot be deleted, expired or have their tag changed. The maintenance flag for config changes is also added here |
| `internal/policydoc` | Policy document **[Proposed]**: lossless `tailscale/hujson` AST, layered validation (size/UTF-8 → HuJSON → field restrictions → `CheckPolicy`), locked mandatory tests (`/* tagcess:locked */` comment; the legacy `#tagcess` member is read and converted to a comment) and targeted edit operations (acls, tagOwners, autoApprovers). No full JSON marshal (ADR 0020) |
| `internal/vpnuser` | Headscale ↔ Zitadel user matching (H-02) and personal access eligibility (H-03): fresh Zitadel read, active account, at least one role in the `vpn` project. Read-only |
| `internal/caddy` | Caddy admin API: load, config read (drift), validation |
| `internal/hostapply` | Container side: writes the allowed setting **patch request** and reads the host helper's result/status file. The candidate config is produced by the host helper from the real config (ADR 0008 update, ADR 0021) |
| `internal/k8s` | **[Proposed]** Ingress/Service in selected namespaces, IngressClass cluster-wide; Certificate metadata is not part of the first release **[Decided]**. Full paged get/list, SSAR evidence, snapshot/freshness and Traefik profile mapping (§10). A standard `net/http` + JSON REST client is proposed; the existing YAML dependency is used only in the narrow credential import. For this get/list-only scope, with no watch, there is no reason to add client-go; this is not a new dependency decision |
| `internal/health` | **[Proposed]** target/Caddy TCP/HTTP/TLS observations, the leaf presented on each host/SNI; Certificate metadata is deferred. Dial checks use the shared network policy; no body or credential |
| `internal/netpolicy` | **[Proposed]** Shared IP/CIDR/port validation and dial checks for API/probe with separate scopes, on top of the existing settings; a UI manages it. Single policy owner **[Decided]** |
| `internal/monitor` | **[Proposed]** observation scheduler, freshness, drift evidence and the monitoring alarm lifecycle. It does not take over ownership of operational alarms from sync and Headscale management |
| `internal/gitlog` | Commits generated artifacts to the local git repository (`git`, exec with arguments) |
| `internal/setup` | **[Proposed]** Setup mode (setup-flow.md §2, §4): setup token and session, the wizard step pipeline (precheck → render → validate → preview → apply → prove), last known good per step, sealing |
| `internal/discover` | **[Proposed]** Read-only host scan run by the host helper (setup-flow.md §3); the Go port of the installer's `probe.py` checks. Copies only allow-listed, secret-free attributes |
| `internal/stack` | **[Proposed]** Deterministic rendering of the fresh-server Compose project and service configs from typed parameters and the release's version manifest; used by the host helper, golden-tested (setup-flow.md §5) |
| `cmd/tagcess-hshelper` | Host helper (ADR 0008/0021). **[Proposed]** A second, typed stack channel for `discover`, `stack.apply` (one component at a time), `stack.remove`, `service.restart`, `stack.upgrade` and `handoff.cleanup`, with a stack `base_rev`; a one-way credential handoff directory for secret values from tagcess to the helper; a Compose backend for Headscale config changes. Both channels share one host lock, and after creation the Headscale `config.yaml` is changed only through the ADR 0021 patch flow. The release's version manifest is embedded only in this binary (setup-flow.md §5.3-§5.5) |
| `internal/web` | templ components, handlers, identity middleware, CSRF, embedded assets (ADR 0007) |
| `deploy/` | Dockerfile, compose, systemd helper (ADR 0008), Caddy snippet |
| `test/compose/` | Integration environment: local Headscale, Caddy, oauth2-proxy (compose). Zitadel runs in the lab (`test/lab/`, a small k3s cluster, ADR 0014). The k8s contracts are tested with local fixtures and optional personal k3s namespace tests (§9) |
| `test/lab/` | Manifests and scripts that run Zitadel on the developer's k3s lab (`tagcess-lab`); `make lab-up` (ADR 0014) |

## 3. Data model (SQLite)
| Table | Contents |
|---|---|
| `sites` | id, kind (`role`/`open`/`system`), `open_reason` (`intentional`/`transition`), system template (`zitadel`/`headscale`/`wireguard_ui`/`tagcess`), roles (ordered), certificate, target, target roles (transition), `magicdns`, maintenance, note, owner (ADR 0010) |
| `site_hosts` | site_id, hostname (unique) |
| `site_api_rules` | site_id, order, kind (`header_present`/`path_regex`), value. No free-form expressions (ADR 0011) |
| `zitadel_owned_uris` | the redirect URI set `O` that tagcess wrote last (ADR 0012) |
| `site_redirects`, `site_headers` | redirects and extra headers |
| ~~`dns_records`~~ | No such table. Manually added MagicDNS records live in `settings` as `site.manual_dns` (JSON); site records are generated, not stored. Persisting them on the first import **[Decided]** |
| `settings` | key/value: dry run, sync interval, WireGuard switch, thresholds; `headscale.protected_tags` (JSON list, cannot be empty) and `headscale.locked_tests` (JSON, locked policy test parameters); both are written from the `/headscale/settings` screen and readers read fresh on every operation **[Proposed]** |
| `changes` | change record: kind, actor, status (`pending_approval`/`applied`/`failed`/`rolled_back`), before/after artifact summaries, error |
| `audit_events` | append-only: time, actor, event, target, diff, result. There is no delete or update query |
| `site_versions` | durable site source versions: site_id (no FK, so the history of a deleted site remains), change (`change_id`), operation, source model snapshot (JSON), Git revision (linked afterwards on a late commit), actor, `rollback_of` (ADR 0017, A-03.4) |
| `policy_revisions` | **[Proposed]** Policy version record (ADR 0020): id, parent/base hash, raw HuJSON, canonical (semantic) hash, actor, time, reason, validation result (with its version), apply status (`applied`/`failed`/`unknown`), `rollback_of`. Headscale is the source of truth; this table is the history and the base hash. Exact column names are fixed at implementation |
| `applied_artifacts` | the last applied content and its hash for each artifact kind (drift detection, rollback) |
| `sync_runs` | time, trigger (webhook/periodic/manual), result, difference summary |
| `webhook_events` | event id and receive time (replay protection; kept for 24 hours) |
| `alerts` | The existing kind/source/first_seen/last_seen/resolved records of sync and Headscale management are kept. **[Proposed]** Dedup by type/subject/source key, severity, ack actor/time, evidence and counters. Monitoring and operational criticals have separate owners; older open alarms are not lost in migration |
| `k8s_connections` | **[Proposed]** endpoint, CA/TLS name and runtime credential reference (no value), selected namespace scopes, Traefik profile/listener addresses, expiry metadata, last authorisation evidence |
| `k8s_snapshots` | **[Proposed]** complete observation identity, connection/scope, observed_at, pagination result; an incomplete read does not replace a complete snapshot. Contains no credential/Secret or user role store |
| `discovery_drafts` | **[Proposed]** separate persistent incomplete site suggestion, site model field choices, snapshot/provenance, conflict and review status; it is not a running site record |
| `health_results` | **[Proposed]** site/host, target or Caddy gate, vantage, endpoint, Host/SNI/path, time, TCP/HTTP/TLS result and duration; no body/header is stored |
| `tls_observations` | **[Proposed]** presented fingerprint/NotAfter/validation per host/SNI and source; Certificate metadata mapping is not part of the first release; no key/Secret |
| `setup_scans`, `setup_findings` | **[Proposed]** Setup staging: scan runs and their secret-free findings; a partial run does not replace the last complete one (setup-flow.md §3.3) |
| `setup_state` | **[Proposed]** Single row: setup token hash and expiry, failure counter, setup session hash, `sealed_at` and the sealing identity |
| `setup_steps` | **[Proposed]** Wizard step: choice (`install`/`connect`/`migrate`/`skip`), state, secret-free parameters, the findings it was based on, last verified parameters and evidence |
| `setup_migration_items` | **[Proposed]** One proposed import action per finding, with its own approval, its prerequisites (setup-flow.md §6 order), state including `uncertain`, and a link to the `changes` record or helper request |
| `settings` (monitoring additions) | **[Proposed]** monitoring intervals/thresholds, target/domain/IP/port allow lists, site path/expected status/maintenance. Non-secret profile and scope are managed from the UI; the credential value is not stored here |

## 4. Change pipeline (all writes go through here)
Changes are applied in order, under a single lock.
1. **Request:** an edit from the UI, a sync result or a rollback produces a `Change`. The actor is recorded
   (the user or `system:sync`).
2. **Render:** DB state and external sources (Zitadel roles) are read, and target artifacts are generated deterministically.
3. **Diff:** The target artifact is compared with its current state in the system. The current state can be the Caddy config, the Headscale
   policy or the DNS file. If there is no difference the operation ends.
4. **Validate:**
   - For Caddy, the admin API `/adapt` (syntax only; CEL and regex errors surface only at `/load`, so
     `path_regex` is additionally compiled with Go `regexp`).
   - For Headscale, gRPC `CheckPolicy`.
   - Model rules (§5 and security.md).
5. **Confirm:** If a protection rule fires, the change waits in `pending_approval`. Examples: the Y-03.4 threshold,
   the S-06 WireGuard switch, an H-07 config change, dry run.
6. **Apply:**
   - Caddy: load with `/load` (if it fails the running config does not change). If it succeeds, write the file atomically, so that Caddy
     gets the same config on restart.
   - Headscale: gRPC `SetPolicy`, node operations.
   - DNS: write the record file atomically to tagcess's DNS directory, then verify with `100.100.100.100`
     (ADR 0013).
   - Zitadel: URI update: `GetApplication` → merge → `UpdateApplication` (only `redirectUris` and the read
     `responseTypes`, `grantTypes`, `clockSkew`, `loginVersion`) → read again and verify
     (ADR 0012).
   - Headscale policy: §4.1. Device, route, tag and key operations: the `internal/hsadmin` pipeline (single writer lock, read-back).
   - Headscale config: tagcess writes an allowed-setting **patch request**; the host helper builds the candidate from the real config,
     does `configtest` + atomic replace + restart, **there is no automatic rollback**, and the status is shown in the UI
     (ADR 0008 update, ADR 0021 simplified). The patch/IPC schema and the maintenance flag are defined with the host helper.
7. **After:**
   - The applied state is read and its hash checked.
   - On a verification mismatch (the written artifact differs when read back) the previous artifact is restored only if it
     can be proven that restoring does not widen access; if it cannot be proven, the live state is kept,
     the change is marked `failed` and a critical alert is raised. If it is uncertain whether the write was applied
     (read-back failed), the previous state is not restored; the last verified/good state is kept and a critical alert is raised.
   - If, after the Headscale policy has been written and verified, only the node expire step fails (for example Headscale
     becomes unreachable), the verified policy is **kept** (returning to the previous, possibly broader policy reopens access);
     the change is marked `failed`, a critical alert is raised and the expire is retried at the next reconcile.
   - The result is written to `audit_events` and `applied_artifacts`; the generated artifact is committed to git.

For changes touching several targets the order is: steps that narrow access first, then those that widen it.
Example: a new site → DNS first, then Caddy, and the Zitadel URI last. If interrupted midway, the applied steps are rolled back
(not if it is uncertain whether the write was applied, or if only the expire fails after a verified Headscale policy;
see §4 step 7 and §7).

**[Proposed]** The site change pipeline (`internal/change/site.go`) applies this as follows: the site record is written last, after all
artifacts have been applied (the DB always holds the last good state). Rollback is done only for a pure addition
(the previous state is narrower); on an edit and a delete the applied steps are not rolled back and a `site_partial` alert is raised. If the
result of a write is uncertain (the live config has changed or cannot be read after a Caddy `/load` error, or a Zitadel write
could not be verified) nothing is rolled back and a `site_unverified` critical alert is raised. Before writing, the equality of each artifact
to the state generated from the records (drift) and the readability of the systems are checked; if either does not hold the change
becomes `blocked`. The first import and "overwrite" go through the same pipeline with a `resync` operation.

### 4.1 Policy writer (ADR 0020)
The policy document is kept as **a single raw HuJSON**; form actions and the raw editor POST the same text, and there is no draft table on the server.
Every request carries a base revision/hash. The writer is the policy branch of the §4 pipeline in detail:
1. **Lock:** the shared writer lock (`change.WithWriterLock`) is taken; the Y-03 reconcile and other writes go through the same lock.
2. **Fresh read (under the lock):** policy (`GetPolicy`), users, nodes and Zitadel roles. If Zitadel cannot be read completely,
   no write is made (role groups cannot be verified; the CLI emergency path stays in security.md §11).
3. **Base hash:** if the request's base does not match the live policy it is considered stale and rejected.
4. **Group merge:** role `groups` are always built from the fresh Zitadel result; manually written role groups in the document are locked and overwritten.
   The document is edited in a targeted way (comments/order/unknown fields are preserved, `internal/policydoc`).
5. **`CheckPolicy`** (+ local validation and locked mandatory tests). On rejection or timeout the live policy and the last revision do not change.
6. **Durable intent/audit:** the "started" record is written before `SetPolicy`.
7. **`SetPolicy`**: once, no blind retry.
8. **`GetPolicy` verification:** the equality of the text read to the text written is checked.
9. **Revision:** on success it is written to `policy_revisions` as `applied`; the lock is held until this record and the audit are done.

If the result of SetPolicy is uncertain (RPC error, read-back failed or does not match) the result is shown as **"application uncertain"**; new writes stop
and the last verified revision is kept. **There is no automatic restore of the old policy** (the old document may reopen access, and Headscale SetPolicy
does not atomically roll back a partial error). The way out is a **controlled recovery** from the UI: a new policy draft is built with the current Zitadel groups, re-validated,
the diff is shown, it is applied with explicit confirmation and read back. UI confirmation does not bypass validation.

**Rollback** is not writing directly to an old revision: a new policy draft is built while preserving the present role groups and goes through the same flow; it produces a new revision
(`rollback_of` filled). Device/key expiry and ownership conversion are not rolled back.

## 5. Sync flow
```
webhook ─┐                              ┌─ Zitadel: vpn project grants + user state (paged, complete)
periodic ├─▶ debounce (2 s) ─▶ reconcile┤
manual ──┘                              └─ Headscale: policy + users + nodes
                         ▼
     desired groups (role → provider identifier list) ── diff against existing groups
                         ▼
     read incomplete/failed? ── yes ─▶ do nothing, alarm (Y-03.3, Y-04.5)
                         ▼ no
     threshold exceeded? ── yes ─▶ pending_approval (Y-03.4)
                         ▼ no
     dry run? ── yes ─▶ only sync_runs + dashboard (Y-06)
                         ▼ no
     change pipeline: update policy groups; expire the untagged nodes of a user who lost all roles or was
     deactivated (Y-04) and revoke their unused personal pre-auth keys
```
The webhook is only a trigger; the data in it is not trusted (Y-01.4). Zitadel does not retry a failed webhook and
cannot filter events by project; so every grant/user event that arrives is only a "reconcile needed" signal
and a periodic reconcile is mandatory (stack notes). On the Zitadel side the target type is `rest_async` **[Proposed]**.

## 6. External interfaces
| Target | Path | Identity | Note |
|---|---|---|---|
| Headscale | gRPC, unix socket (mount) | socket file permissions (`0770`, container in the headscale group) | Full admin without credentials; validation before applying with `CheckPolicy`. Two client types: the narrow sync client (`internal/headscale`) and the administrator client (`internal/headscale/admin`); both on the same socket |
| Caddy | HTTP `localhost:2019` admin API + `/etc/caddy/Caddyfile` | none (localhost only) | `/adapt` only converts; `/load` (`text/caddyfile`) builds the new config in isolation and leaves the old one untouched if it fails. Because systemd starts it without `--resume`, the Caddyfile on disk is read on restart; so the file is written too |
| Zitadel | HTTPS `auth.example.com`, API paths only from the VPN | Service user (JWT profile key), `PROJECT_OWNER` in the `vpn` project | v2 `ListAuthorizations` (filtered by project_id), `ListUsers`, `UpdateApplication` |
| k8s | HTTPS API defined in the UI, CA and, if needed, a separate TLS server name | Time-limited read-only ServiceAccount token; upload/manual renewal from the UI **[Decided]** | **[Proposed]** Ingress/Service/IngressClass get/list; Certificate metadata deferred; no watch/Secret/token creation/resource writes. SSAR POST is only evidence of the chosen effective permission; it is not proof that all authorizers are narrow |
| Host helper | Patch request (request directory, written by the container) + result/status file (result directory, read-only for the container); the candidate is built on the host | File permissions | ADR 0008 (update), ADR 0021. **[Proposed]** a second stack channel `/var/lib/tagcess-host/` with the same file rules for typed stack operations; the helper renders the Compose project itself (setup-flow.md §5.3) |
| DNS | `/var/lib/tagcess/dns/extra-records.json` (directory owned by tagcess; Headscale `extra_records_path` is pointed here) | File permissions: file `0640` group `headscale`, `x` on directories for Headscale | Headscale watches the file with fsnotify, loads it without a restart and pushes to clients; there is no API for extra records (ADR 0013) |
| TLS observation | Credentialless connection to the allowed Caddy and internal listener from the UI with each host/SNI | Standard CA/hostname verification; the profile CA if needed | **[Proposed]** the presented leaf expiry is the primary source; cert-manager Certificate metadata is deferred from the first release. Expiry is not read from a private key/Secret/file mount |

## 7. Failure behaviour
| Situation | Behaviour |
|---|---|
| Zitadel unreachable | Sync stops, groups are kept, an alarm is raised. The UI works; the role list is shown from the last known state. The policy is not written (§4.1; role groups cannot be verified), no personal pre-auth key is produced and no personal device is re-enabled |
| Policy `SetPolicy` result uncertain | "Application uncertain" is shown, new policy writes stop, the last verified revision is kept; no automatic restore. Only controlled recovery from the UI (§4.1) |
| Headscale unreachable | Sync and Headscale screens show an error; the Caddy side keeps working |
| Caddy adapt/load error | The change is not applied, the running config and file do not change, the error is shown |
| DNS file invalid | Headscale logs the error and keeps the old records; tagcess sees the difference in resolver verification and warns |
| Partial application | **Headscale config exception:** there is no automatic rollback, the operation stops and is shown in the UI (ADR 0021; security §8). In other flows: on a verification mismatch the applied steps are rolled back in reverse order only if it can be proven that the rollback does not widen access; if it cannot be proven or the rollback also fails, the live state is kept so as not to widen access again, a critical alarm is raised and manual intervention instructions are shown. If it is uncertain whether the write was applied (read-back failed), or only expire fails after a verified Headscale policy, the previous state is not restored; the last verified state is kept, a critical alarm is raised and the expire is retried |
| tagcess crash / restart | State is in SQLite. On startup, half-finished changes are marked `failed` and the drift check runs |
| Drift (change from outside) | Not overwritten automatically; the difference is shown, and the devops chooses "take into tagcess" or "overwrite" |
| k8s read/credential error **[Proposed]** | The last complete snapshot is kept; the old time, error and freshness warning are visible. No absence/site deletion is inferred from an incomplete inventory; after a manual credential renewal from the UI a successful full read is needed |
| Probe/TLS source cut off **[Proposed]** | Old evidence is kept with its time; target/Caddy/TLS/freshness are shown separately. Losing a source does not resolve an alarm and produces no access change |

## 8. Deployment
Installation and rollback (`fresh` for a new installation, `adopt` for an existing one) are done with the installer: `deploy/install.sh` + `deploy/ansible/`; guide:
docs/install.md. The mount, unit and ordering rules below are applied in that tool's roles.
**[Proposed]** A fresh server is installed with the install script and the setup wizard instead (§8.2,
[setup-flow.md](setup-flow.md)); Ansible keeps only adopt mode until the wizard covers it (setup-flow.md §7).
The tagcess container keeps the mounts below in both layouts.

- **Image:** distroless or alpine based. It contains the `tagcess` binary and `git` and runs with a non-root UID.
- **Container:** `network_mode: host`, `read_only: true`. Only the mounts below are writable. `restart: unless-stopped`.
- **Mounts:**

  | Path | Mode | Purpose |
  |---|---|---|
  | `/var/lib/tagcess` | rw | SQLite, git repository and `dns/extra-records.json` (read by Headscale; ADR 0013) |
  | `/run/tagcess` | rw | `ui.sock`; the Caddy group has access |
  | `/etc/caddy` | rw | Caddyfile generation. Directory mount: atomic rename does not work on a single-file bind mount (EBUSY). The file is written with permissions that the Caddy user can read. **[Decided]** |
  | `/var/run/headscale` | rw | Headscale gRPC socket `headscale.sock` (default path, verified). **Directory** mount: when Headscale restarts it recreates the socket; a single-file bind mount stays attached to the old inode. The gRPC client reconnects by itself if it drops. The directory must also be preserved: the stock `headscale.service` with `RuntimeDirectory=headscale` deletes and recreates the directory on every restart (new inode) and the container mount looks empty; the `deploy/headscale-preserve.conf` drop-in (`RuntimeDirectoryPreserve=yes`) must be installed on the host |
  | `/var/lib/tagcess-headscale/requests` | rw | ADR 0021 b patch request (`<UUID>.json` + `request.ready`) |
  | `/var/lib/tagcess-headscale/results` | ro | ADR 0021 b result/status (`result.json`, `status.json`); the container only reads |
  | `/etc/headscale/policy.hujson` | ro | Import (G-01). The real `config.yaml` is not mounted; a config change goes through the ADR 0008 candidate directory, and the UI uses the secret-free `status.json` projection (ADR 0021 b) |
  | `/etc/letsencrypt/live` | ro | The existing Caddy render/certificate path. Expiry observation does not depend on this mount; it measures only the presented leaf |
  | `/etc/tagcess/secrets` | ro | Secret files (webhook signing key; optional `hook.groups_signing_key_file`: opens the `/groups` `groups` claim endpoint on the same hook listener) |
  | `/var/lib/tagcess-credentials` | rw | **[Proposed]** Directory `0700`, files `0600`; given with `k8s_auth_dir`. Token/CA replaced atomically from the UI; outside the `/var/lib/tagcess` SQLite/git/backup tree. Caddy has no access; secret values do not enter backups/artifact history. If `k8s_auth_dir` is empty no credential is stored, and there is no default inside `data_dir` |

- **Installation steps (against a live installation; run by the operator, in the runbook):**
  1. Zitadel: the service user and its role (security.md §10); the Actions v2 target (`rest_async`, the signing key is shown
     only once here) and executions (the `user.grant` group, `user.deactivated/locked/removed/…`).
  2. k8s **[Decided]**: an authorised cluster administrator establishes the narrow SA/RBAC manifest offered by the UI
     and issues a time-limited token; endpoint/CA/token are uploaded from the UI. The expiry warning and manual upload of a new token are the
     first-release flow; tagcess carries no admin/TokenRequest identity. An automatic provider is outside the scope of the first release.
  3. Headscale: ACL rule `tag:k8s → tag:vpn-server:<hook>`. This rule is added **in file mode, before G-02**.
  4. Caddy snippet: the UI site, removal of `X-Auth-Request-*` headers,
     `reverse_proxy unix//run/tagcess/ui.sock`.
  5. The ADR 0008 systemd units (needed for Headscale config management).
  6. Secret files, compose and first start (in dry-run mode).

### 8.1 oauth2-proxy gate cookie
The operator configures oauth2-proxy; tagcess neither produces nor reads this file. The recommended settings are in
`deploy/oauth2-proxy.example.cfg`:
- **Single cookie:** `cookie_domains` = the parent domain of the `sites.allowed_domains` entries (with a leading dot, for example `.example.com`).
  When the browser signs in on one site, it passes on all sites.
- **Short lifetime:** `cookie_expire = "1h"`, `cookie_refresh` off. The cookie lifetime equals the delay of a role revocation:
  a role taken away in Zitadel takes effect at the latest when the cookie ends. Because the Zitadel session continues, re-login is not noticeable to the user.
- **Sign-out:** the top menu of every tagcess page has "Sign out"; on the 403 page "Sign in with another account" uses the same address. If `gate.client_id` is set the address is `/oauth2/sign_out?rd=<url-encoded https://<issuer>/oidc/v1/end_session?client_id=<id>&post_logout_redirect_uri=https://<tagcess_host>/>`: it deletes the shared cookie and then also ends the Zitadel session (otherwise `/oauth2/start` signs straight back in with the same user). tagcess **only adds** `https://<tagcess_host>/` to the post-logout redirect URI list of the oauth2-proxy app (in the same run as the redirect URI sync, with verified read-back; it does not delete or change what exists); oauth2-proxy `whitelist_domains` must contain the Zitadel host. If `gate.client_id` is empty the old behaviour: `/oauth2/sign_out?rd=%2F` (cookie only).

### 8.2 Fresh install layout **[Proposed]**
Details and rationale: [setup-flow.md](setup-flow.md) §5. **[Decided 2026-10-15]** tagcess never installs an identity provider; an existing
Zitadel is a prerequisite and is only connected (product-decisions §11). The stack therefore has no IdP service.
- **Compose project `tagcess`:** the compose file and service configs under `/etc/tagcess/stack/` are written only by the
  host helper (root), rendered from typed parameters and the release's version manifest (images by tag and digest);
  tagcess never writes them and never gets the Docker socket (ADR 0008/0021 rule kept; **[Decided 2026-10-15]**, setup-flow.md O1).
- **Networks:** Caddy, Headscale, tagcess, oauth2-proxy and the Tailscale client use `network_mode: host` (ADR 0004
  reasons: client IPs, localhost APIs, the tailnet interface).
- **Public ports:** 80/tcp, 443/tcp, 443/udp (Caddy) and 41641/udp (Tailscale). Everything else is loopback or tailnet.
- **Host state of the managed services** (the tagcess mounts are the table above):

  | Host path | Service | Mode |
  |---|---|---|
  | `/etc/tagcess/stack/` | all (each service mounts only its own config) | ro |
  | `/etc/tagcess/stack/secrets/<service>/` | the owning service only | ro |
  | `/var/lib/tagcess-stack/caddy/data` | caddy (`/data`: certificates and keys) | rw |
  | `/var/lib/headscale` | headscale | rw |
  | `/var/run/headscale` | headscale rw; tagcess rw (socket directory, as above) | rw |
  | `/var/lib/tagcess-stack/tailscale` | tailscale (node state) | rw |
  | `/var/lib/tagcess-host/requests`, `/results` | tagcess rw / ro (stack channel of the host helper) | rw / ro |
  | `/var/lib/tagcess-host/handoff/` | tagcess (writes `in/` only); one-way credential handoff, setup-flow.md §5.4 | rw |

- **Group IDs** for the shared sockets are passed at runtime with `group_add`; the image no longer bakes in host GIDs.
- **Upgrades:** a release is activated by installing its host helper, which carries the manifest (`install.sh
  --upgrade`, until signed releases allow it from the UI, #18); then one service at a time through the host helper,
  with backup and proof; a stateful service is not put back on its old image automatically (setup-flow.md §5.6).

## 9. Test architecture
- **Unit:** model validation, render (golden files), diff, sync decisions (table tests), migrator.
- **Handler:** with `httptest`. The identity middleware, CSRF and HTML fragments are tested.
- **Integration** (`integration` build tag, `test/compose`): real Headscale, Caddy and oauth2-proxy (compose).
  Zitadel runs for real in the lab (a small k3s cluster, ADR 0014; there is no local Zitadel); a fake Zitadel is used only in unit tests.
- **End to end:** the chain webhook → reconcile → policy → node expire; add a site → load Caddy →
  oauth2-proxy role check.
- **[Proposed] k8s harness:** temporary SQLite, `httptest` JSON/TLS fixtures, a fake clock and an injected test transport.
  Pagination/403/timeout/decode, CA/SNI/SAN/expired leaf, redirect/SSRF, IPv4/IPv6, snapshot and alarm restart
  are tested. Loopback is possible only in a fixture belonging to the injected test transport; the product UI allow list does not accept loopback.
- **[Proposed] optional k3s contract:** in a personal lab, a separate test namespace, a separate fixture-preparer identity
  and the tagcess get/list+SSAR identity; the narrow Ingress/Service/TLS contract; Certificate metadata is outside the first release. The token is
  prepared with an admin identity and not created in tagcess's runtime path. Labelled resources are cleaned up even on quota/limit and errors;
  there is no global controller/issuer change, lab hardening or real negative resource write. The SSAR result
  proves only the operations queried; the controller version/CA/profile are the preflight evidence of that lab.
- **[Proposed] integration:** under the `integration` tag, compose + the existing healthy lab Zitadel; where the scenario needs it,
  the existing host lab. Preflight shows a missing dependency as an explicit skip/error; a real scenario that does not run does not count as PASS.
- **[Decided]** A final full test covering Linux/systemd, k8s, the full VPN login and a fresh device together is separate and comes last;
  its detailed plan is deferred. There is no generic refactoring phase.

## 10. Observation and draft flow **[Proposed]**
Sources: ADR 0030, 0031 and 0032 are **Accepted** **[Decided]**.
The existing sync, site and Headscale writers above do not change; the new flow is observation and a separate site draft.

1. **Connection/UI:** explicit namespace scope, endpoint/CA/TLS name, time-limited token, Traefik class/controller and
   internal/public listener address/port/default entrypoint evidence. The first profile is Traefik **[Decided]**;
   the installed version is not derived from the source tag, it is verified in the connection preflight. The cluster
   administrator does the first SA/RBAC setup; the manifest, connection test, scope change and manual token renewal are one UI flow.
   The API and probe IP/CIDR/port policy is defined in a single service with separate scopes **[Decided]**;
   the manifest/permission/policy UI and the connection/token UI are separate screens. The policy is not copied in consumers;
   the existing hostname allow list alone is not a dial/port check. Getters are read in the next cycle.
2. **Read:** a narrow get/list ClusterRole for namespace resources + a RoleBinding in the selected namespaces;
   a separate get/list ClusterRoleBinding for IngressClass is proposed. Namespaces list/watch and Secret/Pod/log/exec,
   node/deployment/issuer/RBAC writes or wildcard permissions are not needed. Certificate metadata is deferred;
   the metadata is explicitly "not scanned". A new complete snapshot is not published until all pages/schemas succeed;
   the effective SSAR evidence is stored with principal/verb/resource/scope/time, and no general read-only badge is produced.
3. **Mapping:** internal host/path/backend mapping according to the profile; the `role/open/system` site model is kept.
   Evidence is merged per host; UID/resourceVersion/namespace/class/path/port and observed_at are provenance.
   A shared backend does not merge different hosts into one site; an existing multi-host record is not split. Ingress annotations,
   tls.secretName or the Service IP are not copied directly into a Caddy rule/certificate/target. A new draft
   stays persistent in its incomplete state **[Decided]**; preview makes no external write, Apply is only the existing S-04 pipeline.
4. **Conflict:** the user is asked about every real conflict; if there is route evidence of the controller's actual choice, that is accepted as
   the discovery default, otherwise it stays uncertain **[Decided]**. The first Traefik profile has no runtime winner collector;
   conflicts are uncertain + UI review. A positive effective-route collector/contract is a later proposal; list order or
   class name is not substituted for it. Running access does not widen before an answer arrives.
5. **Measurement:** separate target and Caddy credentialless GET/TCP/TLS; per-host fixed allowed dial + Host/SNI/path,
   the selected expected HTTP codes. The presented leaf and freshness are stored; Certificate metadata/rollout difference is outside the first release. The two-gate assessment
   separates configuration risk from the measurement on the source network; if the internet was not measured it says so. CRD/Gateway and
   hostNetwork coverage gaps do not produce a safe result. Locked system template targets in code are a separate source
   of trust; they are measured or shown as unsupported, and the UI cannot create an arbitrary loopback exception.
   There is no automatic access/config fix.
6. **Dashboard/alarms:** the existing Headscale reader, the last reconcile and the expected Zitadel role matrix tied to source times;
   there is no new persistent user/role store. A monitoring alarm is de-duplicated by type/subject/source; ack
   is not resolution, losing a source does not resolve; maintenance only mutes the monitoring alarm. Resolution of existing
   operational criticals stays with the pipeline that owns them. Policy/Caddy/DNS/URI drift comes only from a complete successful source
   read; URIs outside the known ownership set remain foreign.

**[Decided]** Initial intervals/thresholds (60 s/5 min/6 hours; 3 failures/2 successes; 30/14/7 days) and their management in the UI.
Other model/transport/alarm details are **[Proposed]**; acceptance of the ADRs as a whole is not attributed to them.

### 10.1 Behaviours from lab rounds
These are fixes to lab findings; they contain no new decision that needs an ADR.
- **Setup pending:** while setup is incomplete the dashboard shows a single "Setup pending" box
  (first import, probe IP policy, k8s profile, k8s credential; each linked to the relevant page). Until
  these steps are done the related loops **do not run and produce no alerts**: if the first import is pending, no drift comparison
  is made (no per-artifact freshness alert is opened), if there is no probe policy the health loop takes no measurement, if there is no profile
  the inventory is not read. These states are explained on the loop card as "Setup pending: ..." with `monitor.ErrSetupPending` / `StateMissing`.
  When setup is done the normal alert flow starts in the first round.
- **Public listener optional:** in a cluster reachable only from the tailnet the profile is saved without a public listener.
  In this case the two-gate assessment is **not made** (`GateReport.PublicChecked=false`, no candidate is produced) and the discovery/draft
  screens say "internet exposure check was not performed". This is not a safe result; when a public listener is added the check
  runs.
- **Run immediately after saving:** saving a profile, credential and policy triggers the inventory/alert/drift/health loops
  immediately (`monitor.Loops.Trigger`). Triggers merge: requests arriving during a running round
  cause at most one additional round (unlike the 30 s debounce on the groups hook, the last save is never swallowed).
- **Policy baseline:** when the first import completes, the live Headscale policy is recorded as the applied baseline
  (`policyrev.EnsureBaseline`); if recording fails the import is not broken, and the drift card says why the baseline is missing.
- **[Proposed] Known intentional difference:** the only difference accepted between the generated Caddyfile and the existing Caddyfile is the friendly "No access" 403 page. `CheckSeedParity` drops it only on the generated adapt-JSON, with a narrowly matching allowlist (`internal/render/parity.go` `dropKnownAdditions`: `status_code [403]` inside reverse_proxy `handle_response` + an HTML `Content-Type` header + a 403 `static_response` and the exact `caddyForbiddenPage` body; only if there is no counterpart on the existing side). Every other deviation is reported as a difference; the fixture (`test/fixtures/caddyfile-current.caddy`) does not change. The developer approved it as an exception to the S-03.2/G-01.1 equality. Details: ADR 0010 item 6.
- **wireguard_ui:** a wireguard_ui system site whose "enabled" switch is off is not written to Caddy and is neither measured nor produces alerts.
- **Gate cookie:** see §8.1; "Sign out" in the top menu.
- **Successful webhook/groups call:** every signed call leaves a single INFO line (source and role count; no body, identity,
  header or secret).

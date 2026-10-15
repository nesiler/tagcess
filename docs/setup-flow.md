# Setup flow: install script, discovery and the setup wizard

Design for the "Install wizard and packaging" milestone (issue #25). It turns "a server and a domain" into a working
VPN portal: a short install script on the server, a read-only discovery of what already runs there, and a web setup
wizard that installs or connects every service step by step.

Labels: **[Decided]** cites a developer decision (source given); **[Proposed]** is a proposal of this design and not
a decision; **[Open]** is a question for the developer (§10). Everything new in this document is **[Proposed]** unless
marked otherwise. Facts about external systems carry a source (§11).

Sources: [product-decisions.md](product-decisions.md) §1, §2, §3, §11, §12; [architecture.md](architecture.md);
[security.md](security.md); [install.md](install.md); ADR [0004](adr/0004-docker-host-network.md),
[0008](adr/0008-headscale-restart-helper.md), [0009](adr/0009-zitadel-service-user.md),
[0021](adr/0021-headscale-host-operation-protocol.md), [0030](adr/0030-read-only-k8s-discovery-and-site-draft.md);
[stack-notes](../.agents/skills/stack-notes/reference.md).

## 0. Decisions this design builds on
- **[Decided]** Installation must be easy; the new installation must not repeat the hard company migration
  (product-decisions §1).
- **[Decided]** The product flow (product-decisions §11): the user runs the install script from the README on their
  server; the script installs tagcess, scans what already exists and stores the findings in a staging area of the
  database; the script asks only the minimum (for example the domain and the IP); every other step happens in the UI,
  where Headscale, Caddy, Zitadel and k8s are set up step by step; on an empty server tagcess installs the services,
  when they exist it builds a migration plan; at the end users connect with Tailscale and sign in with Zitadel.
- **[Decided]** On a fresh server the services tagcess installs (tagcess, Caddy, Headscale, the auth proxy) run in
  Docker Compose. Existing installations are connected as they are; tagcess does not move them (product-decisions §11).
- **[Decided 2026-10-15]** tagcess never installs an identity provider. An existing Zitadel (later another OIDC provider
  through a driver) is a prerequisite; the setup wizard only connects to it (product-decisions §11).
- **[Decided]** The first stage keeps oauth2-proxy as the auth proxy; `tagcess-auth` replaces it later
  (product-decisions §4, §11).
- **[Decided]** Everything is chosen in the UI; nothing stays fixed in code or config files, including the Headscale
  `allowed_groups` set, the admin group, addresses, CIDRs and paths (product-decisions §11).
- **[Decided]** A single host: tagcess, Headscale and Caddy on the same server (product-decisions §2). Zitadel first,
  behind a driver structure (product-decisions §3).
- **[Decided]** Zitadel and the k8s target of the test lab stay on the developer's k3s server; tagcess, Headscale, Caddy
  and oauth2-proxy run on one Hetzner VM created from a snapshot (product-decisions §12).
- **[Decided]** The IdP is the only user and role store; tagcess reads roles and never creates users or grants roles
  (AGENTS.md hard rule 3). Fail safe: keep the last known good state, never widen access (hard rule 7).
- **[Decided]** tagcess is not in the traffic path (NFR-01); the UI is reached only through a permission-restricted unix
  socket behind Caddy and the auth proxy (NFR-02, ADR 0004).
- **[Decided 2026-10-15]** The developer's answers to the questions of this design (O1, O2, O4, O5, O6 accepted as
  recommended; O3 and O7 dropped because no IdP is installed) are listed in §10 and marked where they apply.
- Still **[Open]** elsewhere: the release flow (product-decisions §12, issue #18). This design depends on it only for
  how the script and images are published (§1.6).

## 1. Install script
### 1.1 Where it runs and what it is
**[Proposed]** A new POSIX shell script, `deploy/get.sh` (published as the release asset `install.sh` once #18 is
decided), run **as root on the target server**. It replaces neither the wizard nor `deploy/install.sh`: today's
`install.sh` runs on the operator's machine and drives Ansible over SSH (see §7); the new script is local, has no
Ansible or Python dependency and does as little as possible:

1. checks the host;
2. asks the minimum (§1.2);
3. installs Docker if it is missing (with consent);
4. installs the host helper (§5.3);
5. runs the first discovery (§3);
6. starts the bootstrap stack (tagcess, and Caddy when ports 80/443 are free);
7. prints the setup address and the one-time setup token (§2).

Every later choice (which existing IdP to connect, Headscale, auth proxy, k8s, sites) is made in the wizard
(product-decisions §11). The IdP itself must already exist; neither the script nor the wizard installs one.

### 1.2 What it asks
| Question | Default | Check |
|---|---|---|
| Base domain, for example `example.com` | none | RFC 1123 hostname rule of security.md §5. The wizard derives the `tagcess.` and `hs.` names from it; the user can change each name in the wizard |
| Public IPv4 address (IPv6 optional) | the address on the default-route interface | must be a global unicast address on this host; the wizard checks that DNS records point to it |
| ACME contact e-mail | empty (Caddy works without one) | e-mail syntax only |

Non-interactive flags with the same names (`--domain`, `--public-ip`, `--acme-email`, `--yes`) allow scripted runs.
The answers are stored in `/etc/tagcess/install.env` (root `0600`, no secrets) and imported into the tagcess
`settings` table at first start; after that the UI owns them.

### 1.3 Host checks (blockers and warnings)
- **Blockers:** not root; not Linux on amd64/arm64; no systemd; an operating system outside the supported list
  (**[Proposed]** Ubuntu 24.04 and 26.04 LTS, Debian 12 and 13; Docker's apt repository supports these, §11 F1); less than 2 GB RAM or
  10 GB free disk (**[Proposed]** values, to be measured on the lab).
- **Warnings (shown, then the user decides):** ports 80/443 held by a process that is not Caddy (§3.3); an existing
  Headscale, Tailscale, WireGuard, IdP or k8s (these become discovery findings, not script questions).
- The script never stops, reconfigures or removes an existing service.

### 1.4 What it installs
- **Docker Engine and the Compose plugin**, only if missing and only after the user types `yes`: from Docker's apt
  repository (`docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-buildx-plugin`, `docker-compose-plugin`), not with
  the `get.docker.com` convenience script, which Docker's documentation says is not recommended for production and
  which can upgrade Docker unexpectedly (§11 F1). An existing Docker is used as it is if `docker compose version`
  works and the Engine is not older than the tested minimum.
- **The host helper** `tagcess-hshelper` (§5.3): binary with a pinned sha256 from the same release, its systemd units,
  and the request/result directories.
- **The bootstrap stack** (§5): the tagcess container, and the Caddy container when ports 80/443 are free. Nothing else
  is installed by the script.

### 1.5 Idempotency and re-runs
- A re-run reads `/etc/tagcess/install.env` and asks nothing that is already answered (`--reconfigure` asks again).
- Each step checks before it acts: Docker present → skip; helper binary with the same sha256 → skip; stack running →
  `docker compose up -d` is a no-op for unchanged services.
- A re-run always runs a new discovery (§3.4).
- **Before the setup is sealed** (§2.4) a re-run rotates the setup token and prints the address and the new token
  again (the old token stops working).
- **After the setup is sealed** the script changes nothing in the stack. It prints the UI address and points to the
  UI; changes and service upgrades are done in the UI. The one exception is `--upgrade v0.1.y`, which activates a new
  release by replacing only the host helper (§5.6). `--uninstall` stops the stack and keeps every data directory;
  data removal is a separate, explicit `--purge` that asks for the domain name as confirmation.
- Exit codes follow today's installer: `0` done, `1` error or blocker, `3` the user declined a confirmation.
- Output and prompts are English (AGENTS.md "Language"; issue #21 item 4).

### 1.6 How the user gets it
**[Proposed]** Until the release flow is decided (#18), the README shows a two-step command that downloads the script
from a git tag and runs it (`curl -fsSLo install.sh …/v0.1.x/deploy/get.sh && sudo sh install.sh`), never
`curl | sh` from `main`. After #18 it is a release asset with a published checksum.

## 2. First admin before the IdP is connected: setup token and setup mode
Before the IdP is connected and the auth proxy exists, the normal UI gate (Caddy → oauth2-proxy → admin group, security.md §3.1)
cannot work. Setup mode is the only way into tagcess without the gate, and it ends when the gate works (sealing,
§2.4); only a command on the host can open it again.

### 2.1 The setup token
- tagcess creates the token at startup when the setup is not sealed and no valid token exists: 32 bytes from
  `crypto/rand`, shown as Crockford base32 groups. The database stores only its SHA-256 hash in `setup_state`.
- The plain token is written once to `/run/tagcess/setup-token` (owner tagcess UID, `0600`). `/run/tagcess` is the
  existing runtime directory (tmpfs on the host): the token is not in the backed-up data directory and is gone after a
  reboot (tagcess then creates a new one). The install script (root) reads and prints it. It is never logged, never in
  audit, never in a URL.
- Valid for 24 hours; single use (exchanged for a setup session, §2.2); a new token is created by
  `docker compose exec tagcess tagcess -setup-token` (needs root or the `docker` group on the host) or a script re-run.
  Creating a new token invalidates the old one and every setup session.
- **Brute force:** the token has 256 bits, so guessing is not a practical attack; the limits only stop noise. The
  exchange endpoint allows 5 failed attempts per minute per source and 60 per minute in total; a limited request gets
  `429`. There is no lockout that burns the token, so strangers cannot lock the admin out. Comparison is constant time.
- **Source address:** behind Caddy every request reaches the setup listener from loopback. The bootstrap Caddyfile sets
  `header_up X-Tagcess-Client-IP {remote_host}`, which overwrites any client value; the setup listener reads only this
  header and only on loopback connections. Through an SSH tunnel the source is the tunnel (loopback).

### 2.2 The setup session
- `POST /setup/session` with the token (form field, never a query parameter) returns a session cookie
  `__Host-tagcess_setup`: random 32 bytes, hash in `setup_state`, `HttpOnly`, `Secure`, `SameSite=Strict`,
  `Path=/`; idle timeout 1 hour, absolute 12 hours. Only one setup session exists at a time.
- The setup session can open only `/setup/*` (the wizard). The normal UI, the identity headers and the webhook listener
  are not affected by it. Every state-changing setup request needs the CSRF token (security.md T7).
- Audit actor for setup actions: `setup:<first 8 hex of the session hash>`; the audit records the source address.

### 2.3 How the setup page is reached
| Case | Path | Why |
|---|---|---|
| Ports 80/443 free (normal fresh server) | `https://tagcess.<domain>/setup` through the bootstrap Caddy, with a certificate from Caddy's ACME | The user does not need SSH tunnels; the token protects the page (the NetBird and Pangolin installers also open a first-run page on the public address, §11 F7) |
| 80/443 held by another proxy, or DNS not ready | SSH port forward: `ssh -L 9180:127.0.0.1:9180 <server>` then `http://localhost:9180/setup` | No public exposure at all |

- tagcess serves setup on a **separate loopback listener** `127.0.0.1:9180` (port chosen in `install.env`). It never
  reads identity headers, so loopback TCP does not weaken NFR-02; a local process still needs the token.
- Before sealing, the Caddyfile for the tagcess host has the public route `/setup*` → `127.0.0.1:9180`. Until step 5
  is verified everything else answers `503 setup pending`; from then on everything else goes through the normal
  tailnet-only gate snippet (oauth2-proxy → `ui.sock`), so the admin's first gated request (§2.4) can arrive. It is
  generated by the existing `-bootstrap-caddyfile` renderer, extended with these two states (golden-tested).
- Compared with NetBird's `/setup` (open to the first visitor while no user exists), the token closes the race between
  the install and the admin's first visit. **[Decided 2026-10-15]** The public page behind the token with the SSH tunnel as fallback
  (O2).

### 2.4 Sealing
The setup is **sealed** when the normal gate is proven end to end:
1. wizard steps 1-5 are verified (§4), and
2. tagcess has received a request on `ui.sock` whose identity headers contain the configured admin group. That request
   can only arrive over the tailnet, through Caddy and oauth2-proxy, after an IdP login with the admin role.

On seal, in one transaction: the token hash and all setup sessions are deleted, `setup_state.sealed_at` and the admin
identity are recorded, an audit event `setup_sealed` is written; then the setup route is removed from the Caddyfile
through the normal Caddy apply (`/adapt` → `/load` → file), the setup listener closes, and the tagcess host is served
only through the existing tailnet-only gate snippet. After seal `/setup` answers 404.

- **Fail safe:** if the Caddy reload that removes the route fails, the setup listener is closed anyway (no token or
  session exists any more), so the leftover route only produces an error page; a critical alert asks to retry.
- **Re-opening** (lost IdP, lost admin): only from the host, `tagcess -setup-reopen` inside the container. It needs
  explicit confirmation on the terminal, is audited, creates a new token and re-adds the route. The steps already
  verified keep their state; the wizard opens at the first step that is not verified.

## 3. Discovery
### 3.1 Who scans
- **Host scan** by the host helper's read-only `discover` operation (§5.3), as root: the tagcess container is
  non-root and read-only and cannot see host processes, units or listeners. The install script triggers the first
  scan; the wizard triggers later ones.
- **Network probes** by tagcess itself, through the existing `internal/netpolicy` rules: OIDC discovery of an issuer the
  user enters, Headscale `/health`, Caddy admin API `GET /config/`, DNS resolution of the chosen hostnames.
- **Reuse:** the checks of `deploy/ansible/roles/preflight/files/probe.py` (OS, Docker, Headscale version/configtest/
  gRPC/policy check, Caddy validate and drift, certbot, oauth2-proxy, Tailscale, listeners, disk, Headplane/WireGuard/
  dnsmasq/nftables presence) are ported to Go (`internal/discover`) so they are table-driven tests instead of a Python
  file that runs over SSH.

### 3.2 What is scanned (read-only)
| Kind | What is read | What is never read |
|---|---|---|
| Host | OS release, arch, kernel, systemd, CPU, RAM, free disk | – |
| Listeners | owner process or container of 80/tcp, 443/tcp, 443/udp, 3478/udp, 2019, 4180, 8080, 9090, 9443, 50443 and 41641/udp | traffic |
| Reverse proxy on 80/443 | the owner's name and version: Caddy, nginx, Traefik, HAProxy, Apache or unknown | its config files, except Caddy below |
| Caddy | unit or container, version, `caddy validate`, admin API reachability and `GET /config/`, Caddyfile path, the tagcess marker, disk-vs-running drift (as probe.py) | certificates' private keys |
| Headscale | unit or container, version, `configtest`, socket path, `server_url`, `policy.mode`, database type, OIDC issuer, `dns.extra_records_path`, `policy check` result and policy sha256 | `oidc.client_secret`, private keys, the database contents |
| Tailscale | `tailscaled` unit or container, `tailscale status --json`: own tailnet IPs, tags, control URL | auth keys, node keys |
| WireGuard | interface names and peer counts (`wg show interfaces`), names of files in `/etc/wireguard/`, wireguard-ui presence | file contents (they hold private keys) |
| IdP | Zitadel, Keycloak or Authentik as a unit or container (by image/unit name); later the OIDC discovery document of the issuer the user confirms | admin credentials |
| k8s | k3s/kubelet units; presence of `/etc/rancher/k3s/k3s.yaml` or `/root/.kube/config` | their contents: the k8s credential is still imported only through the existing narrow UI flow (K-01, security.md T16) |
| Docker | Engine and Compose versions; containers: name, image, state, published ports, Compose project label | environment variables and mounts' contents (they may hold secrets) |
| Other | Headplane, dnsmasq, nftables presence (as today; reported, never changed) | – |

### 3.3 Staging data model (SQLite)
New tables, all with the `setup_` prefix, so they do not collide with the k8s discovery tables of ADR 0030
(`k8s_drafts` in code, `discovery_drafts` in architecture.md §3):

| Table | Contents |
|---|---|
| `setup_scans` | id, trigger (`install`/`wizard`/`step_precheck`), scanner version, started_at, finished_at, result (`complete`/`partial`/`failed`), error class |
| `setup_findings` | id, run_id, kind (table above), subject key (for example `headscale/systemd`, `listener/443/tcp`), attributes (JSON, schema per kind, secret-free by construction: only allow-listed fields are copied), evidence (which check, result class), observed_at |
| `setup_state` | single row: setup token hash and expiry, failure counter, setup session hash and times, `sealed_at`, sealing identity, re-open count |
| `setup_steps` | step key, choice (`install`/`connect`/`migrate`/`skip`), state (`pending`/`ready`/`applying`/`verified`/`failed`/`uncertain`), parameters (JSON, no secrets), the finding ids and their `observed_at` the choice was based on, last verified parameters and evidence (last known good), verified_at, actor |
| `setup_migration_items` | one proposed import action per finding (§6): action key, finding id and its `observed_at`, state (`proposed`/`approved`/`applying`/`applied`/`declined`/`failed`/`uncertain`), linked `changes.id` or helper request ID, actor and time of the decision, the reason for a revoked approval |

The host helper writes its scan to `results/discovery.json` (size-limited like ADR 0021 b); tagcess validates it with a
strict decoder and stores it. The raw file is not kept.

### 3.4 Freshness
- A partial or failed run never replaces the findings of the last complete run (the k8s snapshot rule of ADR 0030 and
  architecture.md §7).
- Findings older than the latest complete run, or older than 24 hours, are shown as stale.
- **Before a step applies**, tagcess runs a targeted re-scan of the findings the choice depends on (`step_precheck`).
  If a finding changed (for example another process now holds port 443, or Headscale changed version), the step goes
  back to `ready`, the difference is shown and nothing is applied.
- The wizard has a "Scan again" button; the last 10 runs are kept.

## 4. Setup wizard (UI)
### 4.1 Steps and order
| # | Step | Choices | Depends on |
|---|---|---|---|
| 1 | Domain, DNS and TLS (Caddy) | install new / connect existing | – |
| 2 | Identity provider (an existing Zitadel) | connect existing only | 1 |
| 3 | Headscale | install new / connect existing / migrate | 1, 2 |
| 4 | VPN host on the tailnet (Tailscale client) | install new / connect existing | 3 |
| 5 | Auth proxy and UI gate (oauth2-proxy) | install new / connect existing | 1, 2 |
| 6 | Admin access and seal | – | 1-5 |
| 7 | k8s connection (optional) | connect existing | 6 |
| 8 | First sites | from k8s drafts / by hand / import seed (migrate) | 6 |
| 9 | First users | done in the IdP; tagcess shows status | 6 |

Order rationale: Caddy first because every public name needs its certificate; the IdP connection before Headscale because
Headscale's OIDC block needs the IdP client; the seal (step 6) before k8s, sites and users so that the public setup
page is open for as short a time as possible. Steps 7-9 use the existing normal UI flows (K-01 connection, S-01 site
form, k8s drafts, G-01 seed) behind the normal gate; the wizard only links to them and shows their state.

### 4.2 Common rules for every step
- **Choice per step:** *install new* adds a service to the Compose stack (§5) at the version pinned for this tagcess
  release; *connect existing* records how to reach a service that discovery found and checks it; *migrate* proposes
  import actions (§6). Choices that do not fit the findings are not offered (for example "install new Caddy" while
  nginx holds port 443).
- **Pipeline:** precheck (fresh findings, §3.4) → render (deterministic, golden-tested) → validate → preview (diff and
  the exact list of services, files and external objects that will change) → confirm → apply → prove (§4.3) →
  `verified`. The step's last verified parameters are its **last known good** state.
- **Failure (hard rule 7):**
  - A *new* service whose proof fails is stopped and removed by the helper (removing a service that did not exist before
    cannot widen access: the gate then fails closed); its data directory is kept for diagnosis. The step becomes
    `failed`. Exception: the bootstrap Caddy carries the setup page itself, so a failed step 1 keeps it running and
    shows the error.
  - A *changed* service keeps its last known good config where the apply is atomic (Caddy `/load` keeps the running
    config on error, architecture.md §6). Headscale config changes follow ADR 0021: no automatic rollback, the step
    becomes `failed` or `uncertain` and the UI shows the host state.
  - An uncertain result (the apply may have happened, the proof cannot be read) is `uncertain`; later steps stay
    locked until the step is proven or explicitly re-done.
- **No widening by retry:** a re-run of a verified step goes through the same pipeline; a step never changes an
  object it did not create unless the user chose *migrate* and confirmed that item.
- **External writes** use the existing writers: Caddy through `internal/caddy` and the change pipeline; Headscale policy
  through the policy writer (ADR 0020); Zitadel objects through `internal/zitadeladopt`; Headscale config through the
  helper (ADR 0021). The wizard adds no second writer.

### 4.3 The steps
**Step 1: Domain, DNS and TLS (Caddy)**
- Shows the hostnames (`tagcess.` and `hs.<domain>`; each editable) and the DNS records the user must create
  (A/AAAA to the public IP). Checks resolution from the server. **[Decided 2026-10-15]** Caddy's own ACME with HTTP-01/TLS-ALPN and the
  stock Caddy image (O4): every public name, and every site name, needs a public DNS record to the server (a wildcard
  `*.<domain>` record is enough); internal sites still answer only to the tailnet (S-06 closed).
- *Install new:* the Caddy container of the bootstrap stack becomes the managed Caddy (tagcess writes the Caddyfile as
  today, ADR 0005).
- *Connect existing:* an existing Caddy that discovery found (unit or container): admin API URL, Caddyfile path, version
  check, and the existing preflight blockers (validate, disk-vs-running drift). The Caddyfile is then taken over through
  *migrate* (G-01 seed and parity) before tagcess writes it.
- An existing non-Caddy proxy on 80/443 is not supported in this milestone: the step explains it and offers "scan
  again" after the user frees the ports. tagcess never stops a foreign service.
- **Proof:** the presented certificate of `tagcess.<domain>` validates against the system roots (existing
  `internal/health` TLS observation); the Caddy admin API answers; the running config equals the generated one.

**Step 2: Identity provider (an existing Zitadel)**
- **[Decided 2026-10-15]** tagcess never installs an IdP; an existing Zitadel is a prerequisite and this step only
  connects to it (product-decisions §11). Later IdPs come through the driver structure (product-decisions §3). On
  the test lab this is the Zitadel on k3s (product-decisions §12).
- *Connect existing:* the user enters the issuer URL; tagcess fetches its OIDC discovery document; the user pastes a
  one-time admin credential (PAT or key) used only for the bootstrap below and never stored. This **connection
  precheck** (issuer reachable, credential authenticated, read-only reads complete) is what the migration item M-1
  waits for (§6); it is not yet the step's verification.
- **Bootstrap** reuses `internal/zitadeladopt` (today's `cmd/tagcess-zitadel-adopt`): find or create the
  `vpn` project and its roles and the Headscale and oauth2-proxy OIDC apps (objects, not users or grants). The role keys
  and the admin group are chosen in the step (issues #3, #4). Actions targets use a URL the user chooses (issue #24:
  tailnet URL by default, public URL when Zitadel cannot reach the tailnet); the instance-wide groups execution is
  created only after an explicit question that says it is instance-wide (issue #20).
- **Users and grants stay with the IdP (hard rule 3).** Today `zitadeladopt` only *reports* on the `tagcess` service
  user (exists, `PROJECT_OWNER`, `ORG_OWNER_VIEWER`, key) and shows console steps; the step keeps that for a connected
  IdP: it shows the console steps, waits, and re-reads until the service user is complete, then the user uploads its key
  file once; it goes to the helper through the credential handoff (§5.4), which installs it where tagcess reads it
  today (`/etc/tagcess/secrets/zitadel-key.json`, security.md §7). The first admin's role is also granted in the IdP
  console. There is no exception to hard rule 3.
- **After bootstrap** the pasted admin credential is discarded (it is never written). Only the narrow `tagcess`
  service user key stays (security.md §10).
- **Fail safe:** if Zitadel cannot be read completely, or a write's result cannot be read back, the step is `failed` or
  `uncertain` and no later step starts; a bootstrap re-run is find-or-create, so it never creates a second copy.
- **Proof:** OIDC discovery answers on the issuer URL with a valid certificate; the `tagcess` service user
  completes a full paged `ListAuthorizations` (security.md §8 "complete"); both OIDC apps read back with the expected
  redirect URIs. The step becomes verified only after this proof, that is after the bootstrap (M-1) is applied or found
  already satisfied (§6).

**Step 3: Headscale**
- *Install new:* adds the `headscale` container. Its config is rendered by the helper from typed parameters:
  `server_url https://hs.<domain>`; listeners on loopback; the unix socket in a shared host directory (§5.2);
  `policy.mode: database` from the start (ADR 0001, so no G-02 migration is ever needed on a fresh install);
  `dns.extra_records_path` pointing at tagcess's DNS directory (ADR 0013); MagicDNS base domain chosen in the step; the
  OIDC block with the client from step 2 and `allowed_groups` chosen in the UI (issue #4). The initial policy is
  written through the policy writer and contains the locked tests, including admin group → `tag:vpn-server:443` and
  `:80` (issue #22, security.md §12).
- *Connect existing:* socket path and version; the preflight blockers of today's probe (configtest, gRPC, policy check,
  `listen_addr`).
- *Migrate:* file-mode policy → database mode (G-02), e-mail groups → provider identifiers (G-03), DNS path (G-01.2), as
  `setup_migration_items` (§6).
- **Proof:** Headscale `/health`; gRPC `ListUsers` through the socket; `CheckPolicy` of the live policy; the policy
  read back equals the written one.

**Step 4: VPN host on the tailnet**
- *Install new:* adds the `tailscale` container (§5.2) and joins it with a one-time, 10-minute tagged pre-auth key
  (`tag:vpn-server`) created through the Headscale admin client (the same rule as today's `tailscale_join` role); the key
  is passed to the container once and not stored.
- *Connect existing:* an existing `tailscaled` on the host that is logged in to this Headscale.
- **MagicDNS for the UI:** `tagcess.<domain>` has a public record (for its certificate), but the gate accepts only
  tailnet sources. So the step writes the MagicDNS records of the system sites (`tagcess`, and `hs` where the site
  model says so) to the VPN address through the existing site pipeline and DNS file (ADR 0013); tailnet clients
  then reach the UI over the tailnet.
- **Proof:** the node is online in `ListNodes` with `tag:vpn-server`; its tailnet IP is recorded as the VPN address
  (replacing the fixed `vpn_tailnet_ip` setting); the hook listener binds to it; `tagcess.<domain>` resolves to the VPN
  address through `100.100.100.100` (ADR 0013 verification).

**Step 5: Auth proxy and UI gate**
- *Install new:* adds the `oauth2-proxy` container; config rendered from step 2 (client, cookie domain, `cookie_expire
  1h`, no refresh, architecture.md §8.1); the cookie secret is generated by the helper. Today's `oauth2_proxy` role
  logic is reused: the candidate is started and checked on a spare port before it replaces the running one.
- *Connect existing:* an existing oauth2-proxy address (issue #5).
- The UI gate snippet uses the admin group chosen in step 2 instead of the fixed `devops` (issue #3).
- **Proof:** `/ping` answers; `/oauth2/start` redirects to the configured issuer; a request with a forged
  `X-Auth-Request-*` header gets 403 (the existing verify check).

**Step 6: Admin access and seal**
- Shows the admin what to do: install the Tailscale client, `tailscale up --login-server https://hs.<domain>`, sign in
  with the IdP account, open `https://tagcess.<domain>/`.
- Shows live status: the admin's Headscale user and node appear; the IdP role read shows the admin role (if the role is
  missing the screen says which user lacks which role and that it is granted in the IdP console, hard rule 3).
- **Proof and action:** the first gated request with the admin group seals the setup (§2.4).

**Steps 7-9** are the existing flows: k8s connection, profile and credential (K-01, ADR 0030); first sites by hand, from
k8s drafts or from a seed; users get roles in the IdP and appear after the next reconcile. The dashboard "Setup pending"
box (architecture.md §10.1) lists the remaining items, as it does today.

## 5. Runtime layout on a fresh server
### 5.1 Compose project
- One Compose project named `tagcess`. The compose file `/etc/tagcess/stack/compose.yaml` and every service config
  under `/etc/tagcess/stack/` are written **only by the host helper**, rendered deterministically from typed parameters
  and the release's version manifest (§5.5), and golden-file tested. tagcess never writes the compose file.
- Only the enabled services are rendered ("install new" choices); a "connect existing" component has no service.
- Before every apply the helper runs `docker compose config --quiet` on the candidate (it parses and validates the
  model without printing it, §11 F1); on error nothing changes. Services are started with `docker compose up --wait`,
  which returns when they are running or healthy.
- **Network mode [Proposed]:** the services that must see host addresses keep `network_mode: host`, as ADR 0004 already
  decides for tagcess: Caddy (real client IPs for the tailnet-only rules, admin API on localhost), Headscale (loopback
  listeners behind Caddy), tagcess (`ui.sock`, the hook on the tailnet IP, localhost APIs), oauth2-proxy (loopback
  `4180`, as today) and the Tailscale client (it must create the host's tailnet interface). A bridge layout (as NetBird and Pangolin do) would need a new answer for client IPs and the
  tailnet; it is not worth it for one host.

### 5.2 Services
| Service | Image (pinned in the manifest) | Network | Host ports | State on the host |
|---|---|---|---|---|
| `caddy` | `caddy` official image | host | 80/tcp, 443/tcp, 443/udp; admin `127.0.0.1:2019` | `/var/lib/tagcess-stack/caddy/data` (`/data`, must persist: certificates and keys), `/etc/caddy` (Caddyfile, written by tagcess as today) |
| `headscale` | `headscale/headscale` (distroless) | host | none public (`127.0.0.1:8080` behind Caddy; metrics `127.0.0.1:9090`); 3478/udp only if the embedded DERP is enabled | `/etc/tagcess/stack/headscale/` (config, ro), `/var/lib/headscale` (database), `/var/run/headscale` (socket directory, shared with tagcess), tagcess's DNS directory (ro) |
| `tagcess` | `ghcr.io/nesiler/tagcess` | host | none public (`ui.sock`; hook on the tailnet IP; setup listener `127.0.0.1:9180` until sealed) | the architecture.md §8 mounts, plus the stack channel and the handoff directory of the helper (§5.3, §5.4) |
| `oauth2-proxy` | `quay.io/oauth2-proxy/oauth2-proxy` | host | `127.0.0.1:4180` | config and secrets (ro) |
| `tailscale` | `tailscale/tailscale` | host, `/dev/net/tun`, `NET_ADMIN` | 41641/udp (direct connections) | `/var/lib/tagcess-stack/tailscale` (node state) |

- Healthchecks on every service and `depends_on: condition: service_healthy` order the start (§11 F1). `restart: unless-stopped`; read-only root filesystems where the image allows it.
- **Group IDs at runtime:** the tagcess image no longer bakes the host's `caddy`/`headscale` group IDs in at build time;
  the helper passes them as `group_add` (product-decisions §1, issue #18). One published image fits every host.
- **Headscale socket permission:** Headscale and tagcess share the socket directory; the socket keeps Headscale's
  default `0770` (§11 F3), the helper gives it a dedicated group and passes that group to tagcess with `group_add`.
  The image sets no user, so it most likely runs as root (inferred, §11 F3); I-10 checks this with `docker inspect`
  before code depends on it.
- **Tailscale client:** kernel mode (`TS_USERSPACE=false`) with `/dev/net/tun` and `NET_ADMIN`; `TS_STATE_DIR` on a
  persistent directory (otherwise every restart registers a new node); `TS_SOCKET` set explicitly, because the
  container's default differs from the host default; `--login-server` through `TS_EXTRA_ARGS` (§11 F8). Whether
  `NET_RAW` is needed and the Headscale login through `TS_EXTRA_ARGS` are proven in I-12.
- **Public ports on a fresh server:** 80/tcp, 443/tcp, 443/udp, and 41641/udp. Everything else is loopback or tailnet.

### 5.3 How tagcess manages the stack: the host helper, not the Docker socket
**[Decided 2026-10-15]** (O1)
- The Docker socket is root-equivalent: Docker says only trusted users may control the daemon and that the `docker`
  group grants root-level privileges (§11 F2). A socket proxy filters only by API section; creating and starting
  containers, which the wizard needs, stays root-equivalent (§11 F2). ADR 0008 and 0021 already decided that the tagcess
  container gets no Docker socket, D-Bus or root.
- So the existing host helper (`cmd/tagcess-hshelper`, ADR 0021) gets a second channel for **stack operations**,
  `/var/lib/tagcess-host/{requests,results,private}`, with the same file rules as ADR 0021 b (container writes only
  `requests/`, reads `results/`; `private/` root `0700`; `O_NOFOLLOW`, owner and size checks; one pending request;
  journal; `TimeoutStartSec`), plus the handoff directory of §5.4. The Headscale channel of ADR 0021 stays as it is.
- **Operations** (typed JSON, version 1, `request_id`, `op`, `base_rev`, parameters; no paths, image names, commands or
  free text):
  | Operation | What the helper does |
  |---|---|
  | `discover` | the read-only host scan (§3); writes `results/discovery.json` |
  | `stack.apply` | for **one named component**: renders that component's compose service and config files from its templates, the request's typed settings (§5.3.1) and the manifest embedded in its own binary; installs handed-off secrets and generates missing ones (§5.4); validates (`docker compose config --quiet`); backs up; pulls; starts the component; waits for health; reports. The files of every other component must stay byte-identical, otherwise nothing is written |
  | `stack.remove` | stops and removes one service that a failed "install new" added; keeps its data |
  | `service.restart` | restarts one allow-listed service |
  | `stack.upgrade` | moves one service to the digest in the manifest of the helper that is installed now (§5.6) |
  | `handoff.cleanup` | deletes the handoff files of a finished, failed or abandoned request (§5.4) |
- **Stack revision:** the helper publishes in `results/status.json` a `base_rev` (SHA-256 of the secret-free projection
  of the stack: enabled components, their settings and digests). Every write request carries the `base_rev` it was
  built from; a stale one is rejected, so two wizard tabs or a retry cannot apply an older picture of the stack.
- **Headscale config changes in a container:** the ADR 0021 patch flow stays (allow-listed patch → candidate on the host
  → `configtest` → backup → atomic replace → restart → health); the helper gets a second backend that runs `configtest`
  with the Headscale image and restarts with `docker compose restart headscale` instead of `systemctl`. The backend is
  chosen from the discovery finding (systemd for a connected existing Headscale, compose for one tagcess installed).
- **One authority for the Headscale config (both channels):**
  - `stack.apply` renders Headscale's `config.yaml` **only when it creates** the service (no config exists yet). After
    that, the file belongs to the ADR 0021 flow: every later change, including `allowed_groups` (H-07), goes through an
    ADR 0021 patch with its `base_rev`; `stack.apply` never re-renders, overwrites or "repairs" it. A changed setup
    parameter that would change `config.yaml` is turned into an ADR 0021 patch, or refused if the patch schema does not
    cover it yet.
  - Both channels take the same host lock (`flock` on one helper lock file shared by both roots) and the helper refuses a
    stack operation while the ADR 0021 journal is not terminal, and an ADR 0021 patch while a stack operation is not
    terminal.
  - Any stack operation that recreates or restarts the `headscale` service (`stack.apply`, `stack.remove`,
    `service.restart`, `stack.upgrade` on it) is a Headscale config operation for the tagcess side: it needs the DB
    maintenance flag of ADR 0021 (only widening writes stop) and ends like an ADR 0021 operation (result read back,
    reconcile before widening writes resume).
  - The secret-free Headscale projection that the UI and discovery show (`allowed_groups`, `base_rev`, last operation)
    is the ADR 0021 `status.json`; the stack status refers to it and does not copy the values.
- **Trade-off:** the helper is root and runs `docker compose`; its input is small, typed and validated twice (container
  and helper), and it renders everything itself, so a compromised tagcess can ask only for the stacks the helper knows
  how to build. The cost is a bigger helper (it is already root and already packaged by the installer).

#### 5.3.1 Configurable settings and fixed boundaries
**[Decided]** everything is chosen in the UI, including addresses, CIDRs and paths (product-decisions §11). The helper
therefore separates two kinds of values:

| Kind | Examples | How it is set |
|---|---|---|
| **Service settings** (UI) | hostnames; public IPs; ACME e-mail; loopback listen ports of each service and the setup listener; Headscale IP prefixes (IPv4 inside `100.64.0.0/10`, IPv6 inside `fd7a:115c:a1e0::/48`); MagicDNS base domain; embedded DERP on/off; the admin group; oauth2-proxy cookie lifetime within bounds; for *connect existing*: the addresses of the existing services and the paths they use (Caddyfile path, socket path, certificate directory) | Typed fields in the request, validated in the container and again in the helper: hostnames by security.md §5, IPs and prefixes as canonical values inside the allowed ranges, ports 1024-65535 and not used by another finding, durations within fixed bounds. Paths of an existing installation are absolute, without `..`, under an allow-listed root per kind (`/etc/caddy`, `/var/run/headscale`, `/etc/letsencrypt`, …) and must exist as found by discovery; they are read-only facts for the helper, never a place it creates or writes |
| **Helper boundaries** (fixed per release) | host paths of the managed stack (§5.2); which services exist and their images; which ports are published publicly; the socket directories; where secrets live | Part of the helper's templates and manifest; shown read-only in the UI |

**[Proposed]** The host paths of the *managed* stack are an exception to "paths are chosen in the UI": a host path in a
request to a root helper is a host-write primitive, and these paths are internal to the stack (the user never needs to
point them anywhere. The 2026-10-15 answers accepted O1 but did not address this exception; it stays **[Proposed]**
and is listed as the one remaining question in §10.

### 5.4 Secrets on a fresh server
- **Generated by the helper** (root) on first need and used only by services: the oauth2-proxy cookie secret. Never
  written into the compose file, environment lines, results, journals or logs.
- Files under `/etc/tagcess/stack/secrets/<service>/` (`0600` or `0400`, owned by the service's UID) are mounted
  read-only only into the service that needs them; tagcess's own secrets stay in `/etc/tagcess/secrets` (security.md §7),
  which the helper fills and tagcess mounts read-only as today.
- **Received by tagcess** from the IdP API during the bootstrap (step 2): the OIDC client secrets of the Headscale and
  oauth2-proxy apps (Zitadel returns them once) and the Actions target signing keys. They must reach services the
  helper owns.
- **Credential handoff [Proposed]:** a separate directory `/var/lib/tagcess-host/handoff/` (root-owned, `0730`, group
  = the tagcess container's group) is the only path for secret values from tagcess to the helper. Values flow in one
  direction only: since no IdP is installed, the helper never produces a secret that tagcess must read. Request and
  result files never carry values.
  - **tagcess → helper:** tagcess writes `in/<request_id>.<kind>` (atomic rename, `0600`, ≤ 4 KiB) and only then
    publishes the request, which lists the `kind`s it hands off (allow-list: `oidc_secret_headscale`,
    `oidc_secret_oauth2_proxy`, `hook_signing_key`, `groups_signing_key`, `zitadel_service_key`). The helper opens each
    file with the ADR 0021 b rules (`O_NOFOLLOW`, regular file, owner, size), checks that its `request_id` is the one
    being run and its `kind` is listed, installs it into the owning service's secret directory and deletes the drop
    file. A file for another or an already finished request ID is deleted unread (replay).
  - **Cleanup:** `in/` files are deleted when the request reaches a terminal state, on `handoff.cleanup`, at boot for any
    request that is not the journal's current one, and after 15 minutes. A secret is never reconstructed from a result;
    a lost drop file makes the step `failed` and the user re-runs it.
  - Results, journals, logs and audit contain only the kinds installed, never values.

### 5.5 Version manifest
- Each tagcess release has a manifest of the service images it was tested with (name, tag and digest). Images are
  referenced by tag and digest so a moved tag cannot change what runs.
- The manifest is embedded **only in the helper binary**, and the helper publishes it in `results/status.json` for the UI.
  The helper is built after the release's tagcess image is pushed, so the manifest can contain that image's digest too;
  no binary has to contain the digest of the image it is part of. tagcess does not keep its own copy.
- The release notes list these versions (product-decisions §12, release proposal). The current production pins
  (stack-notes) are older than the latest releases (§11 F0). **[Decided 2026-10-15]** (O6): the fresh stack starts on the current releases
  after I-1 re-verifies stack-notes on the lab (Caddy 2.11 first); the adopt path keeps the production pins.

### 5.6 Upgrades of the pinned services
- tagcess never upgrades a service by itself.
- **Release A → B:** a new release becomes available on the host when the helper of release B is installed, because
  the helper carries the manifest. **[Proposed]** Until the release flow decides signing (#18), this activation is a host
  command: `install.sh --upgrade v0.1.y` (root) downloads the release's helper with its published checksum, replaces the
  helper binary and units atomically (the old binary is kept for one step back), and changes nothing else. Activating a
  release from the UI would make the root helper download and run new code on the strength of a request, so it waits
  for signed releases (#18). The activation is a separate step from upgrading services.
- After activation, Settings → Stack shows per service the running digest and the one in the active manifest; the user
  upgrades one service at a time through `stack.upgrade`: backup (Caddy `/data`, Headscale database) → pull → recreate →
  health → the step's proof again.
- On failure: a stateless service (Caddy, oauth2-proxy, Tailscale) is put back on the previous digest. A stateful
  service (Headscale, and tagcess itself) may have migrated its data, so the previous image is not started automatically;
  the service stays stopped or degraded, a critical alert is raised, and restoring the backup is an explicit action with
  confirmation.
- tagcess upgrades itself through the same operation: release B's tagcess digest is in the manifest of helper B. While it
  restarts the sites keep working (NFR-01). A tagcess B that finds a database newer than it can read refuses to start
  (the existing migrator rule); the helper then reports the failed health and keeps the backup.

## 6. Migration path (existing installations)
- **[Decided]** Existing services are connected as they are; tagcess does not move them (product-decisions §11).
  *Migrate* therefore means **taking an existing configuration under tagcess's management**, never moving a service
  into the Compose stack.
- From the findings, the wizard builds a migration plan: one `setup_migration_items` row per proposed action. Each item shows
  the evidence, the exact effect and the import feature that performs it. The user approves, declines or postpones each
  item; nothing runs without its own approval, in the order below.

**Items and their prerequisites [Proposed].** The order follows today's adopt phase order
(`deploy/ansible/group_vars/all/phases.yml`) and the rules it encodes (the hook ACL rule is added in file mode before
G-02, architecture.md §8; G-03 needs the policy writer, so database mode).

| # | Item key | Finding | Action | Performed by | Prerequisites |
|---|---|---|---|---|---|
| M-1 | `idp.bootstrap` | Zitadel without the `vpn` project, apps or a complete service user | Bootstrap (step 2) | `internal/zitadeladopt` | step 2 connection precheck passed (not step 2 verification, which follows M-1) |
| M-2 | `caddy.first_import` | Caddy with a hand-written Caddyfile | Import sites from a seed; apply only after the parity gate | G-01 (`internal/site/seed.go`, `render.SeedParity`, `/sites/first-import`) | M-1; step 1 *connect existing* verified |
| M-3 | `headscale.server_tags` | The VPN host or k8s node without `tag:vpn-server` / `tag:k8s` | Add the node tags (today's `hs_tags`) | the `headscale_adopt` logic, ported in I-19 | step 3 *connect existing* verified |
| M-4 | `headscale.hook_acl` | Policy without `tag:k8s → tag:vpn-server:<hook>` | Add the rule in file mode (today's `hs_hook_acl`) | the `headscale_adopt` logic, ported in I-19 | M-3 |
| M-5 | `headscale.dns_path` | `extra_records_path` outside tagcess's directory | Point it at tagcess's DNS directory | G-01.2 through the Headscale helper (ADR 0021) | step 3 *connect existing* verified |
| M-6 | `headscale.policy_db` | Headscale `policy.mode: file` | Move the policy to database mode without an empty-policy moment | G-02 (today's `g02`) | M-3, M-4 |
| M-7 | `identity.convert` | E-mail based policy groups | Convert to provider identifiers | G-03 (`internal/sync/migrate_identity.go`) | M-1, M-6 |
| M-8 | `headscale.allowed_groups` | Headscale `allowed_groups` not set | Choose the set in the UI | H-07 helper patch (ADR 0021) | M-1 |
| M-9 | `s06.close` | WireGuard / wireguard-ui present, S-06 open | Close S-06 when the transition is over | S-06 switch, `wireguard_ui` system site | M-2; never proposed as approved by default |

**Plan rules [Proposed]:**
- An item can be approved at any time, but it **runs** only when every prerequisite is satisfied: the prerequisite item is
  `applied`, or discovery shows its condition already holds (no item was created for it; see I-18 AC5 for how this is
  recorded and re-checked). An approved item whose
  prerequisite is `proposed`, `approved`, `applying`, `failed`, `uncertain` or `declined` stays waiting, and the screen
  names the prerequisite. Declining an item therefore blocks the items that depend on it; the screen says so before the
  user declines.
- One item runs at a time (`applying`), under the existing writer lock of the feature that performs it.
- A write whose result cannot be read back makes the item `uncertain`; the whole plan stops (no other item starts)
  until the user resolves it with the feature's own recovery flow (for example the policy writer's controlled recovery,
  ADR 0020, or an ADR 0021 result review). `failed` stops only the item and its dependants.
- Before an approved item runs, its findings are re-checked (§3.4). If a finding changed, the approval is revoked: the
  item goes back to `proposed` with the reason recorded, and its dependants that were approved are revoked too.
- S-06 starts open on adoption, and the parity gate accepts only the named `s06_open_start` difference, reported with
  a warning **[Decided]** (ADR 0010 §6, overview.md §9 #19). M-2 keeps that rule unchanged; M-9 is the step that closes
  S-06 later.

- **What moves from today's import features:** their logic stays in the import code of milestone "Import as an optional
  feature"; the wizard is only a new entry point that feeds them findings and records the decisions. The Ansible
  phases that run them today (`hs_tags`, `hs_hook_acl`, `hs_dns_path`, `g02`) become wizard items one by one (§9).
- **Known gap:** G-03 has no way to drop an unmatched e-mail yet (`sync.Input.DroppedEmails` is never set by production
  code); the migration item for G-03 needs it (§9 I-20).

## 7. `deploy/ansible`: removed or kept **[Decided 2026-10-15]** (O5)
Almost every Ansible role serves both modes: only `zitadel_install` is fresh-only (`deploy/ansible/group_vars/all/phases.yml`,
docs/install.md §5). `certbot`, `headscale_install`, `caddy_install` and `tailscale_join` also run in adopt mode, where
they install a missing component after confirmation and re-run on components the installer owns.
- **Fresh mode is retired** once the fresh-install end-to-end test (§9 I-15) passes on the test lab: the `fresh` mode
  choice, the `zitadel_install` role and the fresh-only branches inside shared roles (for example the forced Actions
  switches of `zitadel_seed`, issue #20, and the `tagcess` cookie-profile default of `oauth2_proxy`) are removed with
  their tests. **Shared roles stay** with their adopt behaviour, including the missing-component install and installer-
  owned re-runs. Issues #20-#23 then apply to the wizard steps instead of Ansible (§9 notes).
- **Adopt mode stays** as the supported path for existing installations (including the company installation) until the
  wizard's *connect existing* and *migrate* paths are proven by the adopt end-to-end test (§9 I-21). Only then are
  Ansible and `deploy/install.sh` removed, and `docs/install.md` becomes a short "adopt with the wizard" guide.
- **Reused, not thrown away:** `probe.py` checks → `internal/discover`; `backup.py` → the helper's backup step;
  `roles/guide` texts → wizard step help; `internal/zitadeladopt` → the IdP bootstrap; the `verify` role's checks →
  step proofs and the seal check; `tagcess -bootstrap-caddyfile` → the bootstrap Caddyfile; the hshelper → the host
  helper with a stack channel.
- The developer accepted this plan on 2026-10-15 (O5).

## 8. What this design does not change
- The sync, site, policy and Headscale admin writers, their locks and fail-closed rules (architecture.md §4-§7).
- The NFR-02 trust boundary for the normal UI: identity headers only on `ui.sock`.
- The k8s read-only boundary (security.md §13): discovery only notes that k8s exists; the credential import stays the
  existing UI flow.
- The adopt layout of architecture.md §8 (host systemd Headscale and Caddy).

## 9. Implementation split
Proposed follow-up issues, one concern each, for the "Install wizard and packaging" milestone. Order: I-1 … I-15
deliver a fresh install end to end on the decided test lab (lab VM + the existing Zitadel on k3s); I-16 … I-25
follow. Acceptance criteria are EARS; each issue adds its tests.

**I-1 Version manifest and stack renderer** (`internal/stack`) — risk: auth (generated config) — depends on: none (O6 decided).
- AC1: THE renderer SHALL produce the compose file and service configs from typed parameters and the manifest,
  byte-for-byte deterministic. Test: golden files per component set.
- AC2: THE manifest SHALL reference every service image by tag and digest, including the release's tagcess image;
  it SHALL be embedded only in the helper binary. Test: manifest table test and a build check that the tagcess binary
  has no manifest.
- AC3: IF a parameter fails validation THEN THE renderer SHALL return an error and no output. Test: bad-input table.

**I-2 Host helper stack channel** (`cmd/tagcess-hshelper`) — risk: auth — depends on: I-1.
- AC1: THE helper SHALL accept only the operations of §5.3 with the ADR 0021 b file rules on
  `/var/lib/tagcess-host`. Test: intake table tests (symlink, owner, size, unknown op, unknown field).
- AC2: WHEN `stack.apply` runs THE helper SHALL validate with `docker compose config --quiet` before any change and
  SHALL leave the running stack unchanged on error. Test: runner test with a fake `docker`.
- AC3: THE helper SHALL generate missing secrets as files with mode `0600`/`0400` and SHALL NOT write them into the
  compose file or results. Test: file-mode and redaction test.
- AC4: IF a request's `base_rev` is stale THEN THE helper SHALL reject it and change nothing. Test: intake test.
- AC5: WHEN `stack.apply` runs for one component THE files of every other component SHALL stay byte-identical, and an
  existing Headscale `config.yaml` SHALL never be re-rendered. Test: runner test that applies oauth2-proxy after an
  `allowed_groups` patch and compares the Headscale config.
- AC6: WHILE an ADR 0021 operation is not terminal THE helper SHALL refuse stack operations, and the reverse; both SHALL
  take the shared lock. Test: concurrent-channel test.
- AC7: THE handoff SHALL install only listed kinds for the running request ID, SHALL delete the drop file, and SHALL
  delete unread a file for another or finished request (replay), a symlink, a wrong owner or an oversize file. Test:
  handoff table test.
- AC8: WHEN a request ends, at boot and after the 15-minute timeout THE helper SHALL delete the request's handoff
  files. Test: interruption test (kill between drop and install).
- AC9: Secret values SHALL NOT appear in results, journals, logs or the audit. Test: canary-secret test.

**I-3 Host discovery** (`internal/discover`, helper `discover`) — risk: normal — depends on: I-2.
- AC1: THE scanner SHALL report the kinds of §3.2 and SHALL copy only allow-listed attributes. Test: fixture hosts
  (fake `/proc`, units, command outputs) → golden JSON.
- AC2: THE scanner SHALL NOT read WireGuard config contents, kubeconfig contents, container environments or Headscale
  secrets. Test: canary-secret fixtures never appear in the output.

**I-4 Discovery staging tables** — risk: normal — depends on: I-3.
- AC1: WHEN a run is partial or failed THE store SHALL keep the findings of the last complete run. Test: store test.
- AC2: THE importer SHALL reject a `discovery.json` with unknown fields or over the size limit. Test: decoder table.

**I-5 Setup token and setup session** (`internal/setup`, `internal/web`) — risk: auth — depends on: none.
- AC1: THE system SHALL store only the token hash, SHALL accept the token once and SHALL reject it after 24 h. Test:
  table test with a fake clock.
- AC2: WHEN a source exceeds 5 failed attempts per minute, or all sources 60, THE endpoint SHALL answer 429 and SHALL
  NOT invalidate the token. Test: handler test with `X-Tagcess-Client-IP` on loopback and a spoofed value off loopback.
- AC3: THE setup session SHALL reach only `/setup/*` and every state change SHALL need CSRF. Test: handler tests.
- AC4: WHEN `-setup-token` runs THE system SHALL replace the token and end every setup session. Test: CLI + store test.
- AC5: THE token SHALL NOT appear in logs, audit or responses after the exchange. Test: redaction test.

**I-6 Wizard framework** (`setup_steps`, step pipeline, UI shell) — risk: normal — depends on: I-4, I-5.
- AC1: THE wizard SHALL NOT apply a step whose precheck findings changed; it SHALL show the difference. Test: pipeline
  test with changed findings.
- AC2: WHEN the user opens a step's preview THE wizard SHALL list every service, file and external object the apply
  would change and SHALL make no external write. Test: pipeline test with fake writers.
- AC3: IF a step's proof fails THEN the step SHALL be `failed` and later steps SHALL stay locked. Test: state table.
- AC4: WHEN a new service's proof fails THE wizard SHALL request `stack.remove` for it, except the bootstrap Caddy.
  Test: pipeline test with a fake helper.

**I-7 Install script `deploy/get.sh`** — risk: auth (prints the setup token) — depends on: I-2, I-3, I-5, I-8; #18 for publishing.
- AC1: THE script SHALL ask only domain, public IP and ACME e-mail, and SHALL accept them as flags. Test: shell test.
- AC2: IF Docker is missing THEN THE script SHALL install it from Docker's apt repository only after the user types
  `yes`. Test: shell test with stubbed `apt-get`.
- AC3: WHEN the script runs again before sealing THE script SHALL ask nothing already answered and SHALL rotate and
  print the token; WHEN sealed it SHALL change nothing. Test: shell test of re-runs.
- AC4: THE script SHALL never stop or reconfigure an existing service. Test: static test of the command list.

**I-8 Step 1: domain, DNS, TLS, bootstrap Caddy** — risk: auth (generated Caddy config) — depends on: I-1, I-6.
- AC1: THE bootstrap Caddyfile SHALL have three golden states for the tagcess host: setup route + `503` (before step
  5), setup route + tailnet-only gate (after step 5), gate only (sealed). Test: golden files.
- AC2: THE bootstrap Caddyfile SHALL overwrite `X-Tagcess-Client-IP` with the connection's address. Test: golden file
  and a Caddy adapt test.
- AC3: THE step SHALL be verified only when the presented certificate validates and the running config equals the
  generated one. Test: step test with fake probes.

**I-9 Step 2: connect the existing Zitadel** — risk: auth — depends on: I-6.
- AC1: THE step SHALL find or create the `vpn` project, the chosen roles and both OIDC apps through
  `internal/zitadeladopt`, and SHALL NOT create users or grants. Test: seed test against the fake API (no user/grant
  call).
- AC2: WHILE the `tagcess` service user is incomplete THE step SHALL show the console steps and SHALL stay unverified.
  Test: step test.
- AC3: THE step SHALL ask before creating the instance-wide groups execution and SHALL use the chosen hook URL (#20,
  #24). Test: step test.
- AC4: IF Zitadel cannot be read completely THEN THE step SHALL be `failed` and no later step SHALL start. Test: step
  test with a failing fake API.
- AC5: THE admin credential SHALL NOT be written anywhere. Test: file-system and redaction test.
- AC6: THE OIDC client secrets and Actions signing keys SHALL reach the helper only through the handoff of §5.4 and
  SHALL NOT appear in tagcess's database, logs or audit. Test: step test with a fake helper and canary values.

**I-10 Step 3: Headscale install new** — risk: auth — depends on: I-2, I-9.
- AC1: THE rendered config SHALL use database policy mode, the tagcess DNS path and the chosen `allowed_groups`.
  Test: golden config.
- AC2: THE initial policy SHALL contain the locked admin → `tag:vpn-server:443/80` test (#22). Test: policy golden.
- AC3: THE step SHALL be verified only after `/health`, `ListUsers` through the socket and a policy read-back. Test:
  step test.

**I-11 Compose backend of the Headscale helper** — risk: auth — depends on: I-10.
- AC1: WHEN a config patch is applied to a compose Headscale THE helper SHALL run configtest, replace and restart
  through Compose, without automatic rollback (ADR 0021). Test: helper runner test with a fake `docker`.
- AC2: WHEN a stack operation recreates or restarts `headscale` THE tagcess side SHALL hold the ADR 0021 maintenance flag
  and SHALL run the reconcile before widening writes resume. Test: hostapply service test.

**I-12 Step 4: VPN host joins the tailnet** — risk: auth — depends on: I-10.
- AC1: THE join key SHALL be single-use, tagged `tag:vpn-server`, valid ≤ 10 minutes and never stored. Test: admin
  client test.
- AC2: THE step SHALL write the system sites' MagicDNS records to the VPN address. Test: render/DNS test.
- AC3: THE step SHALL be verified only when the node is online with the tag and `tagcess.<domain>` resolves to the VPN
  address. Test: step test with fakes.

**I-13 Step 5: oauth2-proxy install new + configurable gate group** — risk: auth — depends on: I-9; #3, #5.
- AC1: THE rendered oauth2-proxy config SHALL match architecture.md §8.1 (single cookie, 1 h, no refresh). Test:
  golden config.
- AC2: THE gate SHALL answer 403 to a request with a forged `X-Auth-Request-*` header. Test: compose integration test.

**I-14 Step 6: admin access and seal** — risk: auth — depends on: I-5, I-12, I-13.
- AC1: THE page SHALL show the admin's Headscale user, node and IdP role state. Test: handler test.
- AC2: IF the admin user has no admin role THEN THE page SHALL say so and SHALL NOT seal. Test: handler test.
- AC3: WHEN steps 1-5 are verified and a gated request with the admin group arrives on `ui.sock` THE system SHALL seal:
  token and sessions deleted, `/setup` → 404, audit `setup_sealed`. Test: handler + store test.
- AC4: IF the Caddy reload at seal fails THEN THE setup listener SHALL still close and a critical alert SHALL be raised.
  Test: seal test with a failing fake Caddy.
- AC5: WHEN `-setup-reopen` is confirmed on the host THE system SHALL create a new token, re-add the setup route and
  audit it. Test: CLI test.

**I-15 Fresh install end to end on the test lab** — risk: auth — depends on: I-1 … I-14.
- AC1: WHEN the script runs on a fresh lab VM with a domain and the lab Zitadel THE admin SHALL reach the sealed UI over
  the tailnet with only the script and the wizard. Test: lab acceptance run (recorded, time measured against the
  10-minute goal).

**I-16 Connect an existing Caddy** — risk: auth — depends on: I-6, I-3.
- AC1: THE step SHALL be verified only when the admin API answers, the version is supported, `caddy validate` passes
  and the running config equals the file on disk. Test: step test with fake probes, one failing check per row.
- AC2: IF a check fails or the finding changed since the precheck THEN THE step SHALL stay unverified and SHALL write
  nothing. Test: same.
- AC3: THE configured Caddyfile path SHALL pass the §5.3.1 path rules. Test: validation table.

**I-17 Connect an existing Headscale (systemd backend)** — risk: auth — depends on: I-2, I-3, I-6.
- AC1: THE step SHALL be verified only after the socket answers `ListUsers`, the version is supported, `configtest`
  and `policy check` pass. Test: step test with fakes.
- AC2: WHEN Headscale runs under systemd THE helper SHALL select the systemd backend of ADR 0021, and the compose
  backend otherwise. Test: helper backend-selection test.

**I-18 Migration plan framework** (`setup_migration_items`) — risk: auth — depends on: I-6.
- AC1: THE wizard SHALL build one item per §6 finding with the prerequisites of the §6 table. Test: plan table test per
  finding set.
- AC2: WHILE any prerequisite of an approved item is not `applied` (including `declined`, `failed` and `uncertain`) THE
  item SHALL NOT run. Test: table test over every prerequisite state.
- AC3: IF an item's write is uncertain THEN THE item SHALL be stored as `uncertain` and no other item SHALL start until
  the user resolves it. Test: plan test with a fake writer and a store reload.
- AC4: WHEN a finding changes after approval THE item and its approved dependants SHALL go back to `proposed` with the
  reason recorded. Test: plan test.
- AC5 (review M6, already-satisfied prerequisites): WHEN discovery shows that a prerequisite's condition already holds
  (for example a complete IdP bootstrap, present server tags and hook ACL, database policy mode) THE plan SHALL record
  it as satisfied with its evidence and without a write, SHALL re-check that evidence fresh before each dependant runs,
  and IF the evidence is missing, stale or no longer holds THEN the dependant SHALL NOT run. Test: plan tests over
  partially migrated finding sets (each prerequisite once present, once missing, once invalidated).
- AC6 (review M6, M-1 is not circular): THE M-1 bootstrap item SHALL be runnable after the step 2 connection precheck
  (issuer reachable, admin credential authenticated, complete read-only reads) without step 2 being verified; step 2
  SHALL become verified only after M-1 is applied (or found satisfied) and the step 2 proof passes. Test: plan tests
  with a missing project, missing apps and an incomplete service user.

**I-19 Migration adapters** (G-01 seed and parity, G-01.2 DNS path, G-02, S-06, H-07 `allowed_groups`) — risk: auth —
depends on: I-18, I-16, I-17; milestone "Import as an optional feature".
- AC1: THE G-01 item SHALL apply nothing until the parity gate passes, and SHALL keep the existing gate unchanged: only
  the named `s06_open_start` difference is accepted (with its warning), every other difference fails. Test: the
  existing `TestParity_S06OpenStart` cases run through the adapter.
- AC2: THE G-02 item SHALL never leave Headscale with an empty policy (G-02.2). Test: hsstack integration test.
- AC3: EACH adapter SHALL use its existing pipeline (seed, policy writer, ADR 0021 patch) and SHALL add no second
  writer. Test: adapter tests with fakes.

**I-20 G-03: drop an unmatched e-mail** — risk: auth — depends on: I-18.
- AC1: WHEN the devops marks an unmatched e-mail "drop" THE system SHALL set `DroppedEmails`, allow approval and audit
  it. Test: sync test.

**I-21 Adopt end to end through the wizard** — risk: auth — depends on: I-16 … I-20.
- AC1: WHEN the script runs on a lab host with an existing systemd Headscale, Caddy and WireGuard THE wizard SHALL
  connect and migrate them (M-1 … M-8) without Ansible. Test: lab acceptance run on the adopt target
  (`test/adopttarget` harness).
- AC2: THE first import SHALL pass parity with exactly the reported `s06_open_start` blocks as accepted differences
  (the decided S-06-open start, ADR 0010 §6) and SHALL reject any other difference, including any other widening.
  Test: same run, checking the `accepted` list against the fixture's source-restricted open sites.
- AC3: THE G-02 item SHALL leave no moment with an empty policy, and the live policy after G-02 SHALL equal the file
  policy before it plus M-3/M-4. Test: same run, policy read before and after.

**I-22 Stack upgrades, release A → B** — risk: auth — depends on: I-2, I-7, I-15.
- AC1: WHEN `install.sh --upgrade` runs THE script SHALL replace only the helper (checksum-verified) and keep the
  previous binary; the running services SHALL not change. Test: shell test.
- AC2: THE Settings → Stack page SHALL show per service the running digest and the active manifest digest. Test:
  handler test.
- AC3: WHEN a service is upgraded THE helper SHALL back up, recreate only that service and prove it; IF a stateless
  service fails THEN the previous digest SHALL be restored. Test: helper test with a fake `docker`.
- AC4: IF a stateful service fails THEN THE system SHALL NOT start the previous image automatically and SHALL raise a
  critical alert. Test: same.
- AC5: WHEN release A is upgraded to release B on the lab (helper, then every service, then tagcess itself) THE sealed
  installation SHALL keep working and pass every step proof. Test: lab acceptance run.

**I-23 Retire Ansible fresh mode** — risk: normal — depends on: I-15.
- AC1: THE `fresh` mode, `zitadel_install` and the fresh-only branches inside shared roles SHALL be removed with their
  tests. Test: `make check`.
- AC2: THE adopt re-run and missing-component install tests of `certbot`, `headscale_install`, `caddy_install` and
  `tailscale_join` SHALL stay and pass. Test: existing adopt tests in `deploy/ansible` (named in the PR).

**I-24 Retire Ansible adopt mode and `deploy/install.sh`** — risk: normal — depends on: I-21.
- AC1: THE Ansible tree and `deploy/install.sh` SHALL be removed and `docs/install.md` SHALL describe adopting with the
  wizard. Test: `make check` and the runbook test.

**I-25 Docs** — risk: normal — depends on: I-15.
- AC1: THE README quickstart and `docs/install.md` SHALL describe the script and the wizard. Test: a doc check in
  `deploy/runbook_test.go` for the quickstart commands.

Notes for the coordinator: #20, #22, #23 and #24 describe real needs; with this design they land in I-9 (#20, #24),
I-10 (#22) and I-8/the k8s flow (#23) instead of the Ansible roles (O5 accepted 2026-10-15). #21 items 1-2 disappear with
fresh mode; items 3-4 apply to the script.

## 10. Developer decisions on the questions of this design (2026-10-15)
The developer answered on PR #27 (2026-10-15). The text above applies these answers where it says **[Decided 2026-10-15]**.
- **O1** **[Decided 2026-10-15]** How tagcess manages the Compose stack: the host helper with a typed stack channel (§5.3); tagcess
  never gets the Docker socket.
- **O2** **[Decided 2026-10-15]** How the first admin reaches the setup page: `https://tagcess.<domain>/setup` behind the one-time
  token, with the SSH tunnel as the fallback (§2.3).
- **O3** Dropped. It asked for an exception to hard rule 3 for a Zitadel that tagcess installs. tagcess installs no
  IdP (**[Decided 2026-10-15]**, product-decisions §11), so there is no exception: hard rule 3 stays as written, and the connected IdP's
  console steps for the `tagcess` service user and the first admin's role stay (step 2, step 6).
- **O4** **[Decided 2026-10-15]** Certificates: Caddy's own ACME with HTTP-01/TLS-ALPN and the stock Caddy image; public DNS records
  (a wildcard is enough) for every public and site name (§4.3 step 1).
- **O5** **[Decided 2026-10-15]** `deploy/ansible`: retire fresh mode after I-15, keep adopt mode until I-21 proves the wizard's adopt
  path, then remove Ansible; #20-#24 move to the wizard steps (§7).
- **O6** **[Decided 2026-10-15]** Versions of the first manifest: the fresh stack starts on the current releases after I-1 re-verifies
  stack-notes on the lab (Caddy 2.11 first); the adopt path keeps the production pins (§5.5).
- **O7** Rejected. It asked where "install new Zitadel" is proven; that path is removed with the rest of the IdP
  installation (step 2 offers only *connect existing*; no Zitadel, login UI or Postgres in the stack).

Still **[Open]**: the host paths of the managed stack as an exception to "paths are chosen in the UI" (§5.3.1).
Recommendation: accept the exception (a path in a root helper request is a host-write primitive; these paths are
internal to the stack and shown read-only). Script distribution before the release flow is not a separate question:
§1.6 is **[Proposed]** and follows #18.

## 11. Verified facts and sources
Checked on 2026-10-14 with the researcher agent; "UNVERIFIED" items are checked in the named issue before code depends
on them.
- **F0 Versions.** Latest releases: Headscale v0.29.5, Caddy v2.11.7, Zitadel v4.19.4, oauth2-proxy v7.15.5, Docker
  Engine 29.9.1, Compose v5.6.0 (GitHub releases of `juanfont/headscale`, `caddyserver/caddy`, `zitadel/zitadel`,
  `oauth2-proxy/oauth2-proxy`, `moby/moby`, `docker/compose`). Production pins: stack-notes "Pinned versions".
- **F1 Docker install.** The convenience script installs without asking, is "not recommended for production
  environments" and can cause unexpected major upgrades; the apt repository is the documented alternative; Ubuntu
  26.04, 24.04, 22.04 are supported (https://docs.docker.com/engine/install/ubuntu/). `depends_on` with
  `condition: service_healthy` (https://docs.docker.com/compose/how-tos/startup-order/); `include` and profiles
  (https://docs.docker.com/compose/how-tos/multiple-compose-files/include/). Docker's apt repository supports Debian 13
  and 12 with the same packages (https://docs.docker.com/engine/install/debian/). `docker compose config` renders and
  validates the model, `--quiet` only validates, `--resolve-image-digests` pins tags to digests
  (https://docs.docker.com/reference/cli/docker/compose/config/); `up --wait` waits for running/healthy services
  (https://docs.docker.com/reference/cli/docker/compose/up/); `image` accepts a tag or a digest
  (https://docs.docker.com/reference/compose-file/services/). UNVERIFIED: the combined `name:tag@sha256:…` form on that
  page (I-1).
- **F2 Docker socket.** "Only trusted users should be allowed to control your Docker daemon"
  (https://docs.docker.com/engine/security/#docker-daemon-attack-surface); "The `docker` group grants root-level
  privileges to the user" (https://docs.docker.com/engine/install/linux-postinstall/). Socket proxies filter by API
  section only (https://github.com/Tecnativa/docker-socket-proxy); in linuxserver's variant start/stop/restart work even
  with `POST=0` (https://github.com/linuxserver/docker-socket-proxy).
- **F3 Headscale image.** `docker.io/headscale/headscale` and `ghcr.io/juanfont/headscale`; distroless, binary
  `/ko-app/headscale`, `-debug` tag with a shell; config `/etc/headscale`, data `/var/lib/headscale`, healthcheck
  `headscale health` (https://headscale.net/stable/setup/install/container/; v0.29.4 `.goreleaser.yml`). Defaults:
  `listen_addr 127.0.0.1:8080`, metrics `127.0.0.1:9090`, gRPC `127.0.0.1:50443`, STUN `0.0.0.0:3478` for the embedded
  DERP; `unix_socket /var/run/headscale/headscale.sock` with `unix_socket_permission "0770"` (v0.29.4
  `config-example.yaml`). The image is built on `gcr.io/distroless/base-debian13` and sets no user (v0.29.4
  `.goreleaser.yml`), so it most likely runs as root; UNVERIFIED by inspecting the image (I-10).
- **F4 Caddy image.** `/data` must persist (certificates and keys); ports 80, 443, 443/udp; HTTP challenge needs 80 and
  443; do not bind-mount a single Caddyfile (https://hub.docker.com/_/caddy). Admin API defaults to `localhost:2019`;
  `POST /load` rolls back on failure (https://caddyserver.com/docs/api). `reverse_proxy h2c://host:port` is a supported
  upstream scheme (https://caddyserver.com/docs/caddyfile/directives/reverse_proxy; v2.8.4
  `modules/caddyhttp/reverseproxy/caddyfile.go`).
- **F5 Zitadel.** Latest release v4.19.4 (F0). tagcess only connects to an existing Zitadel (product-decisions §11,
  2026-10-15), so the Zitadel container setup is not part of this design; the connection uses the APIs already in
  stack-notes and ADR 0009.
- **F6 oauth2-proxy.** Image `quay.io/oauth2-proxy/oauth2-proxy`, latest v7.15.5
  (https://oauth2-proxy.github.io/oauth2-proxy/installation); distroless and alpine flavours
  (https://github.com/oauth2-proxy/oauth2-proxy/blob/v7.15.5/Makefile).
- **F7 Other installers.** NetBird's `getting-started.sh` asks for the reverse proxy, domain and e-mail, generates
  `docker-compose.yml` and configs, and the first admin is created at `/setup`, which is accessible only while no user
  exists (https://docs.netbird.io/selfhosted/selfhosted-quickstart). Pangolin's installer asks for the domains and
  e-mail, starts pangolin, gerbil and traefik, and prints a setup token for `/auth/initial-setup`, also visible in the
  pangolin logs (https://docs.pangolin.net/self-host/quick-install).
- **F8 Tailscale container.** Latest release v1.104.1 (GitHub releases of `tailscale/tailscale`). containerboot:
  `TS_USERSPACE` defaults to true, `false` gives kernel mode with `/dev/net/tun`; `TS_STATE_DIR` must persist;
  `TS_EXTRA_ARGS` is passed to `tailscale up`; `TS_SOCKET` defaults to `/tmp/tailscaled.sock` in the source while the
  docs say `/var/run/tailscale/tailscaled.sock`, so it is set explicitly (v1.104.1 `cmd/containerboot/settings.go`,
  `main.go`; https://tailscale.com/docs/features/containers/docker/docker-params). A plain Linux `tailscaled` uses
  `/var/run/tailscale/tailscaled.sock` (v1.104.1 `paths/paths.go`). UNVERIFIED: the needed capabilities beyond
  `NET_ADMIN` and a Headscale login through `TS_EXTRA_ARGS` (I-12).

# Productisation decisions (2026-10-14)

Decisions for turning tagcess from a migration tool specific to one company into a general, open-source product.
Labels: **[Decided]** the developer's decision, **[Proposed]** a proposal (not yet a decision).

## 1. Goal
- **[Decided]** tagcess will be an open-source product. It is also a product our company can sell and support.
- **[Decided]** tagcess will be a system that uses the services it manages (Zitadel, k8s, Headscale, Caddy) as tools.
  Today it is a bridge between these services.
- **[Decided]** Installation must be easy. The company installation was hard because it was a migration; the new installation must not repeat that.
- **[Proposed]** tagcess owns the desired state; Headscale, Caddy, the IdP and k8s are its engines.
  Adopting an existing installation (adopt: parity, seed, S-06/WireGuard, identity conversion) leaves the core and becomes a one-time
  "import" feature. The company installation keeps working as an imported installation.
- **[Proposed]** The easy-install goal: "server + domain → a working VPN portal in 10 minutes". A single published image
  (group IDs at runtime, not at build time), a first-start web wizard, Caddy's own ACME
  (no certbot needed), IdP first setup done through the API, packaging of the host helper.

## 2. Topology
- **[Decided]** A single host for now: tagcess, Headscale and Caddy on the same server.

## 3. Identity provider (IdP)
- **[Decided]** Start with Zitadel.
- **[Decided]** The structure will be a **driver** structure suitable for adding other providers in the future. Providers
  are added one by one, specifically (example order: Zitadel, then Keycloak, then Authentik).
- **[Proposed]** The driver contract:
  - Required: listing role members, reading whether a user is active.
  - Optional (declared as capabilities): change notification (webhook), redirect URI management, first setup
    (bootstrap), groups claim support.
  - The webhook is only a "read now" signal; the real state is always taken by periodic reading. A provider
    without webhooks (Keycloak) or with unsigned ones (Authentik) works this way too.
  - A missing capability is clearly visible in the UI, not silently skipped.
- **[Proposed]** Generic OIDC is either not supported at all or becomes "limited support" with a clear warning: the user list cannot be fetched,
  a user disabled in the IdP is not reported (the device stays on the VPN until the Headscale key expires).

## 4. Authentication (instead of oauth2-proxy)
- **[Decided]** Authentication is brought inside tagcess, as a **new and separate service** (working name `tagcess-auth`).
- **[Decided]** It is added to the plan and done when its turn comes.
- **[Proposed]** Order: after the IdP driver structure. Roles are read from the data tagcess syncs, not from the token claim;
  so a groups claim setting for each IdP (today's Zitadel preuserinfo action) is not needed, and the session of a
  user disabled in the IdP can be dropped immediately.
- **[Proposed]** Security requirements:
  - A separate process: even if tagcess crashes the sites keep working (NFR-01 is preserved).
  - The session lives in a signed, stateless cookie; it is verified locally on every request without querying the database (the NetBird model).
  - The session/token is bound to the host (the resource) it belongs to (the lesson of Pangolin CVE-2026-72001).
  - A mature OIDC library (`zitadel/oidc` v3 RP); PKCE, state, nonce; redirects only to allowed hosts;
    incoming identity headers are removed; CSRF protection on sign-out.
- **[Proposed]** Tailnet identity (identity from the device) is not used alone; at most it becomes an additional signal.

## 5. Licence and business model
- **[Decided 2026-10-14]** Licence: **MIT**. No dual licence, no CLA, no copyright assignment. (Replaces the earlier
  AGPL-3.0 + commercial dual licence + CLA decision.)
- **[Decided]** At the start, revenue comes only from services: **installation, support, migration service**.
- **[Decided]** All features are free for now. This may change in the future.
- **[Proposed]** Zitadel is not embedded in the tagcess package; compose refers to the official image. (Reason: Zitadel is AGPL; distributing
  a modified version creates a source obligation. Talking over the API does not; this is an inference, not legal advice.)
- **[Proposed]** Before release: `THIRD_PARTY_NOTICES` (dependencies are permissive; confirmed with a `go-licenses` scan)
  and a note in the README "not affiliated with Tailscale Inc.".
- **[Decided 2026-10-14]** No trademark search and no legal review now. The priority is a usable product.

## 6. Repository
- **[Decided]** A new repo on GitHub: **`nesiler/tagcess`**, with a clean (new) git history. The old history is not opened because it contains the company's
  domains, IPs and production details.
- **[Decided]** On this Mac the old folder is copied to `tagcess-old` and the working folder is cleaned.
- Status (2026-10-14): the old folder (with its history) is kept as `tagcess-old`.
  The new working folder started with a new git history. The code was committed after company traces were cleaned
  (private-pattern and `gitleaks` scans).
- **[Decided 2026-10-14]** The repository is public.

## 7. Language
- **[Decided]** The UI is in English and Turkish (i18n).
- **[Proposed]** English is the default. Messages are carried in domain packages as codes/keys, not as sentences.

## 8. Roadmap [Proposed]
1. **Open-source preparation:** licence, English README, versioning + CI + GHCR image, cleaning company traces,
   moving constants to config/UI (admin group, oauth2-proxy address, tailnet CIDR, certificate path), `/healthz`
   (the runbook says it exists, there is no handler), a clean public repo.
2. **Separating import:** parity, seed, S-06/WireGuard and identity conversion leave the core.
3. **IdP driver structure:** an `internal/idp` boundary, the Zitadel driver, read-first sync.
4. **Installation wizard and packaging.**
5. **i18n:** English + Turkish. Required for launch.
6. **Launch.**
7. **`tagcess-auth`:** replaces oauth2-proxy.
8. **Keycloak driver**, then Authentik.

## 9. Open issues
- **Release flow:** what a release contains and how it is published (see §12).

## 10. Development process (2026-10-14)
- **[Decided]** Work tracking is GitHub Issues + Milestones. Task files, phase files and progress notes do not enter the public repo (the old ones are in `tagcess-old`).
- **[Decided]** Documents in the public repo are in English.
- **[Decided]** Model roles: today's defaults stay, but are set up so that they can be changed per job as the developer wishes.
- **[Decided]** Three skills: `coordinator`, `issue`, `review`. Everyone does their own task. Merging a branch into `main` and pushing to `main` is only the coordinator's job.
- **[Decided]** The proposed process was accepted: one issue = one branch = one PR; independent review by an equivalent other model; the final approval on auth/security PRs is the developer's; GitHub Actions CI; Renovate/Dependabot; fixtures with generic values.
- **[Decided]** Versioning increases minimally: progress stays within `0.1.*`.
- **[Decided]** The release flow is clarified later; postponed if needed.
- **[Decided]** The first release and the first code push to `main` must definitely be in generic form (no company traces).

## 11. Product flow (2026-10-14)
- **[Decided]** The installation flow, in the developer's words:
  1. A user finds the repo on GitHub and runs the install script from the README on their server.
  2. The script installs tagcess on the server. While it installs, it scans what already exists (reverse proxy,
     VPN, Headscale, ...) and stores the findings in a temporary (staging) area of the database. During a migration
     every decision and every action is taken by the user in the UI.
  3. The script is interactive but asks only the minimum (for example the domain and the IP). The rest of the
     installation is not in the script.
  4. The UI opens on the server. Every installation step happens there: the Headscale, Caddy, Zitadel and k8s
     connections are set up step by step with guidance. On an empty server tagcess installs the services; when
     they already exist it builds a migration plan.
  5. When everything is set up, users connect with Tailscale, signing in with their Zitadel account.
- **[Decided]** On a fresh server the services tagcess installs (tagcess, Caddy, Headscale, Zitadel with its
  database, the auth proxy) run in Docker (Compose), as NetBird and Pangolin do. Existing installations are connected
  as they are; tagcess does not move them.
- **[Decided]** The first stage keeps oauth2-proxy as the auth proxy; `tagcess-auth` replaces it later.
- **[Decided]** Everything is chosen in the UI. Nothing stays fixed in code or config files, including the
  Headscale `allowed_groups` set (ADR 0021), the admin group, addresses, CIDRs and paths.

## 12. CI and release (2026-10-14)
- **[Decided]** CI stays minimal and flexible: lint, unit tests, generated-code check, dependency vulnerability scan
  (`govulncheck`), secret scan (`gitleaks`) and build. No external services (Zitadel, Headscale, Caddy) run on
  GitHub runners. Tests that need a tool the runner lacks skip instead of failing.
- **[Decided]** No local Zitadel in the compose test stack for now; integration tests run on the developer's
  machine and the lab, not in CI (closes the ADR 0014 question).
- **[Open]** Release flow. **[Proposed]**: a release is only tagcess itself (the backend with the embedded UI, later
  `tagcess-auth`): a tag `v0.1.x` builds linux amd64/arm64 binaries, a container image on GHCR, checksums and the
  install script. Headscale, Caddy and Zitadel are not bundled: the setup wizard installs their official
  images/packages at versions pinned and tested for that tagcess release, or connects to existing ones. Each
  release lists those tested versions.
- **[Decided]** Test lab. The parts that can run in Kubernetes (Zitadel, the k8s target) stay on the developer's
  existing k3s server. Everything else (tagcess, Headscale, Caddy, oauth2-proxy) runs on one VM of the cheapest
  fitting type in a separate Hetzner Cloud project, with a fixed (primary) IP. The VM is not kept running: it lives as
  a snapshot and is created from it only for the end-of-day acceptance tests, then snapshotted and deleted again.
  (Hetzner bills a stopped server like a running one; only deleting it stops the cost.)

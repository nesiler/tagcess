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
- **[Decided]** Licence: **AGPL-3.0** core + **commercial dual licence**. Copyright must stay in one hand; external contributions require a **CLA**.
- **[Decided]** At the start, revenue comes only from services: **installation, support, migration service**.
- **[Decided]** All features are free for now. This may change in the future.
- **[Proposed]** (Answer to the developer's question "can it change later?") Yes: as long as copyright stays with us through AGPL + CLA,
  a paid enterprise add-on tier can be added later. However, versions already published under AGPL cannot be withdrawn.
- **[Proposed]** Zitadel is not embedded in the tagcess package; compose refers to the official image. (Reason: Zitadel is AGPL; distributing
  a modified version creates a source obligation. Talking over the API does not; this is an inference, not legal advice.)
- **[Proposed]** Before release: `THIRD_PARTY_NOTICES` (dependencies are permissive; confirmed with a `go-licenses` scan),
  a trademark conflict search for the name "tagcess", a note in the README "not affiliated with Tailscale Inc.".
  Legal review for the licence text and the CLA (no legal advice has been taken).

## 6. Repository
- **[Decided]** A new repo on GitHub: **`nesiler/tagcess`**, with a clean (new) git history. The old history is not opened because it contains the company's
  domains, IPs and production details.
- **[Decided]** On this Mac the old folder is copied to `tagcess-old` and the working folder is cleaned.
- Status (2026-10-14): the old folder (with its history) is kept as `tagcess-old`.
  The new working folder started with a new git history; the first commit contains only LICENSE (AGPL-3.0, gnu.org text) and the
  README. `nesiler/tagcess` was created on GitHub and is **private for now**. The code is committed after company traces are cleaned
  (after a `gitleaks` scan); the repo is then made public (`gh repo edit --visibility public`).

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
- **Copyright holder:** a person or a company (which legal entity)? The dual licence and the CLA are built on this.
- Company traces to clean: 187 files contain a company domain, server name, IP or person name (mostly test fixtures
  and golden files; `internal/render/testdata/caddy-seed.golden` was derived from the company's real Caddyfile).
- The CLA tool (for example cla-assistant) and the commercial licence text.

## 10. Development process (2026-10-14)
- **[Decided]** Work tracking is GitHub Issues + Milestones. Task files, phase files and progress notes do not enter the public repo (the old ones are in `tagcess-old`).
- **[Decided]** Documents in the public repo are in English.
- **[Decided]** Model roles: today's defaults stay, but are set up so that they can be changed per job as the developer wishes.
- **[Decided]** Three skills: `coordinator`, `issue`, `review`. Everyone does their own task. Merging a branch into `main` and pushing to `main` is only the coordinator's job.
- **[Decided]** The proposed process was accepted: one issue = one branch = one PR; independent review by an equivalent other model; the final approval on auth/security PRs is the developer's; GitHub Actions CI; Renovate/Dependabot; fixtures with generic values.
- **[Decided]** Versioning increases minimally: progress stays within `0.1.*`.
- **[Decided]** The release flow is clarified later; postponed if needed.
- **[Decided]** The first release and the first code push to `main` must definitely be in generic form (no company traces).

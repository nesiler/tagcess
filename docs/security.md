# Security model

tagcess writes the configs that decide who reaches which internal service. A mistake directly means unauthorised
access. This document is the reference for security-sensitive changes and for security review.
Labels: decisions are in the ADRs; the details of the controls here are **[Proposed]**.

## 1. Protected assets
- The Caddy config: which site is open to which role.
- The Headscale policy and nodes: network access, SSH, device validity.
- The Zitadel oauth2-proxy app URIs: a wrong redirect leads to an open redirect.
- The permissions tagcess holds: Headscale full admin (socket), the Zitadel service user, k8s read-only.
- The audit log: who changed what.

## 2. Threat actors and scenarios
| # | Actor | Scenario | Main control |
|---|---|---|---|
| T1 | A tailnet user without the `devops` role | Tries to reach the UI | Caddy + oauth2-proxy `devops` check; a second check in tagcess |
| T2 | Another local process or container on the VPN host | Forges an identity header from localhost | The UI is only on a Unix socket; socket permission only for the Caddy group (NFR-02, ADR 0004) |
| T3 | Someone on the tailnet or a compromised pod | Sends a fake webhook | HMAC signature, time window, replay protection, only `tag:k8s` in the ACL; the webhook is only a trigger |
| T4 | Authorised devops (error or malice) | Injects into the Caddyfile or policy through a form field | Strict field validation and structural render (§5) |
| T5 | Authorised devops (error) | Locks themselves and everyone out | Locked sites (S-05), validation and rollback, diff preview |
| T6 | A temporary Zitadel error | An empty role list removes everyone from groups | Complete-read requirement, threshold and approval (Y-03.3, Y-03.4, Y-04.5) |
| T7 | CSRF | An unwanted operation is performed from a devops browser | CSRF token, `SameSite=Strict`, state-changing operations POST only |
| T8 | Health check / target URL | SSRF to internal admin APIs through tagcess | UI target/domain/IP/port allow list, DNS and actual dial IP check; loopback/link-local/metadata/socket and following redirects forbidden; the fixed system template is a separate source of trust (§13) |
| T9 | Secret leakage | Appears in logs, audit, git or the UI | Secrets are passed only as file paths; masking; verified by tests |
| T10 | Authorised devops (error) or a compromised devops session | Deletes/expires devices, changes their tags, approves routes with the administrator client | Only the `internal/hsadmin` pipeline: single writer lock, fresh read, confirmation, "started" audit, read-back; CSRF (T7); nodes with server tags are protected (§12) |
| T11 | Authorised devops (error) | Writes a rule into the policy that widens access or cuts tagcess's own access | `CheckPolicy`, locked mandatory tests, base hash, diff preview; on rejection/uncertainty the live policy is kept (§8, §12) |
| T12 | A personal pre-auth key holder | Registers a device after losing a role or by bypassing OIDC filters | Fresh Zitadel check, single use, explicit expiry time (no upper limit, decided 2026-10-06; default 1 hour), revocation on role loss; the remaining race closes at reconcile (≤ 5 min) (§12) |
| T13 | Key leakage | Pre-auth/API key text appears in a list, log, audit or response | The admin DTO filters the secret out of lists (legacy included); the creation response is no-store and one-time; only the ID in audit (§7, §12) |
| T14 | Partial or uncertain `SetPolicy` | An old or half policy reopens access | No automatic restore of the old policy; "application uncertain", new writes stop; only controlled recovery from the UI (§8, §12) |
| T15 | An over-privileged k8s identity | Another binding/authorizer grants broad rights next to the narrow manifest | SSAR chosen on behalf of the effective tagcess principal; resource-verb-scope-time evidence. No general read-only claim without reviewing all bindings/authorisation paths (§13) |
| T16 | An uploaded kubeconfig/credential | Code execution via exec, arbitrary local file read, CA verification bypass or token leakage | Narrow endpoint/CA/token import; rejection of exec/auth-provider/tokenFile/local path/insecure TLS; atomic separate runtime secret directory; value-free UI/audit and no-store (§13) |
| T17 | Incomplete discovery or limited probe | Partial data becomes a draft that widens access; internal network success is treated as internet security | Last complete snapshot, freshness and uncertainty; a separate draft and S-04 confirmation; risk/vantage/time/scope independent; CRD/Gateway not scanned (§13) |
| T18 **[Proposed]** | Anyone on the internet before the setup is sealed | Reaches the public setup page and configures the server (takes over the installation) | One-time 256-bit setup token printed only on the host, hash-only storage, attempt limits, single setup session, CSRF; setup ends when the gate is proven and only a command on the host re-opens it (§14) |
| T19 **[Proposed]** | A compromised tagcess container | Uses the stack channel of the host helper to run arbitrary containers or mounts (host root) | No Docker socket in tagcess; typed allow-listed operations only; the helper renders the Compose project itself from its own templates and version manifest (§14) |
| T20 **[Proposed]** | A moved or replaced image tag upstream | A different image runs after a pull | Images referenced by tag and digest from the release manifest; upgrades only on explicit action (§14) |

## 3. Trust boundaries
1. **Browser → Caddy → tagcess (ui.sock):** The identity comes from the `X-Auth-Request-User`, `-Email` and `-Groups` headers.
   They are read only on requests coming from ui.sock. If `devops` is not in `groups` the request gets 403.
   The Caddy snippet **removes** client-supplied `X-Auth-Request-*` headers **before** forward_auth. So the
   headers come only from the oauth2-proxy response. An e2e test checks this: a fake header is sent and
   403 is expected.
2. **Zitadel → tagcess (hook, 100.64.0.4:<hook>):** Untrusted input. The body is not parsed before the signature is verified.
3. **tagcess → Headscale/Caddy/Zitadel:** tagcess is a highly privileged client. Its outputs must be validated and
   generated deterministically. **tagcess → k8s** is a separate read-only identity; SA/RBAC bootstrap and
   the permission to mint time-limited tokens are not moved to tagcess (§13).
4. **tagcess → host helper (ADR 0008/0021):** the container only writes an allowed-setting **patch request**; the request
   is handled like untrusted input. The helper checks the allowed keys itself, builds the candidate from the real config on the host
   (secrets stay on the helper side) and does not apply what fails `headscale configtest`.
   **[Proposed]** The stack channel (setup-flow.md §5.3) follows the same rule: typed operations, validated again on the host (§14).
5. **[Proposed] Internet → setup listener (only until sealed):** the setup page is the only path into tagcess that does not pass
   the gate. It trusts no identity header; only the setup token and the setup session it creates (§14).

## 4. Permission matrix
| Actor | Read | Change | Approval |
|---|---|---|---|
| `devops` (UI) | Everything (secrets masked) | Everything | Pending changes |
| `system:sync` | Zitadel, Headscale | Only policy `groups`, node expire and **revoking the unused personal pre-auth keys** of a user who lost roles (only `ExpirePreAuthKey` + listing) | None; waits if the threshold is exceeded |
| `system:monitor` **[Proposed]** | Scoped k8s get/list, selected SSAR; credentialless target/Caddy/TLS and existing observation sources | Only local snapshot/observation/monitoring alarm; no k8s resource writes, TokenRequest or access/config fixes | Cannot approve a draft Apply or recovery of an operational critical |
| Everyone else | Nothing | Nothing | Nothing |

For a change that needs approval, the person making the change and the approver may be the same. Because the team is 2-3 people,
"four eyes" is not mandatory **[Proposed]**. Approval shows that the diff was seen and a deliberate click was made, and is written to the audit log.

## 5. Input validation and render rules
General rule: **reject, do not try to correct.** An allow list is used, not a deny list.

| Field | Rule |
|---|---|
| Hostname | Lowercase RFC 1123 labels; total ≤ 253 characters; under the allowed domain list (from settings) |
| Role | Only role keys read from the Zitadel `vpn` project; also `^[a-z0-9_-]{1,32}$` |
| Target (upstream) | Scheme `http`/`https`; host in the allowed list (default k8s: `100.64.0.5`) or explicitly added; loopback and socket forbidden |
| API exemption: header | Name `^[A-Za-z0-9-]{1,64}$`; no value, always `*` (is the header present) (ADR 0011) |
| API exemption: path regex | Must compile with Go `regexp`; ≤ 200 characters; `` ` ``, `{`, `}`, `'`, line endings and control characters forbidden; `\` is written twice in the CEL string |
| Redirect | Source path `^/[A-Za-z0-9/_.-]*$`; the target is a path of the same site or an allowed hostname; an absolute target `http(s)://<allowed-host>[:port]<site-path>` is also valid (the existing `redir /god-mode … 308` form); code 301/302/307/308 |
| Extra header | Name is an RFC 7230 token, the first character cannot be `+`/`-`/`#`/quote/backtick (Caddy operation prefix / comment / string trap), ≤128; value is printable ASCII; `"`, `{`, `}`, line endings and a trailing `\` forbidden |
| System site | Single host; no role, target, header, redirect or API rule; `system_config` is exact per template (`wireguard_ui` `{"enabled":bool}`, `headscale` `{"headplane":bool}`, `zitadel`/`tagcess` `{}`); the record changes only for the switch and note/owner, cannot be deleted or disabled, and a second template cannot be created (S-05) |
| DNS record | Name by the hostname rule; value is IPv4 or IPv6 |
| Zitadel system site: internal source | Canonical IP/CIDR; no duplicates; ≤32 entries; IPv4 ≥/16, IPv6 ≥/48; `/0`, ambiguous addresses, zones and IPv4-mapped IPv6 forbidden; an empty list is free (it only narrows) **[Decided]** |
| Zitadel system site: login path | 1-32 entries, unique; starts with `/`, `[A-Za-z0-9._~/-]` and a single trailing `*` after a non-empty segment; `/`, `*`, `/*`, `..`, `//` forbidden |

Render rules:
- **Caddyfile:** The text is generated from a template. Every value goes through an escape function; a value that has not passed
  validation cannot enter the template (a separate "validated" type at type level).
  Golden tests and "bad input" fuzz tests are written.
- **Policy:** the document is edited in a **targeted** way on the `tailscale/hujson` AST (`internal/policydoc`): comments, order and
  unknown fields are preserved, there is no full JSON marshal or string concatenation (ADR 0020). Only the role `groups` section
  belongs to sync, the other sections come from the ACL editor; every write passes local validation and Headscale `CheckPolicy`.
- **Zitadel URIs:** Only `https://<validated hostname>/oauth2/callback`; the post-logout URI is not written **[Decided]**.
  URIs added outside tagcess are not touched and are shown with a warning (S-03.3, ADR 0012). Zitadel has no version/etag
  check, the last writer wins: the read-write interval is kept short, it is read again and verified after writing, and the
  periodic comparison shows a manual change as drift.

Accepted risks (developer decision):
- **The `@api` exemption does not look at the value and is valid from every source [Decided].** A request that sends the relevant header (even empty)
  skips that site's role check and passes even when S-06 is off. Same as the existing behaviour; the UI shows this warning
  in the rule form. The backend application's own API authentication is the protection layer.
- **Role-less access from a public IP [Decided].** When the host's `input` policy is `accept`, the non-tailnet branch of the snippets opens the internal sites to
  anyone who knows the name from a public IP without a role check. It is closed by turning the S-06 switch off
  once migration is over: with the switch off, a non-tailnet source gets 403 on role-checked and `open` sites.

## 6. Webhook
1. Body size ≤ 64 KB. The body is read raw.
2. The signature is verified with HMAC over the raw body. The comparison is constant time.
3. The timestamp must be within a ±5 minute window. If the same event arrives again within 24 hours it is rejected. The payload has no
   event ID; the replay key is `aggregateID` + `sequence`.
4. A valid event only triggers a reconcile; the roles in the payload are not used.
5. Responses are short and carry no error details. Rejected requests are logged with rate limiting.

Verified on Zitadel v4.16:
- Header `Zitadel-Signature`, format `t=<unix_ts>,v1=<hex>`.
- Signature: `HMAC-SHA256(key, "<ts>." + rawBody)`.
- There can be several `v1` values, for key rotation; if any matches the signature is valid.

The time window is applied by the `t` value.

## 7. Secret inventory (names and locations only)
| Secret | Location | Use |
|---|---|---|
| Zitadel service user key | `/etc/tagcess/secrets/zitadel-key.json` (ro) | Zitadel API. Role: §10; details ADR 0009 |
| Webhook signing key | `/etc/tagcess/secrets/webhook-signing-key` (ro) | HMAC verification |
| Groups claim signing key (optional) | `/etc/tagcess/secrets/groups-signing-key` (ro); `hook.groups_signing_key_file` | HMAC verification of `/groups` (Zitadel `preuserinfo` rest_call). If not set, `/groups` is not served |
| k8s time-limited ServiceAccount token | **[Proposed]** `/var/lib/tagcess-credentials/` (directory `0700`, file `0600`; outside the SQLite/git/backup directory) | Narrow k8s get/list + selected SSAR; atomic replacement from the UI, the value is never shown back. CA/TLS name and expiry metadata are in the connection profile. If `k8s_auth_dir` is empty no credential is stored (there is no default inside `data_dir`); the connection screen shows a setup error |
| CSRF / session key | `/var/lib/tagcess/csrf-key` (0600; generated on first start if missing) | CSRF token signature |
| Headscale | No secret; unix socket access is protected by file permission | gRPC |
| Setup token **[Proposed]** | Hash in `setup_state`; the plain token only in `/run/tagcess/setup-token` (tagcess UID, `0600`) until it is exchanged, expires (24 h) or the setup is sealed | First admin access before the IdP exists (§14) |
| Setup session **[Proposed]** | Hash in `setup_state`; cookie `__Host-tagcess_setup` | Wizard access until sealed |
| Fresh-stack secrets **[Proposed]**: oauth2-proxy cookie secret, the OIDC client secrets of the Headscale and oauth2-proxy apps, the Actions target signing keys | `/etc/tagcess/stack/secrets/<service>/` (`0600`/`0400`, owner = the service) or `/etc/tagcess/secrets`. The cookie secret is generated by the host helper; the others are received by tagcess from the connected IdP and passed to the helper only through the one-way credential handoff (`/var/lib/tagcess-host/handoff/`, one-time files bound to a request ID, deleted after use). Never in the compose file, environment lines, results, journals or the UI | The managed services (setup-flow.md §5.4) |

The Headscale `config.yaml` never comes to the UI: the container does not mount the config, it only reads the host helper's secret-free `status.json`
summary (current `allowed_groups`, `base_rev`, last operation status); secret fields are neither visible nor changeable from the UI
(ADR 0021 b, **[Decided]**).
- The OIDC client secret is not inside `config.yaml` but in a separate file (the `oidc_client_secret` path). The patch request
  (ADR 0008/0021) contains no secret; secrets stay on the host helper side and the candidate is built on the host from the real config.
  The request can carry only the patch `{"oidc":{"allowed_groups":[...]}}`; extra fields, unknown/duplicate keys or excess size are rejected.
- Pre-auth and API key text is shown only once in the creation response (no-store); it does not enter lists, audit, logs or git (§12).
- k8s credential upload/renewal responses are `Cache-Control: no-store`; the token value is never shown back.
  The credential file does not enter an ordinary SQLite/data backup or the artifact git tree; the UI profile contains only safe
  metadata and the runtime reference. A secret-free comparison does not contain the old/new token text **[Proposed]**.
- The audit diff and git commit are written with fields marked as secret masked. A test checks this.

## 8. Fail-closed rules
- If a read is incomplete or failed, no write is made (Y-03.3, Y-04.5). Zitadel v2 list endpoints filter unauthorised records without returning
  an error; so "complete" = all pages 2xx **and** the number of collected records equals `totalResult`.
- If there is a validation error nothing is applied; on a partial application a verification mismatch is rolled back only if it can be proven that the rollback
  does not widen access, otherwise (for example the Headscale policy) the live state is kept,
  the change is marked `failed` and a critical alert is raised. If it is uncertain whether the write was applied
  (read-back failed) the previous state is not restored, so as not to widen access again; the last verified/good state
  is kept and a critical alert is raised. If only the node expire fails after a verified Headscale policy
  the policy is kept, the change is marked `failed`, a critical alert is raised and the expire is retried (rule 7).
- A change that widens access cannot be saved in an uncertain state (for example the Zitadel role list could not be read).
  Examples: making a site kind "no role", opening a site to a role. While Zitadel cannot be read completely no policy is written,
  no personal pre-auth key is produced and no personal device is re-enabled (§12).
- Unknown webhook event types are ignored. An unknown config field is not written by tagcess.
- **Headscale config exception:** per ADR 0021 there is no automatic
  rollback on any error; the operation stops and is shown in the UI. The conditional rollback rule above
  does not apply to this flow. The maintenance flag stops only the writes that widen (policy, re-enabling, tag, route, pre-auth key creation, DNS);
  writes that narrow (Y-04 expire, key revocation, manual expire/delete) continue **[Decided]**. The ≤5 min bound is exceeded by at most
  the restart window (~120 s). A stuck maintenance is closed by the devops "close maintenance" action (explicit confirmation, audit) **[Decided]**.
- **Observation [Proposed]:** missing k8s pages/401/403/TLS/decode or token expiry does not empty the last full snapshot;
  it produces no absence result and deletes no draft/site/roles. Losing a source does not resolve an alarm; old evidence and a separate freshness remain.
  Target health, two-gate risk or the role matrix is not an automatic permission for an access change.

### Gate cookie lifetime
The access decision depends on the oauth2-proxy cookie in the browser. The cookie is single and shared for all sites
(`cookie_domains` = parent domain) and short (default `1h`, `cookie_refresh` off). **Why:** while the cookie is valid, a role change
in Zitadel is not seen for that request; so the cookie lifetime = the longest delay of a role revocation.
A shorter lifetime means faster revocation and more frequent (silent) re-login. Recommended settings:
`deploy/oauth2-proxy.example.cfg`. To switch accounts, "Sign out" in the top menu is used.

**Sign-out really signs out.** Deleting only the oauth2-proxy cookie is not enough: because the Zitadel session stays open, `/oauth2/start` signs back in with the same
user. If `gate.client_id` is set the sign-out address carries the Zitadel `end_session` address as `rd`. Inputs are validated
(`https` issuer, plain client id, absolute `https` return address; if invalid nothing is produced/started) and the result contains only percent-encoded characters,
so it can safely enter HTML and the Caddyfile. The return address is fixed (`https://<tagcess_host>/`); request input such as the `Host` header
does not enter the redirect. Zitadel returns only to a registered post-logout URI: tagcess **adds** this single address to the oauth2-proxy app (it does not delete/change
any existing URI; the write is verified by read-back). `whitelist_domains` contains only the Zitadel host (the open-redirect surface
does not grow).

## 9. Audit
- Every change is recorded with: actor, time, request source (UI, sync, rollback), diff and result.
- The log is append-only; there is no UPDATE or DELETE query in the application code. A test checks this.
- Terminal records (change, sync_run, audit) are retried a limited number of times; if they still cannot be written, the applied
  external write remains in `changes`/`sync_runs` and a critical `policy_bookkeeping_failed` alert is
  written through an independent path; so an applied change is not silently lost.
- Git commits are the artifact history and do not replace audit.
- **[Proposed]** connection/scope/profile/allow list, credential replacement, draft and ack/maintenance actions are audited without secrets
  behind devops+CSRF. SSAR/evidence carries only principal/resource/verb/scope/time/result; it carries no token,
  custom header or response body. Maintenance/ack can silence a health alarm but cannot delete existing operational
  criticals of sync and Headscale management; the writer that owns them resolves them with a verified recovery.

## 10. Broad permissions and their compensations
| Permission | Why it is needed | Compensation |
|---|---|---|
| Headscale unix socket: full admin without credentials | Headscale has no permission-restricted API | The container is read-only and runs non-root; the socket is open only to the headscale group; the `internal/headscale` client wraps only the RPCs used; policy writes pass `CheckPolicy` |
| Headscale administrator client (`internal/headscale/admin`) **[Proposed]**: device delete/name/tag/route, pre-auth and API keys, expiry; same socket, same full admin permission | Device, key and route management is done from the UI (H-01…H-05) | A separate Go type from the narrow sync client; the sync client surface and `TestHeadscale_ExportedSurface` do not change. Used only by devops-confirmed UI flows (`internal/hsadmin`) and the narrow `KeyRevoker` interface. No creation of API keys; no user deletion/renaming; nodes with server tags are protected |
| Host helper stack channel **[Proposed]**: runs `docker compose` as root | Installing and upgrading the fresh-server services from the UI | tagcess gets no Docker socket; typed operations only, no image/path/command in a request; the helper renders the Compose project from its own templates and the version manifest embedded in its binary; ADR 0021 b file rules; every operation audited on the tagcess side (§14) |
| Zitadel `PROJECT_OWNER` (only the `vpn` project) **[Decided]** | What is needed: `user.read`, `user.grant.read`, `project.app.write`. This is the narrowest ready-made role that covers them. Alternative: define a custom role containing only these three permissions with Zitadel's `RolePermissionMappings` setting (a Zitadel config change) | Whatever the role, the `internal/zitadel` client has no grant write or delete function; a test checks this (rule: tagcess never creates users or grants roles) |

## 11. Emergency (break-glass)
If tagcess breaks, access does not stop (NFR-01). If an emergency change is needed:
- A manual change can be made in the Headscale CLI or the Caddyfile. When tagcess is opened again it shows this as drift
  and does not overwrite it (architecture.md §7).
- This path is for emergencies only and is described in the runbook.

## 12. Security controls for Headscale management
The detailed allowlist, TOCTOU and redaction tests are **[Proposed]**; the proof of the upstream race/recovery is **[Open]**.
- **Full permission, no RBAC.** The Headscale unix socket is full admin without credentials; for remote gRPC/REST an API key also gives
  administrator access without per-operation scope. `tagOwners` is not an RBAC that authorises a devops calling admin RPCs. The boundary is tagcess's own VPN/devops
  authentication, its CSRF and its audit; every write sits behind §3 item 1.
- **Personal pre-auth bypasses OIDC filters (H-03).** A device registered with a key does not pass Headscale's OIDC login (`allowed_groups`,
  existing domain/e-mail filters); the role check at creation time does not prove these filters. So: a fresh Zitadel read requires an active
  account and at least one role in the `vpn` project, and if it cannot be read nothing is produced; single use, default 1 hour (the earlier limit of **at most 30 days** for personal keys was lifted **[Decided 2026-10-06]**, see H-03.2; it still applies to tagged keys); the fact that the user/tag
  choice bypasses the OIDC requirement is visible in the UI. Unused keys of a user who lost all roles or was closed are
  revoked at reconcile (`system:sync`, §4). The race between role loss and revocation is accepted **[Decided]**: the next reconcile (≤ 5 min) closes it.
  A key expiring does not expire the existing node.
- **Personal → tagged conversion is irreversible and bypasses Y-04.** `SetTags` removes user ownership; the previous non-empty tag set can be written
  back, but the user-owned → tagged direction does not return. Y-04 expiry is not applied to tagged devices on role loss. The UI asks for extra confirmation with an "irreversible" and "Y-04
  bypass" warning.
- **Legacy key secret.** `ListPreAuthKeys` returns only a masked prefix for new keys, but may return the full secret for legacy plaintext keys. The admin
  DTO filters the secret out of lists for both kinds; the response body is not logged. The creation response is no-store and shown once. The audit holds
  the key ID, user/tag set, flags, expiry and result; there is no key text.
- **Partial `SetPolicy` risk.** Headscale `SetPolicy` does not atomically roll back a partial error, and `GetPolicy` alone does not prove the live administrator
  state. If the result is uncertain, "application uncertain" is shown, new writes stop and the last verified revision is kept. **There is no automatic restore of the
  old policy**; the old document may reopen access and undo current role narrowing. The way out is controlled recovery from the UI
  (architecture.md §4.1). A single writer is an operating condition: an external CLI write is shown as drift.
- **Zitadel owns the role groups.** The role `groups` in the policy are built from the fresh Zitadel result on every write; manually written role groups
  are locked and overwritten. If Zitadel cannot be read completely no policy is written (the CLI emergency path stays in §11).
- **Locked mandatory tests.** In the `tests` section of the policy tagcess keeps: `devops → tag:vpn-server:443` (tagcess UI),
  `tag:k8s →` the vpn-server webhook port, the SSH access rule. An edit that breaks or deletes them is rejected (like S-05 for sites).
  The entries are marked with a `/* tagcess:locked */` HuJSON comment; the comment does not reach Headscale (the old `"#tagcess"` member made Headscale <0.29.4
  reject the policy with "unknown field"). The marker is only for recognition: the security property is rebuilding the canonical set on every save
  and `CheckPolicy` running the tests; a canonical entry whose comment was deleted is still recognised and re-marked.
- **Server-tagged node protection.** Nodes in the server tag list in settings (for example `tag:vpn-server`, `tag:k8s`) cannot be deleted,
  expired or have their tag changed from the UI. The protection is applied not in the sync client's `ExpireNode` but in the calling layer (`internal/hsadmin`, Y-04).
- **UI confirmation does not bypass controls.** Confirmation shows that the diff was seen; validation, `CheckPolicy`, locked tests, base hash, the protection list
  and the fail-closed rules (§8) are not passed by confirmation; the controlled recovery flow also passes the new draft through the same validations.
- **Write pipeline.** Device/route/tag/key writes follow the order fresh read under the shared writer lock → staleness check → "started" audit → RPC → read-back;
  there is no blind retry on an RPC error. Route and tag writes are full-set read-modify-write, so a stale difference is rejected.
  An uncertain result (for example the creation response was lost) is shown as "uncertain"; a second secret is not produced.
- **Dry run (Y-06)** stops only automatic sync and policy writes; the devops's manual device/key actions are applied and the screen shows the
  "dry run is on" note.

## 13. Read-only k8s discovery and measurement boundary **[Proposed]**
See [requirements](requirements.md) K/P; ADR 0030 to 0032 are **Accepted** **[Decided]**. Uploading a time-limited token from the UI/manual renewal and a single Traefik profile
are **[Decided]**; control/transport/data model details remain **[Proposed]** here.

- **Bootstrap and the working identity are separate.** The UI presents the narrow SA/RBAC manifest; an authorised cluster administrator does the first setup
  and the minting of new time-limited tokens. tagcess does not use an admin kubeconfig; it does no `serviceaccounts/token create`,
  RBAC/issuer/controller or other resource writes. An automatic token provider is outside the first release.
  There is an expiry warning and manual renewal in the UI; expiry/401/403 keeps the last full snapshot. The Pod token rotation of a personal k3s PoC
  is not evidence of automatic renewal for tagcess running outside the cluster.
- **Narrow reading, limited permission evidence.** Ingress/Service get/list in selected namespaces, IngressClass cluster-wide;
  Certificate get/list is outside the first release. Secret, pod/log/exec, node/deployment/issuer and wildcard permissions are not needed;
  there is no watch/namespaces list. The proposal of a shared get/list ClusterRole + selected RoleBinding with a separate IngressClass binding
  does not prove all effective permissions. SSAR queries, with the principal/credential tagcess will use, the required
  reads and selected forbidden Secret/token creation/create/update/patch/delete/out-of-scope operations;
  being a POST does not make it a real resource write. No real negative create/update/delete attempt is made.
  The principal, resource-verb-scope, time and queried result are shown. RBAC bindings are additive; a "read-only verified" badge is not given unless
  other bindings/authorizers are covered in an authorised setup review.
- **Credential import cannot execute.** Only endpoint/CA/token is accepted; exec/auth-provider, tokenFile,
  arbitrary CA/client-key/local file paths, proxy mechanisms and `insecure-skip-tls-verify` are rejected. When connecting to the API
  by IP, a separate TLS server name verified against the CA can be chosen in the UI; a hostname mismatch stops the connection.
  The upload passes size/schema checks and a safe connection test; the new credential is atomically replaced in the protected runtime directory,
  and the old file is not overwritten by a failed candidate. The credential value is absent from SQLite/log/audit/git/data backup/response/HTML; no-store is mandatory.
  The API transport sends the bearer only to the selected endpoint/port with the verified CA/TLS name; DNS/dial cannot deviate to a
  loopback/link-local/metadata target, and the environment HTTP proxy and redirects cannot carry the token to another target.
- **Discovery is not opening access.** A separate persistent incomplete draft is separate from a running `site` record; preview only does
  validation/diff/Caddy `/adapt`, and writes no Caddy `/load`, DNS/URI or k8s. Apply goes through the existing `SitePipeline` S-04 under devops+CSRF; fresh source, base hash,
  system lock and drift are preserved. A pure addition may return only to an old base whose result is known and which does not widen access; on edit/delete/an uncertain write the automatic old
  state does not come back. Route loss/host change does not delete the site or change the access choice by itself.
- **Route evidence and network evidence are separate.** Traefik class/annotation or list order is not evidence of the actual winner.
  The first profile has no runtime route collector; a conflict is uncertain + UI review. If reliable route evidence exists,
  taking the discovery default from the controller and asking the user on every conflict is the earlier **[Decided]** rule;
  it is not a claim of existing support. The two-gate result carries configuration risk, source network/vantage, endpoint,
  Host/SNI/path, time/freshness. Internal network success is not evidence of internet reachability / universal closure;
  if there is no external measurement "Internet reachability not tested". CRD/Gateway/hostNetwork and out-of-scope namespaces are shown as
  not scanned. The check does not automatically fix firewall/Headscale/Caddy/k8s; fixing applications is out of scope.
- **Probe SSRF.** The shared API/probe IP/CIDR/port contract has a single owner in the code, with the UI as consumer **[Decided]**; the API and probe scopes do not mix. An endpoint/domain/IP/port coming from the UI is tied to the selected allow list; the resolved address and
  the actual dial address are checked together, and DNS rebinding cannot go outside the allow list. Loopback, link-local,
  metadata, socket and non-allowed target/port are rejected; redirects are not followed. Only a credentialless GET,
  a safe path and expected HTTP codes; there is no custom auth/header/body and no body storage. The locked
  existing system template targets in code may be a separate immutable source of trust; this does not allow adding an
  arbitrary loopback from the UI. Every fixed target is measured or shown as "unsupported/not measured"; it is not automatically
  counted as healthy. Fixture loopback in tests is allowed only in the injected test transport; the product protection is not loosened.
- **TLS source.** The leaf presented on the Caddy/internal gate is measured with each host's SNI; Certificate metadata
  and its polling are deferred from the first release **[Decided]**, and Secrets/private keys are not read. Default CA/hostname verification is on; only a
  credentialless diagnostic handshake may observe an unverified leaf, which becomes "TLS not verified". A wrong
  SAN/chain/expiry is not counted as healthy because of HTTP success.
- **Dashboard boundary.** The matrix is the expected Caddy access of Zitadel roles × site rule; ACL/device/route,
  S-06/source IP, intentional/transition open and API exemption are explained separately. Source times/stale
  states are visible; there is no second user/role store. Maintenance mutes only that site's monitoring alarm and
  does not stop measurement. Ack is not resolution; losing a source does not resolve a health/drift alarm. Operational uncertainty,
  rollback/bookkeeping criticals are resolved only by the owning pipeline; health success gives them no authority.
- **Test environment.** Temporary SQLite + httptest JSON/TLS + fake clock; in an optional personal k3s a separate namespace,
  fixture preparer and reader identity, with cleanup even on quota/limit and errors. There is no global controller/issuer
  change, lab hardening or real negative resource write. The k8s version/Traefik profile/CA/RBAC
  preflight proves only that environment; the research source tag is not a support matrix. The integration tag
  uses the existing compose + a healthy lab Zitadel/the needed host lab; a missing dependency is an explicit skip/error,
  and a real test that did not run is not PASS. Production acceptance tests are separated by an integration+production tag and a separate runtime opt-in/gate; if the env is missing they SKIP before any network call, and the make e2e/hostlab-e2e targets do not select production acceptance. During planning no production/lab access or lab-up is performed.

## 14. Setup mode and the fresh-server stack **[Proposed]**
Design: [setup-flow.md](setup-flow.md) §2 and §5. **[Decided 2026-10-15]** (setup-flow.md §10): the host helper instead of the Docker
socket (O1) and the public setup page behind the token with the SSH tunnel as fallback (O2); tagcess never installs an
IdP (product-decisions §11), so hard rule 3 applies without exception. The control details below stay **[Proposed]**.

- **Setup token.** Created by tagcess while the setup is not sealed: 32 bytes from `crypto/rand`; only its SHA-256 is
  stored; the plain value is written once to `/run/tagcess/setup-token` (`0600`, runtime directory: not in backups,
  gone after a reboot) for the install script (root) to print. Never in a URL, log, audit or response. Valid 24 hours,
  single use; a new token needs root (or the `docker` group) on the host. Comparison is constant time. Attempts are
  rate-limited (5 failures per minute per source, 60 per minute in total, `429`) without a lockout, so strangers cannot
  burn the admin's token. The source address is the `X-Tagcess-Client-IP` header that the bootstrap Caddyfile
  overwrites with the connection's address; it is read only on loopback connections.
- **Setup session.** `__Host-` cookie, `HttpOnly`, `Secure`, `SameSite=Strict`, 1 hour idle and 12 hours absolute; one at
  a time; it opens only `/setup/*`; every state change needs CSRF (T7). Setup actions are audited with a
  `setup:<id>` actor and the source address.
- **Exposure.** Before sealing, Caddy routes `/setup*` of the tagcess host to a loopback setup listener; everything
  else on that host answers "setup pending" until the auth-proxy step is verified, then goes through the normal
  tailnet-only gate (needed for the sealing request). Without free ports 80/443 the page is reachable only through an SSH
  tunnel. The setup listener reads no identity headers, so NFR-02 for the normal UI is unchanged.
- **Sealing is the end of the bypass.** The setup is sealed only after a request with the admin group arrived on
  `ui.sock` through the real gate. Sealing deletes the token and sessions, then removes the route; the listener closes
  even if the Caddy reload fails (a critical alert asks to retry). Re-opening needs a command on the host and is audited.
- **Bootstrap credentials are temporary.** The admin credential pasted for an existing IdP is used in memory and never
  written; it creates only IdP objects (project, roles, apps, Actions targets), never users or grants (hard rule 3).
  Only the narrow `tagcess` service user (§10) stays; it and the first admin's role are created in the IdP console,
  never by tagcess.
- **No Docker socket in tagcess (T19).** Docker documents the daemon and the `docker` group as root-level; a socket proxy
  still allows container creation. The helper accepts only `discover`, `stack.apply`, `stack.remove`,
  `service.restart`, `stack.upgrade` and `handoff.cleanup` with typed parameters (hostnames by the §5 rule, the typed
  settings of setup-flow.md §5.3.1, component switches); it renders the compose file itself, runs
  `docker compose config --quiet` before any change, mounts no Docker socket into any service and never publishes an
  admin port (Caddy admin, Headscale gRPC) beyond loopback.
- **Credential handoff.** Secret values go from tagcess to the helper only as files in the handoff directory, one way:
  one file per allow-listed kind, bound to the request ID, opened with the ADR 0021 b rules, deleted after use, at the
  end of the request, at boot and after 15 minutes; a file for another or a finished request is deleted unread (no
  replay). The helper never hands a secret to tagcess (no IdP is installed, so there is no bootstrap key or initial
  password to deliver). Results, journals, logs and audit carry only the kinds, never values.
- **One authority for the Headscale config.** After `stack.apply` creates Headscale, its `config.yaml` changes only
  through the ADR 0021 patch flow with its `base_rev`; the stack channel never re-renders it, so a later stack apply
  cannot undo a narrowed `allowed_groups`. Both helper channels share one host lock and refuse to run while the other
  has an unfinished operation; a stack operation that restarts Headscale holds the ADR 0021 maintenance flag. Stack
  requests carry their own `base_rev`; a stale request is rejected.
- **Release activation stays on the host.** The helper's embedded manifest decides which images may run. A new release
  is activated only by installing its helper as root (`install.sh --upgrade`, checksum-verified); the UI cannot make
  the root helper download new code until releases are signed (#18).
- **Configurable values are typed.** UI settings reach the helper as typed, bounded values (hostnames, canonical IPs and
  prefixes inside allowed ranges, ports, durations); paths only for an existing installation, under an allow-listed
  root and as found by discovery, and never as a place the helper writes. The host paths of the managed stack are fixed
  by the release (setup-flow.md §5.3.1).
- **Discovery reads no secrets.** The host scan copies only allow-listed attributes; WireGuard and kubeconfig contents,
  container environments and Headscale secret fields are never read (tested with canary values).
- **Pinned images (T20).** The release manifest pins every service image by tag and digest; nothing is pulled except
  on an explicit apply or upgrade. A failed upgrade of a stateless service returns to the previous digest; a stateful
  service is not started on its old image automatically, because its data may have been migrated (fail safe: stop and
  alert rather than guess).

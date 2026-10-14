# Requirements

Source: [overview.md](overview.md) §5 (functions) and §9 (decisions). Acceptance criteria use the EARS format:
- `WHEN <trigger> THE system SHALL <response>`
- `IF <unwanted condition> THEN THE system SHALL <response>`

Numbers are used as references in tests and issues (`Y-01.2`).
Labels: **[Decided]** developer decision, **[Proposed]** proposal. Unlabelled items are a direct expansion of a function.

## Sync (Y)

**Y-01 Webhook**
- Y-01.1 WHEN a validly signed Zitadel Actions v2 request arrives THE system SHALL accept it (2xx) and start a full
  reconcile within 5 s (Y-01.4: the event is only a trigger). **[Proposed]** (the duration)
- Y-01.2 IF the signature is missing or invalid THEN THE system SHALL return 401, make no change and record the event.
- Y-01.3 IF the timestamp is older than 5 minutes or the same event arrives again THEN THE system SHALL not process
  the request. **[Proposed]**
- Y-01.4 THE system SHALL not treat the webhook content as the source of truth. The event is only a trigger; current
  role information is always read from the Zitadel API.
- Y-01.5 THE system SHALL make the webhook endpoint reachable only over Tailscale
  (ADR 0003).
- Y-01.6 WHEN several events arrive within 2 s THE system SHALL merge them into a single reconcile. **[Proposed]**

**Y-02 Periodic full comparison**
- Y-02.1 THE system SHALL, by default every 5 minutes, read all assignments of the `vpn` project and compare them with the
  policy groups. The interval is adjustable from the UI. **[Proposed]**
- Y-02.2 WHEN a difference is found THE system SHALL apply it under rules Y-03 and Y-04.
  In dry-run mode it SHALL only report.

**Y-03 Groups**
- Y-03.1 THE system SHALL keep a `group:<role>` in the policy for every role in the Zitadel `vpn` project. Group
  members are active users holding that role; they are written by provider identifier
  (ADR 0002). A role holder who has no user in Headscale (has never joined the VPN) is not written to the
  group and appears in the plan as information; the next sync adds them when the person first joins the VPN.
- Y-03.2 THE system SHALL not touch the parts of the policy other than groups during sync.
- Y-03.3 IF Zitadel cannot be read, returns an error or times out THEN THE system SHALL keep the existing groups,
  empty nothing and show a warning on the dashboard.
- Y-03.4 IF a sync would remove more than 30% of the users, or more than 3 users, from groups
  THEN THE system SHALL not apply the change, SHALL show it on the dashboard as a pending change and SHALL ask for a devops
  approval. **[Proposed]**
- Y-03.5 WHEN a new policy is about to be written THE system SHALL first pass it through Headscale validation. If validation
  fails it SHALL not write.
- Y-03.6 THE system SHALL always produce the same policy from the same input (ordered and deterministic).

**Y-04 Role loss**
- Y-04.1 WHEN a user is left with no role in the `vpn` project THE system SHALL expire that user's Headscale
  devices. **[Decided]**
- Y-04.2 WHEN a user is deactivated, locked or deleted in Zitadel THE system SHALL expire their
  devices. **[Decided]**
- Y-04.3 WHEN a user's role changes but at least one role remains THE system SHALL only update
  the group membership and not touch the devices. **[Decided]**
- Y-04.4 THE system SHALL not delete devices, only expire them. **[Decided]**
- Y-04.6 THE system SHALL not expire tagged (shared) devices on role loss. **[Proposed]** In Headscale v0.29.4
  `SetTags` moves the node's `UserID` to the built-in `tagged-devices` user (observed on v0.29.4); the owner of a tagged node is the tag. So
  the filter looks explicitly at the tag, not at `UserID` (see stack notes).
- Y-04.5 IF the user's state and grant list were not read successfully (2xx, completely paginated) from Zitadel in that reconcile
  THEN THE system SHALL not expire. "Complete" means the number of collected records equals `totalResult` in the response:
  the v2 list endpoints filter out unauthorised records without returning an error.

**Y-05 Diff report**
- Y-05.1 THE system SHALL show the Zitadel and Headscale state and the difference between them: missing and extra members,
  unmatched users.
- Y-05.2 THE system SHALL show the time of the last sync, its trigger (webhook, periodic, manual) and its
  result.

**Y-06 Dry run**
- Y-06.1 WHILE dry-run mode is on THE system SHALL compute and show the difference but not write to Headscale
  and not expire devices.
- Y-06.2 THE system SHALL start in dry-run mode on first installation. Turning the mode off is written to the audit log.
  **[Proposed]**

## Sites (S)

**S-01 List**
- S-01.1 THE system SHALL show every site: name(s), kind, roles, target, last change. The health status column
  arrives with K-02.

**S-02 Record**
- S-02.1 THE system SHALL allow adding, editing and deleting sites. The fields are as in S-02 of
  [overview.md](overview.md).
- S-02.2 THE system SHALL support three kinds: role-checked (`role`), no role (`open`; `open_reason` intentional or
  transition) and system site (`system`, locked template: `zitadel`, `headscale`, `wireguard_ui`, `tagcess`). **[Decided]**
  (ADR 0010)
  - **Import of an existing installation:** on the first import, kinds are assigned as follows: the blocks for the Zitadel gate,
    Headscale and wireguard-ui → system; sites that are intentionally unchecked → intentional; unchecked sites
    awaiting migration → transition; all others → role-checked. **[Decided]**
  - The editable fields of system templates are limited: `zitadel` internal source IP and login path list,
    `headscale` Headplane path switch, `wireguard_ui` on/off switch; `tagcess` has no editable field.
- S-02.6 THE system SHALL define the API exemption with only two rule types: `header_present` (header name; the value is
  not looked at) and `path_regex` (a pattern compiled with Go `regexp`). Rules are combined with OR; there are no free-form
  expressions. **[Decided]** (ADR 0011)
- S-02.3 THE system SHALL let roles be chosen only from the existing roles in the Zitadel `vpn` project.
- S-02.4 IF a field is invalid THEN THE system SHALL reject the record and show the error next to the field.
  Examples: hostname format, forbidden characters, regex does not compile, target address not allowed.
- S-02.5 THE system SHALL keep an optional "target roles" field for sites of the "no role (transition)" kind.
  This way, when WireGuard is switched off, the site is converted to role-checked in one step. **[Proposed]**

**S-03 Generation**
- S-03.1 WHEN a site changes THE system SHALL generate from a single record: Caddyfile, MagicDNS record, redirect URIs of the Zitadel
  oauth2-proxy app. Post-logout URIs are not written. **[Decided]**
- S-03.2 THE system SHALL import all existing internal sites and produce the functional equivalent of the current Caddyfile.
  Equivalence is measured with two tests: equality of the generated text to a golden file (determinism) and equality of the `caddy adapt` JSON of the current and
  generated Caddyfile, with host lists sorted in multi-host blocks. Differences are
  reported. **[Decided]** (ADR 0010)
- S-03.3 THE system SHALL update redirect URIs with the ownership set in ADR 0012: the desired set `D`
  (`/oauth2/callback` for every host of every block that uses `forward_auth`, including tagcess's own site) is compared with the last
  set `O` it wrote; only `O \ D` is deleted and what is missing from `D` is added. Foreign URIs are not touched
  and are shown in the UI with a warning. If the list does not change nothing is written; after writing it is read again and verified. **[Decided]**
  (ADR 0012)
- S-03.4 WHEN MagicDNS records change THE system SHALL write the file atomically to the directory owned by tagcess and verify the changed
  names by querying the `100.100.100.100` resolver. If the expected answer does not arrive in time it warns. **[Decided]**
  (ADR 0013)

**S-04 Apply**
- S-04.1 WHEN a site change is saved THE system SHALL: generate → `/adapt` (syntax only) → `/load`
  (the real validation: Caddy builds the new config in isolation) → write the file atomically only if `/load` succeeded. This way
  a Caddyfile that cannot be loaded is never left on disk (a restart reads the file on disk). **[Decided]**
  (ADR 0005)
- S-04.2 IF `/adapt` or `/load` fails THEN THE system SHALL not touch the file, mark the change as
  not applied and show the error (the running config does not change). IF writing the file fails
  THEN it SHALL restore the previous content with `/load` and raise a critical alert.
- S-04.3 WHEN before saving THE system SHALL show the diff of the change to be generated. **[Proposed]**

**S-05 Locked sites**
- S-05.1 THE system SHALL prevent system sites from being deleted and the `zitadel` and `tagcess` templates from being
  disabled. **[Decided]** (ADR 0010)
- S-05.2 THE system SHALL generate the tagcess site from a fixed template: outside the tailnet → 403 (independent of S-06),
  client-supplied `X-Auth-Request-*` headers are removed, `forward_auth allowed_groups=devops` is fixed. **[Decided]**

**S-06 WireGuard switch**
- S-06.1 THE system SHALL be able to turn the unchecked pass of requests coming from WireGuard on and off with a single global
  setting. The change requires confirmation. **[Proposed]** (the confirmation)
- S-06.2 WHILE the switch is off THE system SHALL return 403 to sources outside the tailnet on role-checked and role-less
  (`open`) sites. The `@api` exemption stays valid from every source. This also closes the hole of role-less access
  from a public IP. **[Decided]**
- S-06.3 THE system SHALL start with the switch on at import (the current behaviour). **[Decided]**

**S-07 Certificates**
- S-07.1 WHEN a domain not covered by the existing wildcards is added THE system SHALL not block the record but
  show a certificate warning. This rule is removed once DNS-01 is in place. **[Decided]**

## Headscale (H)
Items H-01 to H-07 are all **[Decided]** unless marked **[Proposed]**. Unlabelled items are a direct expansion of the function.

**H-01 Devices**
- H-01.1 THE system SHALL list devices: owner, tag, IP, last seen, expiry status. The list is refreshed by simple periodic refresh;
  there are no live updates.
- H-01.2 THE system SHALL be able to perform these operations on devices: rename, expire, delete, tag assignment, route and
  exit node approval. Deletion requires confirmation.
- H-01.3 THE system SHALL allow changing the expiry period and turning a device's expiry on and off. On personal
  devices Y-04 takes precedence. (`toggle_expiry`, **[Decided]**)
- H-01.4 WHEN Y-04 expires a personal device THE system SHALL not re-enable the device automatically when the role returns.
  Re-enabling is done only with administrator approval, reading eligibility (active account and allowed role) fresh. The eligibility read and
  the expiry write are under the same writer lock; a reconcile is triggered after enabling, and the remaining window closes within ≤5 min.
- H-01.5 IF the device carries a server tag (a list in settings; default `tag:vpn-server`, `tag:k8s` **[Proposed]**) THEN THE system
  SHALL refuse deleting, expiring and changing the tag.
- H-01.6 WHILE dry run (Y-06) is on THE system SHALL apply manual device actions and SHALL show the
  "dry run is on" note on these screens; only automatic sync and policy writes stop.

**H-02 Users**
- H-02.1 THE system SHALL match Headscale users with Zitadel users and show them. Unmatched ones
  are marked. There is no user creation.
- H-02.2 THE system SHALL not allow deleting or renaming Headscale users; both are out of scope.

**H-03 Keys**
- H-03.1 THE system SHALL list and revoke pre-auth keys. The key value is shown only once, at the moment it is created,
  and is stored nowhere (including audit, logs and UI responses).
- H-03.2 THE system SHALL produce a personal pre-auth key only for an existing OIDC user, an active account and an allowed role;
  the key must be single use with a default lifetime of 1 hour; there is no upper limit on the lifetime, but the lifetime is always explicit and a time
  in the future (Headscale does not support non-expiring pre-auth keys). **[Decided]** (previously: at most 30 days; the
  30 day limit continues for tagged keys).
- H-03.3 WHEN a user loses their role THE system SHALL revoke their unused personal pre-auth key at the next reconcile
  (≤5 min). The race between role loss and revocation is accepted; tagged and server nodes are not affected.
- H-03.4 THE system SHALL be able to produce a tagged pre-auth key for shared devices (tag owner `group:devops`, H-05.1).
  The user/tag combination for tagged pre-auth is determined by experiment **[Proposed]**.
- H-03.5 THE system SHALL offer only listing, expiring and deleting for API keys; there is no API key creation.
- H-03.6 THE system SHALL show the key lifetime separately from the device expiry (the key lifetime is not the device expiry).

**H-04 ACL / policy**
- H-04.1 THE system SHALL let ACL rules be edited in a form and a raw HuJSON view. In the first version the raw view is a plain textarea
  + a server-side error panel; CodeMirror later (ADR 0007).
- H-04.2 IF the policy fails validation THEN THE system SHALL not save and SHALL show the error.
- H-04.3 THE system SHALL show the `groups` section read-only in the ACL editor. This section belongs to sync; role groups
  are locked.
- H-04.4 THE system SHALL keep the document lossless: grants, ssh, tests, nodeAttrs and comments are preserved byte for byte in form editing and
  rollback; only the target changes (ADR 0020).
- H-04.5 IF the document is empty or has neither `acls` nor `grants` THEN THE system SHALL not save (Headscale treats this as allow-all);
  passing CheckPolicy does not remove this protection.
- H-04.6 THE system SHALL rebuild the locked mandatory tests (marked in `tests` with a `/* tagcess:locked */` comment **[Proposed]**) on every save
  (devops → `tag:vpn-server`:443 tagcess UI; `tag:k8s` → vpn-server webhook port; SSH access rule) and SHALL reject an
  edit that breaks them (as S-05 does for sites). Test parameters come from settings **[Proposed]**.
- H-04.7 IF Zitadel cannot be read or verified THEN THE system SHALL not write the policy; the CLI emergency path is in
  security.md §11.
- H-04.8 IF CheckPolicy rejects or times out, or the base revision/hash is stale THEN THE system SHALL not change the
  live policy or the last revision. If the application result is unknown, writing stops; there is no automatic restore,
  the only exit is a controlled UI recovery.

**H-05 Tags**
- H-05.1 THE system SHALL manage tags and tagOwners. The owner of shared device tags is `group:devops`. **[Decided]**
- H-05.2 WHEN a personal device is converted to a tagged device THE system SHALL ask for extra confirmation and show the warning "tagged devices are
  not expired on role loss (Y-04 bypass)". The conversion is irreversible.

**H-06 DNS extra records**
- H-06.1 THE system SHALL manage MagicDNS extra records. Those generated from site records are read-only, those added by
  hand are editable.
- H-06.2 THE system SHALL keep manual records in `settings` (`site.manual_dns`).

**H-07 Headscale config**
- H-07.1 THE system SHALL show the secret-free summary of the Headscale config published by the host helper (`status.json`: current
  `allowed_groups`, `base_rev`, last operation ID/status/stage). The raw or masked full `config.yaml` is not shown and is not mounted into
  the container (ADR 0021 b, **[Decided]**).
- H-07.2 WHEN a config change is requested THE system SHALL: show diff → get confirmation → Headscale config test →
  apply → restart → health check (Headscale `/health` returns 200 within 30 s). If it fails it stops and the status is shown in the UI;
  there is no automatic rollback, recovery is manual and controlled (ADR 0021
  simplified). **[Decided]** Restart method: ADR 0008.
- H-07.3 THE system SHALL manage the VPN entry condition (`oidc.allowed_groups`). Default value: `devops`,
  `developer`, `standard`. **[Decided]** At first only `allowed_groups`; DNS fields later. DNS fields are planned separately.

## Import of an existing installation (G) **[Proposed]**
Moving from a hand-managed state to tagcess. Each step is run by the operator against the live installation.
- G-01.1 THE system SHALL be able to import the existing site blocks from a one-time seed file (JSON, prepared by hand; no Caddyfile
  reader is written), the `extra-records.json` records and the parts of the policy other than groups, and show the difference.
  The generated Caddyfile is not applied until the adapt-JSON equality in S-03.2 holds.
  DNS records that match no site host become H-06 manual records; unmatched Zitadel URIs are marked as
  foreign. **[Decided]** (ADR 0010)
- G-01.2 Pointing Headscale `extra_records_path` to tagcess's DNS directory (a config change, `headscale
  configtest`, restart) is a one-time runbook step; once the ADR 0008 helper is available it does the same job.
  (ADR 0013)
- G-02.1 THE system SHALL support the step of moving the policy from file mode to database mode: the existing policy is loaded
  through the API and the result is verified (ADR 0001).
- G-02.2 **Risk:** Headscale does not copy the policy when switching mode. An empty DB policy is treated as "no policy", which
  most likely means everything is open to everyone. So the switch must be made without leaving a moment in which the policy
  is empty. `headscale policy set` goes to the running server over the gRPC socket, so the "write while the server is stopped"
  method probably does not work. The method is found and tried on a compose Headscale and written in the runbook. It is not applied
  against a live installation without being tried. **[Proposed]**
- G-02.3 The switch (config change and restart) is a one-time step against the live installation, done by the operator by hand with the runbook.
- G-03.1 WHEN the first real sync converts e-mail based groups to provider identifiers THE system SHALL show this as
  a single pending change that hits the Y-03.4 threshold; it SHALL list the old and new identity matching person by
  person. An unmatched e-mail blocks approval; if the devops explicitly marks it "drop", approval can be
  given and this is written to the audit log. **[Decided]**
- ~~G-04.1 WHEN tagcess fully covers Headscale management THE system SHALL have provided every function needed so that Headplane
  can be removed. Removal is a step done by the operator.~~ Out of scope:
  Headplane is ignored, tagcess is the only writer of the policy **[Decided]**.

## k8s (K), read-only
The first release supports only **Traefik**, standard Ingress + Service; CRD/Gateway are shown as not scanned **[Decided]**.
Some `[Proposed]` implementation details below have been accepted in the corresponding work items and are marked **[Decided]** there; the rest remain proposals.
ADR 0030 to 0032 are **Accepted** **[Decided]**.
There is no generic refactoring of existing code; the new discovery flow has no host-specific exceptions **[Decided]**.

**K-01 Discovery and site draft**
- K-01.1 WHEN all pages within the selected namespace scope are read successfully and validly THE system SHALL
  publish the Ingress/Service and cluster-scoped IngressClass observations as a single complete snapshot;
  deletion/absence SHALL be inferred only from this snapshot. IF there is a pagination, 401/403, TLS, timeout or decode error
  THEN THE system SHALL keep the previous complete snapshot and its time and show stale/error;
  it SHALL not treat an incomplete result as an empty inventory and SHALL not delete sites. **[Proposed]**
- K-01.2 WHEN a valid new host belonging to the internal profile is found THE system SHALL propose a site draft
  conforming to the site model; it SHALL merge the Ingress/path evidence for the same host and SHALL not split an existing multi-host site.
  A wildcard/empty host, resource backend, ImplementationSpecific path or ambiguous class/default entrypoint
  SHALL not count as an applicable automatic mapping; the reason for review SHALL be shown. The backend Service/ClusterIP/PodIP
  SHALL not become the target URL; the verified Caddy → internal listener SHALL be used. **[Proposed]**
- K-01.3 WHEN the user stores an incompletely configured suggestion THE system SHALL present the suggestion with its selections
  when it is reopened; storing SHALL not produce any Caddy/DNS/Zitadel/k8s write **[Decided]**. The draft SHALL be kept
  separate from an applied `site` record **[Proposed]**.
- K-01.4 WHEN a private draft is completed THE system SHALL offer the choice between all VPN users (`open/intentional`) or
  selected roles (`role`, at least one role); the access purpose SHALL not change the site kinds
  **[Decided]**. The source rule/S-06, API exemption and system template SHALL be explained separately; an incomplete role list
  SHALL not be turned into VPN-wide access **[Proposed]**.
- K-01.5 WHEN a real route conflict is found THE system SHALL always show a UI review request;
  if the route the controller actually chose is known with reliable evidence, discovery SHALL default to it, otherwise the target
  SHALL stay uncertain. If the answer is delayed the existing Caddy setting SHALL be kept and the new draft SHALL not be applied without confirmation
  **[Decided]**. List order/class name is not evidence; the evidence source/time SHALL be stored **[Proposed]**.
  The first Traefik profile has no runtime winner collector; in the first release a conflict is uncertain + UI review.
  A positive effective-controller route collector/contract is later **[Proposed]**, and is not an exit condition of the first release.
- K-01.6 WHEN a draft is previewed THE system SHALL offer field validation, Caddy `/adapt` and a diff;
  it SHALL make no external system write. WHEN the devops explicitly applies it THE system SHALL use the existing S-04 `SitePipeline`;
  the checks for stale base, system lock, drift and fresh role SHALL not be skipped. **[Proposed]**
- K-01.7 IF the validation/apply step of a confirmed draft fails THEN THE system SHALL not show the draft as applied;
  it SHALL keep S-04's existing conditional rollback contract. Return to a narrower base SHALL be done only for a pure addition whose result is known;
  on an edit/delete or an unknown write the live state SHALL be kept. A rollback failure
  SHALL produce a critical alert and the applied/unknown real state SHALL be visible. **[Proposed]** (see architecture §4)
- K-01.8 WHEN no route matches a managed site in a complete snapshot THE system SHALL keep the site record, access choice and
  roles; it SHALL show the route match and the target response separately. IF the snapshot is incomplete/stale THEN THE system
  SHALL not infer absence. **[Proposed]**
- K-01.9 WHEN a connection is established or a time-limited token is renewed THE system SHALL support, from the UI, the namespace scope,
  API endpoint/CA and uploading a time-limited ServiceAccount token, the expiry warning and manual renewal.
  The UI SHALL present the SA/RBAC manifest; the first setup and issuing a new token belong to the authorised cluster administrator;
  tagcess SHALL not use a cluster admin identity or TokenRequest write permission. An automatic credential provider is outside the
  first release **[Decided]**. IF the token expires THEN THE system SHALL keep the last good snapshot and
  show freshness/error; after a new valid token from the UI it SHALL return to full reading **[Proposed]**.
- K-01.10 WHEN the connection identity is evaluated THE system SHALL show SSAR results per resource-verb-scope for the required get/list and for
  forbidden Secret/token creation/writes/out-of-scope operations, with tagcess's effective principal, time and scope; it SHALL not make real negative
  create/update/delete attempts. It SHALL not say "read-only verified" unless other bindings and authorizers are covered in an
  authorised setup review; the result SHALL belong only to the operations tested. An SSAR POST is not a resource modification. **[Proposed]**
- K-01.11 WHEN a credential is uploaded THE system SHALL build a narrow connection model only from endpoint/CA/token fields; it SHALL reject exec/auth-provider,
  tokenFile/arbitrary local paths and kubeconfigs that disable TLS verification. The credential SHALL be written atomically to a protected separate
  runtime directory; its value SHALL not appear in SQLite/log/audit/git/backups/responses. If needed, a separate TLS server name
  SHALL be defined from the UI together with the verified CA. **[Proposed]**

**K-02 Health and presented TLS**
- K-02.1 WHEN a site's check time arrives THE system SHALL store the target TCP/HTTP/TLS result and the Caddy gate result
  as separate observations; Host/SNI/path, endpoint, source network and time SHALL be visible. The check SHALL run every 60 s
  **[Decided]**; a 5 s timeout and at most 4 concurrent probes SHALL be used **[Proposed]**.
- K-02.2 WHEN a credentialless GET response is received THE system SHALL count as target health only the expected status codes chosen in the UI;
  an arbitrary non-5xx response, 401/403/404 or a Caddy login redirect SHALL not automatically count as
  target health. The default path is `/`; there is no body storage, custom auth/header/body or redirect following. **[Proposed]**
- K-02.3 IF the DNS resolution or actual dial IP of a target coming from the UI is not allowed, is loopback/link-local/metadata/socket, or requires a
  redirect THEN THE system SHALL block the connection/following; it SHALL not count a wrong SNI/TLS result as healthy.
  Endpoint and port SHALL depend on the UI allow list; the shared IP/CIDR/port contract has a single owner in the code, with the UI as consumer **[Decided]**. Locked system template targets in code are a separate
  source of trust; they are measured or shown as unsupported, and the UI creates no loopback exception. **[Proposed]** (see security §13)
- K-02.4 WHEN TLS is measured THE system SHALL store, for each host/SNI, the leaf presented by Caddy and by the internal listener,
  NotAfter and the chain/hostname/validity result; only the expiry alert for the same fingerprint may be
  merged, host checks SHALL not be skipped. Secrets/private keys SHALL not be read. If there is an unverified credentialless
  diagnostic measurement, "TLS not verified" SHALL be shown and it SHALL not count as healthy. **[Proposed]**
- K-02.5 WHEN optional Certificate metadata is found THE system SHALL store the metadata separately from the presented leaf, using the mapping
  namespace + Ingress tls.secretName + Certificate spec.secretName; it SHALL treat multiple/missing matches as
  uncertain and show a metadata-new/leaf-old difference as a rollout difference. The absence of a Certificate is not the absence of TLS.
  **[Proposed, deferred]** Not included in the first release; the developer confirmed this **[Decided]**. The presented leaf is the primary source.
- K-02.6 IF a measurement cannot be taken THEN THE system SHALL keep the last successful observation with its time and a stale label;
  it SHALL not present an old successful result as current health after a failed probe. **[Proposed]**
- K-02.7 WHEN a site target is k8s THE system SHALL perform the target check against Caddy's `(k8s)` upstream (ingress,
  for example `https://100.64.0.5:443`) with the site host as Host/SNI; the login redirect of the Caddy gate does not count as backend health,
  and if the backend returns 5xx/404 the target fails and an alert opens. The certificate is not verified in the same way as Caddy's
  `tls_insecure_skip_verify` behaviour; this measurement is not TLS health (the TLS check is separate and verifying). The Ingress
  address enters the probe target list by itself; the probe IP policy SHALL cover this address and 443. System template
  sites are not measured and stay unknown. **[Decided]**

**K-03 Two-gate audit**
- K-03.1 WHEN a managed internal host/path/backend carries an alternative entrypoint or Service gate THE system
  SHALL show the configuration risk, the measurement result and the evidence freshness separately; an expected internal target response
  SHALL not count as evidence of a leaking gate and SHALL not erase the configuration risk. **[Proposed]**
- K-03.2 WHEN a gate is measured from the network tagcess runs on THE system SHALL present evidence only for that vantage, endpoint,
  Host/SNI/path and time; if there is no external measurement it SHALL show "Internet reachability not tested".
  In the first release no separate internet probe component is built **[Decided]**.
- K-03.3 WHEN coverage is reported THE system SHALL show the standard Ingress/Service and selected namespace boundary and
  the "CRD/Gateway not scanned" information **[Decided]**; it SHALL not count hostNetwork and other unobserved paths as
  safe/closed **[Proposed]**. Service NodePort/LB/externalIPs and IPv4/IPv6 candidates are not evidence of reachability. **[Proposed]**
- K-03.4 WHEN a risk/uncertainty is found THE system SHALL offer evidence and review in the UI; it SHALL not automatically fix a firewall, Headscale,
  Caddy or k8s setting. The API exemption and intentional open SHALL be labelled clearly. **[Proposed]**

## Dashboard and alerts (P)
- P-01.1 THE system SHALL show on the dashboard: the number and list of connected devices, last seen times,
  the last sync result, target/Caddy/TLS, drift and k8s observation freshness; each source SHALL carry its own time.
  Headscale connectivity information is not a guarantee of physical reachability. **[Proposed]**
- P-01.2 WHEN the access matrix is shown THE system SHALL show the **expected Caddy role access** derived from Zitadel vpn roles × site rule;
  it SHALL not give a guarantee of effective end-to-end access. The limits of Headscale ACL/device/route,
  S-06/source IP, open intentional/transition, API exemption and system template SHALL be explained separately. **[Proposed]**
- P-01.3 IF the role/site/Headscale source is missing or stale THEN THE system SHALL present the matrix with the last known source
  times and an uncertainty label; it SHALL not create a second persistent user/role store. **[Proposed]**
- P-02.1 THE system SHALL show alerts only on the dashboard; there is no external notification. **[Decided]** Alert types:
  - Sync error
  - Pending change
  - Certificate expiry thresholds (P-02.3) **[Decided]**
  - Target down
  - Drift
- P-02.2 WHEN a successful complete read proves that the Headscale policy/Caddy live config and file/MagicDNS/owned Zitadel
  URI state differs from the last verified artifact/ownership set THE system SHALL show drift
  and the difference; it SHALL not count a source error as drift, SHALL not take over ownership of foreign URIs and SHALL not overwrite
  them automatically. Existing drift and alarm producers SHALL be kept. **[Proposed]**
- P-02.3 WHEN monitoring starts THE system SHALL use target 60 s, inventory 5 min, presented TLS expiry 6 hours;
  health opening after 3 consecutive failures, resolution after 2 consecutive successes; certificate 30/14/7 days info/warning/critical start
  values, and SHALL apply UI changes to subsequent checks **[Decided]**.
  An immediate critical alert for expired/unverifiable TLS is a separate proposal **[Proposed]**.
- P-02.4 WHEN the same type/subject/source observation is repeated THE system SHALL de-duplicate the persistent alarm;
  it SHALL not duplicate after a restart. WHEN a devops gives an ack THE system SHALL record the acknowledging actor/time,
  and SHALL not resolve the alarm; only a fresh successful observation that removes the cause SHALL resolve it. Losing a source is not a resolution. **[Proposed]**
- P-02.5 WHILE a site is in maintenance THE system SHALL continue measurement/evidence and show only that site's monitoring alarm
  as muted. Existing critical alerts for writes, uncertainty, rollback and bookkeeping SHALL not be closed/suppressed by health
  success or maintenance; only the pipeline that owns them SHALL resolve them with a verified recovery. Older open alarms SHALL be preserved in migration. **[Proposed]**
- P-02.6 IF an observation source is cut off/stays stale THEN THE system SHALL keep the last evidence and open a separate freshness
  alert; it SHALL not resolve the earlier health/drift alarm for this reason. **[Proposed]**
- P-02.7 WHEN a devops changes monitoring settings THE system SHALL manage from the UI the namespace scope, intervals/thresholds,
  the Traefik connection profile, the credential/manual renewal status and the site target/path/expected status/maintenance
  settings; devops+CSRF, validation and secret-free audit SHALL apply. **[Proposed]**

## Audit (A)
- A-01.1 THE system SHALL record every change: who (oauth2-proxy identity or `system:sync`), when, what,
  the before and after diff, the result. Secret values do not enter the record.
- A-01.2 THE system SHALL keep the audit log undeletable from the UI.
- A-02.1 WHEN a generated artifact (Caddyfile, policy, MagicDNS and other generated files) is applied successfully
  and verified by read-back/hash THE system SHALL automatically commit only the verified final artifact to the local git
  repository. The commit records the actor (the user who made the change or `system:sync`), the apply
  time, the list of changed files and the resulting Git revision (to link site source versions).
  **[Decided]** (ADR 0016)
- A-02.2 IF the commit content contains a secret THEN THE system SHALL not commit and SHALL produce an alert/audit entry. **[Decided]**
- A-02.3 IF the git commit fails THEN THE system SHALL not disturb the verified live/disk state, SHALL not widen access,
  SHALL write an audit entry + critical alert and SHALL hold the commit as a durable, ordered retry intent;
  it SHALL not show a missing revision as success. **[Decided]**
- A-02.4 IF it is uncertain whether the artifact was applied (read-back failed) THEN THE system SHALL not commit. **[Decided]**
- A-03.1 WHEN a devops selects an earlier site version THE system SHALL show the return only with a read-only preview
  (current site field validation + Caddy `/adapt` + diff) and SHALL record the live base hash at that moment.
  On confirmation the live base SHALL be read again fresh; if it does not match the hash in the preview (another
  change/race in between) the application SHALL be stopped and a warning shown; if it matches, the existing site change pipeline
  SHALL run, the durable site source version and the linked Caddyfile/MagicDNS/owned Zitadel URI artifacts SHALL be updated in a single
  new Change, the selected version SHALL be audited and it SHALL be proven that the next render preserves the return. **[Decided]** (ADR 0017)
- A-03.2 IF the return would break the system site lock (S-05) or access safety (S-06), or would require widening access
  without explicit confirmation (uncertainty/automatic error recovery) THEN THE system SHALL reject the return.
  An explicitly confirmed return may widen access only under current and complete reads, role checks and the S-05/S-06
  locks. **[Decided]**
- A-03.3 The first version covers only the site source snapshot and its Caddyfile/MagicDNS/owned Zitadel URI artifacts; the UI offers no policy
  Apply for rollback. Policy rollback is a separate item after the policy writer and recommends no manual config step.
  The full scope of A-03 is completed with policy rollback. **[Decided]**
- A-03.4 WHEN a site change (normal or return) is applied successfully THE system SHALL store that site's source
  model as a durable version record and link the record to that change's Git revision; every
  recorded version SHALL be selectable from the UI and the site source model SHALL be rebuildable exactly from the selected version.
  **[Decided]**

## Non-functional (NFR) **[Proposed]**
NFR-01, NFR-02 and NFR-09 derive from developer decisions; the others are proposals.
- NFR-01 tagcess is not in the path traffic takes. If tagcess stops, the VPN, Caddy and oauth2-proxy keep working.
- NFR-02 Only the `devops` role reaches the UI. Because other processes can also reach localhost on host network,
  "trust if it comes from localhost" is not enough: the Caddy → tagcess connection is made over a Unix socket with restricted permissions
  and identity headers are trusted only on requests coming from this socket. **[Decided]**
- NFR-03 Every state-changing request is CSRF protected.
- NFR-04 Secrets are read from files. They do not appear in logs, audit, git or the UI.
- NFR-05 External calls have timeouts. On error, access does not widen (fail-closed).
- NFR-06 It runs as a single binary; state is in SQLite. A restart does not lose state.
- NFR-07 Scale: 15-30 users, about 25 sites. A page loads within 1 s. Sync completes within 10 s.
- NFR-08 Tests: every acceptance criterion is tied to at least one automated test. Integration tests run with local Docker Compose
  (Headscale, Caddy, oauth2-proxy) and a lab Zitadel (a small k3s cluster, ADR 0014).
- NFR-09 Nothing is written to k8s resources. A read-only ServiceAccount is used; the chosen effective permission
  SSAR POST query does not count as a resource write. No bootstrap/token creation permission is added to this identity (K-01.9/10).

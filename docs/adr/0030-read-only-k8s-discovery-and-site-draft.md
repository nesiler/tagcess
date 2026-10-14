# 0030: Read-only Kubernetes discovery and a site draft

- Status: Accepted (the developer accepted it, 2026-10-05)
- Date: 2026-09-29
- Decided by: the developer (2026-10-05); proposal: Codex
- Related: K-01, ADR 0010–0014

## Context

Ingress host/path information feeds the site model; but a controller class name is not proof of internal access. The general connection model is not tied to a particular server or controller brand **[Decided 2026-09-29]**; Kubernetes writes are out of scope.

## Decision

**[Decided 2026-09-29]** A discovery/site proposal with missing settings can be stored and completed later from the UI; storing does not change running access settings (developer: "1- definitely yes"). Every route conflict is asked to the user, and while waiting for the answer it is first evaluated by the default behaviour (developer: "in a conflict, ask me in any case but first decide by the default behaviour"). The default source was clarified by a later answer: "we can accept k8s if there is one; if not, nothing can be done." If the route the controller actually chose can be determined reliably, the temporary discovery result is accepted; otherwise it stays uncertain. The running Caddy config is preserved, a new site is not applied without approval; this decision is not acceptance of the ADR as a whole.

**[Proposed]** An incomplete proposal is kept as a draft separate from an applicable site record; a role record keeps its at-least-one-role requirement. The evidence source/time of the controller decision is stored; a class name or list order alone is not evidence.

**[Decided 2026-09-29]** For private sites the UI offers a choice of all VPN users or selected roles (developer: "2-proposal ok"). The site kinds are kept: open/intentional or role; open does not mean public. The access locks of the system templates are kept.

**[Decided 2026-09-29]** The first version scans only standard Ingress + Service paths. Gateway and controller-specific CRD paths show as "not scanned"; they are not counted as safe/closed (developer: "1- proposal OK"). This is not acceptance of the ADR as a whole.

**[Proposed]** A periodic full snapshot is taken with Ingress and Service get/list in selected namespaces and IngressClass get/list at cluster scope; Certificate metadata was deferred out of the first scope **[Decided 2026-10-04]**. No Secret and no write permissions are granted. The internal controller profile is defined in the UI with verified information. Host-based discovery produces a site draft; Caddy/DNS/URI do not change until the required fields of the chosen access control and the target are validated and the admin starts the S-04 flow. Existing multi-host sites are preserved. For each managed site the route match and the target response are shown separately; a missing setting must not change the access choice. No special exception or tracking is made for named services **[Decided 2026-09-29]**.

## First-trial scope (2026-10-04)

- **[Decided]** The developer chose the simplest flow: uploading the CA/token in the UI and renewing it by hand: "OK, let's start with the simplest."
  The UI presents a narrow SA/RBAC manifest, and an authorized cluster admin does the first cluster setup. Token lifetime/renewal state
  and replacement are in the UI; tagcess does not create the SA/RBAC/token. The automatic provider was removed from the first exit condition.
- **[Decided]** The first controller is Traefik: "we already use traefik in the Rancher RKE, there is no nginx, is there?"
  **[Proposed]** The first profile is limited to standard Ingress/Service and the class/listener information in the UI; there is no actual winner collector.
  A conflict without evidence stays uncertain with a review request. The real version is recorded at lab/installation acceptance.
- **[Proposed]** The selected permissions are tested with the working identity through SelfSubjectAccessReview; there is no real resource-write
  attempt. No "read-only verified" result is produced without reviewing all authorizers/bindings.
- The separate persistent draft, the snapshot/data model, the REST client and the security details were carried over as **[Proposed]**
  into the plan. These answers do not accept the ADR as a whole; the ADR as a whole was accepted later, on 2026-10-05 (see the Acceptance section below).

## Simplification approval (2026-10-04)

**[Decided]** The developer said "YES to all questions. Proposals accepted..." to items a-d. Certificate metadata/distribution difference and
polling were deferred out of the first exit; the presented leaf continues as the main source. The two gate candidates and their measurement
were merged; the shared IP/CIDR/port policy and the policy UI have owners in the plan. Runbook content tests
were removed, the existence/link test stayed. This record accepts the four simplification proposals; for the ADR's other design
proposals and the whole, the ADR as a whole was accepted later, on 2026-10-05 (see the Acceptance section below).

## Consequences

- Pro: the site model and fail-safe are preserved; on an incomplete read the last snapshot stays and freshness is visible.
- Scope: CRD/Gateway paths are not scanned in the first version **[Decided 2026-09-29]**; showing other paths such as node hostNetwork as out of scope is **[Proposed]**.
- **[Decided 2026-09-29]** A provable controller route decision is the default; if there is none, the target is uncertain. The ask-the-user requirement is not removed by the default choice. **[Open]** The contract for obtaining this evidence in supported controller/version profiles is not yet settled.
- The first SA/RBAC trust setup and credential renewal were closed for the first trial with the UI/installer flow above **[Decided]**.
  The automatic provider is a later scope **[Proposed]**; a read-only identity cannot create them.
- **[Open]** A narrow RoleBinding is not the whole of an account's effective permissions; RBAC permissions are additive. Secret/token creation/writing and out-of-scope read permissions must be queried in the PoC on behalf of tagcess's actual working identity, without real resource writes. Single negative permission answers do not prove that all permissions are narrow; other bindings/authorization paths must be reviewed separately. The kubelet renews a token projected into a pod; the first identity and renewal channel for tagcess running outside the cluster is not yet verified.
- **PoC observation (2026-09-29; not a decision):** in a dedicated namespace of a personal k3s lab, a narrow Service/Ingress `get/list` account read with a real Pod token across two token periods; sample reads of Secrets and other namespaces were denied. A time-limited token issued from outside the cluster with an authorized setup identity made the same reads, but automatic renewal of the external token was not shown. All bindings/authorizers of the effective account were not audited. No production cluster was connected to; the PoC's temporary resources were removed.
- **[Proposed]** In the external API connection profile, CA verification is mandatory; if the IP used is not in the certificate name, a separate TLS server name can be defined in the UI; a setting that turns verification off is rejected. In the personal lab a connection verified with the CA and the DNS name in the certificate was achieved. This is not evidence about any particular installation.

## Alternatives considered

- Automatic site apply: roles and exemptions cannot be derived safely from Ingress.
- Admin kubeconfig: contradicts least privilege.
- Watching every cluster resource: unnecessary permission/complexity for the first version.

## Acceptance (2026-10-05)

**[Decided 2026-10-05]** The developer accepted: status Proposed -> Accepted. This decision was given after the closing review;
Open items (for example a real k3s run and production acceptance) stay open.

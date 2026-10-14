# 0031: The two-gate check is reported with evidence and uncertainty

- Status: Accepted (the developer accepted it, 2026-10-05)
- Date: 2026-09-29
- Decided by: the developer (2026-10-05); proposal: Codex
- Related: K-03, K-02, ADR 0030

## Context

Ingress/Service metadata shows a candidate alternative gate; an external firewall, the source network, Host/SNI and path change the result. Public applications are out of scope.

## Decision

**[Decided 2026-09-29]** In the first version a check limited to the configuration and to the network it runs in is enough; no separate measurement component testing from the internet is set up. If there is no external measurement, "Internet access not tested" is shown (developer: "3- check is enough"). This decision is not acceptance of the ADR as a whole.

**[Proposed]** For a managed internal host/path/backend, Caddy and the alternative entrypoint/Service candidates are matched. Configuration evaluation, network measurement and evidence freshness/scope are recorded separately; the same route may both carry risk and be unmeasured from the internet. Every observation carries the source network, endpoint, Host/SNI, path and time. A measurement from the network tagcess runs in is not presented as internet access; if there is no external measurement it shows not tested. The expected Caddy -> internal target response is not counted as evidence of a bypass door or an authorization bypass; it does not erase the configuration risk. A profile mismatch is a wrong-entrypoint warning, not the same as a verified access bypass. Redirects are not followed; API exemptions and intentional open sites are labelled explicitly. No automatic access/config fix is made.

## First-trial scope (2026-10-04)

**[Decided]** A single Traefik profile is used (developer: "we already use traefik in the Rancher RKE, there is no nginx, is there?").
**[Proposed]** Standard Ingress/Service and the class/listener/entrypoint information in the UI are evaluated; there is no separate API integration reading the controller's
actual winner in the first trial. If no evidence can be obtained in a conflict, the target stays uncertain + a review request; configuration risk or a network
response is not winner evidence. The real profile/version is recorded at lab and installation acceptance; earlier source tags are not counted as a support matrix.
Reading an installation is the job of a separate production acceptance; until the full separate test at the very end passes, even read-only is forbidden.
The ADR as a whole was accepted later, on 2026-10-05 (see the Acceptance section below).

## Consequences

- Pro: the evidence source of false assurance and false alarms is visible.
- Con: because of paths that are not scanned (firewall, IPv6, CRD), a universal "closed" result cannot be given.
- **[Decided 2026-09-29]** The new design does not depend on host/IP exceptions; no refactor will be done to make existing code generic
  **[Decided 2026-10-04]**. The first profile was narrowed above; a broad version matrix / actual route collector is a later scope **[Proposed]**.
  Existing production information was not verified; a separate acceptance step is pending.
- Sources and the false positive/negative table: the k8s research notes.

## Alternatives considered

- Open/closed from the Ingress class name only: lacks controller config and network evidence.
- Only HTTP 200/body similarity: may be a default backend or a different route.
- Setting up an external probe service: not chosen for the first version **[Decided 2026-09-29]**; unmeasured internet access is stated explicitly.

## Acceptance (2026-10-05)

**[Decided 2026-10-05]** The developer accepted: status Proposed -> Accepted. This decision was given after the closing review;
Open items (for example a real k3s run and production acceptance) stay open.

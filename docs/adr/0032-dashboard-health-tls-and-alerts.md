# 0032: Dashboard health, presented TLS and the alert lifecycle

- Status: Accepted (the developer accepted it, 2026-10-05)
- Date: 2026-09-29
- Decided by: the developer (2026-10-05); proposal: Codex
- Related: K-02, P-01, P-02, ADR 0030–0031

## Context

The certificate Caddy presents may differ from the cert-manager Certificate metadata. The general design is not tied to a particular server or lab **[Decided 2026-09-29]**. Alerts are on the dashboard only **[Decided]**; health measurement does not cover application business logic.

## Decision

**[Decided 2026-09-29]** Target check every 60 s, Kubernetes inventory every 5 min, presented certificate expiry every 6 hours; a health alert opens after 3 consecutive failures and resolves after 2 successes; certificate 30 days info, 14 days warning, 7 days critical. The intervals/thresholds can be changed from the UI and alerts are on the dashboard only (developer: "3- ok"). This answer is not acceptance of the ADR as a whole.

**[Proposed]** The target is measured over HTTP/TCP/TLS and the Caddy access gate separately. The main source of certificate expiry is the leaf presented on the connection for each host/SNI; using the Certificate metadata as a helper source for renewal/distribution differences was deferred out of the first scope **[Decided 2026-10-04]**; Secrets are not read. The dashboard separates the expected role access from effective end-to-end access. Alerts are deduplicated by a source/subject key; there are active/acknowledged/resolved, maintenance and freshness states. A source outage does not resolve an alarm. Frequency and thresholds are managed from the UI; there is no external notification output.

## Plan handover (2026-10-04)

The developer told us to continue if there are no further blocking questions: "if we have questions to settle apart from these, ask, otherwise we can continue."
The measurement/alert/matrix details were split into tasks as **[Proposed]**; this wording does not accept the ADR as a whole,
and the ADR as a whole was accepted later, on 2026-10-05 (see the Acceptance section below). K-02 is health, K-03 is the two gates; the UI interval/threshold and dashboard-only
decisions are kept as **[Decided]**. The first harness is a fixture + a fake clock; no lab hardening is added.
The product's SSRF checks are not lab hardening; credential-free measurement and runtime credential protection continue.

## Simplification approval (2026-10-04)

**[Decided]** The developer said "YES to all questions. Proposals accepted..." to items a-d. Certificate metadata/distribution difference and
polling were deferred out of the first exit; the presented leaf continues as the main source. The two gate candidates and their measurement
were merged; the shared IP/CIDR/port policy and the policy UI have owners in the plan. Runbook content tests
were removed, the existence/link test stayed. This record accepts the four simplification proposals; for the ADR's other design
proposals and the whole, the ADR as a whole was accepted later, on 2026-10-05 (see the Acceptance section below).

## Consequences

- Pro: the measurement model is preserved in a certbot -> Caddy DNS-01 move; no private key is needed.
- Con: the access and TLS seen by the probe source are measured; not every client is guaranteed.
- **[Decided 2026-09-29]** The initial intervals/thresholds and changing them in the UI were approved. **[Decided 2026-10-04]** The Certificate metadata/distribution difference was deferred. **[Proposed]** The alert data model, maintenance/audit, and an immediate critical alert for expired/unverifiable TLS are separate proposals.
- Security: a target allow list, a DNS/dial IP check, redirect rejection and rejection of arbitrary kubeconfig exec are required.
- Sources, model and isolated test / optional lab limits: the k8s research notes.

## Alternatives considered

- cert-manager only: does not show the Caddy/certbot certificate or the presented leaf.
- TCP only: does not separate a wrong host/path/default backend.
- E-mail/chat/webhook: contradicts the developer's dashboard-only decision.

## Acceptance (2026-10-05)

**[Decided 2026-10-05]** The developer accepted: status Proposed -> Accepted. This decision was given after the closing review;
Open items (for example a real k3s run and production acceptance) stay open.

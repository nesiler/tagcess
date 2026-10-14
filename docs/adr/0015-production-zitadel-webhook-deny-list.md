# 0015: Production Zitadel allows the Tailscale range for the webhook

- Status: Proposed   <!-- Proposed | Accepted | Rejected | Superseded by: NNNN -->
- Date: 2026-09-30
- Decided by: proposal from Codex/Claude (finding of an independent security review)
- Related: ADR 0003, Y-01

## Context
ADR 0003 decides that the Zitadel Actions v2 webhook reaches the VPN host's Tailscale address (today
`100.64.0.4:<hook>`) from the Kubernetes host. The system default of Zitadel v4.16.0 `HTTPClient.DenyList`
contains `100.64.0.0/10` (Tailscale CGNAT) and all private ranges; this list rejects a `CreateTarget` call to a
blocked address with `Errors.Target.DeniedURL`. This was seen live on the lab
Zitadel: the target could not be created without overriding the list.

## Decision (proposal)
In the production Zitadel configuration `HTTPClient.DenyList` is narrowed **only** as far as needed to allow the Tailscale webhook
target: the default list is kept, and only `100.64.0.0/10` (Tailscale CGNAT) is removed from the list.
The other SSRF protection ranges (`10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16`,
`fc00::/7`, `fe80::/10`, ...) are kept as they are. The form applied in the lab is in `test/lab/zitadel-values.yaml`
(default minus `100.64.0.0/10`).
In addition, target access is narrowed: the Actions target points only to the webhook's address/port
(`100.64.0.4:<hook>`) and Tailscale egress is opened only by the ACL rule `tag:k8s -> tag:vpn-server:<hook-port>`.
The number of targets Zitadel can reach is one and fixed; no other address, port or range
is allowed.

## Consequences
- Pro: the Tailscale-only webhook path of ADR 0003 really works in production.
- Con: once the `100.64.0.0/10` block is lifted, the Zitadel HTTP client can send requests to CGNAT addresses.
  Mitigation: the target is pinned to a single address/port and the egress ACL is narrowed to that port only; the list is not opened
  without these two narrowings.
- Follow-up: applied at installation and verified together with the `tag:k8s -> tag:vpn-server:<port>` ACL.
- Follow-up: not applied until the developer accepts or rejects this proposal.

## Alternatives considered
- Serving the webhook from a non-CGNAT (public or LAN) address: contradicts the "no public endpoint" decision of ADR 0003
  and enlarges the attack surface.
- Emptying `DenyList` completely: needlessly broad; removes SSRF protection for all internal ranges.
